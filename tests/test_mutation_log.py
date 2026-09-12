# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The per-folder log primitive: locks, folder identity, events, replay, purge."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from loomground_audit_chain import (
    LOG_ROOT_DEFAULT,
    LogEvent,
    MutationLog,
    folder_hash,
)
from loomground_audit_chain import mutation_log as mutation_log_module
from loomground_audit_chain.mutation_log import purged_pair_ref


class _LockTestFile:
    def __init__(self):
        self.seeks = []

    def fileno(self):
        return 37

    def seek(self, offset):
        self.seeks.append(offset)


def test_file_lock_posix_uses_flock_modes(monkeypatch):
    calls = []
    fake = SimpleNamespace(LOCK_EX=1, LOCK_SH=2, LOCK_UN=3,
                           flock=lambda fd, mode: calls.append((fd, mode)))
    monkeypatch.setattr(mutation_log_module, "_IS_WINDOWS", False)
    monkeypatch.setitem(sys.modules, "fcntl", fake)
    with mutation_log_module._file_lock(_LockTestFile(), exclusive=False):
        calls.append(("body", "ran"))
    assert calls == [(37, fake.LOCK_SH), ("body", "ran"), (37, fake.LOCK_UN)]


def test_file_lock_windows_uses_real_locking_region(monkeypatch):
    calls = []
    fake = SimpleNamespace(LK_LOCK=10, LK_UNLCK=11,
                           locking=lambda fd, mode, size: calls.append((fd, mode, size)))
    fh = _LockTestFile()
    monkeypatch.setattr(mutation_log_module, "_IS_WINDOWS", True)
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    with mutation_log_module._file_lock(fh, exclusive=False):
        calls.append(("body", "ran"))
    assert calls == [(37, fake.LK_LOCK, 1), ("body", "ran"), (37, fake.LK_UNLCK, 1)]
    assert fh.seeks == [0, 0]


def test_file_lock_windows_acquire_failure_is_fail_closed(monkeypatch):
    calls = []

    def locking(fd, mode, size):
        calls.append((fd, mode, size))
        raise OSError("lock unavailable")

    fake = SimpleNamespace(LK_LOCK=10, LK_UNLCK=11, locking=locking)
    monkeypatch.setattr(mutation_log_module, "_IS_WINDOWS", True)
    monkeypatch.setitem(sys.modules, "msvcrt", fake)
    entered = False
    with pytest.raises(OSError, match="lock unavailable"):
        with mutation_log_module._file_lock(_LockTestFile(), exclusive=True):
            entered = True
    assert entered is False
    assert calls == [(37, fake.LK_LOCK, 1)]


def test_file_lock_windows_missing_backend_is_fail_closed(monkeypatch):
    monkeypatch.setattr(mutation_log_module, "_IS_WINDOWS", True)
    monkeypatch.setitem(sys.modules, "msvcrt", None)
    with pytest.raises(RuntimeError, match="requires msvcrt"):
        with mutation_log_module._file_lock(_LockTestFile(), exclusive=True):
            pytest.fail("body must not run without a locking backend")


# --- folder_hash (consumed from loomground-workspace) -------------------------

def test_folder_hash_deterministic(tmp_path):
    p = tmp_path / "x"
    assert folder_hash(p) == folder_hash(p)
    assert len(folder_hash(p)) == 32


def test_folder_hash_distinguishes_paths(tmp_path):
    assert folder_hash(tmp_path / "a") != folder_hash(tmp_path / "b")


def test_folder_hash_handles_string_or_path(tmp_path):
    p = tmp_path / "x"
    assert folder_hash(p) == folder_hash(str(p))


def test_folder_hash_resolves_relative(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert folder_hash(".") == folder_hash(tmp_path)


# --- LogEvent -----------------------------------------------------------------

def test_log_event_requires_pair_id():
    with pytest.raises(ValueError):
        LogEvent(event="ingest", folder_path="/x", pair_id="")


def test_log_event_accepts_empty_folder_path():
    assert LogEvent(event="ingest", folder_path="", pair_id="sha256:abc").folder_path == ""


def test_log_event_rejects_unknown_event():
    with pytest.raises(ValueError):
        LogEvent(event="not_a_real_event", folder_path="/x", pair_id="sha256:abc")


def test_log_event_rejects_unknown_channel():
    with pytest.raises(ValueError):
        LogEvent(event="ingest", folder_path="/x", pair_id="sha256:abc", channel="telegraph")


def test_log_event_round_trip_via_jsonl():
    e1 = LogEvent(event="admit", folder_path="/companies/acme/HR/", pair_id="sha256:abc123",
                  lifecycle_state="admitted", channel="document", problem_id="sha256:p1",
                  source_hash="sha256:s1", actor="agent:nd-rules",
                  extra={"reason": "ok", "confidence": 0.92})
    e2 = LogEvent.from_dict(json.loads(e1.to_jsonl()))
    for f in ("event", "folder_path", "pair_id", "lifecycle_state", "channel",
              "actor", "audit_id", "ts", "extra"):
        assert getattr(e2, f) == getattr(e1, f)


def test_log_event_audit_id_unique_per_construction():
    a = LogEvent(event="ingest", folder_path="/x", pair_id="sha256:abc")
    b = LogEvent(event="ingest", folder_path="/x", pair_id="sha256:abc")
    assert a.audit_id != b.audit_id


# --- append + replay ----------------------------------------------------------

def test_log_creates_directory(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    assert log.log_dir.is_dir()


def test_append_and_replay_round_trip(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    e1 = LogEvent(event="ingest", folder_path="", pair_id="sha256:p1",
                  lifecycle_state="ingested", channel="document")
    assert log.append(e1) == e1.audit_id
    events = list(log.replay())
    assert len(events) == 1
    assert events[0].pair_id == "sha256:p1"
    assert events[0].lifecycle_state == "ingested"
    assert events[0].folder_path == str((tmp_path / "folder").resolve())


def test_append_overwrites_folder_path(tmp_path):
    log = MutationLog(tmp_path / "real", log_root=tmp_path / "logs")
    log.append(LogEvent(event="ingest", folder_path="/totally/wrong/path", pair_id="sha256:p1"))
    [stored] = list(log.replay())
    assert stored.folder_path == str((tmp_path / "real").resolve())


def test_append_raw_convenience(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="ingested")
    [e] = list(log.replay())
    assert e.pair_id == "sha256:p1"


def test_append_order_preserved(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    for i in range(5):
        log.append_raw(event="ingest", pair_id=f"sha256:p{i}", lifecycle_state="ingested")
    assert [e.pair_id for e in log.replay()] == [f"sha256:p{i}" for i in range(5)]


def test_two_folders_have_separate_logs(tmp_path):
    log_a = MutationLog(tmp_path / "HR", log_root=tmp_path / "logs")
    log_b = MutationLog(tmp_path / "Engineering", log_root=tmp_path / "logs")
    log_a.append_raw(event="ingest", pair_id="sha256:hr-pair", lifecycle_state="ingested")
    log_b.append_raw(event="ingest", pair_id="sha256:eng-pair", lifecycle_state="ingested")
    assert {e.pair_id for e in log_a.replay()} == {"sha256:hr-pair"}
    assert {e.pair_id for e in log_b.replay()} == {"sha256:eng-pair"}


def test_two_logs_for_same_folder_share_state(tmp_path):
    path = tmp_path / "folder"
    MutationLog(path, log_root=tmp_path / "logs").append_raw(
        event="ingest", pair_id="sha256:p1", lifecycle_state="ingested")
    [e] = list(MutationLog(path, log_root=tmp_path / "logs").replay())
    assert e.pair_id == "sha256:p1"


# --- partial-write tolerance --------------------------------------------------

def test_malformed_lines_are_skipped(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:good1", lifecycle_state="ingested")
    with log.log_file.open("a") as fh:
        fh.write("this is not valid json\n")
        fh.write('{"event": "ingest"\n')
    log.append_raw(event="ingest", pair_id="sha256:good2", lifecycle_state="ingested")
    assert [e.pair_id for e in log.replay()] == ["sha256:good1", "sha256:good2"]


def test_replay_on_empty_log(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    assert list(log.replay()) == []
    assert log.count() == 0


def test_missing_required_field_in_stored_line_is_skipped(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:good", lifecycle_state="ingested")
    with log.log_file.open("a") as fh:
        fh.write(json.dumps({"event": "ingest", "folder_path": "/x"}) + "\n")
    assert [e.pair_id for e in log.replay()] == ["sha256:good"]


# --- replay_filtered / latest_state / pair_ids --------------------------------

def test_replay_filtered(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="ingested", channel="document")
    log.append_raw(event="ingest", pair_id="sha256:p2", lifecycle_state="ingested", channel="websearch")
    log.append_raw(event="admit", pair_id="sha256:p1", lifecycle_state="admitted")
    docs = list(log.replay_filtered(lambda e: e.channel == "document"))
    assert [d.pair_id for d in docs] == ["sha256:p1"]


def test_latest_state_tracks_transitions(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    for ev, st in (("ingest", "ingested"), ("admit", "admitted"), ("live", "live"), ("delete", "deleted")):
        log.append_raw(event=ev, pair_id="sha256:p1", lifecycle_state=st)
    assert log.latest_state("sha256:p1") == "deleted"


def test_latest_state_unknown_pair(tmp_path):
    assert MutationLog(tmp_path / "folder", log_root=tmp_path / "logs").latest_state("nope") is None


def test_pair_ids_excludes_deleted_by_default(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="live")
    log.append_raw(event="ingest", pair_id="sha256:p2", lifecycle_state="live")
    log.append_raw(event="delete", pair_id="sha256:p1", lifecycle_state="deleted")
    assert log.pair_ids() == {"sha256:p2"}


def test_pair_ids_includes_deleted_when_excludes_overridden(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="live")
    log.append_raw(event="delete", pair_id="sha256:p1", lifecycle_state="deleted")
    assert log.pair_ids(exclude_states=()) == {"sha256:p1"}


def test_count(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    for i in range(3):
        log.append_raw(event="ingest", pair_id=f"sha256:p{i}", lifecycle_state="ingested")
    assert log.count() == 3


# --- purge --------------------------------------------------------------------

def _purge_kwargs():
    return dict(legal_basis="art_17_1_a", requester_ref="test-case-001", reason="test-purge")


def _init_controller_key():
    from loomground_audit_chain import signing
    signing.ensure_controller_keypair()


def test_purge_removes_all_events_for_pair(tmp_path):
    _init_controller_key()
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="ingested")
    log.append_raw(event="admit", pair_id="sha256:p1", lifecycle_state="admitted")
    log.append_raw(event="ingest", pair_id="sha256:p2", lifecycle_state="ingested")
    assert log.purge("sha256:p1", **_purge_kwargs()) == 2
    assert [e.pair_id for e in log.replay() if e.event != "purge"] == ["sha256:p2"]
    assert log.verify_chain().ok


def test_purge_unknown_pair_is_noop(tmp_path):
    _init_controller_key()
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="live")
    assert log.purge("sha256:does-not-exist", **_purge_kwargs()) == 0
    assert len(list(log.replay())) == 1


def test_purge_preserves_other_pairs_malformed_lines(tmp_path):
    _init_controller_key()
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="live")
    with log.log_file.open("a") as fh:
        fh.write("malformed-but-preserved-by-purge\n")
    log.append_raw(event="ingest", pair_id="sha256:p2", lifecycle_state="live")
    log.purge("sha256:p1", **_purge_kwargs())
    raw = log.log_file.read_text()
    assert "malformed-but-preserved-by-purge" in raw
    assert "sha256:p2" in raw
    assert "sha256:p1" not in raw
    assert purged_pair_ref(log.folder_path, "sha256:p1") in raw


def test_purge_requires_documented_grounds(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="live")
    with pytest.raises(ValueError, match="legal_basis"):
        log.purge("sha256:p1")
    with pytest.raises(ValueError, match="unknown legal_basis"):
        log.purge("sha256:p1", legal_basis="art_99", requester_ref="r", reason="x")
    with pytest.raises(ValueError, match="requester_ref"):
        log.purge("sha256:p1", legal_basis="art_17_1_a", reason="x")


def test_purge_single_key_without_controller(tmp_path):
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="live")
    log.append_raw(event="ingest", pair_id="sha256:p2", lifecycle_state="live")
    assert log.purge("sha256:p1", **_purge_kwargs()) == 1
    tomb = [e for e in log.replay() if e.event == "purge"][0]
    assert tomb.extra["erasure_mode"] == "single-key"
    assert tomb.extra["controller_keyid"] is None
    assert log.verify_chain().ok


def test_purged_pair_ref_port_is_rebindable(tmp_path, monkeypatch):
    monkeypatch.setattr(mutation_log_module, "purged_pair_ref",
                        lambda folder, pid: "host-ref:" + pid[-2:])
    log = MutationLog(tmp_path / "folder", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="sha256:p1", lifecycle_state="live")
    log.purge("sha256:p1", **_purge_kwargs())
    assert "host-ref:p1" in log.log_file.read_text()


# --- defaults + tail cache ----------------------------------------------------

def test_default_log_root_is_under_home():
    assert str(LOG_ROOT_DEFAULT).startswith(str(Path.home()))
    assert LOG_ROOT_DEFAULT.parts[-2:] == (".workspace", "log")


def test_resolve_log_root_precedence(tmp_path, monkeypatch):
    from loomground_audit_chain.mutation_log import LOG_ROOT_ENV, resolve_log_root
    assert LOG_ROOT_ENV == "LOOMGROUND_LOG_ROOT"
    assert resolve_log_root() == LOG_ROOT_DEFAULT
    monkeypatch.setenv(LOG_ROOT_ENV, str(tmp_path / "env-root"))
    assert resolve_log_root() == tmp_path / "env-root"
    assert resolve_log_root(tmp_path / "explicit") == tmp_path / "explicit"


def test_unregistered_folder_refused_without_override(tmp_path, monkeypatch):
    from loomground_workspace.folder_context import FolderContextNotAllowed
    monkeypatch.delenv("WORKSPACES_ALLOW_UNREGISTERED", raising=False)
    with pytest.raises(FolderContextNotAllowed):
        MutationLog(tmp_path / "unregistered", log_root=tmp_path / "logs")


def test_many_appends_on_one_instance_chain_verifies(tmp_path):
    folder = tmp_path / "workspace"
    folder.mkdir()
    log = MutationLog(folder, log_root=tmp_path / "log_root")
    for i in range(30):
        log.append(LogEvent(event="ingest", folder_path=str(folder), pair_id=f"pair-{i}"))
    result = log.verify_chain()
    assert result.ok, result
    assert result.total_events == 30


def test_interleaved_writers_invalidate_the_tail_cache(tmp_path):
    folder = tmp_path / "workspace"
    folder.mkdir()
    a = MutationLog(folder, log_root=tmp_path / "log_root")
    b = MutationLog(folder, log_root=tmp_path / "log_root")
    for i in range(6):
        (a if i % 2 == 0 else b).append(
            LogEvent(event="ingest", folder_path=str(folder), pair_id=f"pair-{i}"))
    result = a.verify_chain()
    assert result.ok, result
    assert result.total_events == 6
