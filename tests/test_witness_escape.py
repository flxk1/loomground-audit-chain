# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""One signed, chain-verified event; typed errors; the quarantine port."""
from __future__ import annotations

import os
import subprocess
import sys
import time

import pytest

from loomground_audit_chain import witness_escape as we
from loomground_audit_chain.mutation_log import MutationLog
from loomground_audit_chain.witness_escape import (
    WITNESS_ESCAPE_KIND,
    WitnessEscapeInputError,
    WitnessEscapeQuarantineError,
    WitnessEscapeVerificationError,
    record_witness_escape,
    recent_witness_escapes,
)


@pytest.fixture
def folder(tmp_path, monkeypatch):
    monkeypatch.setenv("LOOMGROUND_LOG_ROOT", str(tmp_path / "logs"))
    f = tmp_path / "org"
    f.mkdir()
    return str(f)


def _escapes(folder):
    return [e for e in MutationLog(folder).replay()
            if (e.extra or {}).get("kind") == WITNESS_ESCAPE_KIND]


def test_records_exactly_one_signed_event_and_chain_still_verifies(folder):
    log = MutationLog(folder)
    assert log.count() == 0
    result = record_witness_escape(folder, ["/etc/passwd", "/tmp/other"], "bot7", run_since=100.0)
    assert result["audit_id"]
    events = list(log.replay())
    assert len(events) == 1
    evt = events[0]
    assert evt.audit_id == result["audit_id"]
    assert evt.actor == "bot7"
    assert evt.signature and evt.prev_hash
    assert evt.extra["kind"] == WITNESS_ESCAPE_KIND
    assert evt.extra["actor"] == "bot7"
    assert evt.extra["count"] == 2
    assert evt.extra["run_since"] == 100.0
    assert len(evt.extra["paths"]) == 2
    assert log.verify_chain().ok


def test_kind_is_placed_at_extra_kind_and_event_stays_system(folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    [evt] = _escapes(folder)
    assert evt.event == "system"
    assert evt.extra["kind"] == "witness-escape"


def test_relative_paths_recorded_not_bare_absolute_paths(folder):
    record_witness_escape(folder, [f"{folder}/../secrets/keys.pem"], "bot7")
    [evt] = _escapes(folder)
    (path,) = evt.extra["paths"]
    assert not path.startswith(folder)
    assert path.startswith("..")


def test_return_shape_is_audit_id_and_event(folder):
    result = record_witness_escape(folder, ["/etc/passwd"], "bot7")
    assert set(result) == {"audit_id", "event"}
    assert isinstance(result["event"], dict)
    assert result["event"]["audit_id"] == result["audit_id"]


def test_recent_witness_escapes_filters_by_actor(folder):
    record_witness_escape(folder, ["/etc/passwd"], "bot7")
    record_witness_escape(folder, ["/tmp/x"], "bot8")
    assert len(recent_witness_escapes(folder, "bot7")) == 1
    assert len(recent_witness_escapes(folder, "bot8")) == 1
    assert recent_witness_escapes(folder, "nobody") == []


def test_recent_witness_escapes_filters_by_since(folder):
    first = record_witness_escape(folder, ["/etc/passwd"], "bot7")
    time.sleep(0.01)
    second = record_witness_escape(folder, ["/tmp/x"], "bot7")
    ts_first, ts_second = first["event"]["ts"], second["event"]["ts"]
    assert ts_second > ts_first
    midpoint = (ts_first + ts_second) / 2
    assert len(recent_witness_escapes(folder, "bot7", since=None)) == 2
    assert len(recent_witness_escapes(folder, "bot7", since=midpoint)) == 1
    assert len(recent_witness_escapes(folder, "bot7", since=ts_second + 1.0)) == 0


def test_no_witness_escape_recorded_reads_as_empty_not_a_failure(folder):
    assert recent_witness_escapes(folder, "bot7") == []


def test_empty_actor_raises_typed_error_before_writing(folder):
    log = MutationLog(folder)
    with pytest.raises(WitnessEscapeInputError):
        record_witness_escape(folder, ["/etc/passwd"], "")
    assert log.count() == 0


def test_empty_paths_raises_typed_error_before_writing(folder, monkeypatch):
    calls = []
    monkeypatch.setattr(we, "quarantine", lambda *a, **k: calls.append(a))
    log = MutationLog(folder)
    with pytest.raises(WitnessEscapeInputError):
        record_witness_escape(folder, ["  ", ""], "bot7")
    assert log.count() == 0 and calls == []


def test_chain_verification_failure_after_append_raises_and_skips_quarantine(folder, monkeypatch):
    class _FakeVerification:
        ok = False
        broken_links = [{"reason": "simulated"}]
        signature_failures = []
        malformed_lines = 0

    calls = []
    monkeypatch.setattr(we.MutationLog, "verify_chain", lambda self: _FakeVerification())
    monkeypatch.setattr(we, "quarantine", lambda *a, **k: calls.append((a, k)))
    with pytest.raises(WitnessEscapeVerificationError):
        record_witness_escape(folder, ["/etc/passwd"], "bot7")
    assert calls == []


def test_quarantine_port_called_with_public_status_transition(folder, monkeypatch):
    calls = []
    monkeypatch.setattr(we, "quarantine", lambda *a, **k: calls.append((a, k)))
    result = record_witness_escape(folder, ["/etc/passwd"], "bot7", log_root=None)
    [(args, kwargs)] = calls
    assert args == (folder, "bot7", "suspended")
    assert kwargs["actor"] == "system"
    assert kwargs["reason"] == f"witness-escape audit_id={result['audit_id']}"
    assert kwargs["log_root"] is None


def test_quarantine_failure_after_clean_append_raises_typed_error_naming_audit_id(folder, monkeypatch):
    def _boom(*a, **k):
        raise RuntimeError("party store unavailable")

    monkeypatch.setattr(we, "quarantine", _boom)
    with pytest.raises(WitnessEscapeQuarantineError) as excinfo:
        record_witness_escape(folder, ["/etc/passwd"], "bot7")
    [evt] = _escapes(folder)
    assert evt.audit_id in str(excinfo.value)


def test_without_a_quarantine_port_the_record_alone_lands(folder):
    assert we.quarantine is None
    result = record_witness_escape(folder, ["/etc/passwd"], "bot7")
    assert [e.audit_id for e in _escapes(folder)] == [result["audit_id"]]


def test_module_exposes_no_self_clear_path():
    names = {"clear_witness_escape", "clear", "release", "resume",
             "reactivate", "unsuspend", "restore", "activate"}
    assert not (names & set(we.__all__))
    for name in names:
        assert not hasattr(we, name)


def test_cli_record_prints_audit_id_and_exits_zero(folder):
    proc = subprocess.run(
        [sys.executable, "-m", "loomground_audit_chain.witness_escape", "record",
         "--folder", folder, "--actor", "bot7",
         "--paths", "/etc/passwd,/tmp/x", "--since", "100.0"],
        env=dict(os.environ), capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stderr
    audit_id = proc.stdout.strip()
    assert audit_id
    assert [e.audit_id for e in _escapes(folder)] == [audit_id]


def test_cli_record_failure_exits_nonzero_with_clear_message(folder):
    proc = subprocess.run(
        [sys.executable, "-m", "loomground_audit_chain.witness_escape", "record",
         "--folder", folder, "--actor", "bot7", "--paths", "   ,  "],
        env=dict(os.environ), capture_output=True, text=True,
    )
    assert proc.returncode != 0
    assert "witness-escape record failed" in proc.stderr
