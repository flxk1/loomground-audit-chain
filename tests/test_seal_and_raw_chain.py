# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""``seal`` (one-call consumer entry), ``events_from_bytes``, and the
directory-addressed raw-dict pair ``append_event`` / ``read_chain``."""
from __future__ import annotations

import json

from loomground_audit_chain import mutation_log as ml
from loomground_audit_chain.mutation_log import (
    GENESIS_HASH,
    MutationLog,
    _canonical_event_hash,
    _signed_bytes,
    append_event,
    events_from_bytes,
    read_chain,
    seal,
)
from loomground_audit_chain.signing import verify_signature
from loomground_workspace.workspace_registry import load_registry


def test_seal_registers_binds_payload_and_reports_head(tmp_path):
    folder = tmp_path / "ws"
    folder.mkdir()
    out = seal(folder, pair_id="doc:1", payload={"a": 1, "b": [2, 3]},
               extra={"kind": "note"}, log_root=tmp_path / "logs")
    assert out["backend"] == ml.SEAL_BACKEND == "audit-chain"
    assert out["verified"] is True and out["audit_id"]
    log = MutationLog(folder, log_root=tmp_path / "logs")
    [evt] = list(log.replay())
    assert evt.source_hash == ml.content_signature(json.dumps({"a": 1, "b": [2, 3]}, sort_keys=True))
    assert evt.extra == {"kind": "note"}
    assert out["head_hash"] == log.head_hash() != GENESIS_HASH
    paths = [w["path"] for w in load_registry(log_root=tmp_path / "logs")["workspaces"]]
    assert str(folder.resolve()) in paths


def test_seal_ports_are_rebindable(tmp_path, monkeypatch):
    folder = tmp_path / "ws"
    folder.mkdir()
    seen = []
    monkeypatch.setattr(ml, "register_workspace", lambda f, log_root=None: seen.append(str(f)))
    monkeypatch.setattr(ml, "content_signature", lambda text: "fixed-fp")
    monkeypatch.setattr(ml, "SEAL_BACKEND", "host-x")
    out = seal(folder, pair_id="doc:2", payload="x", log_root=tmp_path / "logs")
    assert seen == [str(folder)] and out["backend"] == "host-x"
    [evt] = list(MutationLog(folder, log_root=tmp_path / "logs").replay())
    assert evt.source_hash == "fixed-fp"


def test_events_from_bytes_matches_replay_tolerance(tmp_path):
    log = MutationLog(tmp_path / "ws", log_root=tmp_path / "logs")
    log.append_raw(event="ingest", pair_id="p1", lifecycle_state="live")
    log.append_raw(event="ingest", pair_id="p2", lifecycle_state="live")
    data = log.log_file.read_bytes() + b"not json\n" + b"\xff\xfe\n" + b'{"event":"ingest"}\n'
    assert [e.pair_id for e in events_from_bytes(data)] == ["p1", "p2"]


def test_append_event_and_read_chain_link_and_sign(tmp_path):
    d = tmp_path / "unscoped"
    a = append_event(d, {"kind": "namespace_migration", "from": "/a", "to": "/b"})
    b = append_event(d, {"kind": "other"})
    events = list(read_chain(d))
    assert [e["audit_id"] for e in events] == [a, b]
    assert events[0]["prev_hash"] == GENESIS_HASH
    assert events[1]["prev_hash"] == _canonical_event_hash(events[0])
    for e in events:
        assert verify_signature(_signed_bytes({**e, "signature": ""}), e["signature"])
        assert "ts" in e


def test_read_chain_default_root_and_missing_log(tmp_path, monkeypatch):
    assert list(read_chain(tmp_path / "nowhere")) == []
    monkeypatch.setenv(ml.RVND_LOG_ROOT_ENV, str(tmp_path / "root"))
    append_event(tmp_path / "root" / "unscoped", {"kind": "k"})
    assert [e["kind"] for e in read_chain()] == ["k"]
