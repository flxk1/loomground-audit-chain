# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Ed25519 layer: keypairs, signatures on append, rewrite detection, legacy
tolerance, position binding, per-host keys, controller key, migration."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from loomground_audit_chain import signing
from loomground_audit_chain.mutation_log import (
    GENESIS_HASH,
    VALID_EVENTS,
    LogEvent,
    MutationLog,
    _canonical_event_hash,
    _signed_bytes,
)


@pytest.fixture
def keydir(tmp_path):
    return tmp_path / "keys"


def _make_event(folder: Path, i: int) -> LogEvent:
    return LogEvent(event="ingest", folder_path=str(folder), pair_id=f"pair-{i}",
                    actor="test", extra={"i": i})


def _lines(log):
    return [json.loads(l) for l in log.log_file.read_text().splitlines() if l.strip()]


def _write(log, lines):
    log.log_file.write_text("\n".join(json.dumps(l) for l in lines) + "\n")


def test_keypair_generated_on_first_use(keydir, tmp_path):
    assert not keydir.exists()
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    log.append(_make_event(tmp_path / "work", 0))
    host_subdir = keydir / signing._host_id()
    assert (host_subdir / "identity.priv").exists()
    assert (host_subdir / "identity.pub").exists()
    assert not (keydir / "identity.priv").exists()


def test_event_carries_signature(tmp_path):
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    log.append(_make_event(tmp_path / "work", 0))
    obj = _lines(log)[0]
    assert len(obj["signature"]) == 128


def test_verify_chain_passes_on_clean_signed_log(tmp_path):
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    for i in range(5):
        log.append(_make_event(tmp_path / "work", i))
    result = log.verify_chain()
    assert result.ok
    assert result.total_events == 5
    assert result.unsigned_events == 0
    assert result.signature_failures == []


def test_signature_detects_chain_rewrite_attack(tmp_path):
    """Delete an event and recompute downstream prev_hash: the hash chain
    re-validates, the signatures do not."""
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    for i in range(5):
        log.append(_make_event(tmp_path / "work", i))
    lines = _lines(log)
    del lines[2]
    for i in range(1, len(lines)):
        lines[i]["prev_hash"] = _canonical_event_hash(lines[i - 1])
    _write(log, lines)
    result = log.verify_chain()
    assert result.broken_links == []
    assert not result.ok
    assert len(result.signature_failures) >= 1


def test_signature_detects_content_modification(tmp_path):
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    log.append(_make_event(tmp_path / "work", 0))
    log.append(_make_event(tmp_path / "work", 1))
    lines = _lines(log)
    lines[0]["actor"] = "attacker"
    _write(log, lines)
    result = log.verify_chain()
    assert not result.ok
    assert len(result.signature_failures) >= 1 or len(result.broken_links) >= 1


def test_unsigned_events_accepted_as_legacy(tmp_path):
    log_dir = tmp_path / ".workspaces"
    log = MutationLog(tmp_path / "work", log_root=log_dir)
    legacy = {
        "event": "ingest", "folder_path": str(log.folder_path), "pair_id": "legacy-pair",
        "actor": "test", "audit_id": "00000000-0000-0000-0000-000000000001",
        "ts": 1700000000.0, "extra": {}, "lifecycle_state": "", "channel": "system",
        "problem_id": "", "source_hash": "", "prev_hash": GENESIS_HASH,
    }
    log.log_file.write_text(json.dumps(legacy) + "\n")
    log.append(_make_event(tmp_path / "work", 99))
    result = log.verify_chain()
    assert result.ok, result.signature_failures
    assert result.total_events == 2
    assert result.unsigned_events == 1
    assert result.signature_failures == []


def test_signed_payload_binds_chain_position(tmp_path):
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    for i in range(3):
        log.append(_make_event(tmp_path / "work", i))
    lines = _lines(log)
    lines[1]["signature"] = lines[2]["signature"]
    _write(log, lines)
    result = log.verify_chain()
    assert not result.ok
    assert len(result.signature_failures) >= 1


_BASE = {"event": "ingest", "folder_path": "/x", "pair_id": "p", "actor": "u", "audit_id": "a",
         "ts": 1.0, "extra": {}, "lifecycle_state": "", "channel": "system", "problem_id": "",
         "source_hash": ""}


def test_signed_bytes_includes_prev_hash():
    assert _signed_bytes({**_BASE, "prev_hash": "GENESIS"}) != _signed_bytes({**_BASE, "prev_hash": "deadbeef"})


def test_canonical_hash_excludes_signature_and_prev_hash():
    h1 = _canonical_event_hash({**_BASE, "prev_hash": "X", "signature": "Y"})
    h2 = _canonical_event_hash({**_BASE, "prev_hash": "A", "signature": "B"})
    assert h1 == h2 == _canonical_event_hash(_BASE)


def test_canonical_hash_deterministic_across_key_order():
    a = {"b": 1, "a": {"y": 2, "x": 1}}
    b = {"a": {"x": 1, "y": 2}, "b": 1}
    assert _canonical_event_hash(a) == _canonical_event_hash(b)


def test_public_key_export(tmp_path):
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    log.append(_make_event(tmp_path / "work", 0))
    pem = signing.public_key_pem()
    assert "-----BEGIN PUBLIC KEY-----" in pem and "-----END PUBLIC KEY-----" in pem


def test_passphrase_encrypts_keys_at_rest_and_chain_still_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_PASSPHRASE", "correct horse battery")
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    log.append(_make_event(tmp_path / "work", 0))
    assert b"ENCRYPTED" in signing._private_key_path().read_bytes()
    assert log.verify_chain().ok
    monkeypatch.delenv("WORKSPACE_KEY_PASSPHRASE")
    assert signing.identity_public_key_or_none() is not None
    assert log.verify_chain().ok


def test_encrypted_key_without_passphrase_fails_loud(monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_PASSPHRASE", "correct horse battery")
    signing.ensure_keypair()
    monkeypatch.delenv("WORKSPACE_KEY_PASSPHRASE")
    with pytest.raises(RuntimeError, match="WORKSPACE_KEY_PASSPHRASE"):
        signing.ensure_keypair()
    monkeypatch.setenv("WORKSPACE_KEY_PASSPHRASE", "wrong passphrase")
    with pytest.raises(RuntimeError, match="did not decrypt"):
        signing.ensure_keypair()


def test_key_rotation_is_a_first_class_event(tmp_path):
    assert "key_rotation" in VALID_EVENTS
    LogEvent(event="key_rotation", folder_path=str(tmp_path / "ws"), pair_id="sha256:rotate",
             actor="controller", extra={"reason": "host move"})


def _forge(prev, event, host, aid, folder, **extra):
    obj = {"event": event, "channel": "system", "folder_path": str(folder),
           "pair_id": f"sha256:{aid}", "lifecycle_state": "", "problem_id": "",
           "source_hash": "", "actor": "controller", "audit_id": aid, "ts": 1.0,
           "extra": extra, "prev_hash": _canonical_event_hash(prev),
           "signature": "", "host_id": host}
    obj["signature"] = signing.sign_bytes(_signed_bytes({**obj, "signature": ""}))
    return obj


def test_key_rotation_marker_suppresses_strict_host_divergence(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_STRICT_HOST_DIVERGENCE", "1")
    log = MutationLog(tmp_path / "ws", log_root=tmp_path / "logs")
    for i in range(2):
        log.append(LogEvent(event="ingest", folder_path=str(tmp_path / "ws"),
                            pair_id=f"sha256:p{i}", actor="w", extra={"i": i}))
    lines = _lines(log)
    rot = _forge(lines[-1], "key_rotation", "newhost0000", "aaaa-rotation", tmp_path / "ws")
    nxt = _forge(rot, "ingest", "newhost0000", "bbbb-postrotate", tmp_path / "ws")
    _write(log, lines + [rot, nxt])
    post = log.verify_chain()
    assert post.ok
    assert not post.host_divergence_warning


def test_host_divergence_without_marker_is_advisory_then_strict(tmp_path, monkeypatch):
    log = MutationLog(tmp_path / "ws", log_root=tmp_path / "logs")
    log.append(LogEvent(event="ingest", folder_path=str(tmp_path / "ws"), pair_id="sha256:p0"))
    lines = _lines(log)
    _write(log, lines + [_forge(lines[-1], "ingest", "newhost0000", "cccc", tmp_path / "ws")])
    advisory = log.verify_chain()
    assert advisory.ok and len(advisory.host_divergence_warning) == 1
    monkeypatch.setenv("WORKSPACE_STRICT_HOST_DIVERGENCE", "1")
    assert not log.verify_chain().ok


# --- per-host keys + controller key ------------------------------------------

def test_per_host_key_generation(keydir):
    signing.ensure_keypair()
    host_id = signing._host_id()
    assert (keydir / host_id / "identity.priv").exists()
    assert (keydir / host_id / "identity.pub").exists()
    assert not (keydir / "identity.priv").exists()
    assert signing._key_root_dir() == keydir


def test_host_id_shape_and_pin(keydir):
    hid = signing._host_id()
    assert len(hid) == 12
    int(hid, 16)
    assert (keydir / "host-id").read_text().strip() == hid


def test_host_id_env_override(monkeypatch):
    monkeypatch.setenv("WORKSPACE_HOST_ID", "abcdef012345")
    assert signing._host_id() == "abcdef012345"


def test_event_stamps_host_id(tmp_path):
    log = MutationLog(tmp_path / "work", log_root=tmp_path / ".workspaces")
    log.append(LogEvent(event="ingest", folder_path=str(tmp_path / "work"),
                        pair_id="pair-host-id-test", actor="test"))
    obj = _lines(log)[0]
    assert obj["host_id"] == signing._host_id() and len(obj["host_id"]) == 12
    assert list(log.replay())[0].host_id == signing._host_id()


def test_controller_key_separate_from_identity_key():
    signing.ensure_keypair()
    signing.ensure_controller_keypair()
    identity_fp = signing.public_key_fingerprint()
    controller_fp = signing.public_controller_key_fingerprint()
    assert len(identity_fp) == 16 and len(controller_fp) == 16
    assert identity_fp != controller_fp


def test_controller_keypair_idempotent():
    signing.ensure_controller_keypair()
    fp_a = signing.public_controller_key_fingerprint()
    signing.ensure_controller_keypair()
    assert fp_a is not None and fp_a == signing.public_controller_key_fingerprint()


def test_controller_key_not_initialised_returns_none_fingerprint():
    assert signing.public_controller_key_fingerprint() is None
    assert signing.controller_public_key_or_none() is None
    assert signing.verify_controller_signature_strict(b"x", "00" * 64) is False


def test_controller_lives_at_flat_root_not_under_host_subdir(keydir):
    signing.ensure_controller_keypair()
    assert (keydir / "controller.priv").exists()
    assert not (keydir / signing._host_id() / "controller.priv").exists()
    assert signing._controller_private_key_path() == keydir / "controller.priv"


def test_controller_sign_and_verify_roundtrip():
    payload = b"tombstone-content-bytes"
    sig = signing.sign_with_controller(payload)
    assert signing.verify_controller_signature(payload, sig) is True
    assert signing.verify_controller_signature(b"tampered", sig) is False
    assert signing.verify_controller_signature_strict(payload, sig) is True


def test_fingerprint_of_matches_identity_readers():
    _, pub = signing.ensure_keypair()
    assert signing.fingerprint_of(pub) == signing.identity_fingerprint_or_none()
    assert signing.identity_public_pem_or_none().startswith("-----BEGIN PUBLIC KEY-----")
    fp, pem = signing.register_identity()
    assert fp == signing.fingerprint_of(pub) and pem == signing.identity_public_pem_or_none()


# --- legacy flat-root keypair migration ---------------------------------------

@pytest.fixture
def legacy_keydir(keydir):
    keydir.mkdir(parents=True, exist_ok=True)
    (keydir / "identity.priv").write_bytes(
        b"-----BEGIN PRIVATE KEY-----\nPLACEHOLDER-PRIVATE\n-----END PRIVATE KEY-----\n")
    (keydir / "identity.pub").write_bytes(
        b"-----BEGIN PUBLIC KEY-----\nPLACEHOLDER-PUBLIC\n-----END PUBLIC KEY-----\n")
    return keydir


@pytest.fixture
def target_log(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    return MutationLog(workspace, log_root=tmp_path / ".workspaces" / "log")


def _events(log):
    if not log.log_file.exists():
        return []
    return [json.loads(l) for l in log.log_file.read_text(encoding="utf-8").splitlines() if l.strip()]


def test_legacy_keypair_moves_into_host_subdir(legacy_keydir, target_log):
    priv_bytes = (legacy_keydir / "identity.priv").read_bytes()
    pub_bytes = (legacy_keydir / "identity.pub").read_bytes()
    host_id = signing.migrate_legacy_keypair_to_host_subdir(audit_log=target_log)
    assert isinstance(host_id, str) and len(host_id) == 12
    assert not (legacy_keydir / "identity.priv").exists()
    assert not (legacy_keydir / "identity.pub").exists()
    assert (legacy_keydir / host_id / "identity.priv").read_bytes() == priv_bytes
    assert (legacy_keydir / host_id / "identity.pub").read_bytes() == pub_bytes


def test_migration_writes_key_migration_audit_event(legacy_keydir, target_log):
    pre = len(_events(target_log))
    signing.migrate_legacy_keypair_to_host_subdir(audit_log=target_log)
    events = _events(target_log)
    assert len(events) == pre + 1
    last = events[-1]
    assert last["event"] == "system" and last["extra"]["kind"] == "key_migration"
    assert last["extra"]["from_path"].endswith("identity.priv")
    assert "host_id" in last["extra"]


def test_migration_is_idempotent(legacy_keydir, target_log):
    a = signing.migrate_legacy_keypair_to_host_subdir(audit_log=target_log)
    n1 = len(_events(target_log))
    b = signing.migrate_legacy_keypair_to_host_subdir(audit_log=target_log)
    assert a == b and len(_events(target_log)) == n1


def test_migration_noop_on_fresh_install(keydir, target_log):
    keydir.mkdir(parents=True, exist_ok=True)
    pre = len(_events(target_log))
    host_id = signing.migrate_legacy_keypair_to_host_subdir(audit_log=target_log)
    assert len(host_id) == 12 and len(_events(target_log)) == pre
