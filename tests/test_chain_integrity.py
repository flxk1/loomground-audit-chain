# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""Hash chain, head anchor, signature-strip epoch, genesis key pin."""
from __future__ import annotations

import json

from loomground_audit_chain import signing
from loomground_audit_chain.mutation_log import (
    GENESIS_HASH,
    LogEvent,
    MutationLog,
    _canonical_event_hash,
    _signed_bytes,
)


def _log(tmp_path, name="ws"):
    return MutationLog(tmp_path / name, log_root=tmp_path / "logs")


def _ingest(folder, i):
    return LogEvent(event="ingest", folder_path=str(folder), pair_id=f"sha256:p{i}",
                    actor="w", extra={"i": i})


def _lines(log):
    return [json.loads(l) for l in log.log_file.read_text().splitlines() if l.strip()]


def _write(log, lines):
    log.log_file.write_text("\n".join(json.dumps(l) for l in lines) + "\n")


def test_fresh_log_chain_starts_at_genesis(tmp_path):
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    assert _lines(log)[0]["prev_hash"] == GENESIS_HASH
    assert log.head_hash() == _canonical_event_hash(_lines(log)[0])


def test_chain_links_form_correctly(tmp_path):
    log = _log(tmp_path)
    for i in range(3):
        log.append(_ingest(tmp_path / "ws", i))
    lines = _lines(log)
    for i in range(1, 3):
        assert lines[i]["prev_hash"] == _canonical_event_hash(lines[i - 1])


def test_verify_chain_detects_silent_deletion(tmp_path):
    log = _log(tmp_path)
    for i in range(4):
        log.append(_ingest(tmp_path / "ws", i))
    lines = _lines(log)
    del lines[1]
    _write(log, lines)
    r = log.verify_chain()
    assert not r.ok
    assert any(b["reason"] == "prev_hash_mismatch" for b in r.broken_links)


def test_verify_chain_detects_reorder(tmp_path):
    log = _log(tmp_path)
    for i in range(3):
        log.append(_ingest(tmp_path / "ws", i))
    lines = _lines(log)
    lines[0], lines[1] = lines[1], lines[0]
    _write(log, lines)
    assert not log.verify_chain().ok


def test_signature_strip_after_epoch_is_detected(tmp_path):
    log = _log(tmp_path)
    for i in range(3):
        log.append(_ingest(tmp_path / "ws", i))
    lines = _lines(log)
    lines[2]["signature"] = ""
    _write(log, lines)
    r = log.verify_chain()
    assert not r.ok
    assert any(f["reason"] == "unsigned_event_after_signing_epoch" for f in r.signature_failures)


def test_tail_truncation_is_detected_by_anchor(tmp_path):
    log = _log(tmp_path)
    for i in range(4):
        log.append(_ingest(tmp_path / "ws", i))
    _write(log, _lines(log)[:2])
    r = log.verify_chain()
    assert not r.ok
    assert any(b["reason"] == "tail_truncation_anchored_head_missing" for b in r.broken_links)


def test_deleted_log_with_surviving_anchor_is_detected(tmp_path):
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    log.log_file.unlink()
    r = log.verify_chain()
    assert not r.ok and r.total_events == 0


def test_absent_log_without_anchor_still_verifies(tmp_path):
    log = _log(tmp_path)
    assert log.verify_chain().ok
    assert log.head_hash() == GENESIS_HASH


def test_forged_anchor_signature_is_rejected(tmp_path):
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    af = log._anchor_file()
    data = json.loads(af.read_text())
    data["signature"] = "00" * 64
    af.write_text(json.dumps(data))
    r = log.verify_chain()
    assert not r.ok
    assert any(b["reason"] == "anchor_signature_invalid" for b in r.broken_links)


def test_verification_result_is_truthy_iff_ok(tmp_path):
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    assert bool(log.verify_chain()) is True
    lines = _lines(log)
    lines[0]["actor"] = "x"
    _write(log, lines)
    assert bool(log.verify_chain()) is False


# --- genesis key pin ------------------------------------------------------------

def test_pinning_off_by_default_no_registration_event(tmp_path):
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    assert [e["event"] for e in _lines(log)] == ["ingest"]
    r = log.verify_chain()
    assert r.ok and r.key_pin is None


def test_pinning_on_registers_at_genesis_and_verifies(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_PINNING", "1")
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    log.append(_ingest(tmp_path / "ws", 1))
    events = _lines(log)
    assert events[0]["event"] == "key_registration"
    assert events[0]["extra"]["identity_fingerprint"] == signing.identity_fingerprint_or_none()
    r = log.verify_chain()
    assert r.ok and r.key_pin["registered"] and r.key_pin["pin_file"] == "match"


def test_pin_file_written_once_and_relocatable(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_PINNING", "1")
    pin_dir = tmp_path / "readonly_pins"
    monkeypatch.setenv("WORKSPACE_KEY_PIN_DIR", str(pin_dir))
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    pins = list(pin_dir.rglob("identity.pin"))
    assert pins and json.loads(pins[0].read_text())["fingerprint"] == signing.identity_fingerprint_or_none()


def _rewrite_rekeyed(log, monkeypatch, tmp_path):
    lines = _lines(log)
    monkeypatch.setenv("WORKSPACE_KEY_DIR", str(tmp_path / "attacker_keys"))
    signing.ensure_keypair()
    new_fp = signing.identity_fingerprint_or_none()
    new_pem = signing.identity_public_pem_or_none()
    prev = GENESIS_HASH
    out = []
    for o in lines:
        o = dict(o)
        if o["event"] == "key_registration":
            o["extra"] = dict(o["extra"], identity_fingerprint=new_fp, identity_pub=new_pem)
        o["prev_hash"] = prev
        o["signature"] = ""
        o["signature"] = signing.sign_bytes(_signed_bytes({**o, "signature": ""}))
        out.append(o)
        prev = _canonical_event_hash(o)
    _write(log, out)


def test_rekeyed_rewrite_is_caught_by_the_relocated_pin(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_PINNING", "1")
    monkeypatch.setenv("WORKSPACE_KEY_PIN_DIR", str(tmp_path / "readonly_pins"))
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    assert log.verify_chain().ok
    _rewrite_rekeyed(log, monkeypatch, tmp_path)
    r = log.verify_chain()
    assert not r.ok
    assert "key_pin_tampered" in {f["reason"] for f in r.signature_failures}
    assert r.key_pin["pin_file"] == "mismatch"


def test_enforcement_is_not_downgradable_by_unsetting_the_env(tmp_path, monkeypatch):
    monkeypatch.setenv("WORKSPACE_KEY_PINNING", "1")
    monkeypatch.setenv("WORKSPACE_KEY_PIN_DIR", str(tmp_path / "readonly_pins"))
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    _rewrite_rekeyed(log, monkeypatch, tmp_path)
    monkeypatch.delenv("WORKSPACE_KEY_PINNING", raising=False)
    assert not log.verify_chain().ok


def test_unregistered_chain_tolerated_unless_strict(tmp_path, monkeypatch):
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    assert log.verify_chain().ok
    monkeypatch.setenv("WORKSPACE_STRICT_KEY_PINNING", "1")
    r = log.verify_chain()
    assert not r.ok
    assert "chain_unregistered" in {f["reason"] for f in r.signature_failures}


# --- two-key tombstone -----------------------------------------------------------

def test_forged_controller_claim_on_tombstone_fails(tmp_path):
    signing.ensure_controller_keypair()
    log = _log(tmp_path)
    log.append(_ingest(tmp_path / "ws", 0))
    log.append(_ingest(tmp_path / "ws", 1))
    log.purge("sha256:p0", legal_basis="art_17_1_a", requester_ref="r", reason="x")
    r = log.verify_chain()
    assert r.ok and r.purged_with_tombstone >= 1
    lines = _lines(log)
    tomb = lines[-1]
    assert tomb["extra"]["erasure_mode"] == "two-key"
    tomb["extra"]["controller_sig"] = "00" * 64
    tomb["signature"] = signing.sign_bytes(_signed_bytes({**tomb, "signature": ""}))
    _write(log, lines)
    log._write_anchor()
    r = log.verify_chain()
    assert not r.ok
    assert "controller_cosignature_invalid_or_unverifiable" in {f["reason"] for f in r.signature_failures}
