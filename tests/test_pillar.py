# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The chain rendered as the ``intact`` pillar; schema check when the
optional governance-certification peer is installed, skip otherwise."""
from __future__ import annotations

import json

import pytest

from loomground_audit_chain.mutation_log import ChainVerificationResult, LogEvent, MutationLog
from loomground_audit_chain.pillar import intact_attestation


def _clean(tmp_path, n=3):
    log = MutationLog(tmp_path / "ws", log_root=tmp_path / "logs")
    for i in range(n):
        log.append(LogEvent(event="ingest", folder_path=str(tmp_path / "ws"), pair_id=f"p{i}"))
    return log


def test_verified_chain_renders_pillar(tmp_path):
    log = _clean(tmp_path)
    rec = intact_attestation(log.verify_chain(), subject=log.folder_id,
                             entry_ref="evt-1", prev_hash="abc", extra={"span": "urn:x:1"})
    assert rec["pillar"] == "intact" and rec["verified"] is True and rec["findings"] == []
    assert rec["intact"] == {"type": "native-chain", "log_id": log.folder_id,
                             "entry_ref": "evt-1", "algorithm": "ed25519+sha256",
                             "prev_hash": "abc"}
    assert rec["chain"]["total_events"] == 3
    assert rec["extra"] == {"span": "urn:x:1"}
    json.dumps(rec)


def test_broken_chain_is_unverified_with_findings():
    result = ChainVerificationResult(
        ok=False, total_events=2, legacy_events=0,
        broken_links=[{"reason": "prev_hash_mismatch"}], malformed_lines=0,
        signature_failures=[{"reason": "ed25519_signature_invalid"}],
        key_pin={"registered": True, "fingerprint": "f", "pin_file": "mismatch"})
    rec = intact_attestation(result, subject="log-1")
    assert rec["verified"] is False
    assert rec["findings"] == ["broken_link:prev_hash_mismatch",
                               "signature_failure:ed25519_signature_invalid",
                               "key_pin:mismatch"]
    assert rec["intact"]["entry_ref"] == "events:2"
    assert "prev_hash" not in rec["intact"]


def test_pillar_validates_against_governance_certification_schema(tmp_path):
    gc = pytest.importorskip("governance_certification")
    jsonschema = pytest.importorskip("jsonschema")
    from importlib import resources
    schema_text = (resources.files(gc) / "schema" / "GovernanceCertification-v1.schema.json").read_text()
    schema = json.loads(schema_text)
    log = _clean(tmp_path)
    rec = intact_attestation(log.verify_chain(), subject=log.folder_id,
                             entry_ref=list(log.replay())[-1].audit_id,
                             prev_hash=list(log.replay())[-1].prev_hash)
    jsonschema.validate(rec["intact"], {**schema["properties"]["intact"],
                                        "$schema": schema["$schema"]})
    predicate = {
        "verdict": "permit", "action_class": "fs.write",
        "issued_at": "2026-09-11T00:00:00Z",
        "enforced": {"mechanism": "host:gate", "blocked_unless_permitted": True,
                     "decision_ref": rec["intact"]["entry_ref"]},
        "overseen": {"required": False},
        "grounded": {"scheme": "https://example.org/scheme", "ref": "opaque",
                     "digest": {"sha256": "00" * 32}},
        "intact": rec["intact"],
        "legitimate": {"policy_fingerprint": "sha256:00"},
    }
    jsonschema.validate(predicate, schema)
