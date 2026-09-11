# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""A marker anyone could have written must mint nothing.

A host that certifies an action from an on-disk hold marker signs the marker
with the identity key and binds the signature to the action id, so a forged,
legacy-unsigned or replayed marker fails verification."""
from __future__ import annotations

import json

from loomground_audit_chain.signing import sign_bytes, verify_signature


def _marker_signed_bytes(marker: dict, action_id: str) -> bytes:
    body = json.dumps(marker, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"{action_id}|{body}".encode("utf-8")


def _held(action_id="tu-1"):
    marker = {"action_class": "shell.exec", "audit_id": "evt-1", "folder": "/ws", "evidence": []}
    return {"tool_use_id": action_id, "marker": marker,
            "signature": sign_bytes(_marker_signed_bytes(marker, action_id))}


def test_the_marker_is_signed_when_written():
    env = _held()
    assert env["signature"]
    assert verify_signature(_marker_signed_bytes(env["marker"], "tu-1"), env["signature"])


def test_a_forged_marker_verifies_nothing():
    forged = {"tool_use_id": "tu-forged",
              "marker": {"action_class": "shell.exec", "audit_id": "made-up",
                         "folder": "/ws", "evidence": []},
              "signature": "00" * 64}
    assert not verify_signature(_marker_signed_bytes(forged["marker"], "tu-forged"), forged["signature"])


def test_an_unsigned_legacy_marker_verifies_nothing():
    legacy = {"action_class": "shell.exec", "folder": "/ws"}
    assert not verify_signature(_marker_signed_bytes(legacy, "tu-old"), "")


def test_a_marker_cannot_be_replayed_against_another_action():
    env = _held("tu-real")
    assert not verify_signature(_marker_signed_bytes(env["marker"], "tu-other"), env["signature"])


def test_a_tampered_marker_body_fails():
    env = _held("tu-ok")
    env["marker"]["audit_id"] = "other-decision"
    assert not verify_signature(_marker_signed_bytes(env["marker"], "tu-ok"), env["signature"])
