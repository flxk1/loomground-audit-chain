# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The chain as the ``intact`` pillar of a governance certification.

``GovernanceCertification`` (governance-certification, schema v1) requires
five pillars; ``intact`` attests that the decision sits on a tamper-evident
append-only log a verifier can re-check. This module renders that pillar
from a :class:`~.mutation_log.ChainVerificationResult`. The certification
schema is an optional peer: nothing here imports it.
"""

from __future__ import annotations

from typing import Any, Optional

from .mutation_log import ChainVerificationResult

#: ``intact.type`` value for this chain in the certification schema.
INTACT_TYPE = "native-chain"
#: ``intact.algorithm`` value.
ALGORITHM = "ed25519+sha256"


def intact_attestation(
    result: ChainVerificationResult,
    *,
    subject: str,
    entry_ref: str = "",
    prev_hash: str = "",
    extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Render the ``intact`` pillar record for ``subject``'s chain.

    ``intact`` is the schema-shaped pillar object (``type``, ``log_id``,
    ``entry_ref``, ``algorithm``, ``prev_hash`` when given). ``verified`` is
    ``result.ok``; a host mints a certification only when it is true.
    ``findings`` names every reason it is false. ``chain`` carries the
    counts. ``extra`` passes opaque evidence references through unchanged.
    ``entry_ref`` defaults to the whole chain at its current length.
    """
    pillar: dict[str, Any] = {
        "type": INTACT_TYPE,
        "log_id": subject,
        "entry_ref": entry_ref or f"events:{result.total_events}",
        "algorithm": ALGORITHM,
    }
    if prev_hash:
        pillar["prev_hash"] = prev_hash

    findings: list[str] = []
    findings += [f"broken_link:{b.get('reason', '')}" for b in result.broken_links]
    findings += [f"signature_failure:{s.get('reason', '')}" for s in result.signature_failures]
    if result.key_pin and result.key_pin.get("pin_file") == "mismatch":
        findings.append("key_pin:mismatch")

    return {
        "pillar": "intact",
        "verified": bool(result.ok),
        "intact": pillar,
        "findings": findings,
        "chain": {
            "total_events": result.total_events,
            "legacy_events": result.legacy_events,
            "unsigned_events": result.unsigned_events,
            "malformed_lines": result.malformed_lines,
            "purged_with_tombstone": result.purged_with_tombstone,
            "host_divergence": len(result.host_divergence_warning),
            "key_pin": result.key_pin,
        },
        "extra": dict(extra or {}),
    }
