# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""loomground-audit-chain — append-only, hash-chained, Ed25519-signed event log.

Modules: :mod:`.mutation_log` (the chain), :mod:`.signing` (keys),
:mod:`.witness_escape` (out-of-territory records), :mod:`.audit_drop`
(dropped-write marker), :mod:`.pillar` (``intact`` attestation record).
"""
from __future__ import annotations

from . import audit_drop, mutation_log, pillar, signing, witness_escape
from ._version import __version__
from .mutation_log import (
    GENESIS_HASH,
    LOG_ROOT_DEFAULT,
    VALID_EVENTS,
    VALID_LEGAL_BASES,
    ChainVerificationResult,
    DiskFullError,
    LogEvent,
    MutationLog,
    SealedWriteError,
    append_event,
    events_from_bytes,
    folder_hash,
    legacy_folder_hash,
    read_chain,
    resolve_log_root,
)
from .pillar import intact_attestation

__all__ = [
    "__version__",
    "audit_drop", "mutation_log", "pillar", "signing", "witness_escape",
    "GENESIS_HASH", "LOG_ROOT_DEFAULT", "VALID_EVENTS", "VALID_LEGAL_BASES",
    "ChainVerificationResult", "DiskFullError", "LogEvent", "MutationLog",
    "SealedWriteError", "append_event", "events_from_bytes", "folder_hash",
    "legacy_folder_hash", "read_chain", "resolve_log_root",
    "intact_attestation",
]
