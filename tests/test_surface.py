# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 flxk1
"""The preserved public surface (docs/seam.md), the workspace re-exports,
and the host-agnostic boundary."""
from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

import loomground_workspace.identity as lw_identity
import loomground_workspace.paths as lw_paths

SURFACE = {
    "mutation_log": [
        "ChainVerificationResult", "DiskFullError", "GENESIS_HASH", "LOG_ROOT_DEFAULT",
        "LogEvent", "MutationLog", "SealedWriteError", "VALID_EVENTS", "VALID_LEGAL_BASES",
        "_canonical_event_hash", "_file_lock", "_filesystem_is_case_insensitive",
        "_signed_bytes", "append_event", "events_from_bytes", "folder_hash",
        "legacy_folder_hash", "read_chain",
        # named in the seam contract beyond seam-surface.json
        "resolve_log_root", "seal",
    ],
    "signing": [
        "_controller_private_key_path", "_host_id", "_key_root_dir",
        "ensure_controller_keypair", "ensure_keypair", "fingerprint_of",
        "identity_public_key_or_none", "migrate_legacy_keypair_to_host_subdir",
        "public_controller_key_fingerprint", "public_key_fingerprint", "public_key_pem",
        "sign_bytes", "sign_with_controller", "verify_controller_signature",
        "verify_controller_signature_strict", "verify_signature",
    ],
    "witness_escape": [
        "WITNESS_ESCAPE_KIND", "WitnessEscapeInputError", "WitnessEscapeQuarantineError",
        "WitnessEscapeVerificationError", "recent_witness_escapes", "record_witness_escape",
        "main",
    ],
    "audit_drop": ["MARKER_NAME", "durable_drops", "record"],
}

COMPAT_CONSTANTS = {
    ("mutation_log", "RVND_LOG_ROOT_ENV"): "RVND_LOG_ROOT",
    ("signing", "KEY_DIR_ENV"): "WORKSPACE_KEY_DIR",
    ("audit_drop", "LOG_ROOT_ENV"): "WORKSPACE_L0_LOG_ROOT",
}


@pytest.mark.parametrize("module,names", sorted(SURFACE.items()))
def test_every_preserved_name_is_importable(module, names):
    mod = importlib.import_module(f"loomground_audit_chain.{module}")
    missing = [n for n in names if not hasattr(mod, n)]
    assert missing == []


def test_workspace_names_are_re_exported_not_redefined():
    from loomground_audit_chain import mutation_log as ml
    assert ml.folder_hash is lw_identity.folder_hash
    assert ml.legacy_folder_hash is lw_identity.legacy_folder_hash
    assert ml._filesystem_is_case_insensitive is lw_identity._filesystem_is_case_insensitive
    assert ml.LOG_ROOT_DEFAULT is lw_paths.LOG_ROOT_DEFAULT
    src = Path(ml.__file__).read_text()
    for name in ("folder_hash", "legacy_folder_hash", "_filesystem_is_case_insensitive"):
        assert not re.search(rf"^def {name}\(", src, re.M)
    assert not re.search(r"^LOG_ROOT_DEFAULT\s*=", src, re.M)


@pytest.mark.parametrize("key,value", sorted(COMPAT_CONSTANTS.items()))
def test_compatibility_constants_keep_their_values(key, value):
    module, name = key
    assert getattr(importlib.import_module(f"loomground_audit_chain.{module}"), name) == value


def test_signing_default_key_dir_value():
    from loomground_audit_chain import signing
    assert signing.DEFAULT_KEY_DIR.parts[-2:] == (".workspace", "keys")


# Host names spelled character-wise so this file passes the same grep it applies.
_HOST_WORDS = ("r" "v" "n" "d", "cl" "aude", "anth" "ropic", "m" "cp", "CLA" "UDE_CODE")
_HOST_TERMS = re.compile("|".join(_HOST_WORDS), re.I)
_ALLOWED = re.compile(_HOST_WORDS[0].upper() + "_LOG_ROOT")
_HOST_IMPORT = re.compile(r"\b(import|from) " + _HOST_WORDS[0] + r"\b")


def test_source_is_host_agnostic():
    root = Path(__file__).resolve().parents[1] / "src" / "loomground_audit_chain"
    offenders = []
    for py in root.glob("*.py"):
        for i, line in enumerate(py.read_text().splitlines(), 1):
            if _HOST_TERMS.search(line) and not _ALLOWED.search(line):
                offenders.append(f"{py.name}:{i}: {line.strip()}")
            if _HOST_IMPORT.search(line):
                offenders.append(f"{py.name}:{i}: {line.strip()}")
    assert offenders == []


def test_package_root_exports():
    import loomground_audit_chain as pkg
    for name in ("MutationLog", "LogEvent", "ChainVerificationResult", "intact_attestation",
                 "append_event", "read_chain", "__version__"):
        assert hasattr(pkg, name)
    assert pkg.__version__ == "0.1.0"
