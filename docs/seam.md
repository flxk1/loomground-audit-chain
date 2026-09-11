<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Seam: RVND → loomground-audit-chain

Source: RVND commit `bac579b`, `server/src/rvnd/`. Byte-faithful in behaviour, constants and environment-variable values; docstrings condensed and host references removed.

## Module map

| RVND module (bac579b) | Package module |
|---|---|
| `rvnd/mutation_log.py` | `loomground_audit_chain/mutation_log.py` |
| `rvnd/signing.py` | `loomground_audit_chain/signing.py` |
| `rvnd/witness_escape.py` | `loomground_audit_chain/witness_escape.py` |
| `rvnd/audit_drop.py` | `loomground_audit_chain/audit_drop.py` |
| — | `loomground_audit_chain/pillar.py` (new: `intact_attestation`) |

## Preserved public names

From `seam-surface.json` (names RVND callers import), private names included.

- `mutation_log`: `ChainVerificationResult`, `DiskFullError`, `GENESIS_HASH`, `LOG_ROOT_DEFAULT`, `LogEvent`, `MutationLog`, `SealedWriteError`, `VALID_EVENTS`, `VALID_LEGAL_BASES`, `_canonical_event_hash`, `_file_lock`, `_filesystem_is_case_insensitive`, `_signed_bytes`, `append_event`, `events_from_bytes`, `folder_hash`, `legacy_folder_hash`, `read_chain`. Also kept: `seal`, `resolve_log_root`, `VALID_CHANNELS`, `RVND_LOG_ROOT_ENV`, `KEY_PINNING_ENV`, `STRICT_KEY_PINNING_ENV`, `KEY_PIN_DIR_ENV`.
- `signing`: `_controller_private_key_path`, `_host_id`, `_key_root_dir`, `ensure_controller_keypair`, `ensure_keypair`, `fingerprint_of`, `identity_public_key_or_none`, `migrate_legacy_keypair_to_host_subdir`, `public_controller_key_fingerprint`, `public_key_fingerprint`, `public_key_pem`, `sign_bytes`, `sign_with_controller`, `verify_controller_signature`, `verify_controller_signature_strict`, `verify_signature`. Also kept: `DEFAULT_KEY_DIR`, `KEY_PASSPHRASE_ENV`, `HOST_ID_ENV`, `identity_fingerprint_or_none`, `identity_public_pem_or_none`, `register_identity`, `controller_public_key_or_none`, `_private_key_path`, `_public_key_path`.
- `witness_escape`: `WITNESS_ESCAPE_KIND`, `WitnessEscapeInputError`, `WitnessEscapeQuarantineError`, `WitnessEscapeVerificationError`, `recent_witness_escapes`, `record_witness_escape`. Also kept: `WitnessEscapeError`, `WitnessEscapeRecordError`, `main`.
- `audit_drop`: `MARKER_NAME`, `durable_drops`, `record`. Also kept: `drops`, `clear`.

`folder_hash`, `legacy_folder_hash`, `_filesystem_is_case_insensitive` and `LOG_ROOT_DEFAULT` are re-exported from `mutation_log` and originate in `loomground_workspace` (no local definition; `tests/test_surface.py` asserts identity).

`append_event(log_dir, event: dict) -> audit_id` and `read_chain(log_dir=None) -> Iterator[dict]` were imported by `rvnd/_namespace.py` and `rvnd/adapters/solver/datapump.py` at `bac579b` but undefined in `rvnd/mutation_log.py`. They are defined here as the directory-addressed raw-dict pair over `<log_dir>/events.jsonl`, hash-linked and signed with the same scheme; `read_chain()` defaults to `resolve_log_root() / "unscoped"`.

## Compatibility constants

Module-level names a host may rebind; values unchanged from RVND so a zero-definition shim passes RVND's suite.

| Name | Value | Meaning |
|---|---|---|
| `mutation_log.RVND_LOG_ROOT_ENV` | `"RVND_LOG_ROOT"` | env var redirecting the log root; explicit `log_root=` wins |
| `mutation_log.KEY_PINNING_ENV` | `"WORKSPACE_KEY_PINNING"` | opt-in genesis key registration |
| `mutation_log.STRICT_KEY_PINNING_ENV` | `"WORKSPACE_STRICT_KEY_PINNING"` | unregistered chain fails |
| `mutation_log.KEY_PIN_DIR_ENV` | `"WORKSPACE_KEY_PIN_DIR"` | relocate the TOFU pin file |
| `mutation_log.STRICT_HOST_DIVERGENCE_ENV` | `"WORKSPACE_STRICT_HOST_DIVERGENCE"` | host_id shift fails the chain |
| `mutation_log.SEAL_BACKEND` | `"audit-chain"` | `seal()` result `backend`; RVND rebinds to `"rvnd"` |
| `signing.KEY_DIR_ENV` | `"WORKSPACE_KEY_DIR"` | key root override |
| `signing.DEFAULT_KEY_DIR` | `~/.workspace/keys` | key root default (evaluated at import) |
| `signing.KEY_PASSPHRASE_ENV` | `"WORKSPACE_KEY_PASSPHRASE"` | private keys encrypted at rest |
| `signing.HOST_ID_ENV` | `"WORKSPACE_HOST_ID"` | host_id override |
| `audit_drop.LOG_ROOT_ENV` | `"WORKSPACE_L0_LOG_ROOT"` | marker root when `log_root` is not passed |
| `audit_drop.STDERR_PREFIX` | `"[audit-chain]"` | stderr line prefix (RVND used `[rvnd]`) |
| `audit_drop.MARKER_NAME` | `"audit-drops.jsonl"` | durable marker file |

`RVND_LOG_ROOT_ENV` is the one name in `src/` matching the host-agnostic grep; its value is the compatibility surface.

## Host ports

Module-level callables with defaults; a host rebinds them at import time.

| Port | Default | RVND binding |
|---|---|---|
| `mutation_log.purged_pair_ref(folder, pair_id)` | `"pair-ref:" + sha256("pair-ref" ␟ folder_hash ␟ pair_id)[:16]` | `rvnd.forgotten_subjects.purged_pair_ref` (folder-salted) |
| `mutation_log.content_signature(text)` | whitespace/case-normalised sha256 | `rvnd.attestation.core.signature` (identical) |
| `mutation_log.register_workspace(folder, log_root=)` | `loomground_workspace.workspace_registry.add_known_workspace` | `rvnd.registry.add_known_workspace` |
| `witness_escape.quarantine(folder, actor, "suspended", reason=, actor="system", log_root=)` | `None` (record only) | `rvnd.parties.set_party_status` |

## What stays in RVND, and why

- `rvnd/_storage_paths.py` — RVND's zero-definition shim over `loomground_workspace.paths`; the package imports `LOG_ROOT_DEFAULT` from `loomground_workspace` directly.
- `rvnd/adapters/workspace.py` — RVND's adapter seam that defaults the per-principal scope on `list_known_workspaces`; an access-control policy of the host, absent here. `MutationLog.__init__` calls `loomground_workspace.folder_context.resolve_folder_context`, whose allowlist reads the raw registry, so no scoped read is involved.
- `rvnd/forgotten_subjects.py` (salted refs), `rvnd/parties.py` (party register), `rvnd/registry.py`, `rvnd/attestation/` — host concepts reached through the ports above.
- RVND's tests that exercise governance (`decide_action`, `parties`, `hook`, `lock`, `cli.impl`) stay with RVND; their chain-level halves are ported under `tests/`.

## How a host wires it

RVND shims `rvnd.mutation_log`, `rvnd.signing`, `rvnd.witness_escape`, `rvnd.audit_drop` through one `rvnd/adapters/audit_chain.py`:

```python
import loomground_audit_chain.mutation_log as _ml
import loomground_audit_chain.witness_escape as _we
import loomground_audit_chain.audit_drop as _ad
from loomground_audit_chain.mutation_log import *   # re-export, private names explicitly
from loomground_audit_chain.signing import *

_ml.SEAL_BACKEND = "rvnd"
_ad.STDERR_PREFIX = "[rvnd]"

def _purged_pair_ref(folder, pair_id):
    from ..forgotten_subjects import purged_pair_ref
    return purged_pair_ref(folder, pair_id)

def _quarantine(folder, actor, status, **kw):
    from ..parties import set_party_status
    return set_party_status(folder, actor, status, **kw)

_ml.purged_pair_ref = _purged_pair_ref
_we.quarantine = _quarantine
```

Each `rvnd/<module>.py` then holds zero definitions and re-exports from the adapter. The `python -m rvnd.witness_escape` CLI forwards to `loomground_audit_chain.witness_escape.main`.

## Grounding

The chain is a candidate `intact` pillar of governance-certification. `pillar.intact_attestation(result, *, subject, entry_ref="", prev_hash="", extra=None)` returns `{"pillar": "intact", "verified", "intact": {type, log_id, entry_ref, algorithm[, prev_hash]}, "findings", "chain", "extra"}`; `intact` is schema-shaped, `extra` passes opaque evidence references (versum span, 5d-nd digests) through unchanged. `tests/test_pillar.py` validates against the schema when `governance_certification` and `jsonschema` are importable and skips otherwise.
