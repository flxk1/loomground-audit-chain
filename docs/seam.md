<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Host seam

`loomground-audit-chain` owns the chain implementation. Hosts bind policy through
small module-level ports; the package imports no host runtime.

## Public modules

- `mutation_log`: append, replay, purge, seal, verify, and raw `append_event` /
  `read_chain` operations.
- `signing`: host and controller key management, signing, verification, and key
  fingerprints.
- `witness_escape`: record and query signed witness-escape events.
- `audit_drop`: durable markers for failed audit writes.
- `pillar`: render a verified chain as a governance-certification `intact`
  attestation.

Workspace identity, folder hashing, the allowlist, and `LOG_ROOT_DEFAULT` come
from `loomground-workspace` and are re-exported where the chain API requires
them.

## Configuration constants

| Name | Value | Meaning |
|---|---|---|
| `mutation_log.LOG_ROOT_ENV` | `LOOMGROUND_LOG_ROOT` | log-root override; explicit `log_root=` wins |
| `mutation_log.KEY_PINNING_ENV` | `WORKSPACE_KEY_PINNING` | opt-in genesis key registration |
| `mutation_log.STRICT_KEY_PINNING_ENV` | `WORKSPACE_STRICT_KEY_PINNING` | fail an unregistered chain |
| `mutation_log.KEY_PIN_DIR_ENV` | `WORKSPACE_KEY_PIN_DIR` | relocate the TOFU pin file |
| `mutation_log.STRICT_HOST_DIVERGENCE_ENV` | `WORKSPACE_STRICT_HOST_DIVERGENCE` | fail an unmarked host-id shift |
| `mutation_log.SEAL_BACKEND` | `audit-chain` | backend name returned by `seal()` |
| `signing.KEY_DIR_ENV` | `WORKSPACE_KEY_DIR` | key-root override |
| `signing.KEY_PASSPHRASE_ENV` | `WORKSPACE_KEY_PASSPHRASE` | encrypt private keys at rest |
| `signing.HOST_ID_ENV` | `WORKSPACE_HOST_ID` | host-id override |
| `audit_drop.LOG_ROOT_ENV` | `WORKSPACE_L0_LOG_ROOT` | audit-drop marker root |

## Host ports

| Port | Default |
|---|---|
| `mutation_log.purged_pair_ref(folder, pair_id)` | folder-salted opaque pair reference |
| `mutation_log.content_signature(text)` | whitespace/case-normalised SHA-256 |
| `mutation_log.register_workspace(folder, log_root=)` | `loomground_workspace.workspace_registry.add_known_workspace` |
| `witness_escape.quarantine(...)` | record only; no host-state mutation |

A host may replace these callables at startup. Such bindings stay in the host;
the public package remains usable without them.

## Grounding

`pillar.intact_attestation(result, *, subject, entry_ref="", prev_hash="",
extra=None)` returns a schema-shaped `intact` pillar plus findings and chain
metadata. Optional evidence references pass through in `extra` unchanged.
