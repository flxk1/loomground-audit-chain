<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- Copyright 2026 flxk1 -->
# loomground-audit-chain

Append-only, hash-chained, Ed25519-signed events with chain verification and witness-escape records.

## Problem

An event log can be edited after the fact and still read as complete. Append-only, hash-chained, Ed25519-signed events with chain verification and witness-escape records.

## Install

```
pip install loomground-audit-chain
```

Requires `loomground-workspace` 0.1 and `cryptography`. Python 3.10+.

## Usage

```python
from loomground_audit_chain import LogEvent, MutationLog, intact_attestation
log = MutationLog("ws", log_root="logs")
log.append(LogEvent(event="ingest", folder_path="ws", pair_id="doc:0"))
result = log.verify_chain()
result.ok, result.total_events, intact_attestation(result, subject=log.folder_id)
```

Keys live under `~/.workspace/keys/<host_id>/` (`WORKSPACE_KEY_DIR` overrides). The log root defaults to `~/.workspace/log` (`LOOMGROUND_LOG_ROOT` or `log_root=` overrides).

## Example

```
in : three appends, verify_chain(); then delete line 2 of events.jsonl, verify again
out: True 3 0 0
     False ['prev_hash_mismatch']
     native-chain
```

## Interface

- `LogEvent(event, folder_path, pair_id, lifecycle_state, channel, problem_id, source_hash, actor, audit_id, ts, extra)`; `append()` stamps `prev_hash`, `signature`, `host_id`
- `MutationLog(folder, log_root=)`: `append`, `append_raw`, `replay`, `replay_filtered`, `latest_state`, `pair_ids`, `count`, `head_hash`, `verify_chain() → ChainVerificationResult`, `purge(pair_id, legal_basis, requester_ref, reason)`
- `ChainVerificationResult(ok, total_events, legacy_events, broken_links, malformed_lines, unsigned_events, signature_failures, purged_with_tombstone, host_divergence_warning, key_pin)`
- `signing`: `ensure_keypair`, `sign_bytes`, `verify_signature`, `ensure_controller_keypair`, `sign_with_controller`, `verify_controller_signature_strict`, `public_key_fingerprint`, `migrate_legacy_keypair_to_host_subdir`
- `witness_escape.record_witness_escape(folder, paths, actor)` · `recent_witness_escapes(folder, actor, since=)` · CLI `python -m loomground_audit_chain.witness_escape record`
- `audit_drop.record(where, exc, log_root=)` · `durable_drops(log_root)` — a dropped audit write on stderr, in process, and in `audit-drops.jsonl`
- `pillar.intact_attestation(result, *, subject) → dict` with the schema-shaped `intact` object
- host ports: `mutation_log.purged_pair_ref`, `content_signature`, `register_workspace`, `witness_escape.quarantine`; public constants in [docs/seam.md](docs/seam.md)

## Family

Assurance artifacts, pillar: `intact` of [governance-certification](https://github.com/flxk1/governance-certification). Consumes `loomground-workspace` (folder identity, log root, allowlist). Optional for every host consumer. Catalogue: [loomground/CATALOGUE.md](https://github.com/flxk1/loomground/blob/main/CATALOGUE.md).

## Status

0.1.0 · 135 tests · Python >=3.10 · loomground-workspace 0.1

## License

Apache-2.0 `LICENSES/Apache-2.0.txt` (code) · CC-BY-4.0 `LICENSES/CC-BY-4.0.txt` (README) · `NOTICE`
