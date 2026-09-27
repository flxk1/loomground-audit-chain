<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 flxk1 -->
# Changelog

## [0.1.1](https://github.com/flxk1/loomground-audit-chain/compare/loomground-audit-chain-v0.1.0...loomground-audit-chain-v0.1.1) (2026-09-27)


### Documentation

* correct stale claims; add How this is made ([f9a705e](https://github.com/flxk1/loomground-audit-chain/commit/f9a705e5d5fdc2aa3105c5c39abb79224f9dda6f))
* git install, allowlist precondition; add How this is made ([639f46f](https://github.com/flxk1/loomground-audit-chain/commit/639f46ffd0a5744293b1c2f84580f6f26793a09b))
* How this is made names no model vendor ([1f7b71e](https://github.com/flxk1/loomground-audit-chain/commit/1f7b71e9952308a9795adbca1919b375fc796a53))

## 0.1.0

* Published the standalone `mutation_log`, `signing`, `witness_escape`, and `audit_drop` modules under `loomground_audit_chain`; see `docs/seam.md` for the public names, constants, and host ports.
* Consumes `loomground-workspace` directly: `paths.LOG_ROOT_DEFAULT`, `identity.{folder_hash, legacy_folder_hash, _filesystem_is_case_insensitive}`, `folder_context.resolve_folder_context`, `workspace_registry.add_known_workspace`. The first four are re-exported from `mutation_log` for callers that address them there.
* Host-specific edges become module-level ports with defaults: `mutation_log.purged_pair_ref`, `mutation_log.content_signature`, `mutation_log.register_workspace`, `mutation_log.SEAL_BACKEND`, `witness_escape.quarantine`, `audit_drop.STDERR_PREFIX`.
* `mutation_log.append_event` / `read_chain` provide a directory-addressed raw-dict pair over the same hash-link and signature scheme.
* `pillar.intact_attestation` renders a chain verification as the `intact` pillar of governance-certification schema v1; the schema is an optional test-time peer.
* Licence: Apache-2.0 (code) and CC-BY-4.0 (README).
