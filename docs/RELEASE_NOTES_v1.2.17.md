# OwnMesh v1.2.17

OwnMesh v1.2.17 is a hardening patch for control-plane OAuth redemption,
request-body accounting, support-bundle export, credential-store doctor
provenance, privileged-broker replay fencing, and crash-consistent updater
apply/rollback. It preserves the v1.2 product surface, the OAuth/passkey
model, the MCP protocol, and policy fail-closed guarantees. The
machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

Tracked issues: #100 #101 #113 #121 #122 #123 #124 #125 #126 #128.

## Fixed

- **Authorization-code redemption is verify-then-CAS.** A successful
  `authorization_code` grant binds the redeemed code hash to exactly one
  persisted token family before the response is issued. Duplicate or
  mismatched redemption fails closed. D1 migration `0017` adds
  `oauth_tokens.auth_code_hash` and a partial unique index.
- **Form and JSON bodies are bounded by actual bytes.** Content-Length is
  advisory. The stream is authoritative; oversized, truncated, or
  non-UTF-8 form bodies fail closed before parse.
- **Device user codes come from Web Crypto.** RFC 8628 `user_code` values
  are generated with `crypto.getRandomValues` and rejection sampling, not
  a biased modulo over `Math.random()`.
- **TAR metadata is charged to the decompression budget.** Update archives
  count tar header/extension records against the same uncompressed-byte
  ceiling as file contents before the entry is discarded.
- **Support-bundle export is typed and allowlisted.** Preview bytes are
  the exact v2 export. Unlabeled mixed-case high-entropy tokens are
  rejected; the scanner does not echo secrets. Export writes owner-only
  files atomically without requiring credential-registry directory
  custody.
- **Doctor reports credential-store provenance without reading secrets.**
  Residual fallback-entry counts, backend name, and degraded cleanup
  state are non-secret snapshots for `ownmesh doctor`.
- **Privileged-broker replay ledgers reconcile and cap occupancy.** A
  crash-left reservation is consumed, not retried. Capacity and digest
  conflicts fail closed on Linux, macOS, and Windows adapters.
- **Updater apply/rollback is crash-consistent.** Interrupted first
  install, partial-set refusal, and checksum-bound rollback keep the five
  required binaries consistent.

## Compatibility and migration

- Deploying the control plane requires D1 migration `0017`
  (`0017_oauth_auth_code_redemption.sql`). Existing tokens remain valid;
  `auth_code_hash` is NULL for grants other than authorization-code.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages
  remain out of scope.

## Upgrade

1. Run `ownmesh update` or install the signed v1.2.17 archive.
2. Apply D1 migration `0017` when deploying the control plane.
3. Restart the user service if the updater does not do so automatically.
4. Confirm `/health/ready` and run `ownmesh doctor --check-network`.

The v1.2.16 release notes remain available for the previous stable patch.
