# OwnMesh v1.2.34

v1.2.34 hardens the read-only Git and HTTP input boundaries and updates
dependencies with known security advisories. Authentication, exact-action
approval binding, idempotency, and replay protection remain enforced.

## Read-only Git isolation

- Git status/diff no longer execute repository-configured clean/process
  filters, textconv, or external diff drivers under filesystem authority.
  Inherited Git environment and global/system configuration are excluded.
- Bounded private metadata preserves the original object/index identity,
  linked worktrees and split indexes, shallow boundaries, local exclusions,
  SHA-256 object format, and reftable HEAD.
- Diffs show raw content rather than custom filter conversions. Repositories
  whose index contains submodules, or exceeds the bounded capture, return an
  explicit error. Submodule recursion is disabled even during concurrent
  index changes. See [ADR 0023](./adr/0023-read-only-git-helper-isolation.md).

## HTTP input budgets and cancellation

- Device enrollment, proof, and revocation enforce the 1,000,000-byte wire
  budget before JSON parsing. Invalid top-level bodies return 400; oversized
  bodies return 413 before state changes. Bounded legacy revoke query fallback
  remains supported.
- Connector forms enforce their 8 KiB budget while reading. Approval JSON,
  URLencoded forms, and multipart forms are bounded before parsing; repeated
  batch transaction IDs remain supported.
- MCP and OAuth authorize read the original request once. An unread stream
  clone can no longer prevent overflow cancellation from completing.

## Dependency maintenance

- rustls 0.23.45 and rustls-webpki 0.103.15 address the TLS handshake advisory.
- Wrangler 4.148.0, matching Workers types, undici 7.29.1, and a scoped
  miniflare/sharp 0.35.5 override resolve known toolchain dependency advisories.
- chacha20 0.10.2 replaces a yanked release with its SSE2-backend compatibility
  fix. No dependency-audit ignore or threshold relaxation is added.
- The Windows-only portable-pty 0.8.1 path still carries the serial 0.4.0
  maintenance warning. Its existing ConPTY compatibility pin is retained.

## Verification and deployment

Focused tests cover malicious Git helper configurations, normal raw/staged
diffs and repository layouts, streamed body overflow/cancellation, no side
effects on oversized requests, and ordinary multipart/batch approval.
Publication requires the repository's exact-SHA CI, native platform checks,
packaged-artifact E2E, SBOM, checksum, Minisign, and provenance gates.

The shipped surface contract is
[release/SUPPORTED_SURFACES.json](../release/SUPPORTED_SURFACES.json).
This release adds no D1 migration. Self-hosted operators deploy the updated
control plane through their existing Cloudflare workflow and update devices
using the signed portable release or OwnMesh updater.
