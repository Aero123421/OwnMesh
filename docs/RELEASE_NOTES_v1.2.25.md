# OwnMesh v1.2.25

OwnMesh v1.2.25 is the next stable patch release after v1.2.24. It hardens
command custody and restart behavior, adds backward-compatible support for the
modern MCP protocol, and makes the release pipeline test and describe the exact
artifacts it publishes.

No privacy or authorization default is loosened. Telemetry, cloud file relay,
automatic update checks, and unsolicited network activity remain off by
default. The machine-checked product contract is
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json), and its
`completeness_claim` remains false while the disclosed external evidence
waivers remain open.

## Runtime execution custody

- Elevated commands now follow the same admit/execute/finalize split as
  ordinary commands. Policy, exact-action binding, credential generation,
  expiry, journal reservation, and executable pins are captured during
  admission; broker connect, wait, cancellation, output collection, and
  post-response custody re-attestation run without holding the global daemon
  runtime mutex. Finalization can commit only the originating operation's
  in-progress marker (ADR 0015).
- Session supervisor calls remain bounded by their five-second IPC deadline but
  still pass through the runtime mutex. Per-session transition ownership and
  high-concurrency session stress remain explicit follow-up work.
- On restart, a prior-process `in_progress` operation is durably classified
  `recoverable_orphaned` and returned as `OWNMESH_E_OPERATION_ORPHANED`. It is
  never auto-retried. Generic command PID/birth identity is not journaled, so
  automatic process reattachment is not claimed.

## Linux script and interpreter binding

- Linux shebang execution now treats the script and interpreter as one pinned
  compound. Both are re-attested and handed to the child through sealed memfd
  snapshots and proc-fd paths, closing interpreter/script substitution between
  approval and spawn (ADR 0013).
- A bounded Node loader preserves the approved module URL, `argv`, child
  process behavior, and relative imports when the sealed script snapshot is
  executed. Regression tests cover relative-module loading and both script and
  interpreter swaps.
- Supported `/usr/bin/env` shebang forms preserve deterministic interpreter
  resolution. Unsupported option syntax fails closed instead of falling back
  to an unverified path lookup. macOS and Windows retain their existing
  prepared-executable paths.

## Dual-era MCP and catalog compatibility

- One registry and authorization core now serves legacy MCP `2025-03-26` and
  modern stable MCP `2026-07-28` (ADR 0017). Existing clients keep
  initialization and optional session IDs; modern clients use stateless
  request metadata and mirrored HTTP headers.
- Modern requests receive strict method/name/version validation, typed
  `HeaderMismatch` and `UnsupportedProtocolVersion` errors,
  `server/discover`, result types, and deterministic cache hints. Unit tests and
  real workerd E2E exercise both protocol eras.
- Catalog version 1 is frozen against unversioned breaking changes. Existing
  names remain accepted by `tools/call` for the 1.x window, including
  deprecated aliases hidden from the latest list. CI rejects removal of
  callable names, new required fields, property changes, or effect-hint drift.
- Optional `core`, `admin`, and `agents` catalog surfaces are enforced at call
  time. Hiding a tool is never treated as authorization.

## OAuth public-client modernization

- The authorization server advertises and validates bounded Client ID Metadata
  Documents after owner authentication. Retrieval is credential-free HTTPS,
  does not follow redirects, and is revalidated at consent time.
- Authorization responses include RFC 9207 `iss`; existing redirect, issuer,
  resource, PKCE S256, refresh rotation, and token-family bindings remain in
  force. Dynamic Client Registration remains available as the compatibility
  fallback for current ChatGPT and legacy clients.
- Private-key JWT is not advertised or accepted. This release adds no client
  path that can bypass the public-client and owner-consent contract.

## Release artifact evidence

- The tag workflow still requires reusable CI and Security gates plus all five
  Windows, macOS, and Linux archives. It now downloads and checksum-verifies the
  packaged Linux x64 archive and uses its binaries—not workspace debug
  binaries—for workerd device, filesystem, command, profile, session,
  restart/recovery, and two-Agent resumable-transfer tests.
- Publication remains blocked until the exact-artifact gate succeeds.
  Cross-platform archive construction is CI-gated; the deterministic packaged
  runtime E2E executes on Linux.
- Each release emits `ownmesh-release-evidence.json` from exact artifact hashes,
  the current catalog receipt, its frozen compatibility baseline, and release
  gate facts. The receipt is included in the signed checksum chain and GitHub
  provenance. It does not turn fixtures into external-provider evidence.

## Edge diagnostics

- The machine-endpoint probe now uses two independent HTTP stacks and reports
  stable categories for DNS/TLS/connect timeout, Cloudflare edge 1010/denial,
  Worker authentication and 4xx/5xx responses, malformed JSON, and catalog
  mismatch.
- Retries are bounded, output has an explicit JSON schema version, and
  Cloudflare `cf-ray` is reported for operator diagnosis without exposing
  bearer tokens, bodies, or user content.
- Multi-egress scheduling and a narrow Cloudflare WAF skip remain operator
  infrastructure. The release does not silently change a user's zone rules.

## Upgrade and compatibility

1. Upgrade installed device binaries with `ownmesh update` or a verified
   release archive.
2. Redeploy the Control Plane from this tag to obtain dual-era MCP, OAuth, and
   catalog behavior. Publishing a GitHub release cannot update a user's
   self-hosted Cloudflare deployment.
3. Run `ownmesh doctor --json`; add `--check-network` only when an explicit
   control-plane probe is desired.
4. For a developer-mode ChatGPT connection, refresh its tool metadata. For a
   published plugin, the publisher must run **Scan Tools**, submit a new
   metadata version for review, and publish it; a Worker deploy or new chat
   cannot rewrite OpenAI's approved snapshot.

No public CLI command or existing MCP tool name is removed. Existing legacy
MCP clients remain supported, and catalog additions do not invalidate callable
1.x snapshots.

## Verification and remaining boundaries

The release candidate is gated on Rust 1.92 across Linux, macOS, and Windows,
workspace tests, Clippy with warnings denied, frozen pnpm test/typecheck/lint,
dependency audits, SAST, secret scanning, strict CycloneDX SBOM generation,
catalog compatibility, release-quality checks, and the exact packaged-binary
E2E described above.

Portable archives remain protected by SHA-256, a mandatory minisign signature,
strict SBOMs, and GitHub build provenance. The following are still disclosed,
not claimed as completed proof:

- live nine-profile provider receipts on Linux, macOS, and Windows;
- macOS/Windows native broker receipts and the complete public MCP-to-broker
  route receipt;
- a fully automated external published-ChatGPT canary;
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages;
- an independent external security review.
