# OwnMesh v1.2.23

OwnMesh v1.2.23 is the next formal release after v1.2.21. A v1.2.22 source
train was prepared on `main`, but no v1.2.22 tag or GitHub Release was
published. This release therefore includes all v1.2.22 service lifecycle,
endpoint, installer, and session fixes, plus the availability, authorization,
workspace, macOS, and dependency work summarized below.

No privacy or authorization default is loosened. Telemetry, cloud file relay,
and unsolicited network checks remain off by default. The machine-checked
product contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Availability and session recovery

- A remote `command_run` that resolves to the running OwnMesh CLI is rejected
  before spawn with `OWNMESH_E_SELF_REENTRANT_EXEC`. This prevents the child
  from re-entering daemon IPC while its parent holds the runtime mutex and
  blocking every later operation on the device (#160). Identity is checked by
  the executable's OS file identity, including renamed, hard-linked, and
  symlinked paths; `--help` and `--version` remain usable.
- Linux session reconciliation now distinguishes a zombie from a live child
  while retaining the existing process-birth witness against PID reuse.
  `session_show` reconciles provably dead records, and one indeterminate session
  no longer aborts reattach for unrelated sessions (#31).
- `system.diagnose` accepts additive fields from a newer Agent independently of
  the device protocol version. Required checks remain bounded and fail closed,
  with typed reasons for malformed or unsupported diagnosis contracts (#161).

## Authorization and MCP catalog continuity

- Queued device operations bind to a revocation epoch rather than to every
  OAuth refresh-token rotation. Routine refresh no longer invalidates an
  already-authorized operation, while explicit revocation and refresh-token
  reuse still terminally invalidate the affected family (#162).
- MCP exposes one SHA-256 catalog revision on discovery, health, initialize,
  and `tools/list`. The revision is bound into the MCP session id, so a client
  carrying a session from an older deployment receives the protocol-defined
  reinitialize signal instead of silently retaining a stale tool catalog
  (#158).
- Guided Cloudflare deployment verifies the version actually served by the
  origin before reporting success. The machine-endpoint probe separates Worker
  responses from Cloudflare edge rejections and documents the narrowly scoped
  WAF exception for OAuth/MCP metadata endpoints (#158, #159).

## Workspace registry and approval authority

- `workspace.registry.ack` is emitted only after the Control Plane has durably
  persisted the new generation to D1 and DeviceRoom state. The live Agent now
  validates and accepts that strict ACK, so reported activation cannot outrun
  the authoritative registry (#165).
- An approval decision is bound to the original target operation's workspace
  ID and Control Plane version. DeviceRoom resolves that target again at final
  delivery and terminally refuses it if the workspace was removed and
  recreated while approval was pending. Routing-only `workspace_id` metadata is
  stripped before invoking the strict runtime schema (#165).
- Unix workspace-registry locks are close-on-exec, preventing a persistent
  session sidecar from inheriting the daemon's lock and blocking a later daemon
  restart (#165).

## macOS prepared executable custody

macOS 26 can kill a private copy of an Apple restricted platform binary even
when its bytes and embedded signature are unchanged. Prepared execution now
keeps private, digest-verified snapshot custody for ordinary user executables,
but launches a restricted Apple binary only from its root-owned backing path
after verifying the executable and every canonical ancestor are not writable by
the daemon. Custody handles remain open and the path pins are revalidated
immediately before spawn; the approved invocation is still preserved as
`argv[0]` (#164).

## Included v1.2.22 lifecycle and endpoint fixes

Because v1.2.22 was not published, v1.2.23 also includes its complete changes:

- `service start` and `service stop` verify the observable daemon IPC boundary;
  failed or indeterminate service-manager transitions are no longer reported as
  success.
- macOS stops boot out the `KeepAlive` LaunchAgent, and Linux/macOS uninstall
  retains descriptors until the manager proves the service inactive.
- Service install reconciles the descriptor registered with systemd, launchd,
  or Task Scheduler against its persisted structural digest. Windows scheduled
  tasks bind the validated config, state, and runtime directories directly.
- Unix IPC paths use a deterministic owner-only short fallback when the default
  path exceeds `sockaddr_un`; overlong explicit paths are rejected up front.
  Windows named pipes use a SHA-256 digest of the normalized runtime path.
- Structured-pipe sessions publish real EOF and exit status, seal streams on a
  disclosed forced cutoff, and cannot append output after completion.
- The Unix installer recognizes a running Linux daemon whose replaced image is
  reported by `/proc/<pid>/exe` with the ` (deleted)` suffix and performs the
  required restart and version check.

See [the v1.2.22 notes](./RELEASE_NOTES_v1.2.22.md) for the detailed behavior
and compatibility discussion.

## Dependency and CI refresh

- Rust: `hmac` 0.13, `chacha20poly1305` 0.11, `jsonschema` 0.50,
  `thiserror` 2.0.20, `unicode-width` 0.2.2, `windows-sys` 0.61.2,
  `base64` 0.23.1, `zip` 8.6.0, and test-only `minisign` 0.9.1.
- Worker: Wrangler 4.123.0 and `@cloudflare/workers-types` 5.20260817.1.
- CI/release actions: `setup-node` 7.0.0, `checkout` 7.0.1,
  `download-artifact` 8.0.1, `action-gh-release` 3.0.2, and
  `gitleaks-action` 3.0.0.

The Node 26 type proposal was not merged because the supported runtime remains
Node 22.6+. The Windows `portable-pty` 0.9 proposal was also not merged because
OwnMesh intentionally retains 0.8.1 there to avoid the documented ConPTY
cursor-query hang; non-Windows targets already use 0.9.

## Verification

- Rust workspace formatting, locked build/test, all-target Clippy with warnings
  denied, and the Linux stateful suite.
- Frozen pnpm install, 477 TypeScript tests, typecheck, lint, and dependency
  audit.
- Cargo dependency audit, gitleaks, Rust/TypeScript SAST, strict CycloneDX SBOM
  generation, release-graph checks, release-quality mutation tests, signed
  installer tests, and Wrangler dry-run packaging.
- The real-binary Nightly suite exercises E1, E2/E3, and E9 against local
  workerd. E9 includes a two-Agent transfer, zero-byte transfer, 32 MiB
  restart/resume from a durable non-zero cursor, partial cancellation,
  no-overwrite handling, cross-tenant/member denial, and a post-run durable
  state audit for credential and payload leakage.

Formal release assets remain gated by the tag-triggered CI and Security
workflows, mandatory minisign signing of `SHA256SUMS`, strict SBOM validation,
archive membership checks, and GitHub build provenance.

## Compatibility and remaining evidence gaps

- Clients holding an MCP session from an older catalog revision must
  reinitialize after deployment.
- Explicit Unix `service_socket.path` values above the platform limit remain
  invalid; default endpoints fall back automatically. Windows pipe names differ
  from releases before the runtime-path digest and may require
  `ownmesh service restart` after upgrade.
- Authenticode, Apple notarization, native installers, macOS/Windows native
  broker receipts, an automated external ChatGPT receipt, and independent
  external security review remain disclosed gaps. This release does not claim
  those receipts, nor does publishing it imply that any operator's Cloudflare
  deployment was updated.
