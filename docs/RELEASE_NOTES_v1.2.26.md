# OwnMesh v1.2.26

OwnMesh v1.2.26 simplifies external CLI execution by removing the first-class
coding-agent Profile and vendor-adapter layer. External CLIs now use the same
generic exact-program command, process, PTY, and session capabilities as every
other executable.

This is an intentional breaking change for Profile-specific CLI, IPC, and MCP
automation. OwnMesh's own CLI, signed updater and rollback path, daemon, TUI,
Control Plane, installer, generic sessions, filesystem, transfer, approval,
policy, and audit capabilities remain supported.

The machine-checked shipped contract is
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json). Its
registry-scoped `completeness_claim` is true because the admitted surface has no
unimplemented commands or surface-specific evidence waiver. The separate
release-evidence receipt remains false while the disclosed external platform,
packaging, ChatGPT automation, and independent-review blockers remain open.

## Generic external CLI contract

- One-shot work uses exact-argument command execution. Interactive, login, or
  long-running work uses generic process or PTY sessions with bounded stream
  replay and the existing lifecycle controls.
- Callers supply the executable, arguments, and any vendor-defined resume flags.
  OwnMesh does not discover vendor installations, infer authentication state,
  select protocol dialects, normalize vendor events, or construct native resume
  requests.
- Generic structured pipes, PTY/process-tree cleanup, controller leases,
  idempotency, approvals, policy checks, audit, and workspace path resolution
  remain shared runtime infrastructure.

## Removed Profile surface

- The Profile crate, official catalog, custom registry, vendor adapters,
  discovery and authentication probes, normalized event parsers, permission
  bridge, resume/cancel frame generation, fixtures, and live-provider receipt
  waiver are removed.
- The `ownmesh profile` command family and TUI Profiles screen are removed.
- Profile IPC methods and MCP tools are no longer published or callable.
  Profile-specific session kinds and request/state fields are no longer part of
  the public schema.
- MCP catalog v2 records this deliberate break. Catalog v1 remains historical
  evidence and is not a callable compatibility promise for v1.2.26.

## Upgrade behavior

- Removed Profile RPC methods return bounded method-not-found responses.
- Generic `session.open` rejects old Profile fields and kinds with explicit
  invalid-parameter migration guidance; it never silently falls back to a PTY.
- Persisted Profile sessions are discarded rather than guessed into generic
  sessions. Obsolete Profile metadata on an otherwise generic session is
  ignored, so an upgrade cannot panic on old state.
- Existing automation should invoke the external CLI through exact `program`
  and `args`, following that CLI's current documentation for login and resume.
- Published ChatGPT integrations must scan and publish the catalog-v2 metadata;
  redeploying a Worker alone cannot rewrite an approved tool snapshot.

## Security boundary

OwnMesh authorizes the launch and lifecycle of the external process/session,
including exact argv, selected workspace, policy, approval, replay, and audit.
It does not observe or authorize individual filesystem or tool actions performed
inside that child through a vendor protocol.

A workspace or `cwd` binding is path and policy context, not an operating-system
sandbox. An external process may exercise the ambient authority of the OwnMesh
OS user. Operators that need confinement must add the platform's process sandbox
or restricted execution boundary.

No privacy or authorization default is loosened. Telemetry, cloud file relay,
automatic update checks, and unsolicited network activity remain off by
default. Credentials, provider login, model configuration, and external CLI
updates remain under the user and that CLI's control.

## Verification and remaining boundaries

The release workflow requires Rust 1.92 builds and tests on Linux, macOS, and
Windows; strict Clippy; frozen pnpm test, typecheck, and lint; dependency audits;
SAST; gitleaks; strict CycloneDX SBOMs; release-claim checks; and a packaged
Linux x64 workerd E2E covering device routing, filesystem, command, generic
session, restart/recovery, and two-Agent transfer paths.

Portable archives are protected by SHA-256, mandatory minisign verification,
and GitHub provenance. Authenticode, Apple notarization, native installers,
macOS/Windows privileged-route receipts, a fully automated published-ChatGPT
canary, and independent external security review remain disclosed boundaries.
