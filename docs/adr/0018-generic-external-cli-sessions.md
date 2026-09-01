# ADR 0018: Generic external CLI sessions replace coding-agent profiles

- Status: Accepted
- Date: 2026-09-01
- Deciders: OwnMesh runtime maintainers
- Supersedes: [ADR 0016](./0016-dialect-normalization-and-vendor-permission-denial.md)

## Context

First-class coding-agent profiles made OwnMesh responsible for vendor command
discovery, authentication guesses, protocol dialects, normalized event meaning,
permission replies, and native session resume. Those claims change whenever an
external CLI changes and blur OwnMesh's actual authorization boundary. A binary
being present does not prove login or protocol readiness, and a vendor request
inside that child is not an OwnMesh policy decision or approval receipt.

OwnMesh already has a vendor-neutral capability model: exact command argument
vectors, process and PTY sessions, workspace path resolution, controller leases,
bounded replay, policy, approvals, and audit.

## Decision

1. Remove coding-agent Profile definitions, discovery, status, CLI/TUI flows,
   IPC methods, MCP tools and inputs, vendor adapters, fixtures, and release
   receipt claims.
2. Launch every external CLI through generic exact `program` and `args` command
   or session fields. OwnMesh does not select vendor flags, interpret vendor
   output, inspect credentials, or promise vendor-native resume.
3. OwnMesh authorizes the external process/session boundary: executable launch,
   input/output, lifecycle, workspace binding, policy, approvals, and audit. It
   does not observe or authorize tool actions performed internally by the child.
4. `workspace_id` and `cwd` are path-resolution and policy context, not an OS
   sandbox. Operators must add platform confinement when a child must not use
   the ambient authority of the OwnMesh OS user.
5. Removed Profile RPCs return method-not-found. `session.open` rejects legacy
   Profile fields and kinds with explicit upgrade guidance. Persisted Profile
   sessions are discarded rather than guessed into generic sessions; obsolete
   Profile metadata on an otherwise generic session is ignored.
6. Record the intentional public break as MCP catalog v2. Catalog v1 remains
   historical evidence, not a callable compatibility promise.

## Consequences

- External CLI support no longer depends on a vendor allowlist or fast-changing
  wire protocol. Users provide and review the exact executable and arguments.
- Generic raw PTY/process output remains available, but OwnMesh provides no
  normalized vendor events, login state, native conversation identity, or
  adapter-specific permission bridge.
- The security claim is narrower and auditable. A child may still exercise the
  OS user's ambient authority, so workspace selection must never be described as
  process confinement.
- Existing Profile automation must migrate to exact generic `program`/`args`.

## Alternatives considered

- **Keep official profiles but mark them experimental.** The callable surface
  would still imply vendor semantics and retain the same authorization blur.
- **Move profiles to community plugins.** No safe adapter/plugin contract exists,
  and dynamic vendor code is unnecessary for generic process execution.
- **Silently translate old Profile sessions to PTYs.** Translation would guess
  argv, prompt, resume, and replay semantics and could launch the wrong action.
