# OwnMesh v1.2.6

OwnMesh v1.2.6 is a stable correctness and agent-ergonomics release. It keeps
the v1.2 product surface and protocol contract compatible while making remote
state, session cleanup, workspace custody, and MCP responses more dependable.
The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Reliability and correctness

- Device enrollment and live connection presence are now separate facts, with
  observation time and route generation metadata instead of one ambiguous
  `active` state.
- Expired pending operations reconcile through Durable Object restart, alarms,
  new admissions, and legacy D1-only reads without overwriting terminal races.
- Agent reconnect delay resets only after an authenticated ready state, avoiding
  rapid reconnect loops while keeping shutdown responsive.
- Interrupted session starts and stale supervisor records reconcile only after
  exact process-birth or authenticated supervisor evidence; live or uncertain
  processes are never killed from a PID alone.
- Linked Git worktrees retain their original Git directory, index, and worktree
  context. Review execution preserves Rustup proxy invocation while pinning and
  validating both the proxy and canonical backing executable.
- File-read cursors advance correctly, stale expected hashes return a typed
  conflict, Windows child output is normalized to UTF-8, and structured
  executable pinning supports large modern CLI binaries with bounded streaming
  hashing.

## MCP and CLI experience

- Remote filesystem, Git, command, and self-diagnosis calls require an explicit
  workspace selection. The Control Plane, Agent, and result receipt bind the
  same authoritative workspace version.
- Non-async MCP calls wait for up to one second for fast terminal results;
  longer work remains durable and pollable without redispatch.
- Normal MCP responses keep a compact, backwards-compatible JSON envelope.
  Principal, tenant, OAuth, payload-hash, action, and claim details stay in the
  server-side record; bounded diagnostics are explicit opt-in only.
- `ownmesh_system_diagnose` returns typed, redacted checks for enrollment,
  routing, policy, workspace, daemon, supervisor, and stale sessions in one
  common-path call. Recommendations are fixed identifiers, never executable
  model text.
- Codex app-server replay is normalized into bounded semantic events instead of
  unknown events and oversized opaque sidecars.
- The official CLI automatically loads its owner-only managed IPC credential.
  Doctor distinguishes missing, managed, unknown, and not-required credentials
  and uses authenticated daemon status when service state is otherwise unknown.
- `/health` is a storage-free liveness probe. `/health/ready` remains the
  fail-closed D1, schema, Durable Object, and secret readiness endpoint.

## Security and compatibility

- Workspace custody is exact-bound before dispatch and checked again on Agent
  results. Absolute Full Access compatibility remains explicit and cannot be
  mislabeled as a default workspace.
- Typed diagnosis and compact MCP output use allowlists before both immediate
  return and durable storage; raw logs, paths, argv, environment values, and
  credentials are excluded.
- Existing D1 data, OAuth clients, passkeys, refresh tokens, enrolled devices,
  policies, workspaces, sessions, transfers, and protocol version 1 remain
  compatible. No D1 or local-state migration is required.

## Upgrade

1. Upgrade local binaries with the signed installer or release archive.
2. Redeploy the Control Plane so `/health` and MCP advertise version `1.2.6`.
3. Existing machines and ChatGPT connectors do not need re-enrollment.

The v1.2.5 release notes remain available for the previous stable patch.
