# OwnMesh v1.2.14

OwnMesh v1.2.14 is a patch release for long-running MCP operations, hash-bound
transfer replacement, bounded tool grants, batch approval, and fail-closed
journal degradation. It preserves the v1.2 product surface, the OAuth/passkey
model, the MCP protocol, policy fail-closed guarantees, and the Control Plane
storage schema. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Added

- **`ownmesh_get_operation` long-poll.** Optional `wait_ms` (clamped to 25s)
  waits until a terminal snapshot or the wait window. Concurrent waiters per
  tenant are capped; excess calls return the current snapshot with
  `mcp_get_operation_wait_saturated` and do not persist that warning.
- **Detached commands.** `ownmesh_command_run` / `ownmesh_run_command` accept
  `detach: true` so a long-running command is dispatched without the
  synchronous timeout clamp or the five-minute dispatch / poll expiry. Device
  Room keeps the pending correlation past the ordinary 15-minute TTL; the hard
  cap is 24 hours or cancel. Agent reconnect does not start a second spawn of
  an in-process job. If the live loop is gone, the completion is parked and
  every parked row is published on the next session. Completion is retrieved
  with `ownmesh_get_operation`. Concurrent detached jobs per device are capped
  fail-closed. The synchronous `timeout_ms` clamp is configurable via Worker
  env `MCP_MAX_TIMEOUT_MS` (default 300000, hard ceiling 3600000). Timed-out
  synchronous commands include hint
  `use detach:true or a session for long-running commands`.
- **Hash-bound destination replace.** `ownmesh_transfer_plan` accepts optional
  `overwrite_expected_sha256`. Destination replacement is allowed only if the
  existing file matches that hash at preflight and publish. Blind
  `force`/`overwrite` remains rejected.
  `ownmesh transfer plan --overwrite-expected-sha256` exposes the same bound.
- **Bounded tool grants.** `grant_type: "bounded_tool"` lifts policy **Ask**
  only for an explicit tool allowlist, optional workspace, TTL ≤ 4 hours, and
  optional max-use count. Matching requires the mint device id and the
  request's canonical tool plus capability/kind. Principal and device id are
  stamped on the mint approval at enqueue from the verified remote dispatch.
  Deny still wins, including recommended/workspace_only `command.run`. Minting
  is the same fresh-passkey admin path as policy preset
  (`ownmesh grants mint` / `ownmesh_grants_mint`). Revoke and lockdown are
  local tightening. See [ADR 0012](./adr/0012-bounded-tool-grants-and-batch-approval.md).
- **Batch approval inbox.** `/approve` lists pending operations for an
  authenticated human session. Selected sets are bound by a v2 presence cookie
  whose commitment is SHA-256 of server-looked-up `operation_id:payload_hash`
  lines (max 32). Each decision is still consumed per operation. Deny-all of
  the listed pending set requires session + CSRF + same-origin, not a passkey.
  Notification channels never carry approval authority.

## Fixed

- **An unreadable, over-budget, or unremovable-backup op-journal no longer
  refuses `ownmeshd` startup.** The daemon starts read-only
  (`OWNMESH_E_JOURNAL_DEGRADED` for side effects) and surfaces
  `journal_degraded` in `system_diagnose` / `ownmesh doctor`. Local repair is
  `ownmesh doctor --repair-journal --i-understand-replay-risk`.
- **Durable MCP operation quota is operator-configurable.** Worker env
  `MCP_OPS_MAX_PER_TENANT` (default 20_000). Tool responses warn with
  `mcp_ops_quota_pressure` at ≥ 60% occupancy, `ownmesh_system_diagnose`
  reports `control_plane.mcp_ops_quota`, and keyless terminal rows are
  hard-deleted at the 7-day result TTL instead of occupying a 30-day
  idempotency tombstone. Fail-closed `OWNMESH_E_MCP_OP_QUOTA` and keyed receipt
  retention are unchanged.

## Compatibility and migration

- No D1 migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- Operators should redeploy the Control Plane so `/health` and MCP advertise
  version `1.2.14`. Detached commands, hashed overwrite, bounded grants, and
  reconnect completion parking need both the v1.2.14 Control Plane and Agent.
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages remain
  out of scope.

## Upgrade

1. Run `ownmesh update` or install the signed v1.2.14 archive.
2. Deploy the v1.2.14 Control Plane.
3. Confirm `/health/ready` and run `ownmesh doctor --check-network`.

The v1.2.13 release notes remain available for the previous stable update.
