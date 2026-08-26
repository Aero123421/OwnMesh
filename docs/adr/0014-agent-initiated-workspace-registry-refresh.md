# ADR 0014: Agent-initiated workspace registry refresh

- Status: Accepted
- Date: 2026-08-24
- Deciders: OwnMesh maintainers

## Context

A device-local `workspace_add`/`workspace_update`/`workspace_remove` (CLI, TUI,
or MCP) updates the Agent's registry and its generations immediately, but the
Control Plane only learned the registry from the Agent `ready` handshake. The
Control Plane gates git/workspace tools on an observed `local_generation`
(fail-closed), so until the Agent reconnected:

- ChatGPT could list a workspace as `device_local` / `pending_activation`
  (via #93's activation overlay) and then hit `workspace_not_available` on
  exec;
- a workspace added during a live session became unusable for as long as the
  WebSocket stayed up but stale — and, combined with reconnect hangs
  (#140), potentially indefinitely.

The specification asks that remote execution never outrun the Agent
generation; the gap was the reverse direction: local state outran the Control
Plane's observation. This is the roadmap item "Agent-initiated workspace
registry refresh" (v1.2.13 known limitation).

## Decision

Add one additive Agent→Control Plane message, sent only on an established,
authenticated, ready session:

- Message type: `workspace.registry`
- Payload: exactly the same shape as `ready.workspace_registry`:
  `{ "enforce_workspace": bool, "workspaces": [{ "id": "ws_…", "generation": "wsg_…" }, …] }`
  validated by the same allowlist (`readyWorkspaceRegistry`).
- Reply: `workspace.registry.ack` with `{ ok: true }` after the snapshot is
  durably applied.

Semantics:

1. **Full snapshot, not deltas.** Each refresh carries the complete current
   registry (bounded to the existing 64-entry cap). A dropped or rejected
   refresh leaves no partial state to reconcile; the next refresh or handshake
   resends everything.
2. **Same authority as ready.** The Control Plane persists the snapshot via
   the existing `syncDeviceWorkspaces` path used by `ready`. Activation of a
   cloud workspace still requires an observed generation; nothing about the
   activation overlay or the fail-closed gate changes.
3. **Trigger points are device-local mutations** (`ops.workspace.add`,
   `update`, `remove`) plus any future device-local registry change. The Agent
   publishes at most one snapshot per live-loop turn (coalescing bursts).
4. **Backward compatibility.** Older Agents never send the type; older
   Control Planes reject it with `unsupported_message_type` and the Agent
   simply continues (the next reconnect handshake remains a complete
   fallback). Newer Control Planes accept sessions from Agents that never send
   the message.
5. **Fail-closed storage.** If the D1 write fails, the Device Room tears down
   the socket state rather than acknowledging; the Agent treats the lost
   connection like any transport error and re-advertises the full registry in
   the next handshake.

## Consequences

- A workspace registered locally becomes active on the Control Plane within
  one round trip instead of requiring a reconnect, closing the
  `pending_activation → exec` race for ChatGPT-driven flows (#146).
- The Control Plane's durable `device_workspaces` rows now change mid-session;
  consumers that assumed they were stable between handshakes must rely on the
  existing version counters (they already do).
- Reconnects remain a valid recovery path and remain authoritative: every
  handshake still carries the full registry.

## Alternatives considered

- **Deltas (add/update/remove events).** Smaller payloads but require ordered
  delivery, replay, and compaction machinery on the Control Plane; a missed
  delta silently desynchronizes activation. The full snapshot is bounded by
  the same 64-entry cap as `ready` and is idempotent.
- **Polling from the Control Plane.** Would move authority to the network
  side, add Worker→Agent requests, and cannot be fail-closed during agent
  disconnects.
- **Do nothing; document polling of `ownmesh_workspace_show`.** This is the
  interim guidance, but it leaves the availability hole open on Linux where
  reconnect hangs (#140) compounded it.

## Related

- [ADR 0010](./0010-bounded-op-journal-retention.md) — journal semantics for
  operation receipts (unchanged).
- [ADR 0008](./0008-control-plane-authorization-scopes-and-binding.md) — why
  the device remains the only policy engine.
- Issue #146 and the roadmap entry "Agent-initiated workspace registry
  refresh".
