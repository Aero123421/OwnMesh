# OwnMesh v1.2.9

OwnMesh v1.2.9 is a stable runtime-correctness and workspace-authority patch
release. It keeps the v1.2 product surface and authentication boundaries while
adding one additive Control Plane migration. The machine-checked contract
remains [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- Workspace authority is now keyed by both device and workspace ID. Multiple
  devices may safely use `ws_default`, and authenticated Agent readiness keeps
  the Control Plane's bounded workspace registry in sync without sending paths.
  An opaque local generation invalidates old operations when the same ID is
  remapped to another root or removed and added again.
- Restricted devices reject unbound absolute paths before DeviceRoom routing;
  Full Access compatibility remains explicit and the Agent is still the final
  policy authority.
- Cancellation writes a durable fence before network delivery. Offline targets
  receive the cancel control first after reconnect, and Agents no longer replay
  a local outbox before that authoritative reconciliation.
- Public operation phases distinguish dispatch from device execution, and an
  identical idempotency retry still converges after credential rotation without
  weakening the generation bound on the actual dispatch.
- Expired Agent dispatches become durable terminal receipts instead of tearing
  down the WebSocket. Operations known to have started reconcile through the
  daemon's exact-once journal; legacy uncertain records fail closed rather than
  replaying a possible side effect.
- Internal routing contexts retain clock-skew headroom, Windows service restart
  waits for a real daemon stop and ready transition, and profile version probes
  remain bounded even when a descendant inherits their output handles.
- Remote MCP can inspect effective policy with a read-only tool. The deprecated
  session release tool remains callable by older clients but is no longer
  advertised to models.

## Compatibility and migration

- Migration `0016_device_scoped_workspaces.sql` is required before the v1.2.9
  Worker becomes ready. It migrates existing workspace authority and backfills
  each active device's default workspace.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices, policies,
  sessions, transfers, and ChatGPT connectors remain compatible.
- Old Agents remain fail-closed at the local policy boundary; upgrading Agents
  enables Control Plane pre-routing enforcement and workspace synchronization.

## Upgrade

1. Run the signed one-line installer again or install a v1.2.9 archive.
2. Apply the bundled D1 migrations, then deploy the v1.2.9 Control Plane.
3. Confirm `/health/ready` is ready and reconnect each upgraded Agent.

The v1.2.8 release notes remain available for the previous stable patch.
