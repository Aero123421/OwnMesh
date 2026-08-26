# OwnMesh v1.2.10

OwnMesh v1.2.10 is a stable Control Plane compatibility patch. It keeps the
v1.2 product surface, authentication model, and storage schema unchanged. The
machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- Public MCP requests may continue to select Full Access with
  `workspace_id: null`. Before the request reaches an Agent, the Control Plane
  now normalizes that unbound choice to the omitted optional field required by
  `ownmesh.operation/1.0`. Existing v1.2.9 Agents therefore execute valid
  absolute-path operations instead of rejecting the envelope and reconnecting.
- Cancellation controls no longer copy the target operation's workspace onto a
  workspace-independent cancel action. The control remains exactly bound to
  its target operation, principal, tenant, device, and idempotency key, and can
  still be delivered if the target workspace is removed or remapped.

## Compatibility and migration

- No D1 migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- The Control Plane fix is backward-compatible with v1.2.9 Agents.

## Upgrade

1. Self-hosted deployments should deploy the v1.2.10 Control Plane.
2. Install the signed v1.2.10 archive when updating local binaries.
3. Confirm `/health/ready` and run `ownmesh doctor --check-network`.

The v1.2.9 release notes remain available for the previous stable patch.
