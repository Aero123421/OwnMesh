# OwnMesh v1.2.8

OwnMesh v1.2.8 is a stable Git workspace-binding patch release. It keeps the
v1.2 product surface, protocol, storage schema, and authentication boundaries
unchanged. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- Relative Git status, diff, and HEAD operations now reject repository-local
  configuration that redirects the worktree outside the selected OwnMesh
  workspace.
- Rejections return a bounded policy error without exposing the external path.
- Valid linked worktrees remain supported, and explicit absolute Full Access
  operations retain their existing behavior.

## Compatibility

- No D1 or local-state migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices, policies,
  workspaces, sessions, transfers, and ChatGPT connectors remain compatible.

## Upgrade

1. Run the signed one-line installer again, or install a v1.2.8 release archive.
2. Redeploy the Control Plane so `/health` and MCP advertise version `1.2.8`.
3. Existing machines and ChatGPT connectors do not need re-enrollment.

The v1.2.7 release notes remain available for the previous stable patch.
