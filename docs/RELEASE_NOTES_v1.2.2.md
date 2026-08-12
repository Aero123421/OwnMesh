# OwnMesh v1.2.2

OwnMesh v1.2.2 is a stable patch release focused on filesystem grant isolation,
local device-log access, and runtime maintainability. The supported surface
remains the contract recorded in
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Improvements

- Filesystem temporary grants now carry one canonical workspace identifier and
  match native path components. Missing or legacy workspace scope fails closed.
- `ownmesh logs providers` and `ownmesh logs query` provide bounded,
  cursor-paged access to device logs through authenticated local IPC.
- Human-readable log output escapes terminal control characters. JSON output
  preserves the structured daemon response for machine consumers.
- Log bodies have no remote MCP tool and are not persisted in control-plane D1
  operation records.
- The large daemon runtime was split into focused session, transfer, and
  workspace modules while retaining the existing protocol and state formats.
- Setup and Doctor text more clearly separates the recommended access preset
  from the broader full-access option.

## Security and compatibility

- Temporary filesystem grants cannot be reused for the same relative path in a
  different workspace.
- Unix backslashes retain their native filename meaning instead of widening a
  forward-slash path grant.
- Existing configurations, enrolled devices, OAuth sessions, workspaces,
  transfers, and protocol version 1 remain compatible. No data migration is
  required for this release.

## Upgrade

1. Upgrade local binaries with the signed installer or release archive.
2. Re-run the guided control-plane deployment to publish Worker version 1.2.2.
3. Run `ownmesh doctor --json` and use `ownmesh logs providers` to inspect the
   local providers available on the device.

The v1.2.1 release notes remain available for the previous stable patch.
