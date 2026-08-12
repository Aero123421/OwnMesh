# OwnMesh v1.2.4

OwnMesh v1.2.4 is a stable usability and reliability patch focused on the
first-run terminal experience and Windows user-level Agent startup. The
supported product surface remains the machine-checked contract in
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Improvements

- Running `ownmesh` on a new machine opens a compact setup flow for the Worker
  URL, language, access preset, device-code sign-in, device enrollment, and
  Agent startup. The same URL and short-code flow works over SSH.
- The dashboard reports server configuration, account sign-in, device
  enrollment, autostart installation, and Agent liveness as separate facts. It
  no longer labels a configured server as a live connection.
- ChatGPT connector setup is a separate action showing the exact `/mcp` URL;
  it is no longer mixed with enrolling the local computer.
- The command palette and setup dialogs are content-sized, work at 80x24, and
  support bracketed paste while preserving the accepted dark terminal design.
- TUI setup temporarily restores the normal terminal before interactive login,
  so URLs and short codes remain readable and usable on desktop and headless
  systems.
- Windows user autostart now uses the root-level `OwnMesh-ownmeshd` task, which
  does not require permission to create a Task Scheduler folder. Existing
  legacy `OwnMesh\ownmeshd` tasks are detected and removed during migration.

## Security and compatibility

- Repairing authentication or Agent startup does not overwrite unrelated
  instances, update settings, or custom policy rules. Config and policy updates
  use the existing journaled transaction.
- Windows task discovery uses locale-independent task enumeration, rejects
  query failures, and verifies removal of both current and legacy task names.
- The Agent remains a current-user, least-privilege process. No privileged
  fallback was added.
- Existing Cloudflare deployments, OAuth sessions, enrolled devices, protocol
  version 1, workspaces, transfers, and policies remain compatible. No D1 or
  local-state migration is required.

## Upgrade

1. Upgrade local binaries with the signed installer or release archive.
2. Existing v1.2.3 control planes remain protocol-compatible. Redeploy the
   Worker when you want its reported service version to match v1.2.4.
3. Run `ownmesh`; choose **Finish setup** on a new machine or **Repair Agent**
   when an existing machine lacks user autostart.

The v1.2.3 release notes remain available for the previous stable patch.
