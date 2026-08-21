# OwnMesh v1.2.18

OwnMesh v1.2.18 is a Windows installer hotfix for upgrades under Windows
PowerShell 5.1. It preserves the v1.2.17 product surface, OAuth/passkey
model, MCP protocol, and policy fail-closed guarantees. The
machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- **Portable Windows installer upgrade stop no longer dies on a missing
  scheduled task.** Querying or ending `OwnMesh-ownmeshd` /
  `OwnMesh\ownmeshd` when the task is absent used to surface
  `schtasks.exe` stderr as a terminating `NativeCommandError` under
  `$ErrorActionPreference = Stop` in Windows PowerShell 5.1, including
  the published `powershell -File` bootstrap. The installer now routes
  those calls through `cmd.exe` and treats only the process exit code as
  authoritative, so an upgrade can still stop matching install-dir
  processes.

## Compatibility and migration

- No D1 migration is required beyond v1.2.17's `0017`.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages
  remain out of scope.

## Upgrade

1. Run the v1.2.18 `ownmesh-installer.ps1` (or `ownmesh update` from a
   working 1.2.17 CLI).
2. Restart the user service if the installer or updater does not do so
   automatically.
3. Confirm `/health/ready` and run `ownmesh doctor --check-network`.

The v1.2.17 release notes remain available for the previous stable patch.
