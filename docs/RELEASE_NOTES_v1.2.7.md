# OwnMesh v1.2.7

OwnMesh v1.2.7 is a stable Windows installer reliability release. It keeps the
v1.2 product surface, protocol, storage schema, and security boundaries
unchanged. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- The verified PowerShell installer retries a bounded set of transient Windows
  sharing and image-lock failures when replacing an installed binary.
- If a binary remains in use, the upgrade still fails closed, restores the
  previous installation, and tells the operator to close active OwnMesh
  sessions or stop the OwnMesh service before retrying.
- Package signature verification, SHA-256 verification, owner/reparse checks,
  atomic staging, rollback, and post-install hash verification are unchanged.

## Compatibility

- No D1 or local-state migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices, policies,
  workspaces, sessions, transfers, and ChatGPT connectors remain compatible.

## Upgrade

1. Run the signed one-line installer again, or install a v1.2.7 release archive.
2. Redeploy the Control Plane so `/health` and MCP advertise version `1.2.7`.
3. Existing machines and ChatGPT connectors do not need re-enrollment.

The v1.2.6 release notes remain available for the previous stable patch.
