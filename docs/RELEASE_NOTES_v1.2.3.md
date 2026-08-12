# OwnMesh v1.2.3

OwnMesh v1.2.3 is a stable patch release focused on policy correctness,
operator-facing diagnostics, and repeatable real-binary loopback evidence. The
supported product surface remains the machine-checked contract in
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Improvements

- An explicit deny rule now takes effect immediately and cannot be bypassed by
  a previously issued temporary grant.
- Restricted presets ask before reading credential-like workspace paths. The
  daemon derives the sensitive-path tag; clients cannot add or suppress it.
- Policy rule prefixes keep documented textual matching such as `.env` covering
  `.env.production`, while interior traversal is resolved before allow or deny
  matching. Temporary grants remain component- and workspace-bound.
- `ownmesh policy explain` accepts optional path and workspace inputs and uses
  the same default workspace and sensitive facts as execution.
- Local log commands consistently unwrap daemon results, report approval state,
  and document the actual shipped providers and platform limits.
- OAuth scope documentation now matches the exact MCP tool catalog and clearly
  separates Worker variables, secrets, DCR, token revocation, and local admin
  actions.
- A scheduled workflow exercises real ownmeshd binaries through local
  Wrangler/workerd for E1, E2/E3, and resumable two-Agent E9 transfer.

## Security and compatibility

- Full-access presets still contain no hidden asks or denies. The new sensitive
  read rule applies only to restricted presets.
- Development-only health and rate-limit bypasses remain restricted to an
  explicit flag with both request and issuer on loopback; remote hosts retain
  production limits.
- Existing configurations, grants, enrolled devices, OAuth sessions,
  workspaces, transfers, and protocol version 1 remain compatible. No D1 or
  local-state migration is required.

## Upgrade

1. Upgrade local binaries with the signed installer or release archive.
2. Re-run the guided control-plane deployment to publish Worker version 1.2.3.
3. Run `ownmesh doctor --json`, then use
   `ownmesh policy explain read --path <path>` when reviewing a filesystem
   decision.

The v1.2.2 release notes remain available for the previous stable patch.
