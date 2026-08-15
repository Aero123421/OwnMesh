# OwnMesh v1.2.13

OwnMesh v1.2.13 is a real-machine reliability release for Windows and Linux
daemons. It keeps the v1.2 product surface, OAuth/passkey model, MCP protocol,
and Control Plane storage schema unchanged. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- An expired `detach` intent in `session-transition-journal.json` no longer
  aborts sidecar recovery for every session. Closed or otherwise harmless
  records are audited and cleared; a live leftover stays fail-closed for that
  session only, so unrelated `session.open` calls are not blocked with
  `OWNMESH_E_CONFLICT`.
- Completed `op-journal.json` entries are compacted to durable receipts after
  24 hours or when a value exceeds 64KiB, and oldest completed receipts are
  evicted at 75% of the 4MiB / 4096-entry cap. In-progress keys are never
  dropped. Startup rewrites a compacted file so `ownmesh doctor` can warn from
  `stat` size alone.
- Linux user units no longer set `ProtectHome` or `ProtectSystem=strict`. Those
  options present `$HOME` as uid 65534 and hide registered workspaces, which
  put `ownmeshd` into a restart loop. `NoNewPrivileges=true` remains.
- The daemon never sources shell rc files. It prepends an explicit execution
  PATH from `OWNMESH_EXEC_PATH`, `runtime.exec_path` (absolute directories),
  and well-known user tool dirs. Profile `NotInstalled` fails immediately
  instead of spawning a bare name.
- Windows resolver follows PATHEXT and does not prefer extensionless npm
  shims over `.cmd` / `.exe`. Win32 status 193 is `ExecutableFormat` and maps
  to `OWNMESH_E_INVALID_PARAMS`, not `INTERNAL`.
- `system.diagnose` and `ownmesh doctor` no longer report `healthy` when
  sessions, the op-journal, or the user unit sandbox are broken. Session
  states include `degraded` and `broken`. Remote diagnosis still omits
  absolute PATH strings.

## Compatibility and migration

- No D1 migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  valid.
- Re-run `ownmesh service install` on Linux so the generated user unit drops
  `ProtectHome` / `ProtectSystem=strict`. Optional PATH extras can be set with
  `ownmesh config set runtime.exec_path` or `OWNMESH_EXEC_PATH`.
- Control Plane and Agent version `1.2.13`. Existing Agents remain compatible.

## Upgrade

1. Run `ownmesh update` or install the signed v1.2.13 archive.
2. Deploy the v1.2.13 Control Plane.
3. Confirm `/health/ready` and run `ownmesh doctor --check-network`.
