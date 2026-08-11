# ownmesh-broker

Networkless privileged broker for elevated operations.

On Linux, `ownmesh-broker install --trusted-executable <root-owned-ownmeshd>
--daemon-uid <uid> --daemon-gid <gid>` creates a root-only native systemd
service while `ownmeshd` remains an explicit non-root peer identity. It copies
immutable images to `/usr/lib/ownmesh`, gives that daemon-owned UDS and request
secret mode `0600`, and only accepts the strict root-owned configuration at
`/etc/ownmesh/ownmesh-broker.json`. When invoked through sudo, both UID/GID may
be read from `SUDO_UID`/`SUDO_GID`; direct root invocations must supply them.
Windows and macOS lifecycle commands remain unsupported.

## Production status: **UNSUPPORTED**

Until a secure mint authority is established, production entry points are fixed
as fail-closed unsupported:

| Surface | Behavior |
| --- | --- |
| `ownmesh-broker install` / `status` / `run` / `exec` | Explicit `unsupported`, non-zero exit, `installed=false` |
| `ownmesh privileged *` | Explicit `unsupported`, non-zero exit (except uninstall cleanup) |
| `ownmeshd` `ops.exec` with `elevated=true` | Explicit unsupported error; **no** local exec fallback |
| Process execution via production serve | **Removed** — `run_broker` never binds or spawns |

In-process library helpers used by unit tests (`execute_verified*`) may still
exercise MAC/capability crypto with a synthetic peer bind. They are not reachable
from production CLI/daemon elevated paths.

Do **not** hand-write success install records or success E2E fixtures claiming a
live elevated broker.
