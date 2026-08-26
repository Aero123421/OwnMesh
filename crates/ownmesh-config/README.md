# ownmesh-config

Configuration paths, TOML loading, migration, atomic writes, and schema validation.

## Layout

| OS | config | state | runtime |
|---|---|---|---|
| Windows | `%APPDATA%\OwnMesh` | `%LOCALAPPDATA%\OwnMesh` | `%LOCALAPPDATA%\OwnMesh\run` |
| macOS | `~/Library/Application Support/OwnMesh` | `…/state` | `~/Library/Caches/OwnMesh/run` |
| Linux | `$XDG_CONFIG_HOME/ownmesh` | `$XDG_STATE_HOME/ownmesh` | `$XDG_RUNTIME_DIR/ownmesh`, or owner-only `/run/user/<uid>/ownmesh` when `XDG_RUNTIME_DIR` is unset |

Secrets are **never** stored in `config.toml`. Use `ownmesh-identity` for credentials.
