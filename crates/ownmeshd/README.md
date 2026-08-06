# ownmeshd

User-level OwnMesh device agent.

```bash
ownmeshd run       # foreground daemon (default)
ownmeshd status    # probe local IPC
ownmeshd version
```

Serves JSON-RPC over local IPC and answers `daemon.status`. Bootstraps device identity via `ownmesh-identity`.
