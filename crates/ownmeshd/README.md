# ownmeshd

User-level OwnMesh device agent.

```bash
ownmeshd run       # foreground daemon (default)
ownmeshd status    # probe local IPC
ownmeshd version
```

Serves JSON-RPC over local IPC and answers `daemon.status`. Bootstraps device identity via `ownmesh-identity`.

When the active control-plane instance has an issuer/device-bound enrollment
credential, the daemon also maintains an authenticated WebSocket connection to
`/agent/connect`. The E1 transport performs Ed25519 challenge proof, bounded
reconnect, durable sequence resume, and correlation deduplication. Remote
execution remains fail-closed until E2; valid operation requests receive an
explicit unsupported result and are never routed into the local runtime.
