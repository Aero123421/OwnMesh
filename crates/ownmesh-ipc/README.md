# ownmesh-ipc

Local IPC transport between CLI/TUI/session-host and `ownmeshd`.

## Design

- **Windows:** Named Pipe (`\\.\pipe\ownmesh-daemon-…`)
- **Unix:** Domain socket under the user runtime directory
- **Framing:** 4-byte big-endian length + UTF-8 JSON-RPC 2.0
- **Auth:** Daemon-issued token file (`daemon.token`) with restrictive permissions; `ipc.hello` required before other methods
- **Features:** request correlation ids, per-call timeout, cancellation watch, automatic reconnect after daemon restart

## Core API

- `IpcServer` / `ServerConfig` — daemon side
- `IpcClient` / `ClientIdentity` — CLI/TUI side
- `daemon.status` — built-in status method
