# ownmesh-ipc

Local IPC transport between CLI/TUI/session-host and `ownmeshd`.

## Design

- **Windows:** Named Pipe (`\\.\pipe\ownmesh-daemon-…`) with client PID + executable peer identity
- **Unix:** Domain socket under the user runtime directory with `SO_PEERCRED`
- **Framing:** 4-byte big-endian length + UTF-8 JSON-RPC 2.0
- **Auth:** OS peer credentials (server-side principal mapping). Shared `daemon.token` is abolished.
  Optional server-managed per-client non-shared credentials for multi-agent principals under the same OS user.
  Self-reported HELLO `client_name` is never a trusted principal input. Revocation keys are mapped principal keys.
- **Features:** request correlation ids, per-call timeout, cancellation watch, automatic reconnect after daemon restart

## Core API

- `IpcServer` / `ServerConfig` / `AuthGate::local_user()` — daemon side
- `IpcClient` / `ClientIdentity` — CLI/TUI side (`with_client_credential` for issued secrets)
- `daemon.status` — built-in status method
