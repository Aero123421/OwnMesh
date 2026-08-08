# OwnMesh v1.2.0-beta.3 — E2 remote routing candidate

## Summary

This beta wires ChatGPT-facing Streamable HTTP MCP to the real ownmeshd Agent
and local policy runtime for direct filesystem and command operations. It does
not claim production-complete v1.2 and does not close E10 live-account gates.

## What is new

- Public `/mcp` → DeviceRoom → Agent WSS → `DaemonRuntime` production path
- `ownmesh.operation/1.0` request binding (`correlation_id == operation_id`)
- Remote-routing readiness gating on DeviceRoom
- Bounded file read ranges with encoding/integrity metadata
- Real binary × local Wrangler/workerd E2 loopback proof

## What remains unsupported / open

- CLI `exec --device` / `session open <device>`
- Workspace product surfaces (E4)
- Cloud PTY sessions (E5)
- Profile product surfaces (E6)
- Coding patch/Git review flow (E7)
- Elevated broker mint/custody (E8)
- Multi-device transfer (E9)
- Live ChatGPT + live Cloudflare proof (E10)

## Docs

- [`docs/V1.2_E2_REMOTE_ROUTING.md`](./V1.2_E2_REMOTE_ROUTING.md)
- [`docs/chatgpt-connection.md`](./chatgpt-connection.md)
