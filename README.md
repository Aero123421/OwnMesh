# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh is an open-source **capability runtime**: AI clients (ChatGPT MCP), humans (CLI/TUI), and other machines can use **your** Windows / macOS / Linux PCs through a control plane you deploy on **your** Cloudflare account.

OwnMesh is **not** an AI orchestrator. It does not fix ChatGPT above Codex/Claude/etc. It provides capabilities, authn/z, sessions, and audit.

## Status

**v1.0.0** — Apache-2.0 monorepo (Rust workspace + Cloudflare Worker).

## Components

| Binary / package | Role |
|---|---|
| `ownmesh` | CLI (+ launches TUI with no args) |
| `ownmesh-tui` | Rich terminal UI (Ratatui) |
| `ownmeshd` | User-level device agent |
| `ownmesh-session-host` | PTY / long process host |
| `ownmesh-broker` | Networkless privileged broker |
| `@ownmesh/control-plane` | Cloudflare Workers MCP + OAuth + D1 |

## Quick start (dev)

```bash
# Rust 1.92+
cargo test --workspace
cargo run -p ownmesh -- --help

# TypeScript
pnpm install
pnpm -r test
pnpm -r typecheck
cd packages/control-plane && pnpm dev
```

## Deploy your control plane

See [docs/deploy-cloudflare.md](./docs/deploy-cloudflare.md) and [docs/chatgpt-connection.md](./docs/chatgpt-connection.md).

## Design principles

- User-owned control plane (no mandatory central SaaS)
- Local-first data (code, full logs, credentials, sessions stay on PC by default)
- Full Access is first-class — **no hidden hard denies**
- Privileged broker is **networkless**
- Cloud file relay **off** by default
- Telemetry **off** by default

## Spec

- [OWNMESH_SPECIFICATION.ja.md](./OWNMESH_SPECIFICATION.ja.md)
- [IMPLEMENTATION_CHECKLIST.md](./IMPLEMENTATION_CHECKLIST.md)
- [spec-bundle/](./spec-bundle/) schemas & examples

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
