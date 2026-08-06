# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh is an open-source **capability runtime** for user-owned PCs. Deploy the control plane on **your** Cloudflare account, then use ChatGPT (Personal Plugin + Remote MCP + OAuth), any MCP client, or the OwnMesh CLI/TUI to operate Windows, macOS, and Linux machines—and the CLIs that run on them.

OwnMesh does **not** fix roles between AIs (no hidden “ChatGPT is orchestrator / Codex is worker” workflow). It provides capabilities, connection, auth, policy, sessions, and audit.

## Status

OwnMesh **1.0** is under active implementation against [`OWNMESH_SPECIFICATION.ja.md`](./OWNMESH_SPECIFICATION.ja.md). This repository currently ships a buildable workspace skeleton (chapter 0).

## Highlights

| Area | Choice |
| --- | --- |
| Local agent / CLI / TUI | Rust |
| TUI | Ratatui + Crossterm |
| Control plane | TypeScript · Cloudflare Workers · D1 · Durable Objects |
| ChatGPT | Personal Plugin · Streamable HTTP MCP · OAuth 2.1 |
| Policy | allow / ask / deny · Workspace Only → Full Access |
| Elevation | Networkless privileged broker |
| File relay / telemetry | Off by default |
| License | Apache-2.0 |
| Locales (1.0) | English, 日本語, 简体中文, Русский |

## Official CLI profiles (1.0)

1. OpenAI Codex CLI  
2. Claude Code  
3. Kimi Code  
4. OpenCode  
5. Pi Coding Agent  
6. Antigravity CLI (`agy`)  
7. Qwen Code  
8. Hermes Agent  
9. Qoder CLI  

Any other CLI can still run via `ownmesh exec` or `ownmesh session open` without a profile.

## Repository layout

```text
ownmesh/
├── crates/                 # Rust workspace (agent, CLI, TUI, broker, libs)
├── packages/control-plane/ # Cloudflare Workers control plane
├── spec-bundle/            # JSON Schemas + config examples
├── docs/adr/               # Architecture Decision Records
├── OWNMESH_SPECIFICATION.ja.md
└── IMPLEMENTATION_CHECKLIST.md
```

## Quick start (development)

### Prerequisites

- Rust **1.85.0** (see `rust-toolchain.toml`)
- Node.js **≥ 22** and **pnpm 9.15.0** (Corepack recommended)

### Rust workspace

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

### TypeScript (control plane)

```bash
pnpm install
pnpm -r typecheck
pnpm -r lint
```

### Binaries (skeletons)

| Binary | Crate | Role |
| --- | --- | --- |
| `ownmesh` | `crates/ownmesh` | CLI |
| `ownmesh-tui` | `crates/ownmesh-tui` | Terminal UI |
| `ownmeshd` | `crates/ownmeshd` | User-level device agent |
| `ownmesh-session-host` | `crates/ownmesh-session-host` | Detached PTY/session supervisor |
| `ownmesh-broker` | `crates/ownmesh-broker` | Privileged (networkless) broker |

```bash
cargo run -p ownmesh -- --help
```

## Documentation

- [`OWNMESH_SPECIFICATION.ja.md`](./OWNMESH_SPECIFICATION.ja.md) — full product & architecture specification  
- [`IMPLEMENTATION_CHECKLIST.md`](./IMPLEMENTATION_CHECKLIST.md) — implementation order and done criteria  
- [`SECURITY.md`](./SECURITY.md) — vulnerability reporting  
- [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to contribute  
- [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) — community standards  
- [`SECURITY_REVIEW_CHECKLIST.md`](./SECURITY_REVIEW_CHECKLIST.md) — security review gates  
- [`docs/adr/`](./docs/adr/) — ADRs (signing/SBOM/provenance, …)  
- [`spec-bundle/`](./spec-bundle/) — machine-readable schemas and examples  

## Security

Please **do not** open public issues for sensitive reports. See [`SECURITY.md`](./SECURITY.md).

Secrets, tokens, and private keys must never be committed. Local runtime data lives under OS-specific OwnMesh paths and is gitignored (`.ownmesh/`, `.env`, key material, etc.).

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
