# OwnMesh 1.0.0

**Any AI. Any CLI. Any machine. Your cloud.**

First OSS release of OwnMesh — a user-owned capability runtime for Windows, macOS, and Linux.

## Highlights

- Rust local stack: `ownmesh` CLI, `ownmesh-tui`, `ownmeshd`, `ownmesh-session-host`, `ownmesh-broker`
- Domain, protocol, IPC, config, identity crates with tests
- Execution, filesystem, logs, policy (Full Access with **no hidden denies**), sessions/handoff
- Networkless privileged broker with signed requests + replay protection
- Nine official CLI profiles + generic unknown-CLI launch
- P2P transfer planner that **never** silently falls back to cloud relay
- Update/diagnostics defaults: telemetry off, crash reports opt-in only
- Cloudflare Workers control plane: OAuth (PKCE/refresh rotation/reuse detection), MCP `/mcp`, device registry, D1 migrations, DeviceRoom DO stub
- Official languages in TUI strings: en, ja, zh-Hans, ru
- License: Apache-2.0

## Install (from source)

```bash
git clone https://github.com/Aero123421/OwnMesh.git
cd OwnMesh
cargo build --release --workspace
pnpm install
```

## Deploy control plane

See [docs/deploy-cloudflare.md](./deploy-cloudflare.md).

## Security

See [SECURITY.md](../SECURITY.md) and [SECURITY_REVIEW_CHECKLIST.md](../SECURITY_REVIEW_CHECKLIST.md).

External independent audit is recommended for high-risk Full Access deployments; residual risks are documented in the checklists.
