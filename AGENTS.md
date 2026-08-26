# AGENTS.md

## Project

OwnMesh is an Apache-2.0, self-hosted capability runtime. It lets AI clients
(including ChatGPT over MCP), humans, and other machines use a user's Windows,
macOS, or Linux devices through a control plane deployed in the user's own
Cloudflare account.

OwnMesh provides authentication, authorization, device routing, workspaces,
commands, sessions, transfers, approvals, and auditability. It is not an AI
orchestrator, remote desktop, or mandatory central SaaS.

## Technology stack

- Rust 1.92 workspace: CLI, Ratatui TUI, device daemon, IPC, policy, sessions,
  filesystem/command capabilities, updater, and networkless privileged broker.
- TypeScript (Node.js 22+, pnpm): Cloudflare Workers control plane.
- Cloudflare Durable Objects + WebSockets for device routing, D1 for durable
  control-plane state, and OAuth/MCP for client access.
- GitHub Actions, Minisign, SHA-256 checksums, provenance, and CycloneDX SBOMs
  for release assurance.

## Working principles

- Preserve fail-closed authorization, exact action binding, idempotency, and
  replay protection. Never weaken a security boundary for convenience.
- Telemetry, cloud file relay, and unsolicited network activity remain off by
  default. Never log or commit credentials, tokens, private keys, or user data.
- Keep changes scoped and reviewable. Add focused regression tests for changed
  behavior and keep Rust, TypeScript, schemas, docs, and user-facing claims in
  sync.
- Treat displayed state as a product contract: do not claim support or success
  unless the authoritative path is implemented and tested.

## Read before changing

- [README](./README.md) — product overview and component map
- [Contributing](./CONTRIBUTING.md) — setup, quality gates, and PR expectations
- [Security policy](./SECURITY.md) — vulnerability handling and hardening scope
- [Threat model](./docs/THREAT_MODEL.md) — trust boundaries and threats
- [Specification](./OWNMESH_SPECIFICATION.ja.md) — product and protocol intent
- [Roadmap](./docs/ROADMAP.md) — supported direction and remaining work
- [Definition of done](./docs/DOD_1.0.md) — release completion criteria
- [Architecture decisions](./docs/adr/) — security and protocol decisions
- [Cloudflare deployment](./docs/deploy-cloudflare.md) and
  [ChatGPT connection](./docs/chatgpt-connection.md) — operator workflows
