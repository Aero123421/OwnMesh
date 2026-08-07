# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh is an open-source capability-runtime preview: AI clients, humans, and other machines can use user-owned Windows, macOS, and Linux PCs through a control plane deployed to the user's Cloudflare account.

OwnMesh is **not** an AI orchestrator, and the current line is **not feature-complete against the full specification**. It provides a tested runtime foundation, authentication/control-plane paths, policy libraries, local execution, sessions, onboarding/doctor/user-service surfaces, and security invariants.

## Status

**v1.1.0 onboarding train** (workspace package version may still read 1.0.2 until the release cut) — Apache-2.0 monorepo (Rust workspace + Cloudflare Worker).

The CLI currently has **36 explicit unsupported CLI surfaces** from the Rust dispatch registry plus 7 additional hard-error unsupported surfaces (**43 total**). They return machine-visible errors and are excluded from completeness claims. The audited supported/unsupported contract is [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json). In particular, remote execution/session routing fails instead of falling back locally, and `approval watch` fails instead of silently behaving like a one-shot list.

### Supported CLI areas

- `setup` — TTY wizard + non-interactive flags/JSON; privacy defaults (telemetry/relay/update network **OFF**)
- `doctor` — read-only structured diagnostics; global `--json`; network probes only with `--check-network` or a configured control-plane URL
- `service install|start|stop|restart|status|uninstall` — **user-level** `ownmeshd` autostart only (Windows current-user Scheduled Task ONLOGON, macOS LaunchAgent, Linux systemd --user)
- status, login/logout, lockdown/token revoke, config validate
- device enroll/list/show/rotate/revoke
- local execution and local session lifecycle
- approval list/show/decisions, policy inspection/presets
- fail-closed privileged-broker **status** (install/uninstall remain unsupported)

See [`docs/onboarding.md`](./docs/onboarding.md) for setup/doctor/service commands, platform details, and rollback.

Japanese summary: [`README.ja.md`](./README.ja.md).

## Components

| Binary / package | Current role |
|---|---|
| `ownmesh` | CLI (partial; see surface manifest) |
| `ownmesh-tui` | Separate Ratatui UI binary; no-argument CLI launch is unsupported |
| `ownmeshd` | User-level local device agent |
| `ownmesh-session-host` | PTY / long-process host foundation |
| `ownmesh-broker` | Networkless privileged-broker foundation (production install unsupported) |
| `@ownmesh/control-plane` | Cloudflare Worker MCP/OAuth/D1 implementation |

## Quick start (development)

```bash
# Rust 1.92.0 (pinned)
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --all-targets --locked

# TypeScript / Node 22 / pnpm 9.15.0
pnpm install --frozen-lockfile
pnpm -r test
pnpm -r typecheck
pnpm -r lint
```

### First-run (after building `ownmesh` / `ownmeshd`)

```bash
ownmesh setup --control-plane-url https://your-worker.example --non-interactive --force
ownmesh login
ownmesh device enroll
ownmesh service install
ownmesh doctor --json
```

For control-plane deployment, see [docs/deploy-cloudflare.md](./docs/deploy-cloudflare.md) and [docs/chatgpt-connection.md](./docs/chatgpt-connection.md). These guides do not imply live-account or full end-to-end certification.

## User-level service vs privileged broker

| Surface | Privilege | Status |
|---|---|---|
| `ownmesh service …` | Current user only | **Supported** (v1.1.0 onboarding) |
| `ownmesh privileged …` | Would require admin/root | install/uninstall **unsupported**; status fail-closed |

## Release integrity

Tag releases invoke the reusable CI and Security workflows before any release build. Windows, Linux, and macOS **portable archives** are required, and each archive includes `LICENSE`, `NOTICE`, `README.md`, and current release notes. Non-empty CycloneDX SBOMs, SHA-256 checksums, and GitHub build provenance are also required. These archives are not Windows installers, macOS packages, or universal macOS binaries; those package formats remain unimplemented. If both a tracked minisign public key and the matching private-key secret are unavailable, the workflow publishes only a clearly marked **degraded pre-release**. No trust root is currently enrolled; see [`docs/release-keys/README.md`](./docs/release-keys/README.md). Authenticode and Apple notarization remain unsupported under W-SIGN.

## Design invariants

- User-owned control plane; no mandatory central SaaS
- Local-first data by default
- Full Access policy has no hidden hard denies
- Privileged broker is networkless
- Cloud relay and telemetry are off by default
- User-level service management never creates admin/root services

## Specification and release scope

- [release/SUPPORTED_SURFACES.json](./release/SUPPORTED_SURFACES.json) — machine-checked shipped surface
- [docs/onboarding.md](./docs/onboarding.md) — setup / doctor / user service
- [docs/DOD_1.0.md](./docs/DOD_1.0.md) — honest DoD gap audit
- [OWNMESH_SPECIFICATION.ja.md](./OWNMESH_SPECIFICATION.ja.md) — target specification, not a statement of current completeness
- [IMPLEMENTATION_CHECKLIST.md](./IMPLEMENTATION_CHECKLIST.md) — implementation checklist

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
