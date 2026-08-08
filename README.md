# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh is an open-source capability-runtime preview: AI clients, humans, and other machines can use user-owned Windows, macOS, and Linux PCs through a control plane deployed to the user's Cloudflare account.

OwnMesh is **not** an AI orchestrator, and the 1.x line is **not feature-complete against the full specification**. It currently provides a tested runtime foundation, authentication/control-plane paths, policy libraries, local execution, sessions, onboarding/doctor/user-service surfaces, signed distribution/update, and security invariants.

## Status

**v1.1.0** — Apache-2.0 monorepo (Rust workspace + Cloudflare Worker).

The CLI currently has **27 explicit unsupported CLI surfaces** from the Rust dispatch registry plus 7 additional hard-error unsupported surfaces (**34 total**). They return machine-visible errors and are excluded from completeness claims. The audited supported/unsupported contract is [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json). In particular, remote execution/session routing fails instead of falling back locally, and `approval watch` fails instead of silently behaving like a one-shot list.

### Supported CLI areas

- `setup` — TTY wizard + non-interactive flags/JSON; privacy defaults (telemetry/relay/update network **OFF**)
- `doctor` — read-only structured diagnostics; global `--json`; network probes only with `--check-network` or a configured control-plane URL; credentials reported from non-secret metadata only (no keychain load)
- `service install|start|stop|restart|status|uninstall` — **user-level** `ownmeshd` autostart only (Windows current-user Scheduled Task ONLOGON, macOS LaunchAgent, Linux systemd --user)
- `update check|download|apply|channel` — signed GitHub Releases; network off by default; embedded minisign trust root
- status, login/logout, lockdown/token revoke, config validate
- device enroll/list/show/rotate/revoke
- local execution and local session lifecycle
- approval list/show/decisions, policy inspection/presets
- fail-closed privileged-broker **status** (install/uninstall remain unsupported)

See [`docs/onboarding.md`](./docs/onboarding.md) for setup/doctor/service commands, platform details, and rollback. See [`docs/RELEASE_NOTES_v1.1.0.md`](./docs/RELEASE_NOTES_v1.1.0.md) for distribution/update details.

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

## Install (portable)

**Do not** pipe remote installer text into a shell (`curl|sh` / `irm|iex`). Download, inspect, verify against the signed release checksums, then execute from a local path.

macOS / Linux:

```bash
curl -fsSL -o ownmesh-installer.sh \
  https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh
curl -fsSL -O https://github.com/Aero123421/OwnMesh/releases/latest/download/SHA256SUMS
curl -fsSL -O https://github.com/Aero123421/OwnMesh/releases/latest/download/SHA256SUMS.minisig
curl -fsSL -O https://github.com/Aero123421/OwnMesh/releases/latest/download/minisign.pub
minisign -Vm SHA256SUMS -p minisign.pub -x SHA256SUMS.minisig
sha256sum -c SHA256SUMS --ignore-missing  # confirm ownmesh-installer.sh
less ownmesh-installer.sh   # inspect
sh ./ownmesh-installer.sh   # execute only after inspect + verify
```

Windows (PowerShell):

```powershell
Invoke-WebRequest -Uri https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile ownmesh-installer.ps1
# Download SHA256SUMS + SHA256SUMS.minisig + minisign.pub, verify with minisign, inspect the script, then:
powershell -NoProfile -File .\ownmesh-installer.ps1
```

The installer requires **minisign** (on `PATH` or `OWNMESH_MINISIGN`) and verifies `SHA256SUMS.minisig` against the pinned OwnMesh public key **before** trusting any checksum. After checksum verification it enforces the same archive contract as `ownmesh update` (entry/size caps, exact binary+doc allow-list, no duplicates/symlinks/traversal) with member-by-member staging — never full `tar -xzf` / `Expand-Archive`. The shell installer fails closed if `tar -tvzf` listing cannot be parsed safely. Set `OWNMESH_VERSION`, `OWNMESH_INSTALL_DIR`, or `OWNMESH_NO_MODIFY_PATH` as needed. Homebrew formula assets are published as `ownmesh.rb` on each release.

### Local approval / human-operator note (v1.1.0)

`approval approve|deny`, `policy preset`, `unlock`, and `tokens revoke` over ordinary local IPC are **fail-closed** until a distinct OS/UI user-presence proof bound to the operation exists. Same-UID unauthenticated sockets are forgeable and are not treated as human presence.

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
ownmesh update check
```

For control-plane deployment, see [docs/deploy-cloudflare.md](./docs/deploy-cloudflare.md) and [docs/chatgpt-connection.md](./docs/chatgpt-connection.md). These guides do not imply live-account or full end-to-end certification.

## User-level service vs privileged broker

| Surface | Privilege | Status |
|---|---|---|
| `ownmesh service …` | Current user only | **Supported** (v1.1.0 onboarding) |
| `ownmesh privileged …` | Would require admin/root | install/uninstall **unsupported**; status fail-closed |

## Release integrity

Tag releases invoke the reusable CI and Security workflows before any release build. Windows x64, macOS arm64/x64, and Linux musl arm64/x64 **portable archives** are required, and each archive includes `LICENSE`, `NOTICE`, `README.md`, and current release notes. Non-empty CycloneDX SBOMs, per-asset SHA-256 checksums, aggregate `SHA256SUMS`, **minisign signature** (`SHA256SUMS.minisig`), and GitHub build provenance are required. Missing signing keys **fail the release** (no degraded unsigned formal publish). Trust root: [`docs/release-keys/`](./docs/release-keys/). Authenticode and Apple notarization remain unsupported under W-SIGN.

## Design invariants

- User-owned control plane; no mandatory central SaaS
- Local-first data by default
- Full Access policy has no hidden hard denies
- Privileged broker is networkless
- Cloud relay and telemetry are off by default
- User-level service management never creates admin/root services
- Automatic update network checks are off by default

## Specification and release scope

- [release/SUPPORTED_SURFACES.json](./release/SUPPORTED_SURFACES.json) — machine-checked shipped surface
- [docs/onboarding.md](./docs/onboarding.md) — setup / doctor / user service
- [docs/RELEASE_NOTES_v1.1.0.md](./docs/RELEASE_NOTES_v1.1.0.md) — v1.1.0 distribution and onboarding notes
- [docs/DOD_1.0.md](./docs/DOD_1.0.md) — honest DoD gap audit
- [OWNMESH_SPECIFICATION.ja.md](./OWNMESH_SPECIFICATION.ja.md) — target specification, not a statement of current completeness
- [IMPLEMENTATION_CHECKLIST.md](./IMPLEMENTATION_CHECKLIST.md) — implementation checklist
- [CHANGELOG.md](./CHANGELOG.md) — release changelog

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
