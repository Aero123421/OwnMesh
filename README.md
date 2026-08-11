# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh is a self-hosted, open-source capability runtime. ChatGPT and other MCP
clients can use your Windows, macOS, and Linux machines through a control plane
deployed in your own Cloudflare account.

OwnMesh is not an AI orchestrator and does not require a vendor-hosted OwnMesh
account. The local agent stays under your user account; an optional, separate,
networkless broker handles explicitly approved privileged work.

## Status

**v1.2.1 stable** — Apache-2.0 monorepo (Rust workspace + Cloudflare Worker).

The shipped CLI surface has no intentionally unimplemented entries. Its
machine-checked contract is
[`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json).
“Complete” refers to that admitted product surface, not every aspirational item
in the full specification or every optional native package/signing format.

### What is included

- One-command setup for desktop and headless/SSH machines, read-only `doctor`,
  user-level service management, and the bundled dark terminal UI.
- ChatGPT-compatible MCP OAuth with dynamic client registration, rotating
  refresh tokens, built-in single-owner passkey login, and exact callback
  validation.
- Device enroll/list/show/rename/labels/key rotation/revoke.
- Local and authenticated remote execution plus session creation. Remote
  requests require explicit idempotency and never fall back to local execution.
- Nine structured AI CLI profiles, persistent profile sessions, and profile
  scan/list/show/login/test/start/resume commands.
- Approval list/show/watch and typed approve/deny operations.
- Policy inspection, presets, and structured rule mutation; lockdown/unlock and
  token revocation.
- Fresh-passkey authorization for sensitive admin mutations. Decisions are
  bound to the exact operation and are consumed exactly once.
- Authenticated, resumable, bounded device-to-device transfer with explicit
  plan/send/list/status/cancel commands and no overwrite fallback.
- `ownmesh mcp serve --stdio`, a bounded JSONL bridge that uses the configured
  issuer and OS credential store without printing secrets or diagnostics to
  stdout.

## Install

The normal installer verifies the release signature and checksums before
installing binaries.

Linux or macOS:

```bash
curl -fsSL https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh | sh
```

Windows PowerShell:

```powershell
$p="$env:TEMP\ownmesh-installer.ps1"; Invoke-WebRequest https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

For offline-verifiable bootstrap, download `ownmesh-installer.sh` or
`ownmesh-installer.ps1` together with `SHA256SUMS`, `SHA256SUMS.minisig`, and
`minisign.pub`; verify the signature and installer checksum before execution.
The installers also enforce archive entry/size limits, an exact file allowlist,
and reject traversal, links, devices, and duplicate members.

## First run

### 1. Deploy your control plane

Every later step needs its URL, so this comes first. From a clone:

```bash
cd packages/control-plane && corepack enable && pnpm install --frozen-lockfile && pnpm run deploy:guided
```

The guided deploy creates or reuses D1, applies migrations, deploys the Worker,
provisions required secrets, and prints the owner-login URL, the ChatGPT MCP
URL, and the exact `ownmesh setup` command for step 2. See
[`docs/deploy-cloudflare.md`](./docs/deploy-cloudflare.md) and
[`docs/chatgpt-connection.md`](./docs/chatgpt-connection.md).

### 2. Connect a machine

Desktop (opens browser login, enrolls this PC, and installs user autostart):

```bash
ownmesh setup --control-plane-url https://your-worker.example --quickstart
```

SSH or Ubuntu Server (prints a URL and short code for approval on another
device):

```bash
ownmesh setup --control-plane-url https://your-worker.example --quickstart --device-login --non-interactive --force
```

### 3. Verify

Read-only; changes nothing. Add `--check-network` to also probe the control
plane's `/health`:

```bash
ownmesh doctor --json
```

## Security model

- The control plane belongs to the user; there is no mandatory central SaaS.
- Telemetry, cloud relay, and automatic update network checks are off by default.
- Files, command output, and logs remain local unless a requested operation
  explicitly transfers data.
- OAuth/device credentials live in the operating-system credential store, not
  `config.toml`.
- Sensitive admin actions are typed; there is no generic method/parameter
  passthrough. A same-user local socket is not treated as human presence.
- The normal `ownmeshd` service is always user-level. The optional privileged
  broker has no network access.
- Full Access has no hidden hard deny, while every selected policy still applies
  its documented allow/ask/deny behavior.

Optional privileged execution is enabled separately:

```bash
sudo ownmesh privileged install && ownmesh service install
```

On Windows, run `ownmesh privileged install` in an Administrator PowerShell,
then run `ownmesh service install` as the normal user.

## Platform and integration evidence

Portable archives are produced for Windows x64, macOS arm64/x64, and Linux musl
arm64/x64 with LICENSE/NOTICE/release notes, CycloneDX SBOMs, SHA-256 checksums,
mandatory minisign signature, and GitHub build provenance.

The networkless privileged-broker lifecycle is implemented on Linux, macOS, and
Windows. Linux has a native root lifecycle receipt. macOS/Windows native release
receipts and the full public MCP → installed agent → broker E8 receipt remain
open evidence; this is not presented as live proof for those routes.
Authenticode, Apple notarization, MSI/NSIS, and native macOS packages are not
part of v1.2.1.

ChatGPT dynamic registration, OAuth, passkey return, refresh, and MCP linking
have a manual live compatibility receipt. The local workerd suites are
reproducible; a fully automated external ChatGPT E10 receipt remains open.

## Development gates

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
pnpm install --frozen-lockfile
pnpm -r test
pnpm -r typecheck
pnpm -r lint
```

Rust 1.92.0, Node 22, and pnpm 9.15.0 are pinned by the repository.

## Documentation

- [Japanese README](./README.ja.md)
- [Supported surface manifest](./release/SUPPORTED_SURFACES.json)
- [Onboarding and service setup](./docs/onboarding.md)
- [Cloudflare deployment](./docs/deploy-cloudflare.md)
- [ChatGPT connection](./docs/chatgpt-connection.md)
- [Threat model](./docs/THREAT_MODEL.md)
- [v1.2.1 release notes](./docs/RELEASE_NOTES_v1.2.1.md)
- [Target specification](./OWNMESH_SPECIFICATION.ja.md) — roadmap authority,
  not a claim that every optional target is shipped

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
