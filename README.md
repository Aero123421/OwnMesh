# OwnMesh

OwnMesh lets AI clients such as ChatGPT use your Windows, macOS, and Linux
machines. It is self-hosted end to end: an open-source agent runs on each
device, and the control plane is a Cloudflare Worker you deploy into your own
Cloudflare account. There is no vendor-hosted service, no telemetry, no
phone-home.

OwnMesh is not an AI orchestrator or a remote desktop. The local agent runs as
your normal user; privileged work is opt-in and handled by a separate broker
process with no network access.

## What you get

- **ChatGPT as a client, out of the box.** OwnMesh exposes an MCP endpoint
  with OAuth, dynamic client registration, and passkey login for the owner.
- **Multi-device operation.** Enroll devices from the CLI or the built-in
  terminal UI, then run commands, read and write approved paths, query logs,
  open interactive sessions, and transfer files between machines.
- **A policy you control.** Every request passes your allow/ask/deny rules.
  Sensitive actions (approvals, policy changes, unlock) additionally require a
  fresh passkey decision bound to exactly that operation.
- **Honest state everywhere.** What the UI reports is what was verified; the
  shipped CLI surface is machine-checked in
  [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json).

## Install

Linux or macOS:

```bash
curl -fsSL https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh | sh
```

Windows PowerShell:

```powershell
$p="$env:TEMP\ownmesh-installer.ps1"; Invoke-WebRequest https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

Both installers verify the release signature and checksums before they touch
your system. On macOS the one-liner uses Homebrew to fetch `minisign` for the
signature check (install `minisign` yourself, or point `OWNMESH_MINISIGN` at
an existing binary, to skip that). On Linux a pinned, hash-checked `minisign`
is bootstrapped when none is present.

Prefer to verify by hand? Download the installer together with `SHA256SUMS`
and `SHA256SUMS.minisig`, check the signature and checksum, then run it.

Take the public key from a repository clone — not from the release you are
verifying, since a release cannot vouch for itself:
[`docs/release-keys/minisign.pub`](./docs/release-keys/minisign.pub), key ID
`C596813EFB0946A4`. The same key is compiled into the installers and into
`ownmesh update`, so all three agree on one trust root.

After the first install, updates are one command on every platform:

```bash
ownmesh update
```

It re-verifies the signed release chain, drains sessions, replaces all five
binaries atomically, restarts your service, verifies the new versions, and
rolls back if anything fails. `ownmesh update status` shows progress.
Homebrew-managed installs keep using `brew upgrade ownmesh`.

## Setup

### 1. Deploy your control plane

Everything else needs its URL, so start here:

```bash
cd packages/control-plane && corepack enable && pnpm install --frozen-lockfile && pnpm run deploy:guided
```

The guided deploy creates or reuses D1, applies migrations, deploys the
Worker, provisions secrets, and prints the owner-login URL, the ChatGPT MCP
URL, and the exact `ownmesh setup` command for the next step.
Details: [`docs/deploy-cloudflare.md`](./docs/deploy-cloudflare.md),
[`docs/chatgpt-connection.md`](./docs/chatgpt-connection.md).

### 2. Connect a machine

Desktop: launch the TUI and choose **Finish setup**.

```bash
ownmesh
```

SSH or headless servers print a URL and short code that you approve on
another device:

```bash
ownmesh setup --control-plane-url https://your-worker.example --quickstart --device-login --non-interactive --force
```

### 3. Verify

Read-only; change nothing. Add `--check-network` to also probe the control
plane's `/health`:

```bash
ownmesh doctor --json
```

## Security model

- You own the control plane. There is no mandatory central service.
- Telemetry, cloud file relay, and automatic update checks are off by
  default. Files, command output, and logs stay local unless an operation
  explicitly moves them.
- Credentials live in the OS credential store, not in `config.toml`.
- Admin actions are typed operations, never generic method/parameter
  passthrough. A same-user local socket does not count as human presence.
- `ownmeshd` always runs as your user. The optional privileged broker has no
  network access and is installed separately:

```bash
sudo ownmesh privileged install && ownmesh service install
```

(On Windows, run the first command in an Administrator PowerShell, then the
second as the normal user.)

- Full Access has no hidden hard deny. Whichever policy you choose still
  applies its documented allow/ask/deny behavior.

## Release assurance, and what is still open

Releases ship as portable archives for Windows x64, macOS arm64/x64, and
Linux musl arm64/x64, each with SHA-256 checksums, a mandatory minisign
signature, CycloneDX SBOMs, and GitHub build provenance.

Things we have verified vs. things still pending:

- The networkless privileged-broker lifecycle is implemented on all three
  operating systems. Linux has a native root receipt; macOS/Windows native
  receipts and the full MCP → agent → broker receipt are still open evidence,
  and we do not claim them as proven.
- ChatGPT dynamic registration, OAuth, passkey return, refresh, and MCP
  linking have a manual live compatibility receipt; fully automated external
  verification is still pending.
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages are
  not part of this release train.

## Development

Rust 1.92, Node 22, and pnpm 9.15.0 are pinned by the repository. The quality
gates:

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

See [CONTRIBUTING](./CONTRIBUTING.md) for setup and PR expectations.

## Documentation

- [Japanese README](./README.ja.md)
- [Supported surface manifest](./release/SUPPORTED_SURFACES.json)
- [Onboarding and service setup](./docs/onboarding.md)
- [Cloudflare deployment](./docs/deploy-cloudflare.md)
- [ChatGPT connection](./docs/chatgpt-connection.md)
- [Threat model](./docs/THREAT_MODEL.md)
- [Roadmap](./docs/ROADMAP.md) — what is planned next, and what is not
- [v1.2.20 release notes](./docs/RELEASE_NOTES_v1.2.20.md)
- [Target specification](./OWNMESH_SPECIFICATION.ja.md) — roadmap authority,
  not a claim that every optional target is shipped

## License

Apache License 2.0 — see [LICENSE](./LICENSE).
