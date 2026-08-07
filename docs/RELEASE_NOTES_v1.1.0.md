# OwnMesh v1.1.0 — Onboarding, signed distribution, and self-update

v1.1.0 ships first-run onboarding (setup / doctor / user-level `ownmeshd` service) together with production portable distribution: multi-arch release archives, minisign-signed checksums, installers, Homebrew formula rendering, and a fail-closed `ownmesh update` path. It is **not** a claim that the full OwnMesh specification is complete.

## Scope and compatibility

The CLI has **32 explicit unsupported CLI surfaces** from the authoritative Rust registry plus 7 additional hard-error unsupported surfaces (**39 total**), machine-recorded in [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json). They return explicit machine-readable errors and are excluded from completeness.

**Newly supported in 1.1.0:**

- `ownmesh setup` (TTY wizard + non-interactive flags/JSON; privacy defaults OFF)
- `ownmesh doctor` (read-only structured diagnostics; `--json`; network opt-in or when configured)
- `ownmesh service install|start|stop|restart|status|uninstall` (user-level `ownmeshd` only)
- `ownmesh update check`
- `ownmesh update download`
- `ownmesh update apply`
- `ownmesh update channel`

Update defaults keep **network off** (`update.mode = "off"`). Explicit `check` / `download` / `apply` are user-initiated and may contact official GitHub Release endpoints only.

Doctor never writes config or mutates OS services. Network probes run only with `--check-network` or when a control-plane URL is already configured. Outputs redact secret-looking material and never call OS credential `load`/keychain APIs (presence is inferred from non-secret metadata only).

### Human-operator IPC (fail-closed)

Until a distinct OS/UI user-presence proof bound to the approval operation and expiry exists, ordinary local IPC clients **cannot** call `approval.approve` / `approval.deny`, `policy.preset`, `daemon.unlock`, or `token.revoke`. Same-UID unauthenticated connections are forgeable by any local process (including a credentialed agent opening a second socket) and are **not** treated as human presence. The CLI surfaces the same fail-closed error. Offline policy rewrite remains available via `ownmesh setup --force --policy-preset …`.

### Compatibility impact

- Workspace / package / control-plane `SERVICE_VERSION` are **1.1.0**.
- Config schema remains backward-compatible; new update settings default to safe OFF values.
- Privileged broker install/uninstall remain unsupported and side-effect-free.
- CLI no-argument TUI handoff remains unsupported; use `ownmesh-tui`.
- Surfaces that were explicit stubs in 1.0.x and are still listed in the unsupported registry continue to hard-fail (no silent enablement).

## Onboarding and user-level service

- `setup` writes local config/policy as a **journaled two-file transaction** (durable recovery / complete rollback on policy failure so a new config is never left with an old strong policy), with non-TTY / `--non-interactive` support.
- Control-plane URLs use one strict `url::Url` validator (https, or loopback http only); userinfo/query/fragment/control characters are rejected; doctor/setup errors and JSON redact URL secrets.
- Privacy defaults: telemetry OFF, relay OFF, update network OFF.
- `service` manages **current-user** autostart only:
  - Windows: current-user Scheduled Task (ONLOGON / LeastPrivilege)
  - macOS: LaunchAgent (`dev.ownmesh.ownmeshd`)
  - Linux: systemd --user (`ownmesh-ownmeshd.service`)
- Descriptors quote/escape paths, refuse symlink/world-writable executables, and never install admin/root or broker units.
- Rollback: restore `config.toml.bak` / re-run setup with `--force`; `ownmesh service uninstall`.

## Distribution and signing

- Release matrix publishes five portable archives:
  - `ownmesh-windows-x64.zip`
  - `ownmesh-macos-arm64.tar.gz`
  - `ownmesh-macos-x64.tar.gz`
  - `ownmesh-linux-x64.tar.gz` (musl)
  - `ownmesh-linux-arm64.tar.gz` (musl)
- Each archive contains the five binaries (`ownmesh`, `ownmesh-tui`, `ownmeshd`, `ownmesh-session-host`, `ownmesh-broker`) plus `LICENSE`, `NOTICE`, `README.md`, and current release notes.
- CI and Security reusable workflows remain hard prerequisites for release build/publish.
- Non-empty CycloneDX SBOMs and GitHub build provenance remain required.
- Per-asset `.sha256` sidecars plus aggregate `SHA256SUMS` are published.
- **`SHA256SUMS` is minisign-signed and immediately verified against the tracked public key before publish.** Missing `MINISIGN_SECRET_KEY` or trust root **fails the release** (no degraded unsigned formal release).
- Installer scripts and generated `ownmesh.rb` are release assets.

### Minisign trust root

| Field | Value |
| --- | --- |
| Public key file | [`docs/release-keys/minisign.pub`](./release-keys/minisign.pub) |
| Key ID | `C596813EFB0946A4` |
| Fingerprint (SHA-256 of decoded public-key blob) | `1450496b7af985f57466b4b5f0b9c985d6c3e96ed66ee2cebb4f5a94ba5775d9` |

**Rotation:** generate a new minisign keypair offline, commit only the new public key, announce the new key ID/fingerprint in SECURITY.md and release notes, update repository secret `MINISIGN_SECRET_KEY`, and keep the previous public key available for one release train when verifying historical artifacts. Private keys must never be committed.

Verify a release:

```bash
minisign -Vm SHA256SUMS -p minisign.pub
sha256sum -c SHA256SUMS
```

Authenticode and Apple notarization remain unsupported (W-SIGN).

## Update client behavior

- Official GitHub Release metadata only (`api.github.com` / `github.com` asset hosts).
- OS/arch asset selection; stable and beta channels.
- Semver downgrade refused; device protocol major compatibility enforced via signed `ownmesh-release-meta.json`.
- Size and time limits; redirect host allow-list fail-closed.
- Embedded minisign public key; verification order **signature → SHA256SUMS → archive**.
- Staging + atomic multi-binary install with backup/rollback; partial binary sets refused; archive bomb limits enforced before allocation/extraction.
- Homebrew-managed installs print `brew upgrade ownmesh` and refuse self-update.
- Windows running-image replace helper when the live `ownmesh.exe` cannot be swapped.
- JSON output redacts secret-looking fields and URL userinfo/query.

The legacy demo shared-secret manifest signature is isolated under `ownmesh_update::demo` and is **not** used by production CLI paths.

## Installers

- **Never** `curl|sh` / `irm|iex`. Download the installer, inspect it, verify against signed `SHA256SUMS`, then execute from a local path.
- `installers/ownmesh-installer.sh` — macOS/Linux x64/arm64, latest or `OWNMESH_VERSION`. **Requires minisign**; verifies `SHA256SUMS.minisig` against the pinned OwnMesh public key **before** trusting checksums; then SHA-256, traversal refusal, user install dir, atomic copy, PATH guidance, `--version` smoke, untrusted env/URL injection refusal.
- `installers/ownmesh-installer.ps1` — Windows x64, TLS 1.2+, same mandatory minisign + checksum order, temp cleanup, non-admin user install, backup/rollback, no `Invoke-Expression`.
- Update archive extraction caps entry count / per-entry / total uncompressed bytes, streams with bounded reads, and permits only the five required binaries plus declared docs (rejects duplicates, unexpected members, symlinks, devices, path traversal).

## Homebrew

`scripts/render_distribution.py` injects per-arch asset checksums into `packaging/homebrew/ownmesh.rb.template`. The formula installs all five binaries and runs `ownmesh --version`. The optional `service` block starts **current-user `ownmeshd run` only** — it never services `ownmesh-broker`.

## Residual gaps (honest)

- Full specification completeness remains open (see [`docs/DOD_1.0.md`](./DOD_1.0.md)).
- W-SIGN (Authenticode / Apple notarization), W-LIVE-E2E, W-EXT-SEC, W-§12 remain disclosures/deferrals.
- Combined no-argument CLI → TUI handoff remains unsupported.

## Verification commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
pnpm install --frozen-lockfile
pnpm -r test
pnpm -r typecheck
pnpm -r lint
python scripts/check_release_quality.py
python scripts/tests/run_release_quality_tests.py
```
