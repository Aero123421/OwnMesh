# OwnMesh v1.1.0 — Secure distribution and signed self-update

v1.1.0 ships production portable distribution: multi-arch release archives, minisign-signed checksums, installers, Homebrew formula rendering, and a fail-closed `ownmesh update` path. It is **not** a claim that the full OwnMesh specification is complete.

## Scope and compatibility

The CLI has **40 explicit unsupported CLI surfaces** from the authoritative Rust registry plus 7 additional hard-error unsupported surfaces (**47 total**), machine-recorded in [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json). They return explicit machine-readable errors and are excluded from completeness.

**Newly supported in 1.1.0:**

- `ownmesh update check`
- `ownmesh update download`
- `ownmesh update apply`
- `ownmesh update channel`

Update defaults keep **network off** (`update.mode = "off"`). Explicit `check` / `download` / `apply` are user-initiated and may contact official GitHub Release endpoints only.

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
- Staging + atomic multi-binary install with backup/rollback; partial binary sets refused.
- Homebrew-managed installs print `brew upgrade ownmesh` and refuse self-update.
- Windows running-image replace helper when the live `ownmesh.exe` cannot be swapped.
- JSON output redacts secret-looking fields and URL userinfo/query.

The legacy demo shared-secret manifest signature is isolated under `ownmesh_update::demo` and is **not** used by production CLI paths.

## Installers

- `installers/ownmesh-installer.sh` — macOS/Linux x64/arm64, latest or `OWNMESH_VERSION`, SHA-256 (+ minisign when available), traversal refusal, user install dir, atomic copy, PATH guidance, `--version` smoke, untrusted env/URL injection refusal.
- `installers/ownmesh-installer.ps1` — Windows x64, TLS 1.2+, same integrity properties, temp cleanup, non-admin user install, backup/rollback, no `Invoke-Expression`.

## Homebrew

`scripts/render_distribution.py` injects per-arch asset checksums into `packaging/homebrew/ownmesh.rb.template`. The formula installs all five binaries and runs `ownmesh --version`. A `service` block is deferred until the onboarding branch lands.

## Residual gaps (honest)

- Full specification completeness remains open (see [`docs/DOD_1.0.md`](./DOD_1.0.md)).
- W-SIGN (Authenticode / Apple notarization), W-LIVE-E2E, W-EXT-SEC, W-§12 remain disclosures/deferrals.
- Service install/onboarding integration is intentionally out of this train’s installer/formula `service` block.

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
