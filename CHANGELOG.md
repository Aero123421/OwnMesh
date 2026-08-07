# Changelog

## v1.1.0 — 2026-08-07

### Secure distribution

- Multi-arch portable archives: Windows x64, macOS arm64/x64, Linux musl arm64/x64.
- Required minisign signing of `SHA256SUMS` with immediate verify; no degraded unsigned formal release.
- Installers for macOS/Linux (`ownmesh-installer.sh`) and Windows (`ownmesh-installer.ps1`).
- Homebrew formula template + `scripts/render_distribution.py` checksum injection.
- Release assets include installers, `ownmesh.rb`, `ownmesh-release-meta.json`, SBOMs, provenance.

### Self-update

- Production `ownmesh update check|download|apply|channel` against official GitHub Releases.
- Embedded minisign trust root; verify order signature → checksums → archive.
- Fail-closed host allow-list, size/time limits, downgrade refusal, protocol compatibility.
- Atomic multi-binary apply with backup/rollback; Homebrew self-update refused.

### Versioning

- Workspace / packages / control-plane service version aligned to **1.1.0**.

## v1.0.2

See [`docs/RELEASE_NOTES_v1.0.2.md`](./docs/RELEASE_NOTES_v1.0.2.md).
