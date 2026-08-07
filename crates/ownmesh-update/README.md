# ownmesh-update

Signed OwnMesh release verification, download, and atomic multi-binary install.

## Production trust model

1. Official GitHub Release metadata only
2. OS/arch asset selection (`windows-x64`, `macos-arm64/x64`, `linux-arm64/x64`)
3. Verify **`SHA256SUMS.minisig` → `SHA256SUMS` → archive** using the embedded minisign public key
4. Fail-closed host allow-list, size/time limits, semver downgrade refusal, protocol compatibility
5. Stage all five binaries, backup, atomic replace, rollback on failure
6. Homebrew-managed installs refuse self-update (`brew upgrade ownmesh`)

Automatic network checks default to **off**. The legacy shared-secret demo signature lives in `demo` and is not used by production CLI paths.

## Trust root

See [`docs/release-keys/README.md`](../../docs/release-keys/README.md).
