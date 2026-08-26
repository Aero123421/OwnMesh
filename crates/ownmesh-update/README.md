# ownmesh-update

Signed OwnMesh release verification, download, and atomic multi-binary install.

## Production trust model

1. Official GitHub Release metadata only
2. OS/arch asset selection (`windows-x64`, `macos-arm64/x64`, `linux-arm64/x64`)
3. Verify **`SHA256SUMS.minisig` → `SHA256SUMS` → archive** using the embedded minisign public key
4. Fail-closed host allow-list, size/time limits, semver downgrade refusal, protocol compatibility
5. Stage all five binaries, persist a crash-recovery journal, backup, atomic replace, and rollback on failure
6. Homebrew-managed installs refuse self-update (`brew upgrade ownmesh`)

Automatic network checks default to **off**. The legacy shared-secret demo signature lives in `demo` and is not used by production CLI paths.

## User flow

```bash
ownmesh update
ownmesh update status
```

The public command automatically drains active OwnMesh sessions, stops the
user service, replaces the complete five-binary set, restarts the service when
it was previously running, and checks both CLI and daemon versions. Windows
hands the transaction to a hidden detached copy so the installed
`ownmesh.exe` is not self-locked. Linux derives the standard user-systemd bus
environment for headless SSH sessions only when that bus already exists.

The previous binaries remain available until post-update health verification.
An interrupted worker is identified by PID plus OS process-birth identity; the
next invocation restores the durable backup before starting a new transaction.
No background network request is made merely by starting OwnMesh.

## Trust root

See [`docs/release-keys/README.md`](../../docs/release-keys/README.md).
