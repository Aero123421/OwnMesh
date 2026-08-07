# OwnMesh v1.1.3 — portable installer repair

v1.1.3 supersedes v1.1.1 for installation and carries forward the complete portable-installer repair prepared for v1.1.2. The immutable v1.1.2 tag is retained as a historical failed release candidate: its fail-closed tag workflow stopped during Linux tests and published no GitHub Release or release assets.

## Fixed

- `ownmesh-installer.sh` conforms to its `#!/bin/sh` contract and parses under POSIX shells including Ubuntu `dash`.
- CR/LF and shell-metacharacter input rejection no longer relies on Bash-only quoting.
- The optional Linux x64 Minisign 0.11 bootstrap uses the verified upstream archive SHA-256 and exact `minisign-linux/x86_64/minisign` member.
- Unix and Windows installers refuse existing symlink, reparse-point, directory, or other non-file binary destinations.
- Installer rollback restores previous binaries and removes newly installed binaries that had no predecessor. Windows restoration uses an atomic same-volume replacement and verifies the restored digest.
- Successful, preflight-rejected, and successfully rolled-back transactions remove their private backup and staging directories; a backup is retained only when rollback itself fails.
- The Unix Docker-provider mock executable used by the Rust release gate is fully written, synchronized, and closed before an atomic rename into its executable path. This avoids hosted-filesystem `ETXTBSY` failures without retrying or weakening the test.
- The daemon restart regression now waits, with a bounded timeout, for stopped connection tasks to release the credential-registry lock instead of assuming cleanup completes within a fixed 20 milliseconds.

## Regression coverage

- POSIX `sh -n` is unconditional, and the Ubuntu release gate installs a SHA-256-pinned Minisign 0.11 binary before running the signed installer suite; a missing or unusable signer fails the gate.
- Linux tests cover signed happy-path installation, traversal/type/duplicate/size limits, malicious environment values, non-file destinations, rollback behavior, and transaction-file cleanup.
- Windows checks cover PowerShell parsing, signed happy-path installation, all five binary version smokes, reparse/non-file rejection, deterministic mid-replacement failure, digest-exact rollback, and transaction-file cleanup.

## Distribution and trust

- Five portable archives are produced: Windows x64, macOS arm64/x64, and Linux musl arm64/x64.
- `SHA256SUMS` is signed with the existing Minisign trust root (key ID `C596813EFB0946A4`) and verified before publish.
- CycloneDX Rust and control-plane SBOMs plus GitHub build provenance remain required.
- Authenticode and Apple notarization remain unsupported under W-SIGN. This patch does not expand supported product surfaces.
- The CLI surface contract is unchanged: **32 explicit unsupported CLI surfaces** plus 7 additional hard-error unsupported surfaces (**39 total**), recorded in [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).
