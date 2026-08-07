# OwnMesh v1.1.2 — portable installer repair

v1.1.2 supersedes v1.1.1 for installation. It repairs the Unix portable installer discovered during post-publish installation-path verification. The v1.1.1 tag and assets remain unchanged for auditability; its signed portable archives and Windows installer remain valid, but its `ownmesh-installer.sh` must not be used.

## Fixed

- `ownmesh-installer.sh` now conforms to its `#!/bin/sh` contract and parses under POSIX shells including Ubuntu `dash`.
- CR/LF and shell-metacharacter input rejection no longer relies on Bash-only quoting.
- The optional Linux x64 Minisign 0.11 bootstrap uses the verified upstream archive SHA-256 and the exact `minisign-linux/x86_64/minisign` member instead of a disabled placeholder/ambiguous architecture search.
- Unix and Windows installers refuse existing symlink, reparse-point, directory, or other non-file binary destinations.
- Installer rollback restores previous binaries and removes newly installed binaries that had no predecessor, preventing a failed update from leaving a partial new set.

## Regression coverage

- POSIX `sh -n` runs before any Minisign-dependent test and therefore cannot be skipped when Minisign is unavailable.
- Linux tests cover signed happy-path installation, traversal/type/duplicate/size limits, malicious environment values, non-file destinations, and rollback behavior.
- Windows checks cover PowerShell parsing, signed happy-path installation, all five binary version smokes, and fail-closed non-file destination handling with the original file preserved.

## Distribution and trust

- Five portable archives are produced: Windows x64, macOS arm64/x64, and Linux musl arm64/x64.
- `SHA256SUMS` is signed with the existing Minisign trust root (key ID `C596813EFB0946A4`) and verified before publish.
- CycloneDX Rust and control-plane SBOMs plus GitHub build provenance remain required.
- Authenticode and Apple notarization remain unsupported under W-SIGN. This patch does not expand supported product surfaces.
- The CLI surface contract is unchanged: **32 explicit unsupported CLI surfaces** plus 7 additional hard-error unsupported surfaces (**39 total**), recorded in [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).
