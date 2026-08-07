# OwnMesh release signing keys

No OwnMesh minisign trust root is enrolled yet. Consequently, the release workflow must publish v1.0.2 as a degraded pre-release even if a private-key secret is accidentally present.

A future signing-key enrollment must commit the public key as `docs/release-keys/minisign.pub`, announce its key ID and fingerprint in release notes/SECURITY.md, and configure the matching `MINISIGN_SECRET_KEY` repository secret. The workflow signs `SHA256SUMS` and immediately verifies the signature against this tracked public key before permitting a non-degraded release.

Private keys must never be committed to this directory or written to workflow logs.
