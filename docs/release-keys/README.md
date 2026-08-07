# OwnMesh release signing keys

## Active minisign trust root

| Field | Value |
| --- | --- |
| Public key file | [`minisign.pub`](./minisign.pub) |
| Key ID | `C596813EFB0946A4` |
| Fingerprint (SHA-256 of decoded 42-byte public-key blob) | `1450496b7af985f57466b4b5f0b9c985d6c3e96ed66ee2cebb4f5a94ba5775d9` |
| Embedded in | `ownmesh-update` (`EMBEDDED_MINISIGN_PUB`) and release installers |

The matching private key is held only as the repository secret `MINISIGN_SECRET_KEY` (or an offline HSM/operator store). **Private keys must never be committed** to this directory or written to workflow logs.

## Verification

```bash
minisign -Vm SHA256SUMS -p docs/release-keys/minisign.pub
sha256sum -c SHA256SUMS
```

Release publish signs `SHA256SUMS` and immediately verifies the signature against this tracked public key. Missing secret or public key **fails the release** — formal OwnMesh releases do not publish unsigned assets.

## Rotation procedure

1. Generate a new minisign keypair offline (`minisign -G`).
2. Commit only the new `minisign.pub`.
3. Announce the new key ID and fingerprint in `SECURITY.md` and the next release notes.
4. Update `MINISIGN_SECRET_KEY` in repository secrets.
5. Bump the embedded key consumers (`ownmesh-update` include path already tracks this file).
6. Retain the previous public key text in release notes for verifying historical artifacts for at least one release train.

## Related

- ADR: [`docs/adr/0001-release-signing-sbom-provenance.md`](../adr/0001-release-signing-sbom-provenance.md)
- Security policy: [`SECURITY.md`](../../SECURITY.md)
