# ownmesh-identity

Device Ed25519 keys, OS keychain integration, and purpose-separated credential storage.

## Backends

1. **OS keychain** via `keyring`  
   - Windows Credential Manager / DPAPI  
   - macOS Keychain  
   - Linux Secret Service
2. **Encrypted file keystore** (ChaCha20-Poly1305 + Argon2id) for headless environments  
   - Unlock via `OWNMESH_KEYSTORE_PASSWORD` or a restricted `.unlock` key file

## Purposes

- `device-private-key`
- `human-refresh-token`
- `device-enrollment-proof`

`SecretString` / `SecretBytes` redact on `Debug`, `Display`, and serde.
