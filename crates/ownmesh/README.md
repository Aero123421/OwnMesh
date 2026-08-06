# ownmesh

OwnMesh command-line interface.

## Command tree

Full registration of specification §16.2 commands. Live for §5-CLI:

```bash
ownmesh login                 # Authorization Code + PKCE (browser loopback callback)
ownmesh login --device        # RFC 8628 device authorization grant
ownmesh logout
ownmesh device enroll         # challenge/proof with Ed25519 device key
ownmesh device list|show|revoke
ownmesh device rotate-key
ownmesh status
ownmesh config validate
```

Issuer resolution: `OWNMESH_ISSUER` → active config instance → last login session.

Refresh tokens and device private keys are stored via `ownmesh-identity` (OS keychain /
encrypted file fallback). They are never printed or written to `config.toml`.

See `docs/adr/0003-cli-oauth-pkce-device-code.md` for the OAuth contract and RFC anchors.
