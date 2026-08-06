# ADR 0003: CLI OAuth PKCE + Device Code + Enrollment

- Status: Accepted
- Date: 2026-03-22
- Ticket: cli-auth-09

## Context

§5 of the OwnMesh specification requires the CLI to authenticate humans and enroll devices against the control plane. Server endpoints and payload shapes are owned by **cp-04** (`packages/control-plane`). This ADR records the CLI-side choices for **cli-auth-09**.

## Decision

### Browser login (`ownmesh login`)

1. Use **OAuth 2.1 Authorization Code + PKCE S256** (no client secret).
2. Bind a **loopback** HTTP callback on `127.0.0.1`, preferring port **8750** (bootstrap client `client_ownmesh_cli` redirect registration). If busy, bind an ephemeral port and **Dynamic Client Registration** (`POST /oauth/register`) with the exact redirect URI.
3. Open the system browser to `{issuer}/oauth/authorize` with `code_challenge_method=S256`.
4. Exchange the code at `{issuer}/oauth/token` with `grant_type=authorization_code` + `code_verifier`.
5. Store the **refresh token** in the §3 keychain (`ownmesh-identity` `HumanRefreshToken`). Never write refresh/access tokens to `config.toml`, logs, or JSON CLI output.
6. Access tokens are obtained on demand via `grant_type=refresh_token` (server-side rotation/reuse detection remains cp-04).

### Headless fallback (`ownmesh login --device`)

1. Implement **RFC 8628 Device Authorization Grant**.
2. `POST /oauth/device_authorization` → display `verification_uri` + `user_code`.
3. Poll `POST /oauth/token` with `grant_type=urn:ietf:params:oauth:grant-type:device_code`, honoring `authorization_pending`, `slow_down`, `expired_token`, and `access_denied`.

### Device enrollment / revoke / key rotation

1. `POST /v1/devices/enroll` with Ed25519 `public_key` (hex) from the §3 device key store.
2. Sign `challenge.message` and `POST /v1/devices/enroll/proof` with 64-byte hex signature.
3. `POST /v1/devices/revoke` for immediate server-side invalidation.
4. `ownmesh device rotate-key` rotates the local device key in the keychain and best-effort re-enrolls.

### Testing

Rust in-process mock HTTP server mirrors the cp-04 URL/payload contract so `cargo test -p ownmesh` exercises PKCE, device-code, enroll/proof, revoke, and secret redaction without the TS worker.

## Normative references (confirmed)

| Topic | URL |
|---|---|
| PKCE (RFC 7636) | https://datatracker.ietf.org/doc/html/rfc7636 |
| OAuth 2.0 for Native Apps / loopback (RFC 8252) | https://datatracker.ietf.org/doc/html/rfc8252 |
| Device Authorization Grant (RFC 8628) | https://datatracker.ietf.org/doc/html/rfc8628 |
| OAuth 2.0 Token Revocation (RFC 7009) | https://datatracker.ietf.org/doc/html/rfc7009 |
| AS Metadata (RFC 8414) | https://datatracker.ietf.org/doc/html/rfc8414 |
| OAuth 2.1 (draft) | https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13 |
| MCP Authorization | https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization |

## Consequences

- Login/enroll stubs under `commands/mod.rs` are removed; v1.0.1 must not ship chapter-5 stub messages for these commands.
- Control-plane TS package remains read-only for this ticket.
- Rename/labels stay explicitly unsupported (no silent stub claiming “chapter 5”).
