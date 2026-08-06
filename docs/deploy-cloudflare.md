# Deploy OwnMesh Control Plane (Cloudflare)

OwnMesh does **not** require a vendor-hosted SaaS. Deploy this Worker to **your** Cloudflare account.

Standard deploy creates **only**:

| Resource | Binding | Purpose |
|---|---|---|
| Worker | — | OAuth, MCP `/mcp`, device APIs |
| D1 | `DB` | tenants, principals, OAuth clients/tokens, devices, grants, audit metadata |
| Durable Object | `DEVICE_ROOM` | per-device WebSocket room (hibernation) |

**Not** created (fail-closed): R2 buckets, Cloudflare TURN, relay queues.

## One-click deploy

Use Cloudflare’s **Deploy to Cloudflare** button (clones the repo, provisions bindings from `wrangler.jsonc`, builds & deploys):

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/Aero123421/OwnMesh&path=packages/control-plane)

Docs: [Deploy to Cloudflare buttons](https://developers.cloudflare.com/workers/platform/deploy-buttons/)

> Monorepo note: the button treats `packages/control-plane` as the app root when `path=` is set. Ensure that package is self-contained (it is: own `package.json` + `wrangler.jsonc` + `migrations/`).

## Prerequisites (CLI path)

- Cloudflare account
- Node 22+ and pnpm 9+
- Logged in: `pnpm exec wrangler login`

## Wrangler deploy (recommended for developers)

```bash
cd packages/control-plane
pnpm install

# 1) Create D1 (once per account)
pnpm exec wrangler d1 create ownmesh
# Copy the printed database_id into wrangler.jsonc → d1_databases[0].database_id

# 2) Apply SQL migrations (remote)
# Use the binding name DB so renames stay correct:
# https://developers.cloudflare.com/workers/platform/deploy-buttons/
pnpm exec wrangler d1 migrations apply DB --remote

# 3) Deploy Worker + Durable Object
pnpm run deploy
```

`package.json` `deploy` script runs migrations against binding `DB` then `wrangler deploy`.

### Local dev

```bash
pnpm exec wrangler dev
# Local D1 migrations:
pnpm exec wrangler d1 migrations apply DB --local
curl http://127.0.0.1:8787/health
```

### Secrets / vars

| Name | Required | Notes |
|---|---|---|
| `OAUTH_ISSUER` | optional | Defaults to request origin. Set to your canonical `https://<worker>.workers.dev` if behind a custom domain. |
| `AUTH_PROVIDER` | **required for production browser OAuth** | Cloudflare service binding. `POST /authenticate` must return `{ principal_id, tenant_id, display_name? }` for the current Authorization/cookie context. Browser authorization/device verification returns 503 if the binding is absent. |
| `OWNMESH_DEV_AUTH_BYPASS` | optional, default `false` | Local/test-only escape hatch for `login_hint`. Never enable against production data. |
| `ALLOW_DYNAMIC_CLIENT_REGISTRATION` | optional, default `false` | Opt-in DCR. Prefer statically provisioned clients. Unknown clients are never auto-registered by `/oauth/authorize`. |
| `OWNMESH_ALLOWED_ORIGINS` | optional | Comma-separated additional exact origins accepted by device WebSockets. The issuer origin is accepted automatically. |
| `SESSION_SECRET` | optional | Reserved for signed cookies; generate with `openssl rand -hex 32`. **Do not commit secrets.** |

Example (do not commit values):

```bash
pnpm exec wrangler secret put SESSION_SECRET
```

Reference `.dev.vars.example` in this package for local-only vars.

## What gets provisioned (from wrangler.jsonc)

```jsonc
d1_databases: [{ binding: "DB", database_name: "ownmesh", migrations_dir: "migrations" }]
durable_objects.bindings: [{ name: "DEVICE_ROOM", class_name: "DeviceRoom" }]
// no r2_buckets, no turn
```

- **D1 Worker API**: https://developers.cloudflare.com/d1/worker-api/
- **DO WebSocket hibernation**: https://developers.cloudflare.com/durable-objects/best-practices/websockets/
- **Hibernation example**: https://developers.cloudflare.com/durable-objects/examples/websocket-hibernation-server/
- **Wrangler configuration**: https://developers.cloudflare.com/workers/wrangler/configuration/

## OAuth & device endpoints (server contract)

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata (includes `device_authorization_endpoint`) |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 protected resource metadata |
| `POST /oauth/register` | Opt-in Dynamic Client Registration; disabled by default; `redirect_uri` **exact match** policy |
| `GET\|POST /oauth/authorize` | Authenticated principal + explicit consent + auth code + PKCE S256 |
| `POST /oauth/token` | `authorization_code`, `refresh_token` (rotation + reuse detection), `urn:ietf:params:oauth:grant-type:device_code` |
| `POST /oauth/revoke` | Token revoke |
| `POST /oauth/device_authorization` | RFC 8628 device code issue |
| `GET\|POST /oauth/device` | User verification / approve page |
| `POST /v1/devices/enroll` | Device enrollment + challenge (CLI: `cli-auth-09`) |
| `POST /v1/devices/enroll/proof` | Challenge signature proof |
| `GET /v1/devices` | List devices |
| `POST /v1/devices/revoke` or `DELETE /v1/devices?id=` | Revoke device |
| `GET /agent/connect?device_id=&role=agent\|client` | WebSocket → `DeviceRoom` DO |
| `POST /mcp` | Streamable HTTP MCP |
| `GET\|POST /approve` | Authenticated but currently unimplemented; returns 501 fail-closed |

### Enrollment response shape (for CLI)

```json
{
  "device_id": "dev_...",
  "enrollment_token": "atk_...",
  "expires_in": 300,
  "challenge": {
    "id": "ech_...",
    "nonce": "...",
    "message": "ownmesh-device-challenge:<nonce>:<device_id>",
    "expires_at": "2026-08-06T00:05:00.000Z"
  },
  "connect_path": "/agent/connect"
}
```

Proof body: `{ "device_id", "challenge_id", "signature": "<64-byte ed25519 hex>" }`. The server verifies Ed25519 over the exact challenge message, atomically activates the pending device, and returns a `device_credential`. The CLI stores that credential in its secret store. Send it as `Authorization: Bearer ...` plus an allowed exact `Origin` on `/agent/connect`; pending/revoked devices and wrong roles are rejected.

> Existing pre-credential device records cannot be given a recoverable plaintext credential by a migration. Re-enroll those agents once after applying `0003_control_plane_p0.sql`; the old record may then be revoked.

## ChatGPT Personal Plugin / MCP

1. Deploy control plane and note `https://<worker>/mcp`
2. Configure a static OAuth client with **exact** redirect URIs (or deliberately enable `ALLOW_DYNAMIC_CLIENT_REGISTRATION`)
3. In ChatGPT, add the MCP connector / Personal Plugin pointing at your `/mcp` URL
4. Complete OAuth; scopes: `ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access`
5. Enroll a device with `ownmesh device enroll` / `ownmesh login` against your issuer URL (CLI ticket **cli-auth-09**)

**Policy note:** ChatGPT tool calls are **not** the authorization boundary. The local `ownmeshd` policy engine is final.

## Health check

```bash
curl -s https://<worker>/health | jq .
# expect: status=ok, features includes no-r2-turn, storage=d1 when bound
curl -s https://<worker>/v1/migrations/status | jq .
```
