# Deploy OwnMesh Control Plane (Cloudflare)

OwnMesh does **not** require a vendor-hosted SaaS. Deploy this Worker to **your** Cloudflare account.

Standard deploy creates **only**:

| Resource | Binding | Purpose |
|---|---|---|
| Worker | — | OAuth, MCP `/mcp`, device APIs |
| D1 | `DB` | tenants, principals, OAuth clients/tokens, devices, grants, audit metadata |
| Durable Object | `DEVICE_ROOM` | per-device WebSocket room (hibernation) |
| Durable Object | `TRANSFER_ROOM` | transient encrypted transfer coordination |

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

## Guided deploy (recommended)

```bash
cd packages/control-plane
corepack enable
pnpm install --frozen-lockfile
pnpm run deploy:guided
```

The guided command opens Cloudflare sign-in when needed, creates or reuses the
single D1 database named `ownmesh`, applies migrations, deploys the Worker and
Durable Objects, and provisions secrets without writing a plaintext secret
file. It finishes by printing the owner sign-in URL, the one-time owner code,
and the ChatGPT MCP URL.
Re-running it is idempotent: existing owner/signing secrets are not rotated.

For CI or an already-provisioned account, `pnpm run deploy` only applies
migrations and deploys. `pnpm run owner:init` rotates the one-time owner
bootstrap separately.

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
| `OWNER_TOKEN_HASH` | **required by default** | SHA-256 of the high-entropy, one-time passkey bootstrap code. `pnpm run owner:init` creates it without storing the plaintext code in D1. |
| `AUTH_PROVIDER` | optional | External identity service for multi-user deployments. When omitted, the built-in single-owner passkey login is used. |
| `OWNMESH_DEV_AUTH_BYPASS` | optional, default `false` | Local/test-only escape hatch for `login_hint`. Never enable against production data. |
| `ALLOW_DYNAMIC_CLIENT_REGISTRATION` | optional, default `true` | Enables one-URL ChatGPT setup. Exact ChatGPT public callbacks register statelessly; all other DCR requires a tenant `ownmesh.device` token. Set `false` to require manual client provisioning. |
| `OWNMESH_ALLOWED_ORIGINS` | optional | Comma-separated additional exact origins accepted by device WebSockets. The issuer origin is accepted automatically. |
| `MCP_OPS_MAX_PER_TENANT` | optional, default `20000` | Per-tenant cap on durable `mcp_operations` rows (live ops + unexpired keyed idempotency tombstones). Invalid values fail closed to `20000`. At 60% utilization, MCP tool responses include `mcp_ops_quota_pressure` and `ownmesh_system_diagnose` reports `control_plane.mcp_ops_quota`. Exhaustion remains fail-closed (`OWNMESH_E_MCP_OP_QUOTA`). |
| `MCP_MAX_TIMEOUT_MS` | optional, default `300000` | Synchronous `timeout_ms` clamp for `command_run` / `command_shell`. Invalid values fail closed to `300000`. Hard ceiling is `3600000` (1 hour). Detached commands (`detach: true`) ignore this clamp and use a 24-hour correlation TTL instead of the five-minute dispatch expiry. |
| `SESSION_SECRET` | **required** | Signs owner sessions and internal Worker→DO contexts. `owner:init` creates it if absent. **Do not commit secrets.** |

`owner:init` sends values directly to Wrangler over stdin and prints only the
one-time bootstrap code. Open `/login`, enter it once, and register a passkey;
subsequent sign-ins do not accept the bootstrap code. If all passkeys are lost,
run `pnpm run owner:init -- --reset-passkey`. Recovery rotates the browser-session
secret, revokes the owner's OAuth tokens, advances the credential generation,
and removes only the owner passkey records before issuing a new bootstrap code.

### Cloudflare Access email OTP

Cloudflare Access email OTP is an optional **outer gate for a separate operator
dashboard**, not a replacement for OwnMesh OAuth, passkeys, or device policy.
Do not put an interactive Access challenge in front of the OwnMesh MCP hostname:
ChatGPT and enrolled Agents must reach `/.well-known/*`, `/oauth/*`, `/mcp`,
`/agent/connect`, and `/v1/devices/*` without an Access login page in the middle.
Protecting those routes would break OAuth discovery/token exchange or the Agent
WebSocket rather than add useful security.

OwnMesh does not currently ship a separate admin dashboard, so the recommended
single-owner setup is the built-in `/login` passkey flow. If a future deployment
adds an operator-only UI, place it on a distinct hostname or narrowly scoped
path, allow only the owner's exact email, and keep all protocol endpoints on the
unmodified OwnMesh hostname. Access OTPs are single-use and expire after ten
minutes; see Cloudflare's [One-time PIN login](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/one-time-pin/)
and [Access policy](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
documentation.

Manual example (do not commit values):

```bash
pnpm exec wrangler secret put SESSION_SECRET
pnpm exec wrangler secret put OWNER_TOKEN_HASH
```

Reference `.dev.vars.example` in this package for local-only vars.

## What gets provisioned (from wrangler.jsonc)

```jsonc
d1_databases: [{ binding: "DB", database_name: "ownmesh", migrations_dir: "migrations" }]
durable_objects.bindings: [{ name: "DEVICE_ROOM", class_name: "DeviceRoom" }]
ratelimits: [{ name: "AUTH_RATE_LIMITER", ... }, { name: "MCP_RATE_LIMITER", ... }]
// no r2_buckets, no turn
```

The rate-limit bindings are coarse abuse/cost guards. They run before D1 access,
use hashed credentials (or a hashed connecting IP fallback), and never replace
OAuth scopes, device policy, operation binding, or replay protection.

## Capacity and cost guardrails

OwnMesh is tuned for a personal or small-team control plane, not a public file
hosting service:

- Cloudflare currently includes 100,000 Worker requests/day and 10 ms CPU per
  request on Workers Free; D1 Free includes 5 million rows read/day and 100,000
  rows written/day. Check the live [Workers limits](https://developers.cloudflare.com/workers/platform/limits/)
  and [D1 pricing](https://developers.cloudflare.com/d1/platform/pricing/) before
  a larger deployment.
- Device and transfer rooms use the Durable Objects WebSocket Hibernation API,
  so an idle connected Agent does not keep a JavaScript isolate billed as active.
  Cloudflare bills incoming WebSocket messages at a 20:1 ratio for DO request
  billing; see [Durable Objects pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/).
- Transfer payloads are end-to-end encrypted and relayed as bounded WebSocket
  frames; they are not written to D1 or Durable Object storage. A 5 GiB transfer
  uses about 81,920 64-KiB data frames plus acknowledgements (roughly 8,200 DO
  billable requests at Cloudflare's current 20:1 message ratio, before retries).
  Repeated multi-gigabyte transfers should use Workers Paid and be monitored.
- `AUTH_RATE_LIMITER` (60/minute) and `MCP_RATE_LIMITER` (120/minute) protect D1
  and operator budgets from coarse abuse. Cloudflare counters are intentionally
  approximate, so OAuth, local device policy, exact action binding, and replay
  fencing remain the security boundary.

Monitor Worker errors/CPU, Durable Object requests/duration, and D1 row reads
and writes in the Cloudflare dashboard. A `429` from OwnMesh means the caller
should honor `Retry-After`; a Cloudflare 1027/1102 means the account or CPU limit
was reached.

- **D1 Worker API**: https://developers.cloudflare.com/d1/worker-api/
- **DO WebSocket hibernation**: https://developers.cloudflare.com/durable-objects/best-practices/websockets/
- **Hibernation example**: https://developers.cloudflare.com/durable-objects/examples/websocket-hibernation-server/
- **Wrangler configuration**: https://developers.cloudflare.com/workers/wrangler/configuration/

## OAuth & device endpoints (server contract)

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/oauth-authorization-server` | RFC 8414 metadata (includes `device_authorization_endpoint`) |
| `GET /.well-known/oauth-protected-resource` | RFC 9728 protected resource metadata |
| `POST /oauth/register` | Dynamic Client Registration; exact ChatGPT public callbacks are stateless, all other clients require tenant authentication; `redirect_uri` **exact match** policy |
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
| `GET\|POST /approve` | Optional recovery/admin approval (human browser auth + one-time CSRF). Binds exact action hash, original `expires_at`, and approver principal into a device-routed `approval.decision` frame. Not required for normal ChatGPT use when device policy allows. |

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
2. In ChatGPT, create a custom MCP app with that `/mcp` URL and choose OAuth. Leave the advanced client fields empty.
3. Click Create. ChatGPT discovers/registers OAuth and opens OwnMesh sign-in automatically.
4. Sign in with the owner passkey and approve scopes: `ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access`
5. Enroll a device with `ownmesh device enroll` / `ownmesh login` against your issuer URL (CLI ticket **cli-auth-09**)

**Policy note:** ChatGPT tool calls are **not** the authorization boundary. The local `ownmeshd` policy engine is final.

## Health check

```bash
curl -s https://<worker>/health | jq .
# expect: status=ok, liveness=true, features includes no-r2-turn, storage=d1 when bound
curl -s https://<worker>/health/ready | jq .
# expect: status=ok only when required schema and bindings are ready (cached for at most 5 seconds)
curl -s https://<worker>/v1/migrations/status | jq .
```
