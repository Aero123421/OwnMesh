# Deploy OwnMesh Control Plane (Cloudflare)

OwnMesh does **not** require a vendor-hosted SaaS. Deploy this Worker to **your** Cloudflare account.

## Prerequisites

- Cloudflare account
- Node 22+ and pnpm 9+
- `wrangler` (via package devDependency)

## Steps

```bash
cd packages/control-plane
pnpm install
# Create D1 database
pnpm exec wrangler d1 create ownmesh
# Put the database_id into wrangler.jsonc
pnpm exec wrangler d1 migrations apply ownmesh --remote
pnpm exec wrangler deploy
```

Set `OAUTH_ISSUER` to your Worker URL if it differs from the request origin.

## Local dev

```bash
pnpm exec wrangler dev
curl http://127.0.0.1:8787/health
```

## ChatGPT Personal Plugin / MCP

1. Deploy control plane and note `https://<worker>/mcp`
2. Configure OAuth client (Dynamic Registration at `/oauth/register` or static client)
3. In ChatGPT, add the MCP connector / Personal Plugin pointing at your `/mcp` URL
4. Complete OAuth; scopes: `ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access`
5. Enroll a device with `ownmesh` CLI against your issuer URL

**Policy note:** ChatGPT tool calls are **not** the authorization boundary. The local `ownmeshd` policy engine is final.
