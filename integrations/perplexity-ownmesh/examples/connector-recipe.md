# Perplexity custom remote connector recipe (experimental, unverified live)

Compatibility row and receipt format: `docs/client-compatibility.md`.
Endpoint contract (PKCE S256, RFC 8707 `resource`, scope step-up):
`docs/mcp-clients.md`.

## 1. Add the connector

- Transport: Streamable HTTP.
- Server URL: `https://<your-worker>/mcp` (replace with your Worker origin).
- OAuth discovery: Perplexity discovers OwnMesh OAuth metadata automatically;
  if discovery is unavailable in your Perplexity surface, enter the endpoints
  manually: `https://<your-worker>/oauth/authorize` (authorize),
  `https://<your-worker>/oauth/token` (token).
- Registration: standard OAuth client registration applies. The owner
  provisions a client per `docs/mcp-clients.md` when automatic registration
  is unavailable; the end-user flow never requires raw D1 SQL.
- Fixed Perplexity callback values to register (exact, per vendor docs):
  `https://www.perplexity.ai/rest/connections/oauth_callback` and
  `https://enterprise.perplexity.ai/rest/connections/oauth_callback`.
- Scopes: request the narrowest set the task needs (`ownmesh.read` first;
  add `ownmesh.write` / `ownmesh.exec` / `ownmesh.session` /
  `offline_access` only when required).

## 2. Optional Cloudflare Access layering

A Cloudflare Access service-token gate may sit in front of application
OAuth, but it is a separate boundary: passing Access does not grant an
OwnMesh scope, and an OwnMesh token does not pass Access. Configure and
test each layer independently.

## 3. Verify

1. List tools and confirm the catalog responds.
2. Run a read-only call first (device/workspace list).
3. Run a side-effect call only where the Perplexity surface exposes that
   tool class; read/write/exec/session exposure per surface is otherwise
   unproven — record the observed outcome in the live receipt instead of
   assuming it.
4. For long work pass `async: true` and poll `ownmesh_get_operation`.

## 4. Safety

Perplexity's connection UI is not device authorization. The OwnMesh device
policy stays final, and no step here auto-authorizes or silently enables
destructive tools. Never paste tokens, device IDs, or private paths into
the connector form beyond the registered callback and scope list.
