# OwnMesh v1.2.19

OwnMesh v1.2.19 is a ChatGPT MCP interoperability patch. It preserves the
v1.2.18 product surface, OAuth/passkey model, MCP protocol, and policy
fail-closed guarantees. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- **Expired or missing MCP Bearer tokens now return HTTP 401.** `tools/call`
  without a token, and any JSON-RPC method with an invalid token, used to
  return HTTP 200 with JSON-RPC `-32001`. ChatGPT treats that as a successful
  transport round-trip and does not refresh. The Worker now returns 401 with
  `WWW-Authenticate: Bearer` plus `resource_metadata` pointing at
  `/.well-known/oauth-protected-resource/mcp`. Unauthenticated `initialize`
  and `tools/list` remain available for discovery.
- **RFC 9728 path metadata for `/mcp` is published.**
  `GET /.well-known/oauth-protected-resource/mcp` returns the MCP resource
  identifier; `authorization_servers` stays the issuer origin.
- **`ownmesh doctor --check-network` reports control-plane version skew.**
  `/health` HTTP 200 is no longer treated as proof that the Worker matches
  the CLI. A mismatch is a warning and tells the operator to redeploy.

## Compatibility and migration

- No D1 migration is required beyond v1.2.17's `0017`.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible. Redeploy the control-plane Worker so ChatGPT receives the 401
  refresh signal.
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages
  remain out of scope.

## Upgrade

1. Deploy the v1.2.19 control-plane Worker (`pnpm run deploy` in
   `packages/control-plane`) so `/health` reports `1.2.19`.
2. Run the v1.2.19 `ownmesh-installer.ps1` (or `ownmesh update`) on devices.
3. Confirm `ownmesh doctor --check-network` shows matching versions.
4. Open a new ChatGPT chat against `https://<your-worker>/mcp`.
