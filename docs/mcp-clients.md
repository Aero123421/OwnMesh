# Connecting MCP clients other than ChatGPT

OwnMesh exposes one Streamable HTTP MCP endpoint at `https://<your-worker>/mcp`,
protected by OAuth 2.1 with PKCE S256. Any MCP client that speaks that
combination can drive your devices — the endpoint is not ChatGPT-specific.

What *is* ChatGPT-specific is the zero-configuration onboarding path. ChatGPT
discovers `/oauth/register` from OAuth metadata and registers itself before it
holds any OwnMesh credential, so the control plane grants exactly one narrow
exemption: a registration whose single `redirect_uri` is a literal
`https://chatgpt.com/connector/oauth/<slug>` gets a deterministic client id
without creating a database row. Everything else needs a client that you, the
owner, provision. This page describes those routes.

For ChatGPT itself see [`chatgpt-connection.md`](./chatgpt-connection.md).

## Which route to use

| Your client | Route |
| --- | --- |
| Runs on your machine, has a loopback redirect (most desktop MCP clients) | [Owner-provisioned client](#route-1-owner-provisioned-client-recommended) |
| You already have an enrolled device and a token with `ownmesh.device` | [Authenticated DCR](#route-2-authenticated-dynamic-client-registration) |
| You want any client to self-register | [Open DCR](#route-3-open-dynamic-client-registration-not-recommended) |

## What the endpoint requires

Every route produces a **public** client. These constraints are enforced and
are not configurable:

- `token_endpoint_auth_method` must be `none`. Confidential clients are
  rejected: `client_secret_post` and `client_secret_basic` both fail closed.
- PKCE `S256` is mandatory. `plain` is refused.
- `redirect_uri` must match a registered value **exactly** — no prefix or
  wildcard matching, and the value is re-checked at the token endpoint.
- Redirect URIs must be `https://`, or `http://` on a loopback host
  (`127.0.0.1`, `::1`, `localhost`) per RFC 8252 §7.3.
- A refresh token is returned only when you request the `offline_access` scope.

## Scopes

| Scope | Grants |
| --- | --- |
| `ownmesh.read` | Read and discovery: `ownmesh_list_devices`, `ownmesh_get_device`, `ownmesh_fs_list` / `_read` / `_stat`, `ownmesh_git_status` / `_diff`, `ownmesh_workspace_list` / `_show`, `ownmesh_list_profiles`, `ownmesh_profile_show`, `ownmesh_review_show` / `_page`, `ownmesh_transfer_get` / `_list` / `_status`, `ownmesh_get_operation` |
| `ownmesh.write` | Content and resource mutation: `ownmesh_fs_write` / `_patch` / `_delete`, `ownmesh_workspace_add` / `_update` / `_remove`, `ownmesh_review_start`, `ownmesh_transfer_plan` / `_send` / `_cancel` |
| `ownmesh.exec` | Command execution: `ownmesh_command_run`, `ownmesh_command_shell`, `ownmesh_cancel_operation` |
| `ownmesh.session` | Interactive sessions: `ownmesh_session_open` / `_attach` / `_write` / `_resize` / `_replay` / `_list` / `_show` / `_claim` / `_renew` / `_detach` / `_release` / `_give` / `_close` / `_terminate` |
| `ownmesh.device` | Device addressing, dynamic client registration, and typed security administration: `ownmesh_policy_preset`, `ownmesh_policy_rule_add` / `_remove`, `ownmesh_daemon_unlock`, `ownmesh_token_revoke`, `ownmesh_request_approval` |
| `offline_access` | Rotating refresh tokens |

Session tools require `ownmesh.session`, not `ownmesh.exec`; filesystem writes
require `ownmesh.write`, not `ownmesh.read`. A client configured with too narrow
a set gets an authorization failure rather than a silent downgrade.

Request the narrowest set your client needs. Your device policy is still the
final authority: a token with `ownmesh.exec` cannot run commands on a device
whose preset denies `command.run`, and `ownmesh.session` cannot open a PTY on a
device whose preset denies `session.open` (see
[ADR 0007](./adr/0007-restricted-presets-deny-command-execution.md) and the
access preset table in [`onboarding.md`](./onboarding.md)).

The `ownmesh_<family>_<verb>` names above are the canonical catalog. Verb-first
names from the specification (`ownmesh_read_file`, `ownmesh_run_command`,
`ownmesh_open_session`, …) remain callable through `tools/call` as aliases but
are withheld from `tools/list` — see
[ADR 0004](./adr/0004-mcp-tool-naming-and-aliases.md).

## Route 1: owner-provisioned client (recommended)

Nothing needs to be enabled on the Worker. You mint one client row for the
client you are adding.

1. Sign in to your control plane as the owner (passkey login at
   `https://<your-worker>/login`).
2. Find the exact redirect URI your MCP client uses. Desktop clients usually
   print it, or document it as something like `http://127.0.0.1:<port>/callback`.
   It must be byte-exact.
3. Insert the client row into D1, replacing the placeholders:

   ```bash
   cd packages/control-plane
   pnpm exec wrangler d1 execute ownmesh --remote --command \
     "INSERT INTO oauth_clients (client_id, tenant_id, client_name, redirect_uris, created_at)
      VALUES ('client_mydesktop', 'ten_default', 'My MCP client',
              '[\"http://127.0.0.1:7777/callback\"]', datetime('now'));"
   ```

   `redirect_uris` is a JSON array of strings. Use your real tenant id if you
   are not on the single-owner default (`ten_default`).
4. Configure the client with:
   - MCP endpoint: `https://<your-worker>/mcp`
   - Client ID: `client_mydesktop`
   - No client secret
   - Authorization: `https://<your-worker>/oauth/authorize`
   - Token: `https://<your-worker>/oauth/token`
   - PKCE: S256
5. Start the client's login. You will land on the OwnMesh consent page, which
   lists the requested scopes before anything is issued.

To revoke it later, delete the row and run `ownmesh tokens revoke` for any
tokens it obtained.

## Route 2: authenticated dynamic client registration

If you already hold an access token with the `ownmesh.device` scope, you can
register a client over the API. The new client is bound to that token's tenant —
never to a default tenant.

```bash
curl -X POST https://<your-worker>/oauth/register \
  -H "authorization: Bearer $OWNMESH_ACCESS_TOKEN" \
  -H "content-type: application/json" \
  -d '{
        "client_name": "My MCP client",
        "redirect_uris": ["http://127.0.0.1:7777/callback"],
        "token_endpoint_auth_method": "none"
      }'
```

This still requires `ALLOW_DYNAMIC_CLIENT_REGISTRATION=true` on the Worker; the
bearer token authorizes *which tenant* the client joins, and the flag authorizes
*whether the endpoint exists at all*.

The response contains the generated `client_id`. Between 1 and 8 redirect URIs
are accepted, each subject to the https/loopback rule above.

## Route 3: open dynamic client registration (not recommended)

```bash
cd packages/control-plane
pnpm exec wrangler secret put ALLOW_DYNAMIC_CLIENT_REGISTRATION
# enter: true
```

With this set, `/oauth/register` is reachable. Note what it does and does not
change:

- It does **not** let an anonymous caller create database rows for arbitrary
  clients — general registration still requires the `ownmesh.device` bearer
  token described in route 2.
- It **does** advertise `registration_endpoint` in your OAuth metadata and
  enable the stateless ChatGPT callback form.

Leave it off unless you need ChatGPT's automatic registration. Turning it on
does not weaken authorization — every authorize still requires owner login and
exact redirect matching — but it does expose one more unauthenticated endpoint
to rate-limited abuse.

## Verifying the connection

Once the client has a token:

```bash
curl -s https://<your-worker>/mcp \
  -H "authorization: Bearer $OWNMESH_ACCESS_TOKEN" \
  -H "content-type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | head -c 400
```

A healthy response lists the published tools. Alias tools
(`ownmesh_read_file` and friends) stay callable through `tools/call` for
compatibility but are deliberately withheld from `tools/list`, because
publishing two entries with identical schemas gave the model no basis to choose
between them.

## Troubleshooting

| Response | Cause |
| --- | --- |
| `{"error":"registration_disabled"}` | Route 3 flag is off. Use route 1. |
| `{"error":"unauthorized_client","error_description":"unknown client"}` | No client row for that `client_id`. |
| `redirect_uri does not exactly match registration` | Byte-for-byte mismatch, often a trailing slash or a changed loopback port. |
| `only token_endpoint_auth_method=none is supported` | The client is trying to be confidential. Disable its client secret. |
| `PKCE S256 required` | The client sent `plain` or omitted `code_challenge`. |
| `{"error":"insufficient_scope"}` | The token lacks the scope the tool declares. |
