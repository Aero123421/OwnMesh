# Connecting MCP clients other than ChatGPT

OwnMesh exposes one Streamable HTTP MCP endpoint at `https://<your-worker>/mcp`,
protected by OAuth 2.1 with PKCE S256. Any MCP client that speaks that
combination can drive your devices — the endpoint is not ChatGPT-specific.

What *is* ChatGPT-specific is the zero-configuration onboarding path. ChatGPT
discovers `/oauth/register` from OAuth metadata and registers itself before it
holds any OwnMesh credential, so the control plane grants exactly one narrow
exemption: a registration whose single `redirect_uri` is a literal
`https://chatgpt.com/connector/oauth/<slug>` gets a deterministic client id
without creating a database row. ChatGPT clients are also issued a refresh
token without requesting `offline_access`, which no other client gets.
Everything else needs a client that you, the owner, provision. This page
describes those routes.

For ChatGPT itself see [`chatgpt-connection.md`](./chatgpt-connection.md).

## Which route to use

| Your client | Route |
| --- | --- |
| Runs on your machine, has a loopback redirect (most desktop MCP clients) | [Owner-provisioned client](#route-1-owner-provisioned-client-recommended) |
| You already have an enrolled device and a token with `ownmesh.device` | [Authenticated DCR](#route-2-authenticated-dynamic-client-registration) |
| You want to understand or disable the DCR endpoint | [The DCR flag](#route-3-the-dynamic-registration-flag) |

## What the endpoint requires

Every route produces a **public** client. These constraints are enforced and
are not configurable:

- `token_endpoint_auth_method` must be `none`. Confidential clients are
  rejected: `client_secret_post` and `client_secret_basic` both fail closed.
- PKCE `S256` is mandatory. `plain` is refused.
- `redirect_uri` must match a registered value **exactly** — no prefix or
  wildcard matching, and the value is re-checked at the token endpoint.
- Redirect URIs registered through `/oauth/register` must be `https://`, or
  `http://` on a loopback host (`127.0.0.1`, `::1`, `localhost`) per RFC 8252
  §7.3. This is enforced **at registration only**: a row inserted straight into
  D1 (route 1) is not re-checked for scheme or host at authorize time, so it is
  on you not to register a plaintext non-loopback redirect there.
- A refresh token is returned only when you request the `offline_access` scope.
  (The ChatGPT client pair noted above is the one exception.)

## Scopes

| Scope | Grants |
| --- | --- |
| `ownmesh.read` | Read-only tools: device list/get, workspace list/show, file list/read/stat, git status/diff, operation get |
| `ownmesh.write` | Filesystem mutation: write, delete, patch, and workspace add/update/remove |
| `ownmesh.exec` | `ownmesh_command_run`, `ownmesh_command_shell`, `ownmesh_cancel_operation` — **not** sessions |
| `ownmesh.session` | Every session tool, including read-only ones like `session_list` and `session_replay` |
| `ownmesh.device` | Device registry mutation, dynamic client registration, **and the six admin tools** (`policy_preset`, `policy_rule_add`, `policy_rule_remove`, `daemon_unlock`, `token_revoke`, `request_approval`) |
| `offline_access` | Rotating refresh tokens |

A client that requests no scope gets `ownmesh.read ownmesh.device`.

Two of these are easy to get wrong. `ownmesh.exec` does **not** cover sessions —
a token holding only `ownmesh.exec` gets `insufficient_scope` on every
`ownmesh_session_*` tool. And `ownmesh.device` is not merely addressing: it is
the scope the security-admin tools check, so grant it only to clients that need
device or policy administration. (Those tools also require the caller to
administer the target device and a fresh passkey decision, so the scope alone
cannot use them — but it is the gate this table describes.)

Device log query is deliberately **not** in this table. `ownmesh logs` is local
IPC only; there is no MCP tool for it, so log bodies never leave the device
through this endpoint.

Request the narrowest set your client needs. Your device policy is still the
final authority: a token with `ownmesh.exec` cannot run commands on a device
whose preset denies `command.run` (see the access preset table in
[`onboarding.md`](./onboarding.md)).

## Route 1: owner-provisioned client (recommended)

Nothing needs to be enabled on the Worker. You mint one client row for the
client you are adding.

1. Find the exact redirect URI your MCP client uses. Desktop clients usually
   print it, or document it as something like `http://127.0.0.1:<port>/callback`.
   It must be byte-exact.
2. Insert the client row into D1, replacing the placeholders:

   ```bash
   cd packages/control-plane
   pnpm exec wrangler d1 execute ownmesh --remote --command \
     "INSERT INTO oauth_clients (client_id, tenant_id, client_name, redirect_uris, created_at)
      VALUES ('client_mydesktop', 'ten_default', 'My MCP client',
              '[\"http://127.0.0.1:7777/callback\"]', datetime('now'));"
   ```

   `redirect_uris` is a JSON array of strings. Use your real tenant id if you
   are not on the single-owner default (`ten_default`).
3. Configure the client with:
   - MCP endpoint: `https://<your-worker>/mcp`
   - Client ID: `client_mydesktop`
   - No client secret
   - Authorization: `https://<your-worker>/oauth/authorize`
   - Token: `https://<your-worker>/oauth/token`
   - PKCE: S256
4. Start the client's login. You will be asked to sign in as the owner (passkey
   at `https://<your-worker>/login`) and then land on the OwnMesh consent page,
   which lists the requested scopes before anything is issued.

To revoke it later, revoke the tokens first, then delete the row:

```bash
curl -X POST https://<your-worker>/oauth/revoke \
  -H "content-type: application/x-www-form-urlencoded" \
  -d "token=$TOKEN&client_id=client_mydesktop"
```

Deleting the `oauth_clients` row alone does **not** invalidate tokens the client
already holds — the MCP path validates the token, not the client row. Note that
`ownmesh tokens revoke` is a different thing: it revokes a device-local IPC
principal, not a control-plane OAuth token.

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

This needs `ALLOW_DYNAMIC_CLIENT_REGISTRATION=true` on the Worker, which is the
shipped default (see [route 3](#route-3-the-dynamic-registration-flag)). The
bearer token authorizes *which tenant* the client joins; the flag authorizes
*whether the endpoint exists at all*.

The response contains the generated `client_id`. Between 1 and 8 redirect URIs
are accepted, each subject to the https/loopback rule above.

## Route 3: the dynamic-registration flag

`ALLOW_DYNAMIC_CLIENT_REGISTRATION` ships **enabled** — it is `"true"` in `vars`
in `packages/control-plane/wrangler.jsonc`, because ChatGPT needs
`/oauth/register` advertised to connect from the MCP URL alone. Route 2 works
out of the box on a stock deployment; there is nothing to turn on.

What the flag controls:

- It does **not** let an anonymous caller create database rows for arbitrary
  clients — general registration still requires the `ownmesh.device` bearer
  token from route 2.
- It **does** advertise `registration_endpoint` in your OAuth metadata and
  enable the stateless ChatGPT callback form.

To turn it off, edit `vars` in `wrangler.jsonc` and redeploy:

```jsonc
"ALLOW_DYNAMIC_CLIENT_REGISTRATION": "false",
```

Do not use `wrangler secret put` for this name. It is declared in `vars`, and a
plaintext var takes precedence over a secret of the same name on the next
`wrangler deploy`, so the secret would be silently ignored.

Turning it off breaks ChatGPT's automatic onboarding — you would then need the
manual fallback at `/connect/chatgpt`. Route 1 is unaffected either way.

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
| `{"error":"insufficient_scope"}` (HTTP 403) | Registration or REST call: the token lacks `ownmesh.device`. |
| JSON-RPC error `-32003` `insufficient_scope` | A `tools/call`: the token lacks that tool's scope. `data.required` names it. |
