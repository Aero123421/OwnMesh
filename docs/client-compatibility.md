# Client compatibility matrix

Dated: 2026-09-06. OwnMesh SHA: unreleased working tree (no live receipt yet).

This is #199 deliverable 1, minimal slice: one dated table that records what is
actually known per client. **Every row below is `unverified` unless a live
receipt exists.** A static inspection of a client's public docs is not live
support and is never presented as such.

For the endpoint contract every row shares, see
[`mcp-clients.md`](./mcp-clients.md) (public client, PKCE S256, exact
`redirect_uri` match with loopback port flexibility per RFC 8252 §7.3, RFC 8707
`resource` bound to `https://<worker>/mcp`) and
[`chatgpt-connection.md`](./chatgpt-connection.md) (ChatGPT onboarding).

Long-operation pattern (all clients): prefer `async`/`detach`, then poll
`ownmesh_get_operation`; if the operation id is lost, rediscover with
`ownmesh_list_operations` inside the tenant/principal boundary — never
re-execute a side effect blindly.

## Matrix

| Client | Transport / protocol | OAuth registration | Callback URI(s) | Refresh behavior | Scope step-up | Tool classes (read/write/exec/session) | Client timeout / output limits | Catalog refresh / snapshot | Live receipt | Status | Known limitations |
|---|---|---|---|---|---|---|---|---|---|---|---|
| ChatGPT custom Apps / MCP | Streamable HTTP, `2025-03-26` compatible; negotiates `2026-07-28` where offered | Stateless CIMD for exact `https://chatgpt.com/connector/oauth/<slug>`; rotating refresh token issued even without `offline_access` | `https://chatgpt.com/connector/oauth/<slug>` (exact) | Rotating refresh; expired access gets HTTP 401 + `WWW-Authenticate` so the connector can refresh | Re-consent; tool calls return HTTP 403 + `WWW-Authenticate: Bearer error="insufficient_scope"` with step-up `scope` | Per plan/mode; agent mode does not use custom apps, deep research is read/fetch only | OwnMesh command timeout and ChatGPT product limits are separate boundaries | Approved app may use a frozen tool snapshot until an admin refreshes/reviews it; stale sessions get HTTP 404 `catalog_revision` fencing so the client re-initializes | None in-repo | unverified | Write/modify availability differs by workspace plan (dated external fact, not an OwnMesh guarantee) |
| Claude.ai custom remote connector | Streamable HTTP | Owner-provisioned client or authenticated DCR; no ChatGPT-style stateless exemption | Owner-registered HTTPS value (exact) | Server-side: standard rotating refresh with `offline_access`; reuse detected fail-closed | Re-consent via 403 `insufficient_scope` challenge | Unverified per class | Client-side limits apply; use `async`/`detach` + poll for long work | Unverified; same `catalog_revision` fencing applies server-side | None in-repo | unverified | Must be live-tested before any support claim |
| Claude Code remote HTTP MCP | Streamable HTTP | Owner-provisioned or authenticated DCR; `http://` loopback callbacks allow port variation only (RFC 8252 §7.3) | `http://127.0.0.1/callback`-style loopback (port-flexible, path/query/host exact) or owner HTTPS value | Server-side: same rotating refresh as Claude.ai row above | Same as above | Unverified per class | Per-server tool/idle timeouts apply client-side | Unverified | None in-repo | unverified | Ephemeral-loopback-port matching and 403 scope-challenge interop must be proven live first |
| Claude Code plugin-provided MCP | Same as remote HTTP MCP | Same as above; plugin ships `.mcp.json` with endpoint placeholder only, never credentials | Same as above | Same as above | Same as above | Unverified per class | Same as above | Unverified | None in-repo | experimental | No plugin ships yet; installation must never auto-authorize destructive tools |
| Perplexity custom remote connector | Streamable HTTP | Owner-provisioned or authenticated DCR | `https://www.perplexity.ai/rest/connections/oauth_callback`, `https://enterprise.perplexity.ai/rest/connections/oauth_callback` (fixed exact values per [vendor docs](https://www.perplexity.ai/help-center/en/articles/13915507-adding-custom-remote-connectors), accessed 2026-09-06 — unverified live) | Unverified live | Unverified live | Unverified per class | Client-side limits apply | Unverified | None in-repo | unverified | Read/write/exec/session exposure per Perplexity surface is unproven |
| Perplexity Computer Skill + connector | Skill file does not establish the connection; connector row above applies | Same as connector | Same as connector | Same as connector | Same as connector | Unverified per class | Same as above | Unverified | None in-repo | experimental | No Skill bundle ships yet; Skill must stay capability-oriented with no hostnames, credentials, device IDs, or workspace paths |
| MCP Inspector / official SDK reference client | Streamable HTTP | Owner-provisioned client | Owner-registered value (exact) | Standard rotation | 403 challenge + re-consent | Unverified per class | No vendor product limits | `catalog_revision` comparable via `GET /mcp` vs `tools/list` | None in-repo | unverified | Reference baseline only; passing here does not certify any vendor product |

## Receipt format (minimum, when a live test happens)

UTC timestamp; OwnMesh SHA/release; client product/version/plan; endpoint
`catalog_revision`; OAuth registration method; scopes granted; redacted
request/result classes; read outcome; side-effect outcome where the plan
supports it; long-operation polling outcome; limitations/waivers. No tokens,
request bodies, or user content in receipts.
