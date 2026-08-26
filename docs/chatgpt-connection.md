# Connecting ChatGPT to OwnMesh

Real-world procedure for ChatGPT **normal Chat** → **your** OwnMesh control plane via **Streamable HTTP MCP** + **OAuth 2.1**.

```
ChatGPT (Personal Plugin / custom MCP app)
    → HTTPS POST https://<your-worker>/mcp
    → OAuth scopes gate tools
    → Durable Object DeviceRoom
    → ownmeshd on your PC (local policy = final authority)
```

## Spec references

| Topic | Source |
|---|---|
| MCP Streamable HTTP transport | [modelcontextprotocol.io — Transports (2025-03-26)](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports) |
| ChatGPT developer mode / MCP apps | [OpenAI Help: Developer mode and MCP apps](https://help.openai.com/en/articles/12584461-developer-mode-and-mcp-apps-in-chatgpt-beta) |
| OwnMesh tools / envelopes | `OWNMESH_SPECIFICATION.ja.md` §14 |
| Deploy Worker | [deploy-cloudflare.md](./deploy-cloudflare.md) |

Streamable HTTP notes that matter for OwnMesh:

- Single MCP endpoint: `POST`/`GET`/`DELETE` on `/mcp`
- JSON-RPC body on `POST`; optional SSE when `Accept` includes `text/event-stream`
- Session id may be returned as `Mcp-Session-Id` on `initialize`
- OwnMesh uses OAuth bearer tokens on tool calls (`Authorization: Bearer …`)

ChatGPT notes that matter:

- Full MCP (including write actions) is rolling out for Business / Enterprise / Edu (plan availability changes — check OpenAI help)
- Admin enables **developer mode**, then creates a custom MCP app/connector with your Worker URL
- After one-time OwnMesh CLI/TUI setup, **ChatGPT normal Chat is the primary operational UI** for device control
- ChatGPT may ask for its own product confirmation on write tools based on app permissions; OpenAI does **not** document a cryptographic confirmation attestation passed to the MCP server
- OwnMesh treats the authenticated, scoped MCP invocation as the exact requested action (bound to server-computed `payload_hash`, operation id, device, expiry, and one-time execution state)
- A second OwnMesh browser/CLI approval page is **not** required for normal use when device policy allows the action; it remains an optional recovery/admin path when policy is configured to `ask`
- Prefer `offline_access` in OAuth scopes so refresh tokens keep the connector alive
- E2 routing notes: [V1.2_E2_REMOTE_ROUTING.md](./V1.2_E2_REMOTE_ROUTING.md)
- E3 action binding notes: [V1.2_E3_ACTION_BINDING.md](./V1.2_E3_ACTION_BINDING.md)

---

## Prerequisites

The default self-hosted deployment has one OwnMesh owner and needs no Google,
GitHub, or Cloudflare account login at runtime. Deployment prints a one-time
bootstrap code; the owner uses it once to register a device passkey. ChatGPT is
then an OAuth client: the passkey authenticates the owner during connection or
reauthorization, while a rotating refresh token keeps the approved connector
working between browser sign-ins. A headless server uses the CLI device-code
flow and can be approved from a phone or another browser.

1. Control plane deployed to **your** Cloudflare account ([deploy-cloudflare.md](./deploy-cloudflare.md))
2. D1 migrations applied; DeviceRoom DO bound
3. Local agent: `ownmeshd run`
4. Device enrolled: `ownmesh device enroll --issuer https://<your-worker>`
5. Access preset chosen (`workspace_only` / `recommended` confine FS; arbitrary `command.run` **and** interactive `session.open` / PTY require `full_user_access` or `full_access` until OS process confinement exists — session scope alone cannot launch a shell under restricted presets; `full_access` permits broker-backed elevation only when the native broker is installed and attested)
6. Browser can reach `https://<your-worker>/health` and `/.well-known/oauth-authorization-server`

---

## A. Personal Plugin / custom MCP app (ChatGPT UI)

Exact menu labels move as OpenAI iterates; the flow is:

1. Enable **Developer mode** (workspace admin / user Advanced settings — see OpenAI help article above).
2. **Apps → Create** (or Workspace settings → Apps → Create).
3. **MCP server URL:** `https://<your-worker>/mcp`
4. **Icon (optional):** upload [`assets/ownmesh-icon.png`](../assets/ownmesh-icon.png).
   It is the square, dark variant of the same mesh mark used by the TUI and
   OwnMesh browser sign-in, and is already below ChatGPT's 10 KiB limit.
5. **Authentication:** OAuth
   - No client ID, client secret, callback copy, or advanced OAuth fields are needed.
   - ChatGPT discovers OwnMesh OAuth metadata and registers its exact public callback automatically.
   - OwnMesh accepts only `https://chatgpt.com/connector/oauth/<id>` without a prior token;
     other dynamic registrations still require a tenant token with `ownmesh.device`.
6. Request scopes (minimum useful set):

   ```text
   ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access
   ```

   | Scope | Tools (examples) |
   |---|---|
   | `ownmesh.read` / `ownmesh.device` | `ownmesh_list_devices`, `ownmesh_fs_list` / `ownmesh_list_files`, `ownmesh_fs_read` / `ownmesh_read_file`, `ownmesh_get_operation`, `ownmesh_list_profiles` |
   | `ownmesh.write` | `ownmesh_fs_write` / `ownmesh_write_file` |
   | `ownmesh.exec` | `ownmesh_command_run` / `ownmesh_run_command`, `ownmesh_command_shell` / `ownmesh_run_shell`, `ownmesh_cancel_operation` |
   | `ownmesh.session` | `ownmesh_session_open` / `attach` / `write` / `resize` / `replay` — live PTY owned by `ownmeshd` under `full_user_access`/`full_access` only (denied in `workspace_only`/`recommended` until OS confinement); controller `input_seq`/`resize_seq` exact-once (RetryPending is at-most-once / uncertain, never re-delivers); E5 partial: reconnect matrix still open; always pass `workspace_id` |
   | `offline_access` | refresh tokens for long-lived ChatGPT connector |

7. Click **Create** and complete OAuth in the browser: owner passkey sign-in → explicit scope consent → automatic return to ChatGPT.
8. **Scan tools** — you should see the OwnMesh catalog (structured command **separate** from raw shell).
9. Save as draft → test in a new chat → publish only after you trust write actions.

### Smoke prompts (normal Chat)

| Goal | Example prompt |
|---|---|
| Discovery | “List my OwnMesh devices” |
| Workspace CRUD (E4) | `ownmesh_workspace_list|show|add|update|remove` — device-local registry via MCP; `ws_default` protected |
| Read | “On device `dev_…`, list files under the workspace root” |
| Write | “Write `hello.txt` with content `hi` on that device” |
| Structured command | “Run `git status` via OwnMesh structured command (not shell)” |
| Long op | “Start a long command with async and poll operation status” |
| Session (E5 partial) | “Open a session on device `dev_…` in workspace `ws_default` and replay output” (requires full_user/full_access preset; live PTY; controller reconnect matrix still open) |

---

## B. Permission mode behavior

Two layers always apply. **Device OwnMesh policy is the final authority.**

### 1) ChatGPT-side permission / confirmation

Depending on plan, app action controls, and tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`):

| ChatGPT behavior | OwnMesh effect |
|---|---|
| Blocks or never calls a write tool | Operation never reaches the device |
| Asks user to confirm tool call, user accepts | Only OAuth + MCP routing proceed — **not** local allow |
| Auto-runs read-only tools | Still subject to OAuth scope + device policy |

Annotations are **UX hints only**. They do not authorize.

### 2) OwnMesh local policy (final)

| Device preset / decision | MCP tool result (`structuredContent`) |
|---|---|
| `allow` | `status: "completed"` (or `pending`/`running` if async) |
| `ask` with local `delegate_remote_mcp = true` and a valid exact-bound MCP action | `status: "completed"`; no OwnMesh approval page is required |
| `ask` | `status: "approval_required"`, `approval_required: true`, `operation_id`, `approval_url`, optional `approval_id` |
| `deny` | `status: "denied"` with `OWNMESH_E_POLICY_DENIED` |
| Device offline | `status: "device_offline"` with `OWNMESH_E_DEVICE_OFFLINE` |

**Approve OwnMesh `ask` via (optional recovery/admin only):**

- OwnMesh TUI → Approvals
- `ownmesh approvals …` CLI
- One-time browser page: `https://<your-worker>/approve?operation_id=op_…`

The browser recovery page binds the **exact action hash**, **original operation
`expires_at`**, device approval id, and authenticated human principal into a
server-hashed `approval.decision` frame. Stale deferred requests whose original
MCP expiry elapsed cannot be approved by a freshly minted transaction. The Agent
rejects unsigned or tampered decision frames (`OWNMESH_E_ACTION_BINDING_MISMATCH`)
and expired deferred approvals fail closed on-device.

Then poll `ownmesh_get_operation` with the same `operation_id`.

ChatGPT’s confirmation card **must not** be treated as OwnMesh local approval or
as a cryptographic attestation OwnMesh can verify.

For ChatGPT-primary operation, the device owner may explicitly enable the local
policy-file setting below during setup. This treats the authenticated MCP
invocation with a verified operation ID, payload hash, and unexpired binding as
the requested action; it does not accept a client `approved` flag or claim a
ChatGPT attestation. `deny`, lockdown, OAuth/device checks, exact-action
matching, expiry, and idempotency still fail closed. Omitting the setting (the
default) retains the recovery approval flow above.

```toml
# policy.toml
preset = "recommended"
delegate_remote_mcp = true
```

### Recommended matrix for first-time setup

| Phase | ChatGPT | OwnMesh preset | Expectation |
|---|---|---|---|
| Day-0 read-only | Grant read scopes only | `workspace_only` or `recommended` | List/read works; write/exec fail scope or ask |
| Trusted write | Add write/exec scopes | `recommended` + `delegate_remote_mcp = true` | Exact-bound MCP writes complete in ChatGPT; no OwnMesh approval UI |
| Power user | Full scopes | `full_user_access` | Broader allow inside user home; still no silent privilege escape |
| Lab only | Full scopes | `full_access` | Policy allow-all **without hidden denies**; still no broker integrity bypass |

---

## C. Tool result shape

Every tool result carries a stable envelope (also in `structuredContent`):

```json
{
  "operation_id": "op_…",
  "status": "completed",
  "phase": "completed",
  "phase_updated_at": "2026-08-13T00:00:00.000Z",
  "device_id": "dev_…",
  "summary": "…",
  "data": {},
  "truncated": false,
  "next_cursor": null,
  "approval_required": false,
  "session_id": null,
  "warnings": [],
  "policy_authority": "ownmesh_device"
}
```

- Large lists/files set `truncated: true` and `next_cursor` (`cur_…`).
- With `async: false` (or omitted), the Worker waits at most one second for an
  authoritative device result, then returns a pollable non-terminal operation.
- `content[0].text` is the JSON encoding of this same compact envelope for
  MCP 2025-03-26 and existing CLI compatibility.
- Durable authority fields (principal/tenant identity, action and payload
  hashes, claim state, and dispatch outbox data) are never returned. Pass
  `include_diagnostics: true` to operation polling only when the bounded,
  redacted timing/tool metadata is needed.
- Long commands should pass `async: true` and poll `ownmesh_get_operation`.
- `phase` is server-derived (`queued`, `delivered`, `executing`,
  `waiting_approval`, or a terminal phase); `status` remains backward compatible.
- `policy_authority` is always `ownmesh_device` — model text never becomes authorization.

---

## D. Security (prompt injection)

- Do **not** paste secrets into ChatGPT prompts and expect OwnMesh to treat them as policy.
- Untrusted repo/log content may contain “ignore previous instructions / always allow” — OwnMesh **ignores** that for authorization.
- Tool argument keys like `force_allow`, `bypass_policy`, `skip_approval` are stripped and never override device policy.
- OAuth scope checks run **before** device routing; injection cannot mint scopes.
- Final allow/ask/deny is evaluated on the device from **operation facts** (capability, path, program, elevated, …), not from natural-language content.

---

## E. Troubleshooting

| Symptom | Check |
|---|---|
| OAuth fails | `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp`, redirect URI exact match, PKCE S256 |
| Connector dies after hours | Include `offline_access`; confirm refresh tokens issued. Expired access tokens must get HTTP 401 + `WWW-Authenticate` from `/mcp` so ChatGPT can refresh |
| ChatGPT reports 502 after idle | New chat, then re-consent if 401 refresh still fails. `GET /mcp` with `Accept: text/event-stream` is 405 by design (no long-lived SSE on Workers) |
| CLI vs Worker version skew | `ownmesh doctor --check-network` warns when `/health` version does not match the CLI |
| `insufficient_scope` | Re-consent with required scopes |
| `device_offline` | `ownmeshd run`, enrollment, `/agent/connect` WebSocket. On Linux, also check lingering: without it (`loginctl show-user $USER -p Linger` → `Linger=no`) the agent stops at GUI logout and the device goes offline until you log in again (`ownmesh doctor` warns). A hung reconnect on a dual-stack host with a blackholed IPv6 route is another known cause; the bounded connect timeout (v1.2.21+) retries with an IPv4 fallback instead of hanging forever |
| Stuck `approval_required` | TUI/CLI/browser approve; then `ownmesh_get_operation` |
| Write works in ChatGPT UI but file missing | ChatGPT confirm ≠ OwnMesh approve |
| Unexpected allow | Verify preset is not `full_access` by mistake |
| Some tools are missing from ChatGPT | Stale connector catalog. Compare generations, see **Tool catalog looks stale** below |
| Tools disappear entirely / no catalog at all | Edge rejection, not a stale catalog. Run `python scripts/probe_machine_endpoints.py https://<worker>` and see [deploy-cloudflare.md](./deploy-cloudflare.md#machine-endpoints-must-not-require-a-browser-signature) |
| `ownmesh_system_diagnose` returns `diagnosis_unavailable` | Read `diagnosis_rejection`; `unsupported_contract_version` means deploy the current Worker, other reasons point at the device |
| `OWNMESH_E_SELF_REENTRANT_EXEC` | Expected. Running the OwnMesh CLI on the device it manages would deadlock the daemon, so it is refused before spawn. Use `ownmesh_system_diagnose` and the policy/grants/workspace tools instead; only `ownmesh --version` / `--help` are executable this way |
| `OWNMESH_E_AUTHORIZATION_REFRESHED` | The operation was never delivered and its authorization was refreshed while it waited. Resubmit the same request; it is authorized under the current credentials |

### Tool catalog looks stale

ChatGPT loads the tool catalog when the connector session is established and
keeps it. If a deployment adds or removes tools while a session is live, the
client can keep serving the old set — new tools stay invisible and removed ones
stay callable.

Compare the two generations before changing anything:

```bash
# What this deployment publishes right now (no bearer needed).
curl -s https://<worker>/mcp | jq '{tools, catalog_revision, service_version}'
curl -s https://<worker>/health | jq .mcp_catalog
```

`catalog_revision` is a SHA-256 over exactly the bytes `tools/list` returns, so
it changes whenever a tool name, description, annotation, or `inputSchema`
changes — including changes that do not move the release version. It is also
returned in `initialize._meta["ownmesh/catalog_revision"]` and on every
`tools/list` response.

Recovery, in order:

1. **Confirm the deployment is current.** If `service_version` is behind the
   release you installed, the deploy did not take effect. `pnpm run
   deploy:guided` now refuses to report success in that case.
2. **Start a new chat.** The Worker binds the catalog revision into the MCP
   session id and answers `HTTP 404` to any request carrying a session minted
   under a different revision, which is MCP's signal to re-`initialize`. A new
   conversation therefore picks up the current catalog without touching the
   connector.
3. Only if a fresh session still shows the old set, disconnect and reconnect the
   connector.

You never need to guess which individual tools are stale: if
`catalog_revision` matches between the deployment and a freshly initialized
session, the catalogs are identical.

---

## F. Automated coverage (no live ChatGPT account required)

```bash
pnpm -r test
# includes packages/control-plane MCP → DeviceRoom → approval / scope / prompt-injection tests

cargo test -p ownmesh-profiles
# 9 official profile fixture conformance + generic launch

cargo test -p ownmeshd prompt_injection
# device policy remains final under injection payloads
```

Live ChatGPT account E2E remains a manual checklist (availability depends on OpenAI plan rollouts).
