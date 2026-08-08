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
- OwnMesh treats the authenticated, scoped MCP invocation as the exact requested action (bound to operation id, device, expiry, and one-time execution state)
- A second OwnMesh browser/CLI approval page is **not** required for normal use when device policy allows the action; it remains an optional recovery/admin path when policy is configured to `ask`
- Prefer `offline_access` in OAuth scopes so refresh tokens keep the connector alive
- E2 routing notes: [V1.2_E2_REMOTE_ROUTING.md](./V1.2_E2_REMOTE_ROUTING.md)

---

## Prerequisites

1. Control plane deployed to **your** Cloudflare account ([deploy-cloudflare.md](./deploy-cloudflare.md))
2. D1 migrations applied; DeviceRoom DO bound
3. Local agent: `ownmeshd run`
4. Device enrolled: `ownmesh device enroll --issuer https://<your-worker>`
5. Access preset chosen (`workspace_only` → `recommended` → `full_user_access` → `full_access`)
6. Browser can reach `https://<your-worker>/health` and `/.well-known/oauth-authorization-server`

---

## A. Personal Plugin / custom MCP app (ChatGPT UI)

Exact menu labels move as OpenAI iterates; the flow is:

1. Enable **Developer mode** (workspace admin / user Advanced settings — see OpenAI help article above).
2. **Apps → Create** (or Workspace settings → Apps → Create).
3. **MCP server URL:** `https://<your-worker>/mcp`
4. **Authentication:** OAuth  
   - Authorization server metadata: `https://<your-worker>/.well-known/oauth-authorization-server`  
   - Protected resource metadata: `https://<your-worker>/.well-known/oauth-protected-resource`  
   - Dynamic client registration: `POST /oauth/register` (public client + PKCE)
5. Request scopes (minimum useful set):

   ```text
   ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access
   ```

   | Scope | Tools (examples) |
   |---|---|
   | `ownmesh.read` / `ownmesh.device` | `ownmesh_list_devices`, `ownmesh_fs_list` / `ownmesh_list_files`, `ownmesh_fs_read` / `ownmesh_read_file`, `ownmesh_get_operation`, `ownmesh_list_profiles` |
   | `ownmesh.write` | `ownmesh_fs_write` / `ownmesh_write_file` |
   | `ownmesh.exec` | `ownmesh_command_run` / `ownmesh_run_command`, `ownmesh_command_shell` / `ownmesh_run_shell`, `ownmesh_cancel_operation` |
   | `ownmesh.session` | `ownmesh_session_open` / `ownmesh_open_session`, `ownmesh_session_attach` |
   | `offline_access` | refresh tokens for long-lived ChatGPT connector |

6. Complete OAuth in the browser when ChatGPT prompts.
7. **Scan tools** — you should see the OwnMesh catalog (structured command **separate** from raw shell).
8. Save as draft → test in a new chat → publish only after you trust write actions.

### Smoke prompts (normal Chat)

| Goal | Example prompt |
|---|---|
| Discovery | “List my OwnMesh devices” |
| Read | “On device `dev_…`, list files under the workspace root” |
| Write | “Write `hello.txt` with content `hi` on that device” |
| Structured command | “Run `git status` via OwnMesh structured command (not shell)” |
| Session | “Open an interactive session with `bash` on that device” |
| Long op | “Start a long command with async and poll operation status” |

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
| `ask` | `status: "approval_required"`, `approval_required: true`, `operation_id`, `approval_url`, optional `approval_id` |
| `deny` | `status: "denied"` with `OWNMESH_E_POLICY_DENIED` |
| Device offline | `status: "device_offline"` with `OWNMESH_E_DEVICE_OFFLINE` |

**Approve OwnMesh `ask` via:**

- OwnMesh TUI → Approvals
- `ownmesh approvals …` CLI
- One-time browser page: `https://<your-worker>/approve?operation_id=op_…`

Then poll `ownmesh_get_operation` with the same `operation_id`.

ChatGPT’s confirmation card **must not** be treated as OwnMesh local approval.

### Recommended matrix for first-time setup

| Phase | ChatGPT | OwnMesh preset | Expectation |
|---|---|---|---|
| Day-0 read-only | Grant read scopes only | `workspace_only` or `recommended` | List/read works; write/exec fail scope or ask |
| Trusted write | Add write/exec scopes | `recommended` | Writes return `approval_required` until TUI/CLI approve |
| Power user | Full scopes | `full_user_access` | Broader allow inside user home; still no silent privilege escape |
| Lab only | Full scopes | `full_access` | Policy allow-all **without hidden denies**; still no broker integrity bypass |

---

## C. Tool result shape

Every tool result carries a stable envelope (also in `structuredContent`):

```json
{
  "operation_id": "op_…",
  "status": "completed",
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
- Long commands should pass `async: true` and poll `ownmesh_get_operation`.
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
| OAuth fails | `/.well-known/oauth-authorization-server`, redirect URI exact match, PKCE S256 |
| Connector dies after hours | Include `offline_access`; confirm refresh tokens issued |
| `insufficient_scope` | Re-consent with required scopes |
| `device_offline` | `ownmeshd run`, enrollment, `/agent/connect` WebSocket |
| Stuck `approval_required` | TUI/CLI/browser approve; then `ownmesh_get_operation` |
| Write works in ChatGPT UI but file missing | ChatGPT confirm ≠ OwnMesh approve |
| Unexpected allow | Verify preset is not `full_access` by mistake |

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
