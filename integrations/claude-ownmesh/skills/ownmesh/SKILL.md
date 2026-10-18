---
name: ownmesh
description: Drive the user's OwnMesh devices through the scoped MCP endpoint. Use for device, workspace, file, command, session, transfer, and operation tasks.
---

# OwnMesh skill

Status: experimental, unverified live. See `docs/client-compatibility.md`.
Endpoint: `${OWNMESH_WORKER_URL}/mcp` (Streamable HTTP MCP + OAuth 2.1, PKCE S256).
Never commit a Worker URL, token, device ID, or private path. The `.mcp.json`
in this plugin ships an endpoint placeholder only, never credentials.

## Prefer structured tools over raw shell

- Use structured `ownmesh_command_run` with exact `program`/`args`.
  Use raw-shell `ownmesh_command_shell` only when the task genuinely needs
  shell semantics, and say so in the user-visible summary.
- Inspect state before mutation: `ownmesh_list_devices`,
  `ownmesh_workspace_list` / `ownmesh_workspace_show`, and the scoped
  read tool for the target. Do not guess paths or device targets.

## Long operations: async, then poll

- Pass `async: true` (or `detach: true` where the tool supports it) for
  anything slow, then poll `ownmesh_get_operation` with the returned
  `operation_id` until it reaches a terminal phase.
- Keep the `operation_id` (and any caller-supplied `idempotency_key`)
  outside the chat. Retrying the identical call with the same
  `idempotency_key` converges to the one durable operation; it never
  executes a second side effect.
- If the operation ID is lost, rediscover with `ownmesh_list_operations`
  inside the tenant/principal boundary (narrow `since` plus the remembered
  device/tool/key). Never re-execute a side effect blindly, and never
  read a foreign tenant/principal row.

## Page large results

- File listings, reads, and result payloads can set `truncated: true` with
  `next_cursor` (`cur_...`). Follow the cursor instead of widening the
  request. Re-list with a narrower prefix before reading a large tree.

## Two approval layers, never conflated

- Claude's product approval UI is not OwnMesh authorization. A user
  accepting a Claude prompt means only that the MCP call may proceed.
- The OwnMesh device policy is the final authority: `allow` completes,
  `ask` returns `approval_required` with an `operation_id`, `deny` fails
  closed. An `ask` decision is approved only via the owner's TUI/CLI or
  the recovery approval page, then re-polled with `ownmesh_get_operation`.

## Safety invariants (non-negotiable)

- This plugin must never auto-authorize, silently enable destructive
  tools, or skip approval. There is no automatic approval path: every
  write/exec/session call needs an explicit user confirmation in chat
  plus a passing device policy.
- Never place tokens, device IDs, or private workspace paths in committed
  files, prompts, or receipts. Redact them from pasted output.
- Scope failures arrive as HTTP 403 `insufficient_scope` with a step-up
  `scope`; re-consent for the named scope instead of retrying blindly.
- A stale tool catalog surfaces as HTTP 404 `catalog_revision` fencing:
  re-initialize/rediscover tools rather than calling a removed tool.
