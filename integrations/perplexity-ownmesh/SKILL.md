---
name: ownmesh
description: Use an already-connected OwnMesh MCP connector for device, workspace, file, command, session, and transfer tasks.
---

# OwnMesh Computer Skill (Perplexity)

Status: experimental, unverified live. See `docs/client-compatibility.md`.

This Skill does not establish the MCP connection by itself. The Perplexity
custom remote connector must already be configured against
`https://<your-worker>/mcp` (Streamable HTTP MCP + OAuth 2.1, PKCE S256);
this file only teaches the model how to use that connector well. Connector
recipe: `examples/connector-recipe.md`.

## Capability-oriented rules (no hostnames, credentials, device IDs, or paths)

- Work through the connected OwnMesh connector only. Never ask the user to
  paste tokens, device IDs, or private workspace paths into chat, and never
  write such values into files, receipts, or shared prompts.
- Prefer structured `ownmesh_command_run` with exact `program`/`args` over
  raw-shell `ownmesh_command_shell`. Reserve the shell form for tasks that
  genuinely need shell semantics.
- Inspect before mutating: list devices, show the workspace, and read the
  target with a scoped read tool before any write/exec/session call.
- Long work: pass `async: true` (or `detach: true` where supported), keep
  the returned `operation_id`, and poll `ownmesh_get_operation` to a
  terminal phase. Retrying the identical call with the same
  `idempotency_key` converges to one durable operation and never executes
  a second side effect. If the ID is lost, rediscover with
  `ownmesh_list_operations` inside the tenant/principal boundary; never
  re-execute a side effect blindly.
- Page large results: follow `truncated: true` + `next_cursor` (`cur_...`)
  instead of widening the request.
- Two approval layers: the Perplexity product confirmation is not OwnMesh
  authorization. The device policy is the final authority (`allow` completes, `ask`
  returns `approval_required` with an `operation_id`, `deny` fails
  closed). This Skill must never auto-authorize, silently enable
  destructive tools, or skip approval: every side effect needs explicit
  user confirmation plus a passing device policy.
- Scope failures arrive as HTTP 403 `insufficient_scope` with a step-up
  `scope`; re-consent for the named scope. A stale catalog surfaces as
  HTTP 404 `catalog_revision` fencing; re-initialize rather than calling
  a removed tool.
