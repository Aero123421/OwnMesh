# OwnMesh v1.2.0-beta.4 — E3 action binding + bounded I/O

## Summary

This beta hardens the E2 remote routing path with server-side exact-action
authorization binding (E3 slice), bounded command output collection, real
process-tree cancellation, ingress byte caps, and separately authorized
filesystem stat/delete/patch tools with cursor-paginated directory listing.

It does **not** claim production-complete v1.2 and does not close E10
live-account gates.

## CLI surface contract

The CLI contract remains **32 explicit unsupported CLI surfaces** plus 7
additional hard-error surfaces (**39 total**), recorded in
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## What is new

- Server-computed `payload_hash` on `ownmesh.operation/1.0` requests
- Durable D1 binding of `payload_hash`, `idempotency_key`, `workspace_id`,
  `expires_at`, `claim_version`, and canonical `action_json`
- Idempotency key reuse with a different action fails closed
  (`OWNMESH_E_IDEMPOTENCY_MISMATCH`); identical action replays the prior row
- Command stdout/stderr streamed into independently capped rings (no
  `wait_with_output` / unbounded `read_to_end`)
- Cancel registry outside the runtime mutex; long commands are killed and
  surface terminal `cancelled`
- MCP and DeviceRoom enforce application byte caps before JSON parse;
  oversized WebSocket frames are rejected before decode
- MCP tools: `ownmesh_fs_stat`, `ownmesh_fs_delete`, `ownmesh_fs_patch`
- Directory list returns stable name-ordered `next_cursor` / `truncated`

## What remains unsupported / open

- Full E4 workspace CRUD + TOCTOU custody for restricted modes
- E5 cloud PTY sessions / controller leases
- E6 nine profile adapters end-to-end
- E7 bounded unified-diff patch + Git review workflow (hash-checked whole-file
  patch is available; unified-diff apply is not)
- E8 networkless elevated broker mint/custody
- E9 resumable multi-device transfer
- CLI `exec --device` / `session open <device>`
- Live ChatGPT + live Cloudflare proof (E10)

## Docs

- [`docs/V1.2_E2_REMOTE_ROUTING.md`](./V1.2_E2_REMOTE_ROUTING.md)
- [`docs/V1.2_E3_ACTION_BINDING.md`](./V1.2_E3_ACTION_BINDING.md)
- [`docs/chatgpt-connection.md`](./chatgpt-connection.md)
