# OwnMesh v1.2.0-beta.5 — E2/E3 integrity, resume, binary cursors

## Summary

This beta hardens the production MCP → DeviceRoom → Agent → ownmeshd path:

- device-side exact-action verification (`authorization.bound_action` + `payload_hash`)
- required caller `idempotency_key` for side-effect MCP tools
- durable pending redelivery when an Agent becomes `ready` after reconnect
- binary file retrieval with RFC 4648 Base64 and byte-range `next_offset` cursors
- cancel control results accepted as room-only when not claimed into D1

It does **not** claim production-complete v1.2 and does not close E10
live-account gates.

## CLI surface contract

The CLI contract remains **32 explicit unsupported CLI surfaces** plus 7
additional hard-error surfaces (**39 total**), recorded in
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## What is new

- `ownmesh.operation/1.0` request may carry `authorization.bound_action`
- Agent recomputes stable JSON SHA-256 and rejects argument/capability/device/
  workspace/expiry/fact tampering before policy/side effect
  (`OWNMESH_E_ACTION_BINDING_MISMATCH`)
- Write/exec MCP tools require a non-empty `idempotency_key` (schema + runtime)
- DeviceRoom redelivers unfinished durable pending ops on Agent `ready` with a
  fresh seq/message_id; TTL/expiry drops surface
  `OWNMESH_E_OPERATION_EXPIRED` on matching MCP rows when possible
- Binary `fs.read` returns `encoding=base64` (standard padded) and preserves
  byte `next_offset`; MCP does not re-slice Base64 as text `cur_N`
- Cancel device results without a D1 cancel-request row finalize as room-only
  so pending is cleared without fail-closing the Agent socket

## What remains unsupported / open

- Full E4 workspace CRUD + descriptor-rooted TOCTOU custody
- E5 cloud PTY sessions / controller leases
- E6 nine profile adapters end-to-end
- E7 bounded unified-diff patch + Git review workflow
- E8 networkless elevated broker mint/custody
- E9 resumable multi-device transfer
- CLI `exec --device` / `session open <device>`
- Live ChatGPT + live Cloudflare proof (E10)
- Unbounded D1/op-journal flooding quotas still need deeper caps beyond current
  pending/row limits

## Docs

- [`docs/V1.2_E2_REMOTE_ROUTING.md`](./V1.2_E2_REMOTE_ROUTING.md)
- [`docs/V1.2_E3_ACTION_BINDING.md`](./V1.2_E3_ACTION_BINDING.md)
- [`docs/chatgpt-connection.md`](./chatgpt-connection.md)
