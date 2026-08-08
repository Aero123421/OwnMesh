# OwnMesh v1.2.0-beta.6 — E2/E3 durable bounds + fail-closed E2–E9 gate

## Summary

This beta fixes Terra-critical E2/E3 integrity gaps on the production
MCP → DeviceRoom → Agent → ownmeshd path and refuses to paint incomplete
E2–E9 work green.

It does **not** claim production-complete v1.2 and does **not** close E4–E9
or E10.

## CLI surface contract

The CLI contract remains **32 explicit unsupported CLI surfaces** plus 7
additional hard-error surfaces (**39 total**), recorded in
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## What is new

- **Durable dispatch outbox integrity**: `boundMcpOperationRecord` never
  replaces a pending `__ownmesh_dispatch_outbox` with a generic truncation
  object. Client-visible result data is bounded separately (256 KiB);
  outbox bodies use a 900 KiB ceiling and fail closed when larger.
- **Cursor-preserving durable truncation**: oversized results keep
  `next_offset`, `sha256`, `encoding`, `exit_code`, list cursors, and short
  previews instead of a bare wipe.
- **Aligned per-hop budgets**: single-call file read ≤ 160 KiB and command
  output ≤ 200 KiB so Base64/JSON fits durable store + Agent envelope.
  Larger files are retrieved by paging `offset`/`max_bytes`.
- **Directory page UTF-8 byte budget** (~200 KiB) with stable `(name,path)`
  continuation cursors.
- **Durable cancel claims**: `cancel:<target_operation_id>` (or caller key)
  with crash-safe outbox; target becomes `cancel_requested` only after a
  confirmed device route (uncertain ≠ confirmed).
- **E2 workerd proof expanded**: 512 KiB multi-chunk binary read, list/stat/delete.
- **E2–E9 gate fail-closed**: `test_v12_e2_e9_workerd_loopback.py` exits
  non-zero while E4–E9 real-path rows remain open (even when E2/E3 passes).

## What remains unsupported / open

- E4 workspace CRUD + descriptor-rooted TOCTOU custody
- E5 cloud PTY sessions / controller leases
- E6 nine profile adapters end-to-end
- E7 bounded unified-diff patch + Git review workflow
- E8 networkless elevated broker mint/custody
- E9 resumable multi-device transfer
- CLI `exec --device` / `session open <device>`
- Live ChatGPT + live Cloudflare proof (E10)

## Docs

- [`docs/V1.2_E2_REMOTE_ROUTING.md`](./V1.2_E2_REMOTE_ROUTING.md)
- [`docs/V1.2_E3_ACTION_BINDING.md`](./V1.2_E3_ACTION_BINDING.md)
- [`docs/chatgpt-connection.md`](./chatgpt-connection.md)
