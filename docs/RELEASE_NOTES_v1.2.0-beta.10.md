# OwnMesh v1.2.0-beta.10

## Summary

Integrity visit fixing Terra blockers on session policy authority, ordered PTY
input exact-once delivery, and directory-list spool request binding. ChatGPT
remains the primary operational UI via public MCP after device setup.

Unsupported surface contract (authoritative):
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) records
**32 explicit unsupported CLI surfaces** plus 7 additional hard-error surfaces
(**39 total**). Those surfaces remain excluded from completeness claims.

## Production path changes

### E3 — MCP argument allowlist + session policy authority

- `sanitizeMcpArgs(toolName)` keeps only schema-declared keys plus common
  transport fields (`device_id`, `async`, `workspace_id`, `idempotency_key`, …).
- Hidden fields such as session `command` / `cwd`, and all client authority
  keys (`allow`, `skip_approval`, …), are dropped before hash/route.
- Interactive `session.open` is denied under `workspace_only` / `recommended`
  until OS process confinement exists (same posture as `command.run`). Session
  OAuth scope alone cannot launch a shell that escapes workspace custody.
- Policy presets document matching `session.open` deny rules.

### E5 — reserve-before-write controller sequences

- `session.write` / `session.resize` durably reserve
  `(session, seq, payload digest)` **before** any PTY mutation.
- Stale, gapped, or digest-mismatched input never reaches the process.
- Exact-once retries with the same seq+digest replay the receipt without
  re-delivery; pending receipts may retry delivery once after crash.

### E4 — directory spool request binding + byte budget

- Durable v2 list cursors verify stored `root_key` + `recursive` against the
  current listing request (cross-workspace cursor substitution fails closed).
- Aggregate entry/name/path byte budget is checked before every append, not only
  after full JSON serialization.

## Proof

`scripts/tests/test_e2_workerd_loopback.py` covers the public MCP path including
restart under `recommended` where `ownmesh_session_open` with an external marker
command fails closed and creates no marker. Unit coverage: session seq digest
reserve, dir spool cross-workspace cursor reject, MCP allowlist strip.

## Still open (gate remains RED)

- E4 CLI workspace CRUD + full custody matrix promotion
- E5 full controller lease reconnect matrix
- E6 nine official profile adapters
- E7 bounded unified-diff apply + Git review flow
- E8 networkless elevated broker mint/custody
- E9 authenticated resumable transfer
- E10 live ChatGPT + Cloudflare account proof
