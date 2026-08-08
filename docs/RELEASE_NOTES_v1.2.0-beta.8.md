# OwnMesh v1.2.0-beta.8

## Summary

E5 live PTY ownership in `ownmeshd`, tighter E4 write custody, E3 crash-safe dispatch outbox,
bounded PTY pipe fallback, durable large-directory list spools, and E7 git spool integrity/quota.
ChatGPT remains the primary operational UI via public MCP; no second OwnMesh approval UI is
required for normal use after device setup.

Unsupported surface contract (authoritative):
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) records
**32 explicit unsupported CLI surfaces** plus 7 additional hard-error surfaces
(**39 total**). Those surfaces remain excluded from completeness claims.

## Production path changes

### E3 — crash-safe dispatch outbox

- Agent transport persists accepted `operation.request` envelopes in a durable pending
  outbox before side effects finish.
- After crash/reconnect, pending entries resume dispatch (runtime idempotency) or a
  terminal `OWNMESH_E_DISPATCH_LOST` receipt is emitted — D1 no longer strands forever
  on seen-without-completion.
- Outbox capacity rejects without live-entry eviction.

### E5 — cloud sessions own a real PTY

- `ownmesh-session-host` is now a library exposing `LiveHost` (long-lived ConPTY/openpty).
- `ownmeshd` spawns a live host on `session.open` (`kind=pty`), writes real stdin on
  `session.write`, resizes the host on `session.resize`, and drains bounded output into the
  durable session replay ring on `session.replay` / attach.
- Reader join never blocks Drop/terminate (Windows ConPTY can stall `read()` after kill).
- Host teardown runs only after a successful sessions.json commit so persist rollback stays
  transactional (including `host_pid`).
- Public MCP session attach/write/resize/replay/close/claim/release/give/terminate require
  `workspace_id` so exact-action hashes bind the session workspace.
- Public MCP exposes session list/show/claim/release/give/terminate as separately authorized tools.
- CLI pipe fallback no longer uses unbounded `Command::output()`; concurrent capped readers
  + timeout kill contain infinite producers.

### E2/E4 — large directory retrieval

- Directory listings that exceed the 25k in-memory snapshot spill into a private durable
  spool with integrity hash, TTL, and count quota.
- Opaque `v2:` cursors page the full sorted snapshot so Full Access can retrieve every
  entry in chunks without unbounded RSS or silent skips.

### E4 — restricted write custody

- Parent directories are created component-wise (no multi-level `create_dir_all` on untrusted paths).
- The parent directory handle is held across exclusive temp create + rename; Linux uses `renameat`
  against the held dirfd. Post-publish handle revalidation remains fail-closed.

### E7 — git diff spool integrity + quota

- Diff spools live under a per-user private state directory (not world-writable temp).
- Load requires content-hash integrity over spool lines; symlink/preseed paths are rejected.
- Git invocations force `core.fsmonitor` / builtin FS monitor off so repo-local helpers cannot run
  during read-only status/diff.
- Spool directory enforces TTL, max file count, and total byte quota cleanup.

## Still open / fail-closed

- E4 workspace CLI CRUD and full custody race matrix promotion
- E5 controller lease reconnect multi-observer matrix (tools exposed; deeper proof partial)
- E6 nine official profile adapters + generic remote tool execution
- E7 bounded unified-diff apply + full review workflow (no auto-merge/push/rewrite)
- E8 networkless elevated broker Full Access mint/custody
- E9 authenticated resumable transfer
- E10 live ChatGPT + Cloudflare account proof

The `scripts/tests/test_v12_e2_e9_workerd_loopback.py` gate remains **RED (exit 2)** until every
E4–E9 acceptance row is fully evidenced. Partial production paths are not completion.

## Validation focus

- `cargo test -p ownmesh-session-host -p ownmesh-fs -p ownmeshd`
- E2 workerd loopback (includes live PTY marker output via public MCP)
- release-quality / unsupported-surface registry checks against `release/SUPPORTED_SURFACES.json`
