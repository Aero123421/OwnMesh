# ADR 0021: D1 write-amplification resolution (Issue #224 plan F)

- Status: Accepted
- Date: 2026-09-06

## Context

Production telemetry showed 3,260 tool calls consuming 116,861 D1 rows
written per day (35.85 rows/call, 4.85 write statements/call). MCP
operation, audit, and OAuth traffic share one account-level D1 write
budget (Free: 100,000 rows/day), so operation traffic exhausted the budget
and even OAuth authorize transactions failed — while `/health` stayed
green because it never probed write capability.

Root causes (all confirmed against `main` @ `6660c87`):

1. `mcp_operations` wide rows were full-row UPDATED twice per routed call
   (dispatch marker, terminal result), fanning out across 6 plain, 2
   UNIQUE, and 3 partial retention indexes.
2. Five indexes were pure write cost with no readership: payload_hash
   (never a lookup key), the non-unique idempotency composite (covered by
   partial UNIQUEs once queries state the predicate), the outbox
   operation_id index (UNIQUE autoindex covers it), the audit tenant
   index (covered by the retention index), and the updated_at index
   (retention uses partial expiry indexes).
3. Every OAuth refresh paid three bootstrap writes plus two receipt
   cleanups; every device-code poll paid a write; every tool call paid a
   separate audit row plus claim plus two wide updates.
4. No budget reservation, admission control, or degraded mode existed, and
   readiness confused "schema readable" with "writes servable".

## Decision

### P0 — Measurement (PR #225)

Fixed-statement-fingerprint D1 telemetry (`D1TelemetryRecorder`, `classifyD1Error`,
per-statement rows_read/rows_written, baseline renderer). In-memory only,
no request content, no external sink. Gate 1 (90%+ attribution) runs on it.

### P1 — D1 cheap wins (this change)

- `transitionMcpOperation`: status-transition CAS writing only mutable
  result columns; the MCP `patchOp` funnel routes narrow-only patches
  there. Identity and exact-action binding columns are never rewritten
  post-claim.
- `ensureBootstrapSeeded`: single EXISTS read on hot OAuth paths (migration
  0022 seeds the rows); full seed only when absent.
- Single receipt cleanup inside the healthy-rotation batch; the scheduled
  sweep covers retry paths.
- `markDeviceCodePolled` takes `minIntervalMs` and degrades to a
  zero-change conditional UPDATE for sub-interval polls.
- `runRetentionSweep` (tenant-bounded, lease-honoring) served by the new
  `scheduled()` cron (`*/5 * * * *`); request-path leases stay as fallback.
- Migration 0022 drops the five proven-redundant indexes (EXPLAIN proof in
  `store-plan-f-p1.test.ts`), seeds bootstrap rows, and adds `quota_probe`
  and `operation_store_cutover` tables. Idempotency lookups carry
  `length(idempotency_key) > 0` so the planner proves the partial UNIQUE.
- `probeWriteReadiness`: single-row upsert distinguishing quota exhaustion
  from outage without exposing raw errors.

### P2 — Tenant OperationRoom authority (this change)

`OperationStore` facade with a D1 adapter (default, behavior-identical) and
a tenant-sharded `OperationRoom` Durable Object behind
`OWNMESH_OPERATION_STORE=device_do` plus a per-tenant cutover cursor
(`operation_store_cutover`; value `d1` escapes back). Hybrid fallback keeps
pre-cutover rows and in-flight transitions visible across the cutover. Room
receipts double as the audit trail for device-routed calls; injection
attempts and meta tools keep D1 audit rows. Transfers, approvals, and local
tools stay D1 (visible via hybrid fallback).

Tenant sharding — not the device sharding sketched in the issue — because
id-only lookups (polls, cross-isolate transitions) always carry the tenant
but rarely the device; device sharding would need a per-operation directory
write that erases the saving. Per-device side-effect serialization is
unchanged (single daemon lane), so nothing that matters is lost.

### P3 — Audit (adapted, this change)

The issue proposed Queues + R2 immutable segments. The repository forbids
R2/TURN bindings by policy test (spec §5.1 fail-closed), and adding a queue
provision couples every deployment to new billable surface for a gain the
amortization already captures. Adaptation: the operation receipt IS the
audit source in `device_do` mode (no per-call audit row); D1 `audit_events`
remains the authoritative trail for auth, local, and transfer decisions.
Revisit Queues/R2 only with an explicit spec change and per-deployment
opt-in.

### P4 — Admission and degraded modes (this change)

- `checkBudget`: env override (`OWNMESH_DEGRADED_MODE`) wins; otherwise a
  cached single-row probe decides. Any probe failure degrades to
  `auth_only`.
- `/health/ready` reports `auth_write_ready`, `budget_mode`,
  `budget_reset_at`, `budget_probe_category`, and is 503 while `auth_only`.
- MCP: `read_only` rejects non-read risk classes; `auth_only` additionally
  rejects uncovered reads; room-covered reads stay available. Structured
  codes `OWNMESH_QUOTA_SIDE_EFFECT_DISABLED` /
  `OWNMESH_QUOTA_READ_ONLY_DISABLED`, `retryable: false`, UTC-midnight
  `reset_at`.
- OAuth authorize/token/device-decision endpoints answer 503
  `temporarily_unavailable` + `Retry-After` (UTC-midnight reset) in
  `auth_only`. Status polls stay available.

### Capacity after this change

Measured structure (Free 100,000 rows/day, 30% auth reserve):

| mode | rows/call | calls/day @30% reserve |
| --- | --- | --- |
| D1 before | 35.85 | ~1,950 |
| D1 after P1 | ~12–19 (mix-dependent) | ~3,700–5,800 |
| device_do (room + amortized audit) | ~0 D1 + ~2 room rows | ~30,000+ (D1 holds auth only) |

`device_do` is the supported path past ~5k calls/day. Past ~100k
calls/day (Workers request budget) move to Paid; the room design carries
to the issue's 300k/day operating target by tenant sharding.

## Consequences

- D1-default deployments get ~2–3x headroom plus honest degradation
  instead of mysterious OAuth death. No operator action required.
- `device_do` requires the operator to set the flag, deploy the v3 DO
  migration, enable the cron trigger, record a 24h baseline, then set
  per-tenant cutover cursors (deploy doc has the runbook).
- Audit forensics for room-covered calls moves from `audit_events` to
  operation receipts (`ownmesh_get_operation`); injection attempts and
  auth decisions stay in D1.
- New env surface: `OWNMESH_OPERATION_STORE`, `OWNMESH_DEGRADED_MODE`.
  Both fail safe to current behavior when unset or misspelled.

## Alternatives considered

- Device-sharded rooms (issue sketch): rejected — id-only lookups would
  need a directory write per operation.
- Queues + R2 audit export: rejected for now — forbidden bindings by
  policy test; amortization captures the capacity gain.
- Paid-tier-only fix: rejected — cost scales with the same waste and the
  single-D1 serialization bottleneck remains.
- Global D1 write ledger for admission: rejected — the ledger write
  itself costs budget every call; the probe + static estimates suffice.
