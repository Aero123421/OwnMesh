# OwnMesh v1.2.33

OwnMesh v1.2.33 resolves the D1 write-amplification outage class behind
Issue #224: operation, audit, and OAuth traffic no longer share one
unbounded write path, and quota exhaustion degrades explicitly instead of
killing OAuth while health stays green.

The machine-checked shipped contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## D1 write-amplification reduction (plan F P1)

- Status transitions use a narrow compare-and-swap writing only mutable
  result columns; identity and exact-action binding columns are never
  rewritten post-claim.
- Hot OAuth paths verify-then-skip bootstrap with a single read (migration
  `0022_plan_f_p1.sql` seeds the rows); refresh keeps one batch-inner
  receipt cleanup; device-code polls degrade to zero-change conditional
  writes under their interval.
- Retention drains through a scheduled 5-minute cron sweep; request-path
  leases stay as fallback. Every batch stays indexed and capped.
- Five proven-redundant hot indexes are dropped with EXPLAIN proof
  (idempotency lookups state the partial-UNIQUE predicate so the planner
  keeps using them); idempotency, audit-listing, outbox, and retention
  plans stay index-backed with no table scans.

## Tenant OperationRoom authority (plan F P2, opt-in)

- `OperationStore` facade with a behavior-identical D1 adapter (default)
  and a tenant-sharded `OperationRoom` Durable Object behind
  `OWNMESH_OPERATION_STORE=device_do` plus a per-tenant cutover cursor
  (`operation_store_cutover`; value `d1` escapes back).
- Hybrid fallback keeps pre-cutover rows and in-flight transitions visible
  across the cutover; same-key retries converge without double execution.
- Room receipts double as the audit trail for device-routed calls;
  injection attempts and meta tools keep D1 audit rows. Transfers,
  approvals, and local tools stay D1.
- New `OPERATION_ROOM` binding and v3 DO migration; see
  [ADR 0021](./adr/0021-d1-write-amplification-resolution.md) and the
  cutover runbook in [deploy-cloudflare.md](./deploy-cloudflare.md).

## Budget admission and degraded modes (plan F P4)

- A cached single-row write probe drives the budget: any D1 write failure
  degrades to `auth_only`; `OWNMESH_DEGRADED_MODE` overrides manually.
- `/health/ready` reports `auth_write_ready`, `budget_mode`,
  `budget_reset_at`, and `budget_probe_category`, and is 503 while
  `auth_only`.
- MCP gates by risk class with structured non-retryable codes
  (`OWNMESH_QUOTA_SIDE_EFFECT_DISABLED` /
  `OWNMESH_QUOTA_READ_ONLY_DISABLED`) plus UTC-midnight reset; room-covered
  reads stay available.
- OAuth authorize, token (including refresh), device issuance, and device
  decisions answer 503 `temporarily_unavailable` plus `Retry-After` while
  `auth_only`; status polls stay available.

## Connector recovery contract (Issue #227, CI-testable half)

- Quota exhaustion degrades without killing the refresh family; recovery
  needs no connector reinstall and response-loss retries converge.
- Transient 503, `invalid_grant`, and reuse stay distinct; a mid-rotation
  D1 failure throws without revoking the family.
- Same-key retries converge to the one durable operation; manual
  reauthorization keeps prior receipts reachable via `ownmesh_get_operation`.
- Operator recovery table and long-running-work rules are documented in
  [chatgpt-connection.md](./chatgpt-connection.md#recovery-contract-transient-failure-vs-reauth-vs-offline-vs-unknown).

## Cloudflare migration and deployment

- Migration `0022_plan_f_p1.sql` seeds bootstrap rows, drops the five
  redundant indexes, and adds `quota_probe` and `operation_store_cutover`.
- Enable the `triggers.crons` entry for the retention sweep; request-path
  leases cover deployments without cron.
- No R2/queue bindings are added (spec §5.1 fail-closed stands); audit
  amortization captures the capacity gain instead.

## Verification

- 535 control-plane tests (37 new: telemetry, narrow CAS, sweep, probe,
  cutover, room authority, hybrid fallback, budget, recovery contract),
  EXPLAIN proofs for every dropped index, full Rust cross-platform CI,
  dependency audits, SAST, secret scanning, SBOM, and release-quality
  gates are required before publication.
- Capacity figures are projections pending the Gate-1 production baseline;
  the `device_do` cutover runbook requires a 24h baseline first.
