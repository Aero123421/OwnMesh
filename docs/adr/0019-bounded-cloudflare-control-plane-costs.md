# ADR 0019: Bound Cloudflare control-plane cost by request

- Status: Accepted
- Date: 2026-09-02

## Context

The production `mcp_operations` claim path performed tenant-wide deletion,
compaction, and `COUNT(*)` work before each insert. Cost therefore grew with
retained history and exhausted the account-wide D1 daily row-read allowance,
which in turn surfaced as an uncaught Worker 1101 on OAuth and Agent paths.
`ownmesh_get_operation(wait_ms)` also queried D1 every 100 ms, and an uncertain
DeviceRoom delivery required replaying the original tool call.

These are availability defects, but the repair must not weaken exact-action
binding, replay protection, cancellation fences, retention, or the per-tenant
admission cap.

## Decision

1. A deployment-time migration backfills one per-tenant operation counter.
   SQLite triggers maintain it in the same statement transaction as every
   operation insert, delete, or tenant move.
2. Admission is one `INSERT ... SELECT`: its counter predicate, operation
   insert, uniqueness checks, and counter increment are atomic. A rejected
   insert is resolved by point lookups and otherwise fails closed as quota
   exhaustion. Request-path `COUNT(*)` is forbidden.
3. Retention uses a per-tenant maintenance lease and three partial-index-backed
   batches of at most 128 rows. Work is amortized across requests and can never
   scale with table cardinality in one invocation.
4. Idempotency lookup uses equality predicates matching the unique indexes.
   Device-less bindings have a dedicated partial unique index because SQLite
   otherwise treats `NULL` values as distinct.
5. MCP waits use a strict two-read exponential/deadline fallback instead of a
   100 ms loop. Cross-isolate notification is not assumed.
6. `dispatch_uncertain` recovery uses a durable data compare-and-swap lease,
   exponential equal-jitter backoff, five attempts, the immutable outbox body,
   original OAuth client/scope checks, current principal authority, and a final
   cancellation observation before DeviceRoom applies its own dispatch fence.
   Status polling can drive recovery without replaying the original tool call.
7. Non-detached command correlation lives for at least the admitted command
   timeout plus a bounded one-minute result grace. Detached work keeps its
   existing 24-hour cap.
8. Recognized D1 runtime failures return sanitized `503 storage_unavailable`
   with `Retry-After` instead of exposing a Worker exception page. Unknown
   exceptions remain uncaught so programming defects are not misclassified.
9. Agent reconnect uses bounded full jitter. Observability persistence remains
   opt-in in the operator's Cloudflare account; OAuth query-bearing invocation
   logs are not enabled by the shipped default.

## Consequences

- Normal operation claims and waits have cost independent of retained row
  count. At the retention boundary, a claim remains within eight D1 statements.
- Concurrent admission is exact and cannot overrun the configured tenant cap.
- Retention backlog drains in bounded batches over subsequent tenant traffic.
- Recovery may wait until the next jittered retry time and stops after five
  attempts; it never reconstructs or mutates an authorized action.
- A D1 outage remains unavailable and fail-closed, but OAuth and Agent callers
  receive a retryable protocol response rather than Cloudflare 1101 HTML.

## Alternatives rejected

- Raising D1 quotas or shortening retention only postpones table-size
  amplification and can weaken replay protection.
- A cached `COUNT(*)` outside the database transaction admits races above the
  cap.
- A cron-only cleanup leaves the hot-path count scan and creates synchronized
  maintenance spikes.
- Keeping 100 ms polling or unrestricted redelivery violates per-invocation and
  daily budgets.
- Enabling persistent invocation logs by default conflicts with OwnMesh's
  privacy contract and can retain OAuth callback query parameters.
