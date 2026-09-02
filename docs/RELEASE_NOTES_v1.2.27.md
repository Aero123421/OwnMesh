# OwnMesh v1.2.27

OwnMesh v1.2.27 hardens the self-hosted Cloudflare control plane after a
production D1 daily-limit outage. MCP operation admission, retention, waits,
and uncertain delivery recovery now have explicit per-request bounds while
preserving exact-action authorization and replay protection.

The machine-checked shipped contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json); this
release changes availability and cost behavior, not the admitted tool surface.

## Cloudflare cost and availability

- Replaced request-path `COUNT(*)` and tenant-wide operation cleanup with a
  transactionally maintained per-tenant counter and three partial-index-backed
  retention batches of at most 128 rows.
- Admission is one atomic SQLite statement, so concurrent claims cannot exceed
  `MCP_OPS_MAX_PER_TENANT`. Existing idempotency receipts continue to win even
  at capacity, and unexpired receipts are never evicted.
- Rewrote idempotency lookup as indexable equality predicates and added an exact
  unique binding for operations without a device.
- Replaced 100 ms `wait_ms` polling with a strict two-read exponential/deadline
  fallback. A 25-second wait no longer issues roughly 250 D1 reads.
- Recognized D1 runtime failures now return a sanitized retryable HTTP 503 for
  OAuth, MCP, API, and Agent connection paths instead of an uncaught Worker
  1101 page.

## Delivery and reconnect recovery

- `dispatch_uncertain` rows use a durable compare-and-swap retry lease,
  exponential equal jitter, and a five-attempt ceiling. `ownmesh_get_operation`
  can recover delivery without replaying the original tool call.
- Every retry rechecks the original OAuth client and scope, current principal
  revocation authority, operation expiry, and cancellation fence; DeviceRoom
  still performs the final authoritative deduplication and dispatch check.
- Long-running command correlation now covers the admitted command timeout plus
  one minute of result-delivery grace. Detached work retains the 24-hour cap.
- Agent reconnect backoff now applies full jitter to avoid a synchronized surge
  when Cloudflare recovers.

## Verification

- SQLite migration tests load both 10,000-row and 20,000-row fixtures and prove
  identical index-backed query plans for idempotency and retention.
- Regression coverage enforces the wait read budget, atomic quota failure,
  counter maintenance, status-driven retry leasing, long-command TTL, sanitized
  outage responses, and jitter bounds.
- Wrangler is updated to 4.128.0 with current Workers types and compatibility
  date 2026-08-28. Persistent Workers observability remains disabled by default;
  operators may opt in using the query-safe recipe in the deployment guide.

This release closes GitHub issues #194, #201, #202, and #206.
