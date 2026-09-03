# ADR 0020: Control-plane acknowledged device receipt reclamation

- Status: Accepted
- Date: 2026-09-03

## Context

The device op journal deliberately refused new side effects at 4096 entries
unless a completed receipt was at least 30 days old. That protected exact-once
execution, but a busy, healthy device could reach the cap much sooner even
though the control plane had already durably stored every terminal result.
Deleting receipts based only on age, socket delivery, or an untrusted message
would weaken replay protection.

Separately, D1 `audit_events` was append-only. Read limits bounded responses but
did not bound retained rows or request cost.

## Decision

1. DeviceRoom advertises `operation_commit_reconcile` only when it supports the
   additive reconciliation exchange.
2. After a terminal result is compare-and-swap persisted to D1, DeviceRoom
   reserves and persists its outbound sequence, then sends an authenticated
   `operation.reconcile` commit acknowledgement to that Agent.
3. To repair old or lost acknowledgements, the Agent pages positively completed
   journal operation ids in batches of at most 64. DeviceRoom performs bounded
   point lookups and returns both the checked page and its terminal subset,
   filtered to the authenticated device and correlated to that exact page.
4. The Agent atomically removes only completed entries whose stored
   `operation_id` is in that terminal subset. It never removes in-progress,
   malformed, forward-version, missing, non-terminal, or foreign-device state.
   A failed local persist rolls the removal back.
5. D1 audit events receive a 30-day default TTL, a 50,000-row default
   per-tenant cap, bounded summaries, an indexed 128-row retention batch, and
   migration-maintained counters. Environment overrides remain bounded by hard
   ceilings.

## Consequences

- A healthy connected device can reclaim committed receipts continuously and
  recover a full journal after upgrade without manual deletion.
- Lost acknowledgements are harmless; reconnect restarts a bounded scan.
- D1 unavailability causes no receipt deletion and the existing fail-closed
  behavior remains intact.
- D1 audit storage and each maintenance invocation are bounded.
