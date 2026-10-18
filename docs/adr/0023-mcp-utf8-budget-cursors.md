# ADR 0023: MCP UTF-8 byte budgets and cursor safety

- Status: Proposed
- Date: 2026-09-08

## Context

MCP list and text helpers previously measured JavaScript UTF-16 string length,
which could exceed a caller's byte budget for non-ASCII data and could split a
surrogate pair. A first item or complete codepoint that cannot fit also needs
an explicit outcome: returning an oversized value violates the budget, while
silently advancing a cursor loses data. Device read results may already carry
an absolute byte cursor that must not be reused after control-plane shrinking.

## Decision

1. Measure JSON list pages and text content with UTF-8 byte length.
2. Truncate text only at complete Unicode codepoints. If an empty prefix is
   the only budget-safe result, return `OWNMESH_E_OUTPUT_BUDGET_TOO_SMALL`
   with bounded `max_bytes` and `required_bytes` details and no cursor.
3. Return the same sanitized error for an oversized first list item or an
   empty page whose JSON framing cannot fit; never advance its cursor.
4. If a device supplied an absolute result cursor and the control plane would
   return fewer bytes, return the budget error rather than a cursor that skips
   unseen data. Completed device results remain completed in the operation
   store, subject to its existing size and retention limits, and can be
   retrieved by operation id.

## Consequences

Clients can increase `max_bytes` for a new page request. For an action that
already completed, poll the operation id included in the sanitized error;
changing the arguments of an idempotency-bound action is not a replay of that
action. Truncation measures wire bytes and never splits a valid surrogate pair.
The explicit error is a public MCP contract and callers must handle it.

## Alternatives considered

- Emit the first oversized item: rejected because it violates the requested
  byte budget.
- Return an empty page and advance the cursor: rejected because it silently
  loses the item.
- Keep UTF-16 offsets: rejected because they do not describe wire bytes and
  can split a Unicode codepoint.
