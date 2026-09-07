/**
 * D1 / SQLite error classification.
 *
 * Issue #224 (C-1-2): quota exhaustion must be distinguishable from a real
 * database outage so a later change can reserve OAuth budget and serve a
 * distinct readiness state. This module only classifies; it never logs or
 * returns raw error text, bind values, tokens, or principal/device IDs.
 *
 * Fail-closed: anything unrecognized is `unknown`. Callers must treat
 * `unknown` as an error, never as success.
 */

export type D1ErrorCategory =
  | "quota_exceeded"
  | "transient_unavailable"
  | "schema_missing"
  | "constraint_conflict"
  | "invalid_query"
  | "unknown";

function messageOf(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) {
    const code = (error as { code?: unknown }).code;
    const codeText = typeof code === "string" || typeof code === "number" ? ` [${code}]` : "";
    return `${error.name}: ${error.message}${codeText}`;
  }
  try {
    const message = (error as { message?: unknown } | null)?.message;
    if (typeof message === "string" && message.length > 0) return message;
    return String(error);
  } catch {
    return "unknown error";
  }
}

/**
 * Classify a caught storage error from a fixed set of message patterns.
 *
 * Patterns are intentionally generic: D1 surfaces quota/busy errors with
 * evolving text, so an unrecognized message falls through to `unknown`
 * (fail-closed) instead of being misreported.
 *
 * Bare-word guards (Issue #227 SHOULD): never match lone `quota` / `timeout`
 * substrings — validation messages, option names (`timeout_ms`), or user
 * content can contain those words without any storage failure. Only compound
 * storage phrases (e.g. `quota exceeded`, `timed out`, `database timeout`)
 * classify; anything else stays `unknown` and callers rethrow fail-closed.
 */
export function classifyD1Error(error: unknown): D1ErrorCategory {
  const message = messageOf(error).toLowerCase();
  if (
    message.includes("rows written") ||
    message.includes("row limit") ||
    message.includes("daily limit") ||
    message.includes("limit exceeded") ||
    message.includes("quota exceeded") ||
    message.includes("quota exhausted") ||
    message.includes("quota limit") ||
    message.includes("exceeds quota") ||
    message.includes("over quota") ||
    message.includes("too many writes")
  ) {
    return "quota_exceeded";
  }
  if (
    message.includes("sqlite_busy") ||
    message.includes("database is locked") ||
    message.includes("database table is locked") ||
    message.includes("database is busy") ||
    // Word-boundary timeout phrases only: `\b` prevents `timeout_ms` option
    // names or validation text (`request timeout_ms invalid`) from
    // misclassifying as a storage outage. Bare `timeout` is never matched.
    /\btimed out\b/.test(message) ||
    /\bdatabase timeout\b/.test(message) ||
    /\bquery timeout\b/.test(message) ||
    /\bstatement timeout\b/.test(message) ||
    /\brequest timeout\b/.test(message) ||
    message.includes("temporarily unavailable") ||
    message.includes("service unavailable") ||
    message.includes("econnreset") ||
    message.includes("etimedout") ||
    message.includes("overloaded")
  ) {
    return "transient_unavailable";
  }
  if (
    message.includes("no such table") ||
    message.includes("no such column") ||
    message.includes("no such index") ||
    message.includes("missing table") ||
    message.includes("unknown column")
  ) {
    return "schema_missing";
  }
  if (
    message.includes("unique constraint failed") ||
    message.includes("primary key") ||
    message.includes("foreign key constraint failed") ||
    message.includes("check constraint failed") ||
    message.includes("constraint failed")
  ) {
    return "constraint_conflict";
  }
  if (
    message.includes("syntax error") ||
    message.includes("malformed") ||
    message.includes("bind parameter") ||
    message.includes("wrong number of") ||
    message.includes("datatype mismatch")
  ) {
    return "invalid_query";
  }
  // Generic D1 identity fallback: a bare `D1_ERROR` / `D1DatabaseError` /
  // `D1 database` prefix without a more specific phrase above is a transient
  // outage (e.g. `D1_ERROR: database unavailable` in fault-injection tests).
  // Placed after constraint/invalid_query so a D1-wrapped logic bug (e.g.
  // `D1_ERROR: UNIQUE constraint failed`) still classifies precisely.
  if (
    message.includes("d1_error") ||
    message.includes("d1databaseerror") ||
    message.includes("d1 database")
  ) {
    return "transient_unavailable";
  }
  return "unknown";
}

/**
 * Issue #227 SHOULD-1: single retryable-storage predicate.
 *
 * Retryable means the operation may succeed after the D1 daily-budget reset
 * without credential rotation: `quota_exceeded` / `transient_unavailable` /
 * `schema_missing`. `constraint_conflict` and `invalid_query` are caller bugs
 * (never retryable), and `unknown` stays fail-closed (rethrow, never 503).
 * All OAuth/MCP/index storage guards must use this instead of ad-hoc
 * `timeout`/`quota` substring regexes.
 */
export function isRetryableStorageError(error: unknown): boolean {
  const category = classifyD1Error(error);
  return (
    category === "quota_exceeded" ||
    category === "transient_unavailable" ||
    category === "schema_missing"
  );
}

/**
 * Issue #227 SHOULD-5: single reason classifier for degraded 503 envelopes.
 * OAuth and MCP share the reason vocabulary; only the fallthrough differs
 * because the transports differ (OAuth REST `temporarily_unavailable` vs
 * MCP JSON-RPC `operation_store_unavailable`). Envelope shapes stay separate
 * (see oauth.ts `oauthUnavailableEnvelope`, mcp.ts `mcpUnavailableData`).
 */
export function storageUnavailableReason(
  category: D1ErrorCategory,
  surface: "oauth" | "mcp",
): string {
  if (category === "quota_exceeded") return "d1_write_quota_exceeded";
  if (category === "transient_unavailable") return "d1_unavailable";
  if (category === "schema_missing") return "schema_not_ready";
  return surface === "mcp" ? "operation_store_unavailable" : "oauth_temporarily_unavailable";
}
