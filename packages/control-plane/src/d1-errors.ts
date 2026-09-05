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
 */
export function classifyD1Error(error: unknown): D1ErrorCategory {
  const message = messageOf(error).toLowerCase();
  if (
    message.includes("rows written") ||
    message.includes("row limit") ||
    message.includes("daily limit") ||
    message.includes("limit exceeded") ||
    message.includes("quota") ||
    message.includes("too many writes")
  ) {
    return "quota_exceeded";
  }
  if (
    message.includes("sqlite_busy") ||
    message.includes("database is locked") ||
    message.includes("database table is locked") ||
    message.includes("database is busy") ||
    message.includes("timed out") ||
    message.includes("timeout") ||
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
  return "unknown";
}
