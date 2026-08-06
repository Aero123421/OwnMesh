/** Timestamp / expiry helpers aligned with Rust `ownmesh-domain`. */

import { SchemaError } from "./ids.ts";

/** Default clock skew allowance in milliseconds (60s). */
export const DEFAULT_CLOCK_SKEW_MS = 60_000;

export function parseTimestamp(raw: string): Date {
  const ms = Date.parse(raw);
  if (Number.isNaN(ms)) {
    throw new SchemaError(
      "OWNMESH_E_INVALID_ARGUMENT",
      `invalid RFC3339 timestamp '${raw}'`,
    );
  }
  return new Date(ms);
}

/** Format a Date as RFC3339 UTC with `Z` and no milliseconds when zero. */
export function formatTimestamp(date: Date): string {
  const iso = date.toISOString();
  // toISOString always has `.sssZ`; strip `.000` for fixture stability.
  return iso.replace(/\.000Z$/, "Z");
}

export function isExpiredAt(
  expiresAt: string | Date,
  now: string | Date,
  skewMs: number = DEFAULT_CLOCK_SKEW_MS,
): boolean {
  const expMs =
    typeof expiresAt === "string" ? parseTimestamp(expiresAt).getTime() : expiresAt.getTime();
  const nowMs = typeof now === "string" ? parseTimestamp(now).getTime() : now.getTime();
  return nowMs >= expMs + skewMs;
}

export function checkExpiryAt(
  expiresAt: string | Date,
  now: string | Date,
  skewMs: number = DEFAULT_CLOCK_SKEW_MS,
): void {
  if (isExpiredAt(expiresAt, now, skewMs)) {
    throw new SchemaError(
      "OWNMESH_E_EXPIRED",
      `expired at ${typeof expiresAt === "string" ? expiresAt : formatTimestamp(expiresAt)}`,
    );
  }
}
