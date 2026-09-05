/**
 * D1 write-budget admission and degraded modes for Issue #224 (P4).
 *
 * The #224 outage was operation traffic exhausting the shared account-level
 * D1 write budget, after which even OAuth authorize transactions failed while
 * /health stayed green. This module gives that failure a name, a probe, and
 * explicit degradation semantics:
 *
 * - normal: everything allowed.
 * - read_only (operator override): side-effect tools rejected with a
 *   structured, non-retryable-until-reset error; reads attempted.
 * - auth_only (probe-detected D1 write exhaustion or operator override):
 *   MCP calls fail fast without attempting D1 writes (except room-covered
 *   reads); OAuth authorize/token endpoints answer 503 with Retry-After.
 *
 * No new durable state: the probe is one single-row upsert cached briefly
 * per isolate, and Retry-After always points at the next UTC midnight (the
 * D1 daily-budget reset). Nothing secret-bearing is ever returned.
 */

import type { D1ErrorCategory } from "./d1-errors.ts";
import type { ControlPlaneStore } from "./store.ts";

export type BudgetMode = "normal" | "read_only" | "auth_only";

export type BudgetState = {
  mode: BudgetMode;
  /** Why this mode holds: operator override, live probe, or default. */
  source: "env" | "probe" | "default";
  /** Next UTC midnight: when a quota-driven mode may lift. */
  resetAt: string;
  checkedAt: number;
  probeCategory?: D1ErrorCategory;
};

/** Operator override; unknown values are ignored (fail safe to probe). */
export function resolveBudgetOverride(env: { OWNMESH_DEGRADED_MODE?: string }): BudgetMode | null {
  const raw = (env.OWNMESH_DEGRADED_MODE || "").trim().toLowerCase();
  if (raw === "read_only" || raw === "auth_only") return raw;
  if (raw === "normal" || raw === "") return null;
  return null;
}

/** Seconds from now until the next UTC midnight (D1 budget reset). */
export function secondsUntilUtcReset(nowMs = Date.now()): number {
  const now = new Date(nowMs);
  const reset = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1);
  return Math.max(0, Math.floor((reset - nowMs) / 1000));
}

export function utcResetIso(nowMs = Date.now()): string {
  const now = new Date(nowMs);
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1)).toISOString();
}

const BUDGET_CACHE_TTL_MS = 30_000;
type BudgetCacheEntry = { at: number; state: BudgetState };
const budgetCache = new WeakMap<object, BudgetCacheEntry>();
/** Concurrent checks share one probe (mirrors schemaReadinessFor). */
const budgetPending = new WeakMap<object, { at: number; pending: Promise<BudgetState> }>();

function budgetCacheKey(store: ControlPlaneStore, env: object): object {
  return (env as { DB?: object }).DB || store;
}

/**
 * Current budget mode. Env override wins; otherwise a cached single-row D1
 * write probe decides. Any probe failure degrades to auth_only (D1 cannot
 * take writes, and MCP requires durable writes), with the raw category kept
 * for readiness reporting only.
 */
export async function checkBudget(
  store: ControlPlaneStore,
  env: { OWNMESH_DEGRADED_MODE?: string; DB?: object },
  nowMs = Date.now(),
): Promise<BudgetState> {
  const override = resolveBudgetOverride(env);
  if (override) {
    return {
      mode: override,
      source: "env",
      resetAt: utcResetIso(nowMs),
      checkedAt: nowMs,
    };
  }
  const key = budgetCacheKey(store, env);
  const cached = budgetCache.get(key);
  if (cached && nowMs - cached.at < BUDGET_CACHE_TTL_MS) return cached.state;
  const inflight = budgetPending.get(key);
  if (inflight && nowMs - inflight.at < BUDGET_CACHE_TTL_MS) return inflight.pending;
  const pending = (async (): Promise<BudgetState> => {
    let state: BudgetState;
    try {
      const probe = await store.probeWriteReadiness();
      state = probe.ok
        ? { mode: "normal", source: "probe", resetAt: utcResetIso(nowMs), checkedAt: nowMs }
        : {
          mode: "auth_only",
          source: "probe",
          resetAt: utcResetIso(nowMs),
          checkedAt: nowMs,
          probeCategory: probe.category,
        };
    } catch {
      state = {
        mode: "auth_only",
        source: "probe",
        resetAt: utcResetIso(nowMs),
        checkedAt: nowMs,
        probeCategory: "unknown",
      };
    }
    budgetCache.set(key, { at: Date.now(), state });
    return state;
  })();
  budgetPending.set(key, { at: nowMs, pending });
  try {
    return await pending;
  } finally {
    if (budgetPending.get(key)?.pending === pending) budgetPending.delete(key);
  }
}
