/**
 * D1 statement telemetry for Issue #224 (C-1-1, C-1-3).
 *
 * Records per-statement `rows_read` / `rows_written` / `changes` against a
 * FIXED fingerprint set so a 24h baseline can attribute billed D1 rows to
 * audit / operation / OAuth paths without changing storage behavior.
 *
 * Privacy boundaries (per AGENTS.md and the telemetry default-off rule):
 * - keys are fixed fingerprints only; SQL text, bind values, token hashes,
 *   principal/device IDs, commands, paths, and result bodies are NEVER stored.
 * - in-memory only; nothing is sent to Cloudflare Logs/Analytics or any
 *   external sink by this module. Quota enforcement counters live in durable
 *   storage owned by a later PR, never here.
 * - all allocations are bounded: fixed fingerprint map + capped sample rings.
 */

import { classifyD1Error, type D1ErrorCategory } from "./d1-errors.ts";

/** Fixed D1 statement fingerprints. Additions require a code change + test. */
export const D1_FINGERPRINTS = [
  "oauth.bootstrap.tenant",
  "oauth.bootstrap.principal",
  "oauth.bootstrap.client",
  "oauth.bootstrap.check",
  "oauth.authorize_tx.insert",
  "oauth.authorize_tx.consume",
  "oauth.code.insert",
  "oauth.code.read",
  "oauth.code.redeem",
  "oauth.token.issue",
  "oauth.token.read",
  "oauth.token.rotate_batch",
  "oauth.token.reuse_revoke",
  "oauth.token.ledger_read",
  "oauth.token.ledger_write",
  "oauth.token.revoke",
  "oauth.refresh.receipt_cleanup",
  "oauth.refresh.receipt_read",
  "audit.append",
  "audit.append.conflict_check",
  "audit.compact.lease",
  "audit.retention.delete",
  "audit.compact.lease_reset",
  "mcp.compact.lease",
  "mcp.retention.delete",
  "mcp.retention.compact",
  "mcp.retention.lease_reset",
  "mcp.retention.delete_one",
  "mcp.operation.insert",
  "mcp.operation.get",
  "mcp.operation.lookup",
  "mcp.operation.update.dispatch",
  "mcp.operation.update.terminal",
  "mcp.operation.update.cancel",
  "mcp.operation.update.other",
  "approval.transaction.insert",
  "approval.transaction.consume",
  "approval.transaction.get",
  "approval.outbox.batch",
  "approval.outbox.get",
  "approval.outbox.claim",
  "approval.outbox.release",
  "approval.outbox.attempt",
  "approval.outbox.deliver",
  "quota.probe",
  "retention.sweep.receipts",
  "store.cutover.get",
  "store.cutover.set",
] as const;

export type D1Fingerprint = (typeof D1_FINGERPRINTS)[number];

/** Bounded sample ring per fingerprint for p50/p95/p99. */
const ROWS_WRITTEN_SAMPLE_CAP = 256;

export type D1StatementOutcome = {
  fingerprint: D1Fingerprint;
  ok: boolean;
  rowsRead?: number;
  rowsWritten?: number;
  changes?: number;
  durationMs?: number;
  /** True for run()/batch (writes); false for first()/all() (reads). */
  isWrite?: boolean;
  errorCategory?: D1ErrorCategory;
};

export type D1FingerprintSummary = {
  fingerprint: D1Fingerprint;
  statements: number;
  ok: number;
  errors: Record<D1ErrorCategory, number>;
  rowsRead: number;
  rowsWritten: number;
  changes: number;
  zeroChangeWrites: number;
  durationMsTotal: number;
  rowsWrittenAvg: number;
  rowsWrittenP50: number;
  rowsWrittenP95: number;
  rowsWrittenP99: number;
};

export type D1TelemetrySnapshot = {
  recordedAt: string;
  fingerprints: D1FingerprintSummary[];
};

function toNonNegativeInt(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.min(Math.floor(n), Number.MAX_SAFE_INTEGER);
}

/** Defensively read D1Result.meta without trusting its shape. */
export function extractD1Meta(result: unknown): {
  rowsRead: number;
  rowsWritten: number;
  changes: number;
} {
  if (!result || typeof result !== "object") return { rowsRead: 0, rowsWritten: 0, changes: 0 };
  const meta = (result as { meta?: unknown }).meta;
  const changes = toNonNegativeInt((result as { changes?: unknown }).changes);
  if (!meta || typeof meta !== "object") return { rowsRead: 0, rowsWritten: 0, changes };
  const m = meta as Record<string, unknown>;
  return {
    rowsRead: toNonNegativeInt(m.rows_read ?? m.rowsRead),
    rowsWritten: toNonNegativeInt(m.rows_written ?? m.rowsWritten),
    changes: toNonNegativeInt(m.changes ?? changes),
  };
}

function emptyErrors(): Record<D1ErrorCategory, number> {
  return {
    quota_exceeded: 0,
    transient_unavailable: 0,
    schema_missing: 0,
    constraint_conflict: 0,
    invalid_query: 0,
    unknown: 0,
  };
}

type FingerprintBucket = {
  statements: number;
  ok: number;
  errors: Record<D1ErrorCategory, number>;
  rowsRead: number;
  rowsWritten: number;
  changes: number;
  zeroChangeWrites: number;
  durationMsTotal: number;
  samples: number[];
};

function percentile(sorted: number[], p: number): number {
  if (sorted.length === 0) return 0;
  const rank = Math.min(sorted.length - 1, Math.max(0, Math.ceil((p / 100) * sorted.length) - 1));
  return sorted[rank] ?? 0;
}

export class D1TelemetryRecorder {
  private readonly buckets = new Map<D1Fingerprint, FingerprintBucket>();

  record(outcome: D1StatementOutcome): void {
    let bucket = this.buckets.get(outcome.fingerprint);
    if (!bucket) {
      bucket = {
        statements: 0,
        ok: 0,
        errors: emptyErrors(),
        rowsRead: 0,
        rowsWritten: 0,
        changes: 0,
        zeroChangeWrites: 0,
        durationMsTotal: 0,
        samples: [],
      };
      this.buckets.set(outcome.fingerprint, bucket);
    }
    const rowsRead = toNonNegativeInt(outcome.rowsRead);
    const rowsWritten = toNonNegativeInt(outcome.rowsWritten);
    const changes = toNonNegativeInt(outcome.changes);
    const durationMs = toNonNegativeInt(outcome.durationMs);
    bucket.statements += 1;
    bucket.rowsRead += rowsRead;
    bucket.rowsWritten += rowsWritten;
    bucket.changes += changes;
    bucket.durationMsTotal += durationMs;
    if (outcome.ok) {
      bucket.ok += 1;
      if (outcome.isWrite && changes === 0) bucket.zeroChangeWrites += 1;
    } else {
      bucket.errors[outcome.errorCategory ?? "unknown"] += 1;
    }
    if (bucket.samples.length >= ROWS_WRITTEN_SAMPLE_CAP) bucket.samples.shift();
    bucket.samples.push(rowsWritten);
  }

  recordBatchResult(
    fingerprint: D1Fingerprint,
    results: unknown,
    durationMs: number,
  ): void {
    let rowsRead = 0;
    let rowsWritten = 0;
    let changes = 0;
    if (Array.isArray(results)) {
      for (const result of results) {
        const meta = extractD1Meta(result);
        rowsRead += meta.rowsRead;
        rowsWritten += meta.rowsWritten;
        changes += meta.changes;
      }
    }
    this.record({ fingerprint, ok: true, rowsRead, rowsWritten, changes, durationMs, isWrite: true });
  }

  recordBatchError(fingerprint: D1Fingerprint, error: unknown, durationMs: number): void {
    this.record({
      fingerprint,
      ok: false,
      durationMs,
      isWrite: true,
      errorCategory: classifyD1Error(error),
    });
  }

  reset(): void {
    this.buckets.clear();
  }

  snapshot(): D1TelemetrySnapshot {
    const fingerprints: D1FingerprintSummary[] = [];
    for (const [fingerprint, bucket] of this.buckets) {
      const sorted = [...bucket.samples].sort((a, b) => a - b);
      fingerprints.push({
        fingerprint,
        statements: bucket.statements,
        ok: bucket.ok,
        errors: { ...bucket.errors },
        rowsRead: bucket.rowsRead,
        rowsWritten: bucket.rowsWritten,
        changes: bucket.changes,
        zeroChangeWrites: bucket.zeroChangeWrites,
        durationMsTotal: bucket.durationMsTotal,
        rowsWrittenAvg: bucket.statements === 0 ? 0 : bucket.rowsWritten / bucket.statements,
        rowsWrittenP50: percentile(sorted, 50),
        rowsWrittenP95: percentile(sorted, 95),
        rowsWrittenP99: percentile(sorted, 99),
      });
    }
    fingerprints.sort((a, b) => b.rowsWritten - a.rowsWritten || b.statements - a.statements);
    return { recordedAt: new Date().toISOString(), fingerprints };
  }

  /**
   * Baseline report for Issue #224 Gate 1: fingerprint,count,
   * sum_rows_read,sum_rows_written,avg,p50,p95,p99,zero_change,errors.
   * Contains fingerprint names and numbers only — no request content.
   */
  renderBaselineReport(): string {
    const snapshot = this.snapshot();
    const lines = [
      "# D1 statement baseline (fingerprint,count,rows_read,rows_written,avg,p50,p95,p99,zero_change_writes,errors)",
      `recorded_at=${snapshot.recordedAt}`,
    ];
    let totalStatements = 0;
    let totalRowsRead = 0;
    let totalRowsWritten = 0;
    let totalErrors = 0;
    for (const summary of snapshot.fingerprints) {
      totalStatements += summary.statements;
      totalRowsRead += summary.rowsRead;
      totalRowsWritten += summary.rowsWritten;
      const errorTotal =
        summary.errors.quota_exceeded +
        summary.errors.transient_unavailable +
        summary.errors.schema_missing +
        summary.errors.constraint_conflict +
        summary.errors.invalid_query +
        summary.errors.unknown;
      totalErrors += errorTotal;
      lines.push(
        `${summary.fingerprint},${summary.statements},${summary.rowsRead},${summary.rowsWritten},` +
          `${summary.rowsWrittenAvg.toFixed(2)},${summary.rowsWrittenP50},${summary.rowsWrittenP95},` +
          `${summary.rowsWrittenP99},${summary.zeroChangeWrites},${errorTotal}`,
      );
    }
    lines.push(`total,${totalStatements},${totalRowsRead},${totalRowsWritten},,,, ,,${totalErrors}`);
    return `${lines.join("\n")}\n`;
  }
}

/**
 * Structural subset of the store's SqlStatement so this module stays
 * dependency-free (no import cycle with store.ts). Observation only:
 * errors are classified, recorded, and rethrown unchanged.
 */
export interface InstrumentedStatementSource {
  bind(...values: unknown[]): InstrumentedStatementSource;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  run<T = Record<string, unknown>>(): Promise<{
    success?: boolean;
    meta?: unknown;
    results?: T[];
  }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
}

export function instrumentStatement<TStmt extends InstrumentedStatementSource>(
  inner: TStmt,
  fingerprint: D1Fingerprint,
  recorder: D1TelemetryRecorder,
): TStmt {
  const api: InstrumentedStatementSource = {
    bind(...values: unknown[]): InstrumentedStatementSource {
      inner.bind(...values);
      return api;
    },
    async first<T = Record<string, unknown>>(colName?: string): Promise<T | null> {
      const start = Date.now();
      try {
        const row = await inner.first<T>(colName);
        recorder.record({ fingerprint, ok: true, durationMs: Date.now() - start, isWrite: false });
        return row;
      } catch (error) {
        recorder.record({
          fingerprint,
          ok: false,
          durationMs: Date.now() - start,
          isWrite: false,
          errorCategory: classifyD1Error(error),
        });
        throw error;
      }
    },
    async run<T = Record<string, unknown>>(): Promise<{
      success?: boolean;
      meta?: unknown;
      results?: T[];
    }> {
      const start = Date.now();
      try {
        const result = await inner.run<T>();
        const meta = extractD1Meta(result);
        recorder.record({
          fingerprint,
          ok: true,
          rowsRead: meta.rowsRead,
          rowsWritten: meta.rowsWritten,
          changes: meta.changes,
          durationMs: Date.now() - start,
          isWrite: true,
        });
        return result;
      } catch (error) {
        recorder.record({
          fingerprint,
          ok: false,
          durationMs: Date.now() - start,
          isWrite: true,
          errorCategory: classifyD1Error(error),
        });
        throw error;
      }
    },
    async all<T = Record<string, unknown>>(): Promise<{ results: T[] }> {
      const start = Date.now();
      try {
        const result = await inner.all<T>();
        const meta = extractD1Meta(result);
        recorder.record({
          fingerprint,
          ok: true,
          rowsRead: meta.rowsRead,
          rowsWritten: meta.rowsWritten,
          changes: meta.changes,
          durationMs: Date.now() - start,
          isWrite: false,
        });
        return result;
      } catch (error) {
        recorder.record({
          fingerprint,
          ok: false,
          durationMs: Date.now() - start,
          isWrite: false,
          errorCategory: classifyD1Error(error),
        });
        throw error;
      }
    },
  };
  return api as TStmt;
}
