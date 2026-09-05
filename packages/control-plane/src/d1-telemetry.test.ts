/**
 * D1 statement telemetry for Issue #224 (C-1-1, C-1-3).
 *
 * Proves the recorder attributes rows to fixed fingerprints, the statement
 * wrapper observes without changing results or error behavior, and the store
 * hot paths (audit / operation / OAuth bootstrap) emit the expected
 * fingerprints on the same sqlite path used for D1 tests.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  D1_FINGERPRINTS,
  D1TelemetryRecorder,
  extractD1Meta,
  instrumentStatement,
  type D1Fingerprint,
} from "./d1-telemetry.ts";
import { SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";

test("extractD1Meta reads D1-shaped and sqlite-shaped results defensively", () => {
  assert.deepEqual(extractD1Meta({ meta: { rows_read: 12, rows_written: 34, changes: 2 } }), {
    rowsRead: 12,
    rowsWritten: 34,
    changes: 2,
  });
  assert.deepEqual(extractD1Meta({ success: true, meta: { changes: 1 }, results: [] }), {
    rowsRead: 0,
    rowsWritten: 0,
    changes: 1,
  });
  assert.deepEqual(extractD1Meta({ changes: 3 }), { rowsRead: 0, rowsWritten: 0, changes: 3 });
  for (const bad of [null, undefined, 42, "nope", { meta: null }, { meta: { rows_written: -5 } }]) {
    const meta = extractD1Meta(bad);
    assert.ok(meta.rowsRead >= 0 && meta.rowsWritten >= 0 && meta.changes >= 0);
  }
  assert.deepEqual(extractD1Meta({ meta: { rows_read: NaN, rows_written: Infinity } }), {
    rowsRead: 0,
    rowsWritten: 0,
    changes: 0,
  });
});

test("recorder aggregates counts, sums, zero-change writes, and percentiles", () => {
  const recorder = new D1TelemetryRecorder();
  const fp: D1Fingerprint = "audit.append";
  for (let rows = 1; rows <= 10; rows += 1) {
    recorder.record({ fingerprint: fp, ok: true, rowsWritten: rows, changes: 1, isWrite: true });
  }
  recorder.record({ fingerprint: fp, ok: true, changes: 0, isWrite: true });
  recorder.record({ fingerprint: fp, ok: false, isWrite: true, errorCategory: "quota_exceeded" });
  recorder.record({ fingerprint: "audit.compact.lease", ok: true, isWrite: false });

  const snapshot = recorder.snapshot();
  const append = snapshot.fingerprints.find((s) => s.fingerprint === fp);
  assert.ok(append);
  assert.equal(append.statements, 12);
  assert.equal(append.ok, 11);
  assert.equal(append.errors.quota_exceeded, 1);
  assert.equal(append.rowsWritten, 55);
  assert.equal(append.zeroChangeWrites, 1);
  // Samples are [1..10, 0 (zero-change write), 0 (error)]; nearest-rank p50 is 4.
  assert.equal(append.rowsWrittenP50, 4);
  assert.ok(append.rowsWrittenP95 >= append.rowsWrittenP50);
  assert.ok(append.rowsWrittenP99 >= append.rowsWrittenP95);

  const report = recorder.renderBaselineReport();
  assert.match(report, /audit\.append,12,0,55,/);
  assert.match(report, /quota_exceeded|total,/);

  recorder.reset();
  assert.equal(recorder.snapshot().fingerprints.length, 0);
});

test("recorder fingerprint set is fixed and bounded", () => {
  assert.equal(new Set(D1_FINGERPRINTS).size, D1_FINGERPRINTS.length);
  const recorder = new D1TelemetryRecorder();
  for (let i = 0; i < 600; i += 1) {
    recorder.record({ fingerprint: "mcp.operation.update.terminal", ok: true, rowsWritten: i, changes: 1, isWrite: true });
  }
  const summary = recorder.snapshot().fingerprints[0]!;
  assert.equal(summary.statements, 600);
  assert.equal(summary.rowsWritten, (599 * 600) / 2);
});

test("instrumentStatement observes without changing results or errors", async () => {
  const recorder = new D1TelemetryRecorder();
  const seen: unknown[][] = [];
  const inner: SqlStatement = {
    bind(...values: unknown[]) {
      seen.push(values);
      return inner;
    },
    async first<T>() {
      return { row: 1 } as T;
    },
    async run() {
      return { success: true, meta: { rows_read: 2, rows_written: 7, changes: 1 }, results: [] };
    },
    async all<T>() {
      return { results: [{ row: 1 } as T] };
    },
  };
  const wrapped = instrumentStatement(inner, "mcp.operation.get", recorder);
  const first = await wrapped.bind("a", "b").first<{ row: number }>();
  assert.deepEqual(first, { row: 1 });
  assert.deepEqual(seen, [["a", "b"]]);
  const run = await wrapped.run();
  assert.equal((run.meta as { changes: number }).changes, 1);
  const all = await wrapped.all<{ row: number }>();
  assert.deepEqual(all.results, [{ row: 1 }]);

  const snapshot = recorder.snapshot();
  const summary = snapshot.fingerprints.find((s) => s.fingerprint === "mcp.operation.get");
  assert.ok(summary);
  assert.equal(summary.statements, 3);
  assert.equal(summary.rowsWritten, 7);

  const failure = new Error("UNIQUE constraint failed: oauth_tokens.refresh_token_hash");
  const failing = instrumentStatement(
    {
      bind() {
        return this;
      },
      first<T>(): Promise<T | null> {
        throw failure;
      },
      run() {
        throw failure;
      },
      all<T>(): Promise<{ results: T[] }> {
        throw failure;
      },
    },
    "oauth.token.issue",
    recorder,
  );
  await assert.rejects(failing.run(), (error: unknown) => error === failure);
  const failed = recorder.snapshot().fingerprints.find((s) => s.fingerprint === "oauth.token.issue");
  assert.ok(failed);
  assert.equal(failed.errors.constraint_conflict, 1);
});

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

function openSqliteStore(): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, file), "utf8"));
  }
  type SqlVal = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const stmt = db.prepare(query);
      let bound: SqlVal[] = [];
      const api: SqlStatement = {
        bind(...values: unknown[]) {
          bound = values.map((v) => (v === undefined ? null : (v as SqlVal)));
          return api;
        },
        async first<T>(colName?: string) {
          const row = stmt.get(...bound) as Record<string, unknown> | undefined;
          if (!row) return null;
          if (colName) return (row[colName] as T) ?? null;
          return row as T;
        },
        async run() {
          const info = stmt.run(...bound) as { changes: number };
          return { success: true, meta: { changes: info.changes }, results: [] };
        },
        async all<T>() {
          return { results: stmt.all(...bound) as T[] };
        },
      };
      return api;
    },
    exec(query: string) {
      db.exec(query);
    },
    async batch<T>(statements: SqlStatement[]): Promise<T[]> {
      const run = async (): Promise<T[]> => {
        db.exec("BEGIN IMMEDIATE");
        try {
          const results: unknown[] = [];
          for (const statement of statements) results.push(await statement.run());
          db.exec("COMMIT");
          return results as T[];
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      };
      const result = batchTail.then(run, run);
      batchTail = result.then(() => undefined, () => undefined);
      return result;
    },
  };
  return { db, store: new SqlStore(adapter, "sqlite") };
}

test("SqlStore hot paths emit fixed fingerprints without behavior change", async () => {
  const { db, store } = openSqliteStore();
  try {
    await store.ensureBootstrap();
    const stamp = new Date().toISOString();
    await store.appendAudit({
      id: "aud_tel_1",
      tenant_id: "ten_tel",
      kind: "test",
      summary: "telemetry probe",
      created_at: stamp,
    });
    const claimed = await store.claimMcpOperationByIdempotency({
      operation_id: "op_tel_1",
      tenant_id: "ten_tel",
      principal_id: "prin_tel",
      device_id: "dev_tel",
      tool: "ownmesh_fs_stat",
      status: "pending",
      summary: "telemetry probe",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: "op_tel_1",
      idempotency_key: "idem_tel_1",
      policy_authority: "ownmesh_device",
      created_at: stamp,
      updated_at: stamp,
    });
    assert.equal(claimed.outcome, "created");
    const dispatched = await store.updateMcpOperation("op_tel_1", { status: "dispatched" }, ["pending"]);
    assert.ok(dispatched);
    const completed = await store.updateMcpOperation(
      "op_tel_1",
      { status: "completed", summary: "done" },
      ["dispatched"],
    );
    assert.equal(completed?.status, "completed");

    const snapshot = store.getD1TelemetrySnapshot();
    const counts = new Map(snapshot.fingerprints.map((s) => [s.fingerprint, s.statements]));
    for (const fp of [
      "oauth.bootstrap.tenant",
      "oauth.bootstrap.principal",
      "oauth.bootstrap.client",
      "audit.append",
      "mcp.operation.insert",
      "mcp.operation.update.dispatch",
      "mcp.operation.update.terminal",
    ] as D1Fingerprint[]) {
      assert.ok((counts.get(fp) ?? 0) >= 1, `expected fingerprint ${fp}`);
    }
    // Every emitted fingerprint comes from the fixed set (no dynamic keys).
    for (const summary of snapshot.fingerprints) {
      assert.ok((D1_FINGERPRINTS as readonly string[]).includes(summary.fingerprint));
    }
    const report = store.renderD1BaselineReport();
    assert.match(report, /mcp\.operation\.update\.dispatch/);
    assert.match(report, /mcp\.operation\.update\.terminal/);
    assert.match(report, /^total,\d+,\d+,\d+,/m);
    assert.doesNotMatch(report, /telemetry probe/);

    store.resetD1Telemetry();
    assert.equal(store.getD1TelemetrySnapshot().fingerprints.length, 0);
  } finally {
    db.close();
  }
});
