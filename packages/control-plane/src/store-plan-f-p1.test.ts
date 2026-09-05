/**
 * Issue #224 plan F (P1): narrow CAS transitions, seeded bootstrap, retention
 * sweep, write probe, cutover cursor, poll throttle, and post-0022 index proof.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { MemoryStore, SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";
import type { D1Fingerprint } from "./d1-telemetry.ts";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

function openSqliteStore(onPrepare?: (sql: string) => void): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, file), "utf8"));
  }
  type SqlVal = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      onPrepare?.(query);
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

function makeOp(id: string) {
  const stamp = new Date().toISOString();
  return {
    operation_id: id,
    tenant_id: "ten_p1",
    principal_id: "prin_p1",
    device_id: "dev_p1",
    tool: "ownmesh_command_run",
    status: "pending",
    summary: "probe",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: id,
    payload_hash: "ph_probe",
    idempotency_key: `idem_${id}`,
    policy_authority: "ownmesh_device" as const,
    created_at: stamp,
    updated_at: stamp,
  };
}

function fpCounts(store: SqlStore): Map<string, number> {
  return new Map(store.getD1TelemetrySnapshot().fingerprints.map((s) => [s.fingerprint, s.statements]));
}

test("transitionMcpOperation is a narrow CAS preserving identity binding", async () => {
  for (const store of [new MemoryStore(), openSqliteStore().store]) {
    await store.ensureBootstrap();
    await store.putMcpOperation(makeOp("op_narrow_1"));
    const terminal = await store.transitionMcpOperation(
      "op_narrow_1",
      { status: "completed", summary: "done", data: { ok: true } },
      ["pending"],
    );
    assert.ok(terminal);
    assert.equal(terminal.status, "completed");
    assert.equal(terminal.summary, "done");
    assert.equal(terminal.payload_hash, "ph_probe");
    assert.equal(terminal.idempotency_key, "idem_op_narrow_1");
    // Idempotency binding still resolves after the narrow rewrite.
    const owner = await store.getMcpOperationByIdempotency({
      principalId: "prin_p1",
      tenantId: "ten_p1",
      deviceId: "dev_p1",
      idempotencyKey: "idem_op_narrow_1",
    });
    assert.equal(owner?.operation_id, "op_narrow_1");
    // CAS loss returns null instead of overwriting.
    assert.equal(
      await store.transitionMcpOperation("op_narrow_1", { status: "failed" }, ["pending"]),
      null,
    );
    assert.equal((await store.getMcpOperation("op_narrow_1"))?.status, "completed");
    assert.equal(await store.transitionMcpOperation("op_missing", { status: "failed" }), null);
    if (store instanceof SqlStore) {
      const counts = fpCounts(store);
      assert.ok((counts.get("mcp.operation.update.terminal") ?? 0) >= 1);
    }
  }
});

test("ensureBootstrapSeeded skips writes on a migrated store", async () => {
  const { store } = openSqliteStore();
  await store.ensureBootstrapSeeded();
  const counts = fpCounts(store);
  assert.ok((counts.get("oauth.bootstrap.check") ?? 0) >= 1);
  assert.equal(counts.get("oauth.bootstrap.tenant") ?? 0, 0);
  assert.equal(counts.get("oauth.bootstrap.principal") ?? 0, 0);
  assert.equal(counts.get("oauth.bootstrap.client") ?? 0, 0);
  // Dogfood the fallback: without seed rows the full bootstrap runs.
  const { store: bare } = openSqliteStore();
  bare.resetD1Telemetry();
  assert.equal((await bare.getClient("client_ownmesh_cli"))?.client_id, "client_ownmesh_cli");
});

test("runRetentionSweep drains TTL backlog with bounded stats", async () => {
  const mem = new MemoryStore();
  await mem.ensureBootstrap();
  const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
  await mem.appendAudit({ id: "aud_old_1", tenant_id: "ten_sweep", kind: "test", summary: "expired", created_at: new Date().toISOString() });
  await mem.putMcpOperation({ ...makeOp("op_sweep_1"), tenant_id: "ten_sweep", status: "completed" });
  // Age the rows past TTL without tripping the inline request-path prune.
  const memAudit = mem.audits.find((entry) => entry.id === "aud_old_1")!;
  memAudit.created_at = old;
  const memOp = mem.mcpOperations.get("op_sweep_1")!;
  memOp.created_at = old;
  memOp.updated_at = old;
  const memStats = await mem.runRetentionSweep({ tenantLimit: 8 });
  assert.ok(memStats.tenantsSwept >= 1);
  assert.ok(memStats.auditDeleted >= 1, JSON.stringify(memStats));
  assert.ok(memStats.operationsDeleted + memStats.operationsCompacted >= 1, JSON.stringify(memStats));
  assert.equal((await mem.listAudit("ten_sweep", 10)).length, 0);

  const { db, store } = openSqliteStore();
  try {
    await store.ensureBootstrap();
    const now = new Date().toISOString();
    await store.appendAudit({ id: "aud_old_1", tenant_id: "ten_sweep", kind: "test", summary: "expired", created_at: now });
    await store.putMcpOperation({ ...makeOp("op_sweep_1"), tenant_id: "ten_sweep", status: "completed" });
    // Simulate an aged backlog: backdate rows and release both leases.
    db.prepare(`UPDATE audit_events SET created_at = ? WHERE id = 'aud_old_1'`).run(old);
    db.prepare(`UPDATE audit_event_tenant_counters SET maintenance_after = '1970-01-01T00:00:00.000Z' WHERE tenant_id = 'ten_sweep'`).run();
    db.prepare(`UPDATE mcp_operations SET created_at = ?, updated_at = ? WHERE operation_id = 'op_sweep_1'`).run(old, old);
    db.prepare(`UPDATE mcp_operation_tenant_counters SET maintenance_after = '1970-01-01T00:00:00.000Z' WHERE tenant_id = 'ten_sweep'`).run();
    const stats = await store.runRetentionSweep({ tenantLimit: 8 });
    assert.ok(stats.tenantsSwept >= 1);
    assert.ok(stats.auditDeleted >= 1, JSON.stringify(stats));
    assert.ok(stats.operationsDeleted + stats.operationsCompacted >= 1, JSON.stringify(stats));
    assert.equal((await store.listAudit("ten_sweep", 10)).length, 0);
    const second = await store.runRetentionSweep({ tenantLimit: 8 });
    assert.equal(second.auditDeleted, 0);
    assert.equal(second.operationsDeleted, 0);
    assert.equal(second.operationsCompacted, 0);
  } finally {
    db.close();
  }
});

test("probeWriteReadiness and cutover cursor round-trip", async () => {
  const { store: sqlStore } = openSqliteStore();
  for (const store of [new MemoryStore(), sqlStore]) {
    assert.deepEqual(await store.probeWriteReadiness(), { ok: true });
    assert.equal(await store.getOperationStoreCutover("ten_cut"), null);
    await store.setOperationStoreCutover("ten_cut", "2026-09-06T00:00:00.000Z");
    assert.equal(await store.getOperationStoreCutover("ten_cut"), "2026-09-06T00:00:00.000Z");
  }
  const counts = fpCounts(sqlStore);
  assert.ok((counts.get("quota.probe") ?? 0) >= 1);
  assert.ok((counts.get("store.cutover.get") ?? 0) >= 1);
  assert.ok((counts.get("store.cutover.set") ?? 0) >= 1);
});

test("markDeviceCodePolled throttles sub-interval polls without a write", async () => {
  const { db, store } = openSqliteStore();
  try {
    await store.ensureBootstrap();
    await store.putDeviceCode({
      device_code: "dc_poll_1",
      user_code: "POLL-0001",
      client_id: "client_ownmesh_cli",
      scope: "ownmesh.read",
      verification_uri: "https://cp.test/oauth/device",
      interval_sec: 5,
      expires_at: Date.now() + 60_000,
      status: "pending",
    });
    await store.markDeviceCodePolled("dc_poll_1", 60_000);
    const first = (await store.getDeviceCode("dc_poll_1"))?.last_polled_at ?? 0;
    assert.ok(first > 0);
    await store.markDeviceCodePolled("dc_poll_1", 60_000);
    assert.equal((await store.getDeviceCode("dc_poll_1"))?.last_polled_at, first);
    await store.markDeviceCodePolled("dc_poll_1", 0);
  } finally {
    db.close();
  }
  const mem = new MemoryStore();
  await mem.putDeviceCode({
    device_code: "dc_poll_2",
    user_code: "POLL-0002",
    client_id: "c",
    scope: "s",
    verification_uri: "https://cp.test/d",
    interval_sec: 5,
    expires_at: Date.now() + 60_000,
    status: "pending",
  });
  await mem.markDeviceCodePolled("dc_poll_2", 60_000);
  const memFirst = (await mem.getDeviceCode("dc_poll_2"))?.last_polled_at ?? 0;
  await mem.markDeviceCodePolled("dc_poll_2", 60_000);
  assert.equal((await mem.getDeviceCode("dc_poll_2"))?.last_polled_at, memFirst);
});

test("0022 index drops keep every hot lookup indexed (no SCAN)", async () => {
  const issuedSql: string[] = [];
  const { db, store } = openSqliteStore((sql) => {
    issuedSql.push(sql);
  });
  try {
    await store.ensureBootstrap();
    // Prove the planner against the statements the store REALLY issues, not
    // hand-written copies: EXPLAIN the captured lookup verbatim.
    await store.putMcpOperation({
      operation_id: "op_idx_1",
      tenant_id: "ten_idx",
      principal_id: "prin_idx",
      device_id: "dev_idx",
      tool: "ownmesh_fs_stat",
      status: "completed",
      summary: "index probe",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: "op_idx_1",
      payload_hash: "ph_idx",
      idempotency_key: "idem_idx_1",
      policy_authority: "ownmesh_device",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    const found = await store.getMcpOperationByIdempotency({
      principalId: "prin_idx",
      tenantId: "ten_idx",
      deviceId: "dev_idx",
      idempotencyKey: "idem_idx_1",
    });
    assert.equal(found?.operation_id, "op_idx_1");
    const lookupSql = issuedSql.find((sql) => sql.includes("FROM mcp_operations") && sql.includes("idempotency_key = ?"));
    assert.ok(lookupSql, "idempotency lookup must be issued");
    const livePlan = (
      db.prepare(`EXPLAIN QUERY PLAN ${lookupSql}`).all("prin_idx", "ten_idx", "dev_idx", "k") as Array<{
        detail: string;
      }>
    )
      .map((row) => row.detail)
      .join("\n");
    assert.match(livePlan, /uq_mcp_ops_idempotency/);
    assert.doesNotMatch(livePlan, /SCAN mcp_operations/);
    const plan = (sql: string, ...params: Array<string | number>) =>
      (db.prepare(`EXPLAIN QUERY PLAN ${sql}`).all(...params) as Array<{ detail: string }>)
        .map((row) => row.detail)
        .join("\n");
    // Idempotency equality is served by the partial UNIQUE indexes (the
    // explicit length() predicate lets the planner prove the partial index).
    const idem = plan(
      `SELECT * FROM mcp_operations WHERE principal_id = ? AND tenant_id = ? AND device_id = ? AND idempotency_key = ? AND length(idempotency_key) > 0 ORDER BY created_at DESC LIMIT 1`,
      "p",
      "t",
      "d",
      "k",
    );
    assert.match(idem, /uq_mcp_ops_idempotency/);
    assert.doesNotMatch(idem, /SCAN mcp_operations/);
    const idemNoDevice = plan(
      `SELECT * FROM mcp_operations WHERE principal_id = ? AND tenant_id = ? AND device_id IS NULL AND idempotency_key = ? AND length(idempotency_key) > 0 ORDER BY created_at DESC LIMIT 1`,
      "p",
      "t",
      "k",
    );
    assert.match(idemNoDevice, /uq_mcp_ops_idempotency/);
    assert.doesNotMatch(idemNoDevice, /SCAN mcp_operations/);
    // Audit listing is served by the retention index (dropped idx_audit_tenant).
    const audit = plan(
      `SELECT id FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?`,
      "t",
      50,
    );
    assert.match(audit, /idx_audit_events_retention/);
    assert.doesNotMatch(audit, /SCAN audit_events/);
    // Outbox by operation_id uses the UNIQUE autoindex (dropped idx_mcp_outbox_op).
    const outbox = plan(`SELECT id FROM mcp_approval_outbox WHERE operation_id = ?`, "o");
    assert.match(outbox, /sqlite_autoindex/);
    assert.doesNotMatch(outbox, /SCAN mcp_approval_outbox/);
    // Retention batches use the 0019 partial indexes (dropped idx_mcp_ops_updated).
    const retention = plan(
      `SELECT operation_id FROM mcp_operations WHERE tenant_id = ? AND status = 'tombstone' AND updated_at < ? ORDER BY updated_at, operation_id LIMIT ?`,
      "t",
      new Date().toISOString(),
      128,
    );
    assert.match(retention, /idx_mcp_ops_tombstone_expiry/);
    assert.doesNotMatch(retention, /SCAN mcp_operations/);
    // Dropped indexes are really gone.
    const names = (
      db.prepare(`SELECT name FROM sqlite_master WHERE type = 'index'`).all() as Array<{ name: string }>
    ).map((row) => row.name);
    for (const dropped of [
      "idx_mcp_ops_payload_hash",
      "idx_mcp_ops_idempotency",
      "idx_mcp_outbox_op",
      "idx_audit_tenant",
      "idx_mcp_ops_updated",
    ]) {
      assert.ok(!names.includes(dropped), `${dropped} must be dropped by 0022`);
    }
  } finally {
    db.close();
  }
});

test("healthy refresh performs the single batch-inner receipt cleanup", async () => {
  const { store } = openSqliteStore();
  await store.ensureBootstrap();
  const issued = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");
  const rotated = await store.rotateRefresh(issued.refresh_token);
  assert.equal(rotated.ok, true);
  const counts = fpCounts(store);
  // The per-request outer cleanup is gone; cleanup lives in the rotate batch.
  assert.equal(counts.get("oauth.refresh.receipt_cleanup") ?? 0, 0);
  assert.ok((counts.get("oauth.token.rotate_batch") ?? 0) >= 1);
  const fps = [...counts.keys()] as D1Fingerprint[];
  assert.ok(fps.length > 0);
});
