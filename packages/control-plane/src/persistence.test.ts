/**
 * Proves D1 migrations apply on real SQLite and that token/device/revoke
 * persist via the same SQL store path used with Workers D1 bindings.
 *
 * D1 API: https://developers.cloudflare.com/d1/worker-api/
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { handleMcp, OperationTracker, type OperationRouter } from "./mcp.ts";
import {
  AUDIT_MAX_PER_TENANT_DEFAULT,
  AUDIT_MAX_PER_TENANT_HARD_CEILING,
  AUDIT_RETENTION_DAYS_DEFAULT,
  AUDIT_RETENTION_DAYS_HARD_CEILING,
  MemoryStore,
  parseAuditMaxPerTenant,
  parseAuditRetentionDays,
  SqlStore,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { encodeDevicePublicKey } from "./store.ts";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

/** Adapt node:sqlite to the D1-like SqlDatabase interface. */
function openSqliteStore(
  mcpOpsMaxPerTenant?: number,
  auditMaxPerTenant?: number,
  auditRetentionDays?: number,
): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const f of files) {
    const sql = readFileSync(join(migrationsDir, f), "utf8");
    db.exec(sql);
  }

  type SqlVal = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const stmt = db.prepare(query);
      let bound: SqlVal[] = [];
      const api: SqlStatement = {
        bind(...values: unknown[]) {
          bound = values.map((v) =>
            v === undefined ? null : (v as SqlVal),
          );
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
          const rows = stmt.all(...bound) as T[];
          return { results: rows };
        },
      };
      return api;
    },
    exec(query: string) {
      db.exec(query);
    },
    async batch<T>(statements: SqlStatement[]): Promise<T[]> {
      // Mirror D1 atomic batch via a real SQLite transaction (production path).
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

  const store = new SqlStore(adapter, "sqlite", {
    mcpOpsMaxPerTenant,
    auditMaxPerTenant,
    auditRetentionDays,
  });
  return { db, store };
}

test("all control-plane migrations apply cleanly on sqlite", () => {
  const { db } = openSqliteStore();
  const tables = db
    .prepare(
      `SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`,
    )
    .all() as { name: string }[];
  const names = tables.map((t) => t.name);
  for (const need of [
    "tenants",
    "principals",
    "oauth_clients",
    "oauth_tokens",
    "devices",
    "grants",
    "audit_events",
    "oauth_auth_codes",
    "device_codes",
    "used_refresh_tokens",
    "enrollment_challenges",
    "device_credentials",
    "device_verification_transactions",
    "revoked_refresh_families",
    "schema_migrations",
    "mcp_operation_tenant_counters",
    "audit_event_tenant_counters",
  ]) {
    assert.ok(names.includes(need), `missing table ${need}`);
  }
});

test("audit retention is indexed, bounded by TTL, and fails closed at tenant quota", async () => {
  const { db, store } = openSqliteStore(undefined, 2, 1);
  try {
    const stale = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(
      `INSERT INTO audit_events
       (id, tenant_id, principal_id, device_id, kind, summary, created_at)
       VALUES ('aud_stale', 'ten_audit', NULL, NULL, 'test', 'stale', ?)`,
    ).run(stale);
    const plan = (
      db.prepare(
        `EXPLAIN QUERY PLAN
         SELECT id FROM audit_events
         WHERE tenant_id = ? AND created_at < ?
         ORDER BY created_at, id LIMIT ?`,
      ).all("ten_audit", new Date().toISOString(), 128) as Array<{ detail: string }>
    ).map((row) => row.detail).join("\n");
    assert.match(plan, /idx_audit_events_retention/);
    assert.doesNotMatch(plan, /SCAN audit_events/);

    const append = (id: string) => store.appendAudit({
      id,
      tenant_id: "ten_audit",
      kind: "test",
      summary: id,
      created_at: new Date().toISOString(),
    });
    await append("aud_1");
    await append("aud_2");
    assert.equal(
      (db.prepare("SELECT COUNT(*) AS c FROM audit_events WHERE tenant_id = 'ten_audit'")
        .get() as { c: number }).c,
      2,
      "expired event must be pruned before admission",
    );
    await assert.rejects(append("aud_over"), /audit_event_quota_exceeded/);

    db.prepare("DELETE FROM audit_events WHERE id = 'aud_1'").run();
    await append("aud_3");
    const counter = db.prepare(
      "SELECT event_count FROM audit_event_tenant_counters WHERE tenant_id = 'ten_audit'",
    ).get() as { event_count: number };
    assert.equal(counter.event_count, 2);
  } finally {
    db.close();
  }
});

test("audit bounds apply to MemoryStore and invalid overrides use finite defaults", async () => {
  assert.equal(parseAuditRetentionDays("bad"), AUDIT_RETENTION_DAYS_DEFAULT);
  assert.equal(parseAuditRetentionDays(0), AUDIT_RETENTION_DAYS_DEFAULT);
  assert.equal(
    parseAuditRetentionDays(AUDIT_RETENTION_DAYS_HARD_CEILING + 1),
    AUDIT_RETENTION_DAYS_HARD_CEILING,
  );
  assert.equal(parseAuditMaxPerTenant("bad"), AUDIT_MAX_PER_TENANT_DEFAULT);
  assert.equal(parseAuditMaxPerTenant(0), AUDIT_MAX_PER_TENANT_DEFAULT);
  assert.equal(
    parseAuditMaxPerTenant(AUDIT_MAX_PER_TENANT_HARD_CEILING + 1),
    AUDIT_MAX_PER_TENANT_HARD_CEILING,
  );

  const store = new MemoryStore({ auditMaxPerTenant: 1, auditRetentionDays: 1 });
  await store.appendAudit({
    id: "aud_old",
    tenant_id: "ten_memory",
    kind: "test",
    summary: "old",
    created_at: new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString(),
  });
  await store.appendAudit({
    id: "aud_current",
    tenant_id: "ten_memory",
    kind: "test",
    summary: "x".repeat(10_000),
    created_at: new Date().toISOString(),
  });
  assert.equal((await store.listAudit("ten_memory", 10)).length, 1);
  assert.ok((await store.listAudit("ten_memory", 1))[0]!.summary.length <= 4_096);
  await assert.rejects(
    store.appendAudit({
      id: "aud_over",
      tenant_id: "ten_memory",
      kind: "test",
      summary: "over",
      created_at: new Date().toISOString(),
    }),
    /audit_event_quota_exceeded/,
  );
});

test("MCP admission and retention plans stay index-backed at 10k and 20k rows", async () => {
  const plans: string[] = [];
  for (const size of [10_000, 20_000]) {
    const { db, store } = openSqliteStore(size);
    try {
      const stamp = new Date().toISOString();
      db.prepare(
        `WITH RECURSIVE seq(n) AS (
           SELECT 1 UNION ALL SELECT n + 1 FROM seq WHERE n < ?
         )
         INSERT INTO mcp_operations
           (operation_id, tenant_id, principal_id, device_id, tool, status, summary,
            data_json, truncated, approval_required, warnings_json, correlation_id,
            idempotency_key, created_at, updated_at)
         SELECT printf('op_fixture_%05d', n), 'ten_fixture', 'prin_fixture', 'dev_fixture',
                'ownmesh_fs_stat', 'completed', 'fixture', '{}', 0, 0, '[]',
                printf('cor_fixture_%05d', n), printf('idem_fixture_%05d', n), ?, ?
         FROM seq`,
      ).run(size, stamp, stamp);

      const quota = await store.getMcpOperationQuota("ten_fixture");
      assert.equal(quota.rows, size);
      assert.equal(quota.limit, size);

      const detail = (
        db.prepare(
          `EXPLAIN QUERY PLAN
           SELECT * FROM mcp_operations
           WHERE principal_id = ? AND tenant_id = ? AND device_id = ?
             AND idempotency_key = ?
           ORDER BY created_at DESC LIMIT 1`,
        ).all("prin_fixture", "ten_fixture", "dev_fixture", "idem_fixture_00001") as Array<{
          detail: string;
        }>
      ).map((row) => row.detail).join("\n");
      assert.match(detail, /uq_mcp_ops_idempotency|idx_mcp_ops_idempotency/);
      assert.doesNotMatch(detail, /SCAN mcp_operations/);

      const retention = (
        db.prepare(
          `EXPLAIN QUERY PLAN
           SELECT operation_id FROM mcp_operations
           WHERE tenant_id = ? AND status = 'tombstone' AND updated_at < ?
           ORDER BY updated_at, operation_id LIMIT ?`,
        ).all("ten_fixture", stamp, 128) as Array<{ detail: string }>
      ).map((row) => row.detail).join("\n");
      assert.match(retention, /idx_mcp_ops_tombstone_expiry/);
      assert.doesNotMatch(retention, /SCAN mcp_operations/);
      plans.push(detail.replace(/\d+/g, "#"), retention.replace(/\d+/g, "#"));

      await assert.rejects(
        store.claimMcpOperationByIdempotency({
          operation_id: `op_over_${size}`,
          tenant_id: "ten_fixture",
          principal_id: "prin_fixture",
          device_id: "dev_fixture",
          tool: "ownmesh_fs_stat",
          status: "pending",
          summary: "must fail closed at quota",
          data: {},
          truncated: false,
          next_cursor: null,
          approval_required: false,
          warnings: [],
          correlation_id: `op_over_${size}`,
          idempotency_key: `idem_over_${size}`,
          policy_authority: "ownmesh_device",
          created_at: stamp,
          updated_at: stamp,
        }),
        /mcp_operation_quota_exceeded/,
      );

      db.prepare("DELETE FROM mcp_operations WHERE operation_id = ?")
        .run("op_fixture_00001");
      const afterDelete = db.prepare(
        `SELECT operation_count FROM mcp_operation_tenant_counters WHERE tenant_id = ?`,
      ).get("ten_fixture") as { operation_count: number };
      assert.equal(afterDelete.operation_count, size - 1);
    } finally {
      db.close();
    }
  }
  assert.equal(plans[0], plans[2], "10k and 20k idempotency plans must match");
  assert.equal(plans[1], plans[3], "10k and 20k retention plans must match");
});

test("SqlStore public transfer list returns the same owner-visible operation ids as status", async () => {
  const { db, store } = openSqliteStore();
  try {
    await store.ensureBootstrap();
    const token = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read ownmesh.write");
    for (const id of ["dev_source", "dev_destination"]) {
      await store.putDevice({ id, tenant_id: "ten_default", principal_id: "prin_dev", name: id, hostname: id, os: "test", arch: "test", agent_version: "test", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked: false, created_at: new Date().toISOString(), status: "active" });
    }
    await store.putWorkspace({ workspace_id: "ws_source", tenant_id: "ten_default", device_id: "dev_source", owner_principal_id: "prin_dev", version: 1, local_generation: "wsg_11111111111111111111111111111111", active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    await store.putWorkspace({ workspace_id: "ws_destination", tenant_id: "ten_default", device_id: "dev_destination", owner_principal_id: "prin_dev", version: 1, local_generation: "wsg_22222222222222222222222222222222", active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() });
    const router: OperationRouter = {
      async routeToDevice() { return { status: "routed_to_device" }; },
      async routeLiveToDevice() { return { status: "routed_to_device" }; },
    };
    const invoke = async (name: string, args: Record<string, unknown>) => {
      const request = new Request("https://cp.test/mcp", {
        method: "POST",
        headers: { authorization: `Bearer ${token.access_token}`, "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
      });
      const response = await handleMcp(request, store, new URL("https://cp.test/mcp"), router, {
        tracker: new OperationTracker(),
        transferTicketSecret: "sql-transfer-list-secret",
      });
      return await response.json() as { result?: { structuredContent?: { operation_id: string; data: Record<string, unknown>; next_cursor?: string | null } } };
    };

    const ids: string[] = [];
    for (let index = 0; index < 4; index += 1) {
      const created = await invoke("ownmesh_transfer_plan", {
        source_device_id: "dev_source",
        destination_device_id: "dev_destination",
        source_workspace_id: "ws_source",
        destination_workspace_id: "ws_destination",
        source_path: `in/${index}.bin`,
        destination_path: `out/${index}.bin`,
        idempotency_key: `sql-list-${index}`,
      });
      const transferId = created.result!.structuredContent!.operation_id;
      ids.push(transferId);
      const status = await invoke("ownmesh_transfer_status", { transfer_id: transferId });
      assert.equal(status.result!.structuredContent!.operation_id, transferId);
    }
    const sameCreatedAt = "2026-08-10T12:00:00.000Z";
    for (const id of ids) {
      db.prepare("UPDATE mcp_operations SET created_at = ? WHERE operation_id = ?")
        .run(sameCreatedAt, id);
    }
    const template = await store.getMcpOperation(ids[0]);
    assert.ok(template);
    const foreignRows = [
      { operationId: "op_sql_foreign_principal", tenantId: "ten_default", principalId: "prin_foreign" },
      { operationId: "op_sql_foreign_tenant", tenantId: "ten_foreign", principalId: "prin_dev" },
    ];
    for (const foreign of foreignRows) {
      const meta = template.data.__ownmesh_transfer_plan as Record<string, unknown>;
      await store.putMcpOperation({
        ...template,
        operation_id: foreign.operationId,
        correlation_id: foreign.operationId,
        tenant_id: foreign.tenantId,
        principal_id: foreign.principalId,
        idempotency_key: foreign.operationId,
        data: {
          ...template.data,
          __ownmesh_transfer_plan: {
            ...meta,
            transfer_id: foreign.operationId,
            tenant_id: foreign.tenantId,
            principal_id: foreign.principalId,
          },
        },
        created_at: sameCreatedAt,
        updated_at: sameCreatedAt,
      });
    }
    const foreignBefore = await Promise.all(
      foreignRows.map((foreign) => store.getMcpOperation(foreign.operationId)),
    );
    const first = await invoke("ownmesh_transfer_list", { limit: 2 });
    const firstContent = first.result!.structuredContent!;
    assert.equal(firstContent.next_cursor, "cur_2");
    const second = await invoke("ownmesh_transfer_list", {
      limit: 2,
      cursor: firstContent.next_cursor,
    });
    const combined = [
      ...(firstContent.data.transfers as Array<Record<string, unknown>>),
      ...(second.result!.structuredContent!.data.transfers as Array<Record<string, unknown>>),
    ].map((entry) => String(entry.operation_id));
    assert.deepEqual(combined, [...ids].sort().reverse());
    assert.equal(new Set(combined).size, ids.length, "pagination must not duplicate or omit");
    for (const foreign of foreignRows) assert.equal(combined.includes(foreign.operationId), false);
    assert.deepEqual(
      await Promise.all(foreignRows.map((foreign) => store.getMcpOperation(foreign.operationId))),
      foreignBefore,
      "foreign principal/tenant rows must not be reconciled or rewritten",
    );
  } finally {
    db.close();
  }
});

test("SqlStore atomically updates only owned, active device metadata", async () => {
  const { db, store } = openSqliteStore();
  try {
    await store.ensureBootstrap();
    await store.putDevice({
      id: "dev_sql_metadata",
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      name: "before",
      labels: [],
      hostname: "sql-host",
      os: "test",
      arch: "test",
      agent_version: "test",
      protocol_version: "ownmesh.device/1.0",
      public_key: "ab".repeat(32),
      revoked: false,
      created_at: new Date().toISOString(),
      status: "active",
    });

    const updated = await store.updateDeviceMetadata(
      "dev_sql_metadata",
      "prin_dev",
      { name: "after", labels: ["linux", "gpu"] },
    );
    assert.equal(updated?.name, "after");
    assert.deepEqual(updated?.labels, ["linux", "gpu"]);

    assert.equal(
      await store.updateDeviceMetadata("dev_sql_metadata", "prin_foreign", { name: "stolen" }),
      null,
    );
    assert.equal((await store.getDevice("dev_sql_metadata"))?.name, "after");

    assert.equal(await store.revokeDevice("dev_sql_metadata", "prin_dev"), true);
    assert.equal(
      await store.updateDeviceMetadata("dev_sql_metadata", "prin_dev", { name: "revived" }),
      null,
    );
    assert.equal((await store.getDevice("dev_sql_metadata"))?.name, "after");
  } finally {
    db.close();
  }
});

test("sql store persists tokens, devices, revoke across store instances", async () => {
  const { db, store } = openSqliteStore();
  await store.ensureBootstrap();
  await store.markMigration("0001_init.sql");
  await store.markMigration("0002_oauth_device_enrollment.sql");
  await store.markMigration("0003_control_plane_p0.sql");

  const tok = await store.issueTokens(
    "client_ownmesh_cli",
    "prin_dev",
    "ownmesh.read ownmesh.device offline_access",
  );
  assert.ok(tok.access_token.startsWith("atk_"));
  assert.ok(await store.getAccess(tok.access_token));

  await store.putDevice({
    id: "dev_persist01abcdef",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    name: "laptop",
    hostname: "laptop",
    os: "linux",
    arch: "x64",
    agent_version: "1.0.1",
    protocol_version: "ownmesh.device/1.0",
    public_key: encodeDevicePublicKey("ab".repeat(32), {
      hostname: "laptop",
      os: "linux",
      arch: "x64",
      agent_version: "1.0.1",
    }),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  });

  // New store handle on same DB = "new isolate" persistence proof
  type SqlVal = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const stmt = db.prepare(query);
      let bound: SqlVal[] = [];
      const api: SqlStatement = {
        bind(...values: unknown[]) {
          bound = values.map((v) =>
            v === undefined ? null : (v as SqlVal),
          );
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
          return { success: true, meta: { changes: info.changes } };
        },
        async all<T>() {
          return { results: stmt.all(...bound) as T[] };
        },
      };
      return api;
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
  const store2 = new SqlStore(adapter, "sqlite");
  assert.ok(await store2.getAccess(tok.access_token));
  const devices = await store2.listDevices("prin_dev");
  assert.equal(devices.length, 1);
  assert.equal(devices[0]!.id, "dev_persist01abcdef");
  assert.equal(devices[0]!.os, "linux");

  await store2.revokeToken(tok.access_token);
  assert.equal(await store2.getAccess(tok.access_token), null);

  assert.equal(await store2.revokeDevice("dev_persist01abcdef", "prin_dev"), true);
  assert.equal((await store2.listDevices("prin_dev")).length, 0);

  const applied = await store2.appliedMigrations();
  assert.ok(applied.includes("0001_init.sql"));
  assert.ok(applied.includes("0002_oauth_device_enrollment.sql"));
  assert.ok(applied.includes("0003_control_plane_p0.sql"));
});

test("sql store refresh rotation + reuse detection persists", async () => {
  const { store } = openSqliteStore();
  await store.ensureBootstrap();
  const first = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const rotated = await store.rotateRefresh(first.refresh_token);
  assert.equal(rotated.ok, true);
  if (!rotated.ok) return;
  const reuse = await store.rotateRefresh(first.refresh_token);
  assert.equal(reuse.ok, false);
  if (!reuse.ok) assert.equal(reuse.error, "reuse");
  assert.equal(await store.getAccess(rotated.token.access_token), null);
});

test("sql store expired refresh is invalid_grant", async () => {
  const { store, db } = openSqliteStore();
  await store.ensureBootstrap();
  const first = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read offline_access");
  const { sha256Hex } = await import("./util.ts");
  const hash = await sha256Hex(first.refresh_token);
  db.prepare(`UPDATE oauth_tokens SET refresh_expires_at = ? WHERE refresh_token_hash = ?`).run(
    new Date(Date.now() - 5_000).toISOString(),
    hash,
  );
  const expired = await store.rotateRefresh(first.refresh_token);
  assert.equal(expired.ok, false);
  if (!expired.ok) assert.equal(expired.error, "invalid_grant");
});
