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
import { SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";
import { encodeDevicePublicKey } from "./store.ts";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

/** Adapt node:sqlite to the D1-like SqlDatabase interface. */
function openSqliteStore(): { db: DatabaseSync; store: SqlStore } {
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

  const store = new SqlStore(adapter, "sqlite");
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
  ]) {
    assert.ok(names.includes(need), `missing table ${need}`);
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
  db.prepare(`UPDATE oauth_tokens SET expires_at = ? WHERE refresh_token_hash = ?`).run(
    new Date(Date.now() - 5_000).toISOString(),
    hash,
  );
  const expired = await store.rotateRefresh(first.refresh_token);
  assert.equal(expired.ok, false);
  if (!expired.ok) assert.equal(expired.error, "invalid_grant");
});
