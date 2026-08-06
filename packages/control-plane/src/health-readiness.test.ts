/**
 * Health + migration readiness: never synthesize applied migrations;
 * probe required P0/MCP schema and return 503 when absent.
 * SESSION_SECRET must be bound for /health 200.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import worker, { __setTestStore } from "./index.ts";
import {
  MemoryStore,
  SqlStore,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";

const ctx = {} as ExecutionContext;
const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");
const TEST_SESSION_SECRET = "test-session-secret-health-readiness";

type SqlVal = null | number | string | bigint | Uint8Array;

function adaptSqlite(db: DatabaseSync): SqlDatabase {
  return {
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
  };
}

function applyMigrations(db: DatabaseSync, files: string[]): void {
  for (const f of files) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
}

function allMigrationFiles(): string[] {
  return readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
}

function openStoreWith(files: string[]): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  applyMigrations(db, files);
  return { db, store: new SqlStore(adaptSqlite(db), "sqlite") };
}

/** Minimal DurableObjectNamespace stub so /health can see DEVICE_ROOM bound. */
function fakeDeviceRoom(): DurableObjectNamespace {
  return {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: async () => new Response(null, { status: 204 }),
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function readyEnv(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    DEVICE_ROOM: fakeDeviceRoom(),
    SESSION_SECRET: TEST_SESSION_SECRET,
    ...extra,
  };
}

const MCP_SCHEMA_KEYS = [
  "mcp_operations",
  "mcp_approval_transactions",
  "mcp_approval_outbox",
] as const;

const P0_SCHEMA_KEYS = [
  "devices_status",
  "revoked_refresh_families",
  "device_credentials",
  "device_verification_transactions",
  "authorize_transactions",
] as const;

test("empty schema_migrations is not fabricated on /v1/migrations/status", async () => {
  const store = new MemoryStore();
  // Intentionally do not markMigration — applied must stay [].
  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/v1/migrations/status"),
      {},
      ctx,
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      applied: string[];
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
      store_kind: string;
    };
    assert.deepEqual(body.applied, []);
    assert.equal(body.schema_ready, true);
    assert.equal(body.store_kind, "memory");
    for (const k of P0_SCHEMA_KEYS) assert.equal(body.schema_checks[k], true);
    for (const k of MCP_SCHEMA_KEYS) assert.equal(body.schema_checks[k], true);
  } finally {
    __setTestStore(null);
  }
});

test("sqlite DB missing P0 schema → /health 503 with schema_ready:false", async () => {
  // Only 0001_init: devices has no status; P0 tables absent.
  const { store } = openStoreWith(["0001_init.sql"]);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  for (const k of P0_SCHEMA_KEYS) assert.equal(readiness.checks[k], false);
  for (const k of MCP_SCHEMA_KEYS) assert.equal(readiness.checks[k], false);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      readyEnv(),
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      status: string;
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
      session_secret_bound: boolean;
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.status, "not_ready");
    assert.equal(body.session_secret_bound, true);
    for (const k of P0_SCHEMA_KEYS) assert.equal(body.schema_checks[k], false);
    for (const k of MCP_SCHEMA_KEYS) assert.equal(body.schema_checks[k], false);

    const mig = await worker.fetch(
      new Request("https://cp.test/v1/migrations/status"),
      {},
      ctx,
    );
    const migBody = (await mig.json()) as {
      applied: string[];
      schema_ready: boolean;
    };
    // schema_migrations table may not exist yet → empty, never synthesized.
    assert.deepEqual(migBody.applied, []);
    assert.equal(migBody.schema_ready, false);
  } finally {
    __setTestStore(null);
  }
});

test("full schema → /health 200 with schema_ready:true; MemoryStore ready", async () => {
  const mem = new MemoryStore();
  const memReady = await mem.schemaReadiness();
  assert.equal(memReady.schema_ready, true);
  for (const k of P0_SCHEMA_KEYS) assert.equal(memReady.checks[k], true);
  for (const k of MCP_SCHEMA_KEYS) assert.equal(memReady.checks[k], true);

  __setTestStore(mem);
  try {
    const memHealth = await worker.fetch(
      new Request("https://cp.test/health"),
      readyEnv(),
      ctx,
    );
    assert.equal(memHealth.status, 200);
    const memBody = (await memHealth.json()) as {
      schema_ready: boolean;
      status: string;
      durable_objects: boolean;
      session_secret_bound: boolean;
      schema_checks: Record<string, boolean>;
    };
    assert.equal(memBody.schema_ready, true);
    assert.equal(memBody.status, "ok");
    assert.equal(memBody.durable_objects, true);
    assert.equal(memBody.session_secret_bound, true);
    for (const k of MCP_SCHEMA_KEYS) assert.equal(memBody.schema_checks[k], true);
  } finally {
    __setTestStore(null);
  }

  const files = allMigrationFiles();
  const { store } = openStoreWith(files);
  // Record real migration rows only — no synthesis path.
  for (const f of files) await store.markMigration(f);

  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, true);
  for (const k of P0_SCHEMA_KEYS) assert.equal(readiness.checks[k], true);
  for (const k of MCP_SCHEMA_KEYS) assert.equal(readiness.checks[k], true);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      readyEnv(),
      ctx,
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      status: string;
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
      durable_objects: boolean;
      session_secret_bound: boolean;
    };
    assert.equal(body.status, "ok");
    assert.equal(body.schema_ready, true);
    assert.equal(body.schema_checks.authorize_transactions, true);
    assert.equal(body.schema_checks.mcp_operations, true);
    assert.equal(body.schema_checks.mcp_approval_transactions, true);
    assert.equal(body.schema_checks.mcp_approval_outbox, true);
    assert.equal(body.durable_objects, true);
    assert.equal(body.session_secret_bound, true);

    const mig = await worker.fetch(
      new Request("https://cp.test/v1/migrations/status"),
      {},
      ctx,
    );
    assert.equal(mig.status, 200);
    const migBody = (await mig.json()) as {
      applied: string[];
      schema_ready: boolean;
    };
    assert.deepEqual(migBody.applied, files);
    assert.equal(migBody.schema_ready, true);
  } finally {
    __setTestStore(null);
  }
});

test("schema ready but DEVICE_ROOM absent → /health 503 not_ready", async () => {
  const mem = new MemoryStore();
  assert.equal((await mem.schemaReadiness()).schema_ready, true);

  __setTestStore(mem);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      { SESSION_SECRET: TEST_SESSION_SECRET }, // no DEVICE_ROOM
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      status: string;
      schema_ready: boolean;
      durable_objects: boolean;
      session_secret_bound: boolean;
    };
    assert.equal(body.status, "not_ready");
    assert.equal(body.schema_ready, true);
    assert.equal(body.durable_objects, false);
    assert.equal(body.session_secret_bound, true);
  } finally {
    __setTestStore(null);
  }

  const files = allMigrationFiles();
  const { store } = openStoreWith(files);
  for (const f of files) await store.markMigration(f);
  assert.equal((await store.schemaReadiness()).schema_ready, true);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      { SESSION_SECRET: TEST_SESSION_SECRET }, // schema ready, DEVICE_ROOM unbound
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      status: string;
      schema_ready: boolean;
      durable_objects: boolean;
    };
    assert.equal(body.status, "not_ready");
    assert.equal(body.schema_ready, true);
    assert.equal(body.durable_objects, false);
  } finally {
    __setTestStore(null);
  }
});

test("schema ready but SESSION_SECRET unbound → /health 503 not_ready", async () => {
  const mem = new MemoryStore();
  assert.equal((await mem.schemaReadiness()).schema_ready, true);

  __setTestStore(mem);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      { DEVICE_ROOM: fakeDeviceRoom() }, // no SESSION_SECRET
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      status: string;
      schema_ready: boolean;
      session_secret_bound: boolean;
      durable_objects: boolean;
    };
    assert.equal(body.status, "not_ready");
    assert.equal(body.schema_ready, true);
    assert.equal(body.session_secret_bound, false);
    assert.equal(body.durable_objects, true);
  } finally {
    __setTestStore(null);
  }

  const files = allMigrationFiles();
  const { store } = openStoreWith(files);
  for (const f of files) await store.markMigration(f);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      { DEVICE_ROOM: fakeDeviceRoom() },
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      status: string;
      session_secret_bound: boolean;
    };
    assert.equal(body.status, "not_ready");
    assert.equal(body.session_secret_bound, false);
  } finally {
    __setTestStore(null);
  }
});

test("missing 0005 MCP objects → schema_ready:false while 0003/0004 retained", async () => {
  // Through 0004 only — MCP tables absent.
  const files = allMigrationFiles().filter(
    (f) => !f.startsWith("0005") && !f.startsWith("0006"),
  );
  const { store } = openStoreWith(files);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  for (const k of P0_SCHEMA_KEYS) assert.equal(readiness.checks[k], true, k);
  for (const k of MCP_SCHEMA_KEYS) assert.equal(readiness.checks[k], false, k);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      readyEnv(),
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.schema_checks.authorize_transactions, true);
    assert.equal(body.schema_checks.mcp_operations, false);
    assert.equal(body.schema_checks.mcp_approval_outbox, false);
  } finally {
    __setTestStore(null);
  }
});

test("missing required column on 0003/0004 table → schema_ready:false", async () => {
  // Full migrations, then replace device_credentials with a column-deficient table.
  const { db, store } = openStoreWith(allMigrationFiles());
  assert.equal((await store.schemaReadiness()).schema_ready, true);
  db.exec(`DROP TABLE device_credentials`);
  db.exec(`CREATE TABLE device_credentials (
    credential_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL
  )`);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.checks.device_credentials, false);
  assert.equal(readiness.schema_ready, false);
  // Other 0003/0004/0005 probes remain true.
  assert.equal(readiness.checks.devices_status, true);
  assert.equal(readiness.checks.revoked_refresh_families, true);
  assert.equal(readiness.checks.authorize_transactions, true);
  assert.equal(readiness.checks.mcp_operations, true);
  assert.equal(readiness.checks.mcp_approval_outbox, true);
});

test("unavailable storage without DB/testStore → /health 503 schema_ready:false", async () => {
  __setTestStore(null);
  const res = await worker.fetch(new Request("https://cp.test/health"), {}, ctx);
  assert.equal(res.status, 503);
  const body = (await res.json()) as {
    schema_ready: boolean;
    storage: string;
    status: string;
  };
  assert.equal(body.schema_ready, false);
  assert.equal(body.storage, "unavailable");
  assert.equal(body.status, "not_ready");
});
