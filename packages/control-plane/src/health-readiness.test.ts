/**
 * Health + migration readiness: never synthesize applied migrations;
 * probe required P0 schema and return 503 when absent.
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
    assert.equal(body.schema_checks.devices_status, true);
    assert.equal(body.schema_checks.device_credentials, true);
    assert.equal(body.schema_checks.device_verification_transactions, true);
    assert.equal(body.schema_checks.authorize_transactions, true);
  } finally {
    __setTestStore(null);
  }
});

test("sqlite DB missing P0 schema → /health 503 with schema_ready:false", async () => {
  // Only 0001_init: devices has no status; P0 tables absent.
  const { store } = openStoreWith(["0001_init.sql"]);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  assert.equal(readiness.checks.devices_status, false);
  assert.equal(readiness.checks.device_credentials, false);
  assert.equal(readiness.checks.device_verification_transactions, false);
  assert.equal(readiness.checks.authorize_transactions, false);

  __setTestStore(store);
  try {
    const res = await worker.fetch(new Request("https://cp.test/health"), {}, ctx);
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      status: string;
      schema_ready: boolean;
      schema_checks: {
        devices_status: boolean;
        device_credentials: boolean;
        device_verification_transactions: boolean;
        authorize_transactions: boolean;
      };
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.status, "not_ready");
    assert.equal(body.schema_checks.devices_status, false);
    assert.equal(body.schema_checks.device_credentials, false);
    assert.equal(body.schema_checks.device_verification_transactions, false);
    assert.equal(body.schema_checks.authorize_transactions, false);

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
  assert.equal((await mem.schemaReadiness()).schema_ready, true);
  const room = fakeDeviceRoom();

  __setTestStore(mem);
  try {
    const memHealth = await worker.fetch(
      new Request("https://cp.test/health"),
      { DEVICE_ROOM: room },
      ctx,
    );
    assert.equal(memHealth.status, 200);
    const memBody = (await memHealth.json()) as {
      schema_ready: boolean;
      status: string;
      durable_objects: boolean;
    };
    assert.equal(memBody.schema_ready, true);
    assert.equal(memBody.status, "ok");
    assert.equal(memBody.durable_objects, true);
  } finally {
    __setTestStore(null);
  }

  const files = allMigrationFiles();
  const { store } = openStoreWith(files);
  // Record real migration rows only — no synthesis path.
  for (const f of files) await store.markMigration(f);

  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, true);
  assert.equal(readiness.checks.devices_status, true);
  assert.equal(readiness.checks.device_credentials, true);
  assert.equal(readiness.checks.device_verification_transactions, true);
  assert.equal(readiness.checks.authorize_transactions, true);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      { DEVICE_ROOM: room },
      ctx,
    );
    assert.equal(res.status, 200);
    const body = (await res.json()) as {
      status: string;
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
      durable_objects: boolean;
    };
    assert.equal(body.status, "ok");
    assert.equal(body.schema_ready, true);
    assert.equal(body.schema_checks.authorize_transactions, true);
    assert.equal(body.durable_objects, true);

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
      {}, // no DEVICE_ROOM
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

  const files = allMigrationFiles();
  const { store } = openStoreWith(files);
  for (const f of files) await store.markMigration(f);
  assert.equal((await store.schemaReadiness()).schema_ready, true);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health"),
      {}, // schema ready, DEVICE_ROOM unbound
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
