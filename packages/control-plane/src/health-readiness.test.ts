/**
 * Health + migration readiness: never synthesize applied migrations;
 * probe required P0/MCP schema and return 503 when absent.
 * SESSION_SECRET and a browser-auth boundary must be bound for /health/ready 200.
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

function adaptSqlite(db: DatabaseSync, onPrepare?: () => void): SqlDatabase {
  return {
    prepare(query: string): SqlStatement {
      onPrepare?.();
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

function openStoreWith(
  files: string[],
  onPrepare?: () => void,
): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  applyMigrations(db, files);
  return { db, store: new SqlStore(adaptSqlite(db, onPrepare), "sqlite") };
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
    OWNER_TOKEN_HASH: "0".repeat(64),
    ...extra,
  };
}

const MCP_SCHEMA_KEYS = [
  "mcp_operations",
  "mcp_approval_transactions",
  "mcp_approval_outbox",
] as const;

const WORKSPACE_SCHEMA_KEYS = [
  "device_workspaces",
  "device_workspace_members",
] as const;

const P0_SCHEMA_KEYS = [
  "devices_status",
  "revoked_refresh_families",
  "device_credentials",
  "device_verification_transactions",
  "authorize_transactions",
] as const;

/** 0002 OAuth/device enrollment + schema_migrations ledger. */
const M0002_SCHEMA_KEYS = [
  "oauth_auth_codes",
  "device_codes",
  "used_refresh_tokens",
  "enrollment_challenges",
  "schema_migrations",
] as const;

const ALL_SCHEMA_KEYS = [
  ...M0002_SCHEMA_KEYS,
  ...P0_SCHEMA_KEYS,
  ...MCP_SCHEMA_KEYS,
  ...WORKSPACE_SCHEMA_KEYS,
] as const;

test("/health is D1-free liveness; concurrent /health/ready checks coalesce one bounded scan", async () => {
  let queryCount = 0;
  const { store } = openStoreWith(allMigrationFiles(), () => {
    queryCount += 1;
  });

  // Measure a single complete scan without populating the Worker cache.
  await store.schemaReadiness();
  const oneProbeQueryCount = queryCount;
  assert.ok(oneProbeQueryCount > 1, "a complete schema probe uses multiple D1 queries");
  queryCount = 0;

  __setTestStore(store);
  try {
    const liveness = await worker.fetch(
      new Request("https://cp.test/health"),
      readyEnv(),
      ctx,
    );
    assert.equal(liveness.status, 200);
    const livenessBody = (await liveness.json()) as Record<string, unknown>;
    assert.equal(livenessBody.status, "ok");
    assert.equal(livenessBody.liveness, true);
    assert.equal("schema_ready" in livenessBody, false);
    assert.equal("schema_checks" in livenessBody, false);
    assert.equal(queryCount, 0, "liveness must not access D1");

    const [first, second] = await Promise.all([
      worker.fetch(new Request("https://cp.test/health/ready"), readyEnv(), ctx),
      worker.fetch(new Request("https://cp.test/health/ready"), readyEnv(), ctx),
    ]);
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(queryCount, oneProbeQueryCount, "concurrent readiness checks share one scan");

    const cached = await worker.fetch(
      new Request("https://cp.test/health/ready"),
      readyEnv(),
      ctx,
    );
    assert.equal(cached.status, 200);
    assert.equal(queryCount, oneProbeQueryCount, "fresh readiness result is reused briefly");
  } finally {
    __setTestStore(null);
  }
});

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
    for (const k of ALL_SCHEMA_KEYS) assert.equal(body.schema_checks[k], true, k);
  } finally {
    __setTestStore(null);
  }
});

test("sqlite DB missing P0 schema → /health/ready 503 with schema_ready:false", async () => {
  // Only 0001_init: devices has no status; 0002+/P0/MCP tables absent.
  const { store } = openStoreWith(["0001_init.sql"]);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  for (const k of ALL_SCHEMA_KEYS) assert.equal(readiness.checks[k], false, k);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
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
    for (const k of ALL_SCHEMA_KEYS) assert.equal(body.schema_checks[k], false, k);

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

test("pre-0016 workspace schema is never reported ready", async () => {
  const files = allMigrationFiles().filter((file) => file !== "0016_device_scoped_workspaces.sql");
  const { store } = openStoreWith(files);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  assert.equal(readiness.checks.device_workspaces, false);
  assert.equal(readiness.checks.device_workspace_members, false);

  __setTestStore(store);
  try {
    const response = await worker.fetch(
      new Request("https://cp.test/health/ready"),
      readyEnv(),
      ctx,
    );
    assert.equal(response.status, 503);
    const body = (await response.json()) as {
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.schema_checks.device_workspaces, false);
    assert.equal(body.schema_checks.device_workspace_members, false);
  } finally {
    __setTestStore(null);
  }
});

test("full schema → /health/ready 200 with schema_ready:true; MemoryStore ready", async () => {
  const mem = new MemoryStore();
  const memReady = await mem.schemaReadiness();
  assert.equal(memReady.schema_ready, true);
  for (const k of ALL_SCHEMA_KEYS) assert.equal(memReady.checks[k], true, k);

  __setTestStore(mem);
  try {
    const memHealth = await worker.fetch(
      new Request("https://cp.test/health/ready"),
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
    for (const k of ALL_SCHEMA_KEYS) assert.equal(memBody.schema_checks[k], true, k);
  } finally {
    __setTestStore(null);
  }

  const files = allMigrationFiles();
  const { store } = openStoreWith(files);
  // Record real migration rows only — no synthesis path.
  for (const f of files) await store.markMigration(f);

  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, true);
  for (const k of ALL_SCHEMA_KEYS) assert.equal(readiness.checks[k], true, k);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
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
    for (const k of ALL_SCHEMA_KEYS) assert.equal(body.schema_checks[k], true, k);
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

test("schema ready but DEVICE_ROOM absent → /health/ready 503 not_ready", async () => {
  const mem = new MemoryStore();
  assert.equal((await mem.schemaReadiness()).schema_ready, true);

  __setTestStore(mem);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
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
      new Request("https://cp.test/health/ready"),
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

test("schema ready but SESSION_SECRET unbound → /health/ready 503 not_ready", async () => {
  const mem = new MemoryStore();
  assert.equal((await mem.schemaReadiness()).schema_ready, true);

  __setTestStore(mem);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
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
      new Request("https://cp.test/health/ready"),
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
  // Through 0004 only — MCP tables absent (also skip later MCP ALTERs/indexes).
  const files = allMigrationFiles().filter(
    (f) =>
      !f.startsWith("0005") &&
      !f.startsWith("0006") &&
      !f.startsWith("0007") &&
      !f.startsWith("0008") &&
      !f.startsWith("0009"),
  );
  const { store } = openStoreWith(files);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  for (const k of M0002_SCHEMA_KEYS) assert.equal(readiness.checks[k], true, k);
  for (const k of P0_SCHEMA_KEYS) assert.equal(readiness.checks[k], true, k);
  for (const k of MCP_SCHEMA_KEYS) assert.equal(readiness.checks[k], false, k);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
      readyEnv(),
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.schema_checks.oauth_auth_codes, true);
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
  // Other 0002/0003/0004/0005 probes remain true.
  assert.equal(readiness.checks.oauth_auth_codes, true);
  assert.equal(readiness.checks.devices_status, true);
  assert.equal(readiness.checks.revoked_refresh_families, true);
  assert.equal(readiness.checks.authorize_transactions, true);
  assert.equal(readiness.checks.mcp_operations, true);
  assert.equal(readiness.checks.mcp_approval_outbox, true);
});

test("missing 0002 objects → schema_ready:false and /health/ready 503", async () => {
  // 0001 only already covers absence; also verify after 0001 the 0002 keys are false
  // while applying 0002 alone (plus 0001) makes 0002 true and later keys false.
  const { store } = openStoreWith([
    "0001_init.sql",
    "0002_oauth_device_enrollment.sql",
  ]);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  for (const k of M0002_SCHEMA_KEYS) assert.equal(readiness.checks[k], true, k);
  for (const k of P0_SCHEMA_KEYS) assert.equal(readiness.checks[k], false, k);
  for (const k of MCP_SCHEMA_KEYS) assert.equal(readiness.checks[k], false, k);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
      readyEnv(),
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.schema_checks.oauth_auth_codes, true);
    assert.equal(body.schema_checks.device_codes, true);
    assert.equal(body.schema_checks.devices_status, false);
  } finally {
    __setTestStore(null);
  }
});

test("missing required 0002 index → schema_ready:false and /health/ready 503", async () => {
  const { db, store } = openStoreWith(allMigrationFiles());
  assert.equal((await store.schemaReadiness()).schema_ready, true);
  db.exec(`DROP INDEX idx_auth_codes_client`);
  db.exec(`DROP INDEX idx_mcp_ops_updated`);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  assert.equal(readiness.checks.oauth_auth_codes, false);
  assert.equal(readiness.checks.mcp_operations, false);
  // Unrelated objects stay ready.
  assert.equal(readiness.checks.device_codes, true);
  assert.equal(readiness.checks.mcp_approval_outbox, true);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
      readyEnv(),
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.schema_checks.oauth_auth_codes, false);
    assert.equal(body.schema_checks.mcp_operations, false);
  } finally {
    __setTestStore(null);
  }
});

test("missing 0007 claim columns → schema_ready:false and /health/ready 503", async () => {
  // Through 0006 only — claimed_at present, claim_token/version absent.
  // Keep 0008 (mcp_operations action binding) so only outbox claim columns fail.
  const files = allMigrationFiles().filter((f) => !f.startsWith("0007"));
  const { store } = openStoreWith(files);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  assert.equal(readiness.checks.mcp_approval_outbox, false);
  // Everything else through 0006 should pass (claimed_at is present).
  for (const k of M0002_SCHEMA_KEYS) assert.equal(readiness.checks[k], true, k);
  for (const k of P0_SCHEMA_KEYS) assert.equal(readiness.checks[k], true, k);
  assert.equal(readiness.checks.mcp_operations, true);
  assert.equal(readiness.checks.mcp_approval_transactions, true);

  __setTestStore(store);
  try {
    const res = await worker.fetch(
      new Request("https://cp.test/health/ready"),
      readyEnv(),
      ctx,
    );
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      schema_ready: boolean;
      schema_checks: Record<string, boolean>;
    };
    assert.equal(body.schema_ready, false);
    assert.equal(body.schema_checks.mcp_approval_outbox, false);
  } finally {
    __setTestStore(null);
  }
});

test("missing 0006 claimed_at column → schema_ready:false", async () => {
  // Drop 0006/0007 outbox claim columns; keep 0008 action-binding on mcp_operations.
  const files = allMigrationFiles().filter(
    (f) => !f.startsWith("0006") && !f.startsWith("0007"),
  );
  const { store } = openStoreWith(files);
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, false);
  assert.equal(readiness.checks.mcp_approval_outbox, false);
  assert.equal(readiness.checks.mcp_operations, true);
  assert.equal(readiness.checks.mcp_approval_transactions, true);
});

test("MemoryStore and SqlStore both report full 0002–0009 readiness", async () => {
  const mem = new MemoryStore();
  const memR = await mem.schemaReadiness();
  assert.equal(memR.schema_ready, true);
  for (const k of ALL_SCHEMA_KEYS) assert.equal(memR.checks[k], true, `mem:${k}`);

  const { store } = openStoreWith(allMigrationFiles());
  const sqlR = await store.schemaReadiness();
  assert.equal(sqlR.schema_ready, true);
  for (const k of ALL_SCHEMA_KEYS) assert.equal(sqlR.checks[k], true, `sql:${k}`);
});

test("unavailable storage without DB/testStore → /health/ready 503 schema_ready:false", async () => {
  __setTestStore(null);
  const res = await worker.fetch(new Request("https://cp.test/health/ready"), {}, ctx);
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
