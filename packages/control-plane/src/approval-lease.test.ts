/**
 * Approval outbox claim lease: claimed_at persistence, stale reclaim,
 * live-claim single winner, and handleApprove release-on-throw.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import { handleApprove } from "./mcp.ts";
import {
  MemoryStore,
  MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS,
  SqlStore,
  type McpOperationRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { randomId, sha256Hex } from "./util.ts";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

function adaptSqlite(db: DatabaseSync): SqlDatabase {
  type SqlVal = null | number | string | bigint | Uint8Array;
  return {
    prepare(query: string): SqlStatement {
      const stmt = db.prepare(query);
      let bound: SqlVal[] = [];
      const api: SqlStatement = {
        bind(...values: unknown[]) {
          bound = values.map((v) => (v === undefined ? null : (v as SqlVal)));
          return api;
        },
        async first<T = Record<string, unknown>>(colName?: string) {
          const row = stmt.get(...bound) as Record<string, unknown> | undefined;
          if (!row) return null;
          if (colName) return (row[colName] as T) ?? null;
          return row as T;
        },
        async run() {
          const info = stmt.run(...bound) as { changes: number };
          return { success: true, meta: { changes: Number(info.changes || 0) } };
        },
        async all<T = Record<string, unknown>>() {
          return { results: stmt.all(...bound) as T[] };
        },
      };
      return api;
    },
    exec(query: string) {
      db.exec(query);
    },
    async batch<T = unknown>(statements: SqlStatement[]) {
      db.exec("BEGIN");
      try {
        const out: T[] = [];
        for (const s of statements) out.push((await s.run()) as T);
        db.exec("COMMIT");
        return out;
      } catch (err) {
        try {
          db.exec("ROLLBACK");
        } catch {
          /* ignore */
        }
        throw err;
      }
    },
  };
}

function openSql(): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  for (const f of readdirSync(migrationsDir).filter((x) => x.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  return { db, store: new SqlStore(adaptSqlite(db), "sqlite") };
}

async function seed(store: MemoryStore | SqlStore) {
  await store.ensureBootstrap();
  await store.putClient({
    client_id: "client_mcp",
    tenant_id: "ten_default",
    client_name: "mcp",
    redirect_uris: ["http://127.0.0.1/cb"],
    created_at: new Date().toISOString(),
  });
  return store.issueTokens(
    "client_mcp",
    "prin_dev",
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device",
  );
}

async function putDevice(store: MemoryStore | SqlStore, id: string) {
  await store.putDevice({
    id,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    name: id,
    hostname: id,
    os: "test",
    arch: "x64",
    agent_version: "1.0.0",
    protocol_version: "ownmesh.device/1.0",
    public_key: "pk",
    status: "active",
    revoked: false,
    created_at: new Date().toISOString(),
  });
}

function approvalOp(opId: string, deviceId: string): McpOperationRecord {
  const now = new Date().toISOString();
  return {
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_write",
    status: "approval_required",
    summary: "needs human",
    data: { tool: "ownmesh_fs_write" },
    truncated: false,
    next_cursor: null,
    approval_required: true,
    approval_url: `https://cp.test/approve?operation_id=${opId}`,
    warnings: [],
    correlation_id: randomId("cor_"),
    policy_authority: "ownmesh_device",
    created_at: now,
    updated_at: now,
  };
}

async function mintTx(store: MemoryStore | SqlStore, opId: string, deviceId: string) {
  const csrf = `csrf_${randomId("")}`;
  const txId = randomId("apr_");
  await store.putMcpApprovalTransaction({
    id: txId,
    csrf_hash: await sha256Hex(csrf),
    operation_id: opId,
    principal_id: "prin_dev",
    tenant_id: "ten_default",
    device_id: deviceId,
    expires_at: Date.now() + 15 * 60 * 1000,
    consumed: false,
    created_at: new Date().toISOString(),
  });
  return { txId, csrf };
}

async function beginAndClaim(store: MemoryStore | SqlStore, label: string) {
  await store.ensureBootstrap();
  const deviceId = `dev_lease_${label}`.padEnd(24, "a").slice(0, 24);
  await putDevice(store, deviceId);
  const opId = randomId("op_");
  await store.putMcpOperation(approvalOp(opId, deviceId));
  const { txId, csrf } = await mintTx(store, opId, deviceId);
  const csrfHash = await sha256Hex(csrf);
  const started = await store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve");
  assert.equal(started!.status, "created");
  const claimed = await store.claimMcpApprovalOutboxDelivery(txId);
  assert.ok(claimed);
  assert.equal(claimed!.delivery_status, "delivering");
  assert.ok(claimed!.claimed_at, "claim must persist claimed_at");
  assert.ok(claimed!.claim_token, "claim must issue claim_token");
  assert.ok((claimed!.claim_version ?? 0) >= 1, "claim must increment claim_version");
  return { store, deviceId, opId, txId, csrf, claimed };
}

test("migration 0006 adds mcp_approval_outbox.claimed_at", () => {
  const sql = readFileSync(
    join(migrationsDir, "0006_approval_outbox_claim_lease.sql"),
    "utf8",
  );
  assert.match(sql, /ALTER TABLE mcp_approval_outbox ADD COLUMN claimed_at TEXT/);
  const { db, store: _s } = openSql();
  const cols = db
    .prepare(`PRAGMA table_info(mcp_approval_outbox)`)
    .all() as Array<{ name: string }>;
  assert.ok(cols.some((c) => c.name === "claimed_at"));
  // named TTL const is finite and positive
  assert.ok(MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS > 0);
  assert.ok(Number.isFinite(MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS));
});

test("SCHEMA_READINESS_OBJECTS includes claimed_at on mcp_approval_outbox", async () => {
  const { store } = openSql();
  const readiness = await store.schemaReadiness();
  assert.equal(readiness.schema_ready, true);
  assert.equal(readiness.checks.mcp_approval_outbox, true);
});

test("claim sets claimed_at; live concurrent claims yield a single winner", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    await store.ensureBootstrap();
    const deviceId = `dev_live_${store.kind}`.padEnd(24, "a").slice(0, 24);
    await putDevice(store, deviceId);
    const opId = randomId("op_");
    await store.putMcpOperation(approvalOp(opId, deviceId));
    const { txId, csrf } = await mintTx(store, opId, deviceId);
    const csrfHash = await sha256Hex(csrf);
    await store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve");

    const [c1, c2] = await Promise.all([
      store.claimMcpApprovalOutboxDelivery(txId),
      store.claimMcpApprovalOutboxDelivery(txId),
    ]);
    const winners = [c1, c2].filter(Boolean);
    assert.equal(winners.length, 1, "exactly one live claim winner");
    assert.equal(winners[0]!.delivery_status, "delivering");
    assert.ok(winners[0]!.claimed_at);
    assert.ok(winners[0]!.claim_token);
    assert.ok((winners[0]!.claim_version ?? 0) >= 1);

    // Second claim while lease is live still loses.
    const again = await store.claimMcpApprovalOutboxDelivery(txId);
    assert.equal(again, null);

    const box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.ok(box!.claimed_at);
    void csrf;
  }
});

test("stale delivering claim can be reclaimed after lease expiry", async () => {
  // Memory: backdate claimed_at directly (no sleep).
  {
    const store = new MemoryStore();
    const { txId, claimed: first } = await beginAndClaim(store, "mem_stale");
    const row = store.mcpApprovalOutbox.get(txId)!;
    row.claimed_at = new Date(
      Date.now() - MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS - 1_000,
    ).toISOString();
    store.mcpApprovalOutbox.set(txId, row);

    const reclaimed = await store.claimMcpApprovalOutboxDelivery(txId);
    assert.ok(reclaimed, "stale delivering must be reclaimable");
    assert.equal(reclaimed!.delivery_status, "delivering");
    assert.ok(reclaimed!.claimed_at);
    const claimedMs = Date.parse(reclaimed!.claimed_at!);
    assert.ok(Date.now() - claimedMs < 5_000, "claimed_at refreshed on reclaim");
    assert.ok(reclaimed!.claim_token);
    assert.notEqual(reclaimed!.claim_token, first.claim_token, "reclaim issues new token");
    assert.equal(
      reclaimed!.claim_version,
      (first.claim_version ?? 0) + 1,
      "reclaim increments version",
    );
  }

  // SQL: backdate claimed_at via UPDATE.
  {
    const { db, store } = openSql();
    const { txId, claimed: first } = await beginAndClaim(store, "sql_stale");
    const staleTs = new Date(
      Date.now() - MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS - 1_000,
    ).toISOString();
    db.prepare(
      `UPDATE mcp_approval_outbox SET claimed_at = ? WHERE id = ?`,
    ).run(staleTs, txId);

    const reclaimed = await store.claimMcpApprovalOutboxDelivery(txId);
    assert.ok(reclaimed, "stale SQL delivering must be reclaimable");
    assert.equal(reclaimed!.delivery_status, "delivering");
    const claimedMs = Date.parse(reclaimed!.claimed_at!);
    assert.ok(Date.now() - claimedMs < 5_000);
    assert.ok(reclaimed!.claim_token);
    assert.notEqual(reclaimed!.claim_token, first.claim_token);
    assert.equal(reclaimed!.claim_version, (first.claim_version ?? 0) + 1);
  }
});

test("handleApprove: route throw releases live claim (no leak, no success)", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    await store.ensureBootstrap();
    const deviceId = `dev_throw_${store.kind}`.padEnd(24, "a").slice(0, 24);
    await putDevice(store, deviceId);
    const opId = randomId("op_");
    await store.putMcpOperation(approvalOp(opId, deviceId));
    const { txId, csrf } = await mintTx(store, opId, deviceId);
    const tok = await seed(store);

    const routeToDevice = async () => {
      throw new Error("simulated DO/D1 failure");
    };

    const res = await handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${tok.access_token}`,
          origin: "https://cp.test",
        },
        body: JSON.stringify({
          decision: "approve",
          transaction_id: txId,
          csrf_token: csrf,
          operation_id: opId,
        }),
      }),
      store,
      {
        principal: { id: "prin_dev", tenant_id: "ten_default" },
        originAllowed: true,
        routeToDevice,
      },
    );

    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      error?: string;
      delivery_status?: string;
      retryable?: boolean;
      ok?: boolean;
    };
    assert.equal(body.ok, undefined);
    assert.equal(body.error, "delivery_failed");
    assert.equal(body.delivery_status, "pending");
    assert.equal(body.retryable, true);

    const box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "pending", "claim must be released");
    assert.equal(box!.claimed_at, null);
    assert.ok((box!.attempts ?? 0) >= 1);
    assert.match(String(box!.last_error || ""), /simulated DO\/D1 failure/);

    const op = await store.getMcpOperation(opId);
    assert.equal(op!.status, "approval_required");

    // Retry after release can claim and deliver once.
    let routes = 0;
    const ok = await handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${tok.access_token}`,
          origin: "https://cp.test",
        },
        body: JSON.stringify({
          decision: "approve",
          transaction_id: txId,
          csrf_token: csrf,
          operation_id: opId,
        }),
      }),
      store,
      {
        principal: { id: "prin_dev", tenant_id: "ten_default" },
        originAllowed: true,
        routeToDevice: async () => {
          routes += 1;
          return { status: "routed_to_device" as const, detail: {} };
        },
      },
    );
    assert.equal(ok.status, 200);
    assert.equal(routes, 1);
    assert.equal((await store.getMcpApprovalOutbox(txId))!.delivery_status, "delivered");
  }
});
