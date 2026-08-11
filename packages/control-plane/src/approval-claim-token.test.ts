/**
 * Approval outbox claim ownership: claim_token + claim_version issued on
 * claim/reclaim, release/finalize gated to the claim owner only.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
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
  const deviceId = `dev_ctok_${label}`.padEnd(24, "a").slice(0, 24);
  await putDevice(store, deviceId);
  const opId = randomId("op_");
  await store.putMcpOperation(approvalOp(opId, deviceId));
  const { txId, csrf } = await mintTx(store, opId, deviceId);
  const csrfHash = await sha256Hex(csrf);
  const started = await store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve");
  assert.equal(started!.status, "created");
  assert.equal(started!.outbox.claim_token ?? null, null);
  assert.equal(started!.outbox.claim_version ?? 0, 0);
  const claimed = await store.claimMcpApprovalOutboxDelivery(txId);
  assert.ok(claimed);
  return { store, deviceId, opId, txId, csrf, claimed: claimed! };
}

test("migration 0007 adds claim_token and claim_version columns", () => {
  const sql = readFileSync(
    join(migrationsDir, "0007_approval_claim_token.sql"),
    "utf8",
  );
  assert.match(sql, /ALTER TABLE mcp_approval_outbox ADD COLUMN claim_token TEXT/);
  assert.match(
    sql,
    /ALTER TABLE mcp_approval_outbox ADD COLUMN claim_version INTEGER NOT NULL DEFAULT 0/,
  );
  const { db } = openSql();
  const cols = db
    .prepare(`PRAGMA table_info(mcp_approval_outbox)`)
    .all() as Array<{ name: string }>;
  assert.ok(cols.some((c) => c.name === "claim_token"));
  assert.ok(cols.some((c) => c.name === "claim_version"));
});

test("claim issues random token and increments version (MemoryStore + SqlStore)", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    const { txId, claimed } = await beginAndClaim(store, `issue_${store.kind}`);
    assert.equal(claimed.delivery_status, "delivering");
    assert.ok(claimed.claim_token && claimed.claim_token.length > 8);
    assert.match(claimed.claim_token, /^clm_/);
    assert.equal(claimed.claim_version, 1);

    const persisted = await store.getMcpApprovalOutbox(txId);
    assert.equal(persisted!.claim_token, claimed.claim_token);
    assert.equal(persisted!.claim_version, 1);
  }
});

test("reclaim issues a new token and bumps version; old owner is invalidated", async () => {
  // Memory
  {
    const store = new MemoryStore();
    const { txId, claimed: first, opId } = await beginAndClaim(store, "mem_reclaim");
    const oldToken = first.claim_token!;
    const oldVersion = first.claim_version!;

    const row = store.mcpApprovalOutbox.get(txId)!;
    row.claimed_at = new Date(
      Date.now() - MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS - 1_000,
    ).toISOString();
    store.mcpApprovalOutbox.set(txId, row);

    const second = await store.claimMcpApprovalOutboxDelivery(txId);
    assert.ok(second);
    assert.notEqual(second!.claim_token, oldToken);
    assert.equal(second!.claim_version, oldVersion + 1);

    // Old owner cannot release or finalize.
    await store.releaseMcpApprovalOutboxClaim(txId, oldToken, oldVersion, "stale");
    let box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.equal(box!.claim_token, second!.claim_token);
    assert.equal(box!.attempts, 0);

    const finOld = await store.finalizeMcpApprovalDelivery(txId, oldToken, oldVersion);
    assert.equal(finOld, null);
    box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.equal((await store.getMcpOperation(opId))!.status, "approval_required");

    // New owner finalizes.
    const finNew = await store.finalizeMcpApprovalDelivery(
      txId,
      second!.claim_token!,
      second!.claim_version!,
    );
    assert.ok(finNew);
    assert.equal(finNew!.status, "approval_required");
    assert.equal((await store.getMcpApprovalOutbox(txId))!.delivery_status, "delivered");
  }

  // SQL
  {
    const { db, store } = openSql();
    const { txId, claimed: first, opId } = await beginAndClaim(store, "sql_reclaim");
    const oldToken = first.claim_token!;
    const oldVersion = first.claim_version!;

    const staleTs = new Date(
      Date.now() - MCP_APPROVAL_OUTBOX_CLAIM_LEASE_MS - 1_000,
    ).toISOString();
    db.prepare(`UPDATE mcp_approval_outbox SET claimed_at = ? WHERE id = ?`).run(
      staleTs,
      txId,
    );

    const second = await store.claimMcpApprovalOutboxDelivery(txId);
    assert.ok(second);
    assert.notEqual(second!.claim_token, oldToken);
    assert.equal(second!.claim_version, oldVersion + 1);

    await store.releaseMcpApprovalOutboxClaim(txId, oldToken, oldVersion, "stale");
    let box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.equal(box!.claim_token, second!.claim_token);
    assert.equal(box!.attempts, 0);

    const finOld = await store.finalizeMcpApprovalDelivery(txId, oldToken, oldVersion);
    assert.equal(finOld, null);
    box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.equal((await store.getMcpOperation(opId))!.status, "approval_required");

    const finNew = await store.finalizeMcpApprovalDelivery(
      txId,
      second!.claim_token!,
      second!.claim_version!,
    );
    assert.ok(finNew);
    assert.equal((await store.getMcpApprovalOutbox(txId))!.delivery_status, "delivered");
  }
});

test("release rejects wrong/missing token or version without state change", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    const { txId, claimed } = await beginAndClaim(store, `rel_${store.kind}`);
    const token = claimed.claim_token!;
    const version = claimed.claim_version!;
    const before = await store.getMcpApprovalOutbox(txId);

    await store.releaseMcpApprovalOutboxClaim(txId, "wrong_token", version, "nope");
    let box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.equal(box!.claim_token, token);
    assert.equal(box!.attempts, before!.attempts);
    assert.equal(box!.claimed_at, before!.claimed_at);

    await store.releaseMcpApprovalOutboxClaim(txId, token, version + 99, "nope");
    box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.equal(box!.attempts, before!.attempts);

    await store.releaseMcpApprovalOutboxClaim(txId, "", version, "nope");
    box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");

    // Legitimate owner succeeds.
    await store.releaseMcpApprovalOutboxClaim(txId, token, version, "route_failed");
    box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "pending");
    assert.equal(box!.claimed_at, null);
    assert.equal(box!.claim_token, null);
    assert.equal(box!.attempts, (before!.attempts ?? 0) + 1);
    assert.match(String(box!.last_error || ""), /route_failed/);
    // Version is retained (monotonic); next claim will bump it.
    assert.equal(box!.claim_version, version);
  }
});

test("finalize rejects wrong/missing token or version without state change", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    const { txId, claimed, opId } = await beginAndClaim(store, `fin_${store.kind}`);
    const token = claimed.claim_token!;
    const version = claimed.claim_version!;

    assert.equal(
      await store.finalizeMcpApprovalDelivery(txId, "wrong", version),
      null,
    );
    assert.equal(
      await store.finalizeMcpApprovalDelivery(txId, token, version + 1),
      null,
    );
    assert.equal(await store.finalizeMcpApprovalDelivery(txId, "", version), null);

    let box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivering");
    assert.equal(box!.claim_token, token);
    assert.equal((await store.getMcpOperation(opId))!.status, "approval_required");

    const ok = await store.finalizeMcpApprovalDelivery(txId, token, version);
    assert.ok(ok);
    assert.equal(ok!.status, "approval_required");
    box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivered");
  }
});

test("owner release then re-claim gets new token/version; prior token cannot finalize", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    const { txId, claimed: first } = await beginAndClaim(store, `cycle_${store.kind}`);
    const t1 = first.claim_token!;
    const v1 = first.claim_version!;

    await store.releaseMcpApprovalOutboxClaim(txId, t1, v1, "retry");
    assert.equal((await store.getMcpApprovalOutbox(txId))!.delivery_status, "pending");

    const second = await store.claimMcpApprovalOutboxDelivery(txId);
    assert.ok(second);
    assert.notEqual(second!.claim_token, t1);
    assert.equal(second!.claim_version, v1 + 1);

    assert.equal(await store.finalizeMcpApprovalDelivery(txId, t1, v1), null);
    assert.equal(
      (await store.getMcpApprovalOutbox(txId))!.delivery_status,
      "delivering",
    );

    const done = await store.finalizeMcpApprovalDelivery(
      txId,
      second!.claim_token!,
      second!.claim_version!,
    );
    assert.ok(done);
    assert.equal((await store.getMcpApprovalOutbox(txId))!.delivery_status, "delivered");
  }
});
