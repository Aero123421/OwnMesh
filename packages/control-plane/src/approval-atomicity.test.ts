/**
 * Approval pipeline atomicity: consume+outbox batch, pending→delivering claim,
 * transactional finalize, fail-closed CHECK constraints, /approve scope gate.
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
  SqlStore,
  type McpOperationRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { randomId, sha256Hex } from "./util.ts";
import worker, { __setTestStore } from "./index.ts";

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
      // Simulate D1 atomic batch: all-or-nothing via explicit transaction.
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

async function seed(store: MemoryStore | SqlStore, scope =
  "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device") {
  await store.ensureBootstrap();
  await store.putClient({
    client_id: "client_mcp",
    tenant_id: "ten_default",
    client_name: "mcp",
    redirect_uris: ["http://127.0.0.1/cb"],
    created_at: new Date().toISOString(),
  });
  return store.issueTokens("client_mcp", "prin_dev", scope);
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

async function mintTx(
  store: MemoryStore | SqlStore,
  opId: string,
  deviceId: string,
) {
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

test("migration 0005 CHECK constraints on decision and delivery_status", () => {
  const sql = readFileSync(join(migrationsDir, "0005_mcp_operations.sql"), "utf8");
  assert.match(sql, /decision TEXT NOT NULL CHECK \(decision IN \('approve', 'deny'\)\)/);
  assert.match(
    sql,
    /delivery_status TEXT NOT NULL DEFAULT 'pending'\s+CHECK \(delivery_status IN \('pending', 'delivering', 'delivered'\)\)/s,
  );
  assert.match(sql, /decision TEXT CHECK \(decision IS NULL OR decision IN \('approve', 'deny'\)\)/);

  const { db } = openSql();
  // Valid insert OK
  db.prepare(
    `INSERT INTO mcp_approval_outbox
     (id, operation_id, principal_id, tenant_id, device_id, decision,
      correlation_id, delivery_status, attempts, last_error, created_at, delivered_at)
     VALUES ('o1','op1','p','t',NULL,'approve','cor1','pending',0,NULL,'now',NULL)`,
  ).run();

  assert.throws(() => {
    db.prepare(
      `INSERT INTO mcp_approval_outbox
       (id, operation_id, principal_id, tenant_id, device_id, decision,
        correlation_id, delivery_status, attempts, last_error, created_at, delivered_at)
       VALUES ('o2','op2','p','t',NULL,'maybe','cor2','pending',0,NULL,'now',NULL)`,
    ).run();
  });

  assert.throws(() => {
    db.prepare(
      `INSERT INTO mcp_approval_outbox
       (id, operation_id, principal_id, tenant_id, device_id, decision,
        correlation_id, delivery_status, attempts, last_error, created_at, delivered_at)
       VALUES ('o3','op3','p','t',NULL,'approve','cor3','shipped',0,NULL,'now',NULL)`,
    ).run();
  });
});

test("beginMcpApprovalOutbox is atomic: no consumed-without-outbox window", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    await store.ensureBootstrap();
    const deviceId = `dev_atomic_${store.kind}`.padEnd(24, "a").slice(0, 24);
    await putDevice(store, deviceId);
    const opId = randomId("op_");
    await store.putMcpOperation(approvalOp(opId, deviceId));
    const { txId, csrf } = await mintTx(store, opId, deviceId);
    const csrfHash = await sha256Hex(csrf);

    const started = await store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve");
    assert.ok(started);
    assert.equal(started!.status, "created");
    assert.equal(started!.outbox.delivery_status, "pending");
    assert.equal(started!.outbox.correlation_id, `cor_${txId}`);
    assert.equal(started!.tx.consumed, true);

    const outbox = await store.getMcpApprovalOutbox(txId);
    assert.ok(outbox, "outbox must exist whenever tx is consumed");
    assert.equal(outbox!.decision, "approve");
    assert.equal(outbox!.correlation_id, `cor_${txId}`);
  }
});

test("outbox conflict cannot consume a transaction without creating its outbox", async () => {
  const { db, store } = openSql();
  await store.ensureBootstrap();
  const deviceId = "dev_outbox_conflict_01abcd";
  await putDevice(store, deviceId);
  const opId = randomId("op_");
  await store.putMcpOperation(approvalOp(opId, deviceId));
  const { txId, csrf } = await mintTx(store, opId, deviceId);

  db.prepare(
    `INSERT INTO mcp_approval_outbox
     (id, operation_id, principal_id, tenant_id, device_id, decision,
      correlation_id, delivery_status, attempts, last_error, created_at, delivered_at)
     VALUES (?, ?, 'prin_dev', 'ten_default', ?, 'approve', ?, 'pending', 0, NULL, ?, NULL)`,
  ).run("apr_existing", opId, deviceId, "cor_existing", new Date().toISOString());

  const started = await store.beginMcpApprovalOutbox(
    txId,
    await sha256Hex(csrf),
    "prin_dev",
    "approve",
  );
  assert.equal(started, null);
  const tx = db
    .prepare(`SELECT consumed, decision FROM mcp_approval_transactions WHERE id = ?`)
    .get(txId) as { consumed: number; decision: string | null };
  assert.equal(tx.consumed, 0);
  assert.equal(tx.decision, null);
  assert.equal(await store.getMcpApprovalOutbox(txId), null);
});

test("concurrent begin yields one created decision; loser resumes authoritative outbox", async () => {
  const { store } = openSql();
  await store.ensureBootstrap();
  const deviceId = "dev_conc_begin_01abcdefab";
  await putDevice(store, deviceId);
  const opId = randomId("op_");
  await store.putMcpOperation(approvalOp(opId, deviceId));
  const { txId, csrf } = await mintTx(store, opId, deviceId);
  const csrfHash = await sha256Hex(csrf);

  const [a, b] = await Promise.all([
    store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve"),
    store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve"),
  ]);
  const results = [a, b].filter(Boolean);
  assert.equal(results.length, 2);
  const created = results.filter((r) => r!.status === "created");
  const resumed = results.filter(
    (r) => r!.status === "pending_retry" || r!.status === "already_delivered",
  );
  // Exactly one creator; the other must see the same outbox (resume), not null.
  assert.equal(created.length, 1);
  assert.equal(resumed.length, 1);
  assert.equal(created[0]!.outbox.id, resumed[0]!.outbox.id);
  assert.equal(created[0]!.outbox.correlation_id, resumed[0]!.outbox.correlation_id);
});

test("pending→delivering claim: only one concurrent route; loser gets authoritative state", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    await store.ensureBootstrap();
    const deviceId = `dev_claim_${store.kind}`.padEnd(24, "a").slice(0, 24);
    await putDevice(store, deviceId);
    const opId = randomId("op_");
    await store.putMcpOperation(approvalOp(opId, deviceId));
    const { txId, csrf } = await mintTx(store, opId, deviceId);
    const csrfHash = await sha256Hex(csrf);
    const started = await store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve");
    assert.equal(started!.status, "created");

    const [c1, c2] = await Promise.all([
      store.claimMcpApprovalOutboxDelivery(txId),
      store.claimMcpApprovalOutboxDelivery(txId),
    ]);
    const claims = [c1, c2];
    assert.equal(claims.filter(Boolean).length, 1);
    assert.equal(claims.find(Boolean)!.delivery_status, "delivering");

    // Loser path via handleApprove returns authoritative conflict, no second delivery.
    const deliveries: string[] = [];
    const routeToDevice = async () => {
      deliveries.push("route");
      return { status: "routed_to_device" as const, detail: {} };
    };

    // Winner still holding delivering — concurrent POST must not route again.
    const tok = await seed(store);
    const lose = await handleApprove(
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
    assert.equal(lose.status, 409);
    const body = (await lose.json()) as {
      authoritative?: boolean;
      delivery_status?: string;
      operation_id?: string;
    };
    assert.equal(body.authoritative, true);
    assert.equal(body.delivery_status, "delivering");
    assert.equal(body.operation_id, opId);
    assert.equal(deliveries.length, 0);

    // Winner finalizes once (must present claim owner token/version).
    const winner = claims.find(Boolean)!;
    assert.ok(winner.claim_token);
    assert.ok((winner.claim_version ?? 0) >= 1);
    const updated = await store.finalizeMcpApprovalDelivery(
      txId,
      winner.claim_token!,
      winner.claim_version!,
    );
    assert.ok(updated);
    assert.equal(updated!.status, "pending");
    const box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box!.delivery_status, "delivered");
  }
});

test("concurrent /approve: exactly one delivery; duplicate returns authoritative state", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    await store.ensureBootstrap();
    const deviceId = `dev_race_apr_${store.kind}`.padEnd(24, "a").slice(0, 24);
    await putDevice(store, deviceId);
    const opId = randomId("op_");
    await store.putMcpOperation(approvalOp(opId, deviceId));
    const { txId, csrf } = await mintTx(store, opId, deviceId);
    const tok = await seed(store);

    let routes = 0;
    const routeToDevice = async (
      _d: string,
      op: { correlation_id: string },
    ) => {
      routes += 1;
      // Stable correlation from outbox id.
      assert.equal(op.correlation_id, `cor_${txId}`);
      return { status: "routed_to_device" as const, detail: { recipients: 1 } };
    };

    const post = () =>
      handleApprove(
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

    const [r1, r2] = await Promise.all([post(), post()]);
    const statuses = [r1.status, r2.status].sort();
    // One success (200), one authoritative conflict/already-used (409 or 400).
    assert.ok(statuses.includes(200), `expected one 200, got ${statuses}`);
    assert.ok(
      statuses.includes(409) || statuses.includes(400),
      `expected loser 409/400, got ${statuses}`,
    );
    assert.equal(routes, 1, "exactly one device delivery");

    const op = await store.getMcpOperation(opId);
    assert.equal(op?.status, "pending");
    assert.equal(op?.approval_required, false);
    const box = await store.getMcpApprovalOutbox(txId);
    assert.equal(box?.delivery_status, "delivered");

    // Retry after delivered does not re-deliver.
    const third = await post();
    assert.equal(third.status, 400);
    const thirdBody = (await third.json()) as { authoritative?: boolean; delivery_status?: string };
    assert.equal(thirdBody.authoritative, true);
    assert.equal(thirdBody.delivery_status, "delivered");
    assert.equal(routes, 1);
  }
});

test("delivery failure releases claim to pending; retry delivers once", async () => {
  const store = openSql().store;
  await store.ensureBootstrap();
  const deviceId = "dev_retry_claim_01abcdef";
  await putDevice(store, deviceId);
  const opId = randomId("op_");
  await store.putMcpOperation(approvalOp(opId, deviceId));
  const { txId, csrf } = await mintTx(store, opId, deviceId);
  const tok = await seed(store);

  let failNext = true;
  let routes = 0;
  const routeToDevice = async () => {
    if (failNext) {
      failNext = false;
      return { status: "device_offline" as const, detail: {} };
    }
    routes += 1;
    return { status: "routed_to_device" as const, detail: {} };
  };

  const post = () =>
    handleApprove(
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

  const failed = await post();
  assert.equal(failed.status, 503);
  const failBody = (await failed.json()) as { delivery_status?: string; retryable?: boolean };
  assert.equal(failBody.delivery_status, "pending");
  assert.equal(failBody.retryable, true);
  assert.equal((await store.getMcpApprovalOutbox(txId))?.delivery_status, "pending");
  assert.equal((await store.getMcpOperation(opId))?.status, "approval_required");

  const ok = await post();
  assert.equal(ok.status, 200);
  assert.equal(routes, 1);
  assert.equal((await store.getMcpApprovalOutbox(txId))?.delivery_status, "delivered");
  assert.equal((await store.getMcpOperation(opId))?.status, "pending");
});

test("finalize does not overwrite fast terminal op result", async () => {
  for (const store of [new MemoryStore(), openSql().store] as const) {
    await store.ensureBootstrap();
    const deviceId = `dev_fast_${store.kind}`.padEnd(24, "a").slice(0, 24);
    await putDevice(store, deviceId);
    const opId = randomId("op_");
    await store.putMcpOperation(approvalOp(opId, deviceId));
    const { txId, csrf } = await mintTx(store, opId, deviceId);
    const csrfHash = await sha256Hex(csrf);

    const started = await store.beginMcpApprovalOutbox(txId, csrfHash, "prin_dev", "approve");
    assert.ok(started);
    const claimed = await store.claimMcpApprovalOutboxDelivery(txId);
    assert.ok(claimed);
    assert.ok(claimed!.claim_token);
    assert.ok((claimed!.claim_version ?? 0) >= 1);

    // Fast device result lands before finalize.
    const terminal = await store.updateMcpOperation(
      opId,
      {
        status: "success",
        summary: "device finished early",
        approval_required: false,
        data: { early: true },
      },
      ["approval_required"],
    );
    assert.equal(terminal?.status, "success");

    const finalized = await store.finalizeMcpApprovalDelivery(
      txId,
      claimed!.claim_token!,
      claimed!.claim_version!,
    );
    assert.ok(finalized);
    assert.equal(finalized!.status, "success", "must keep fast terminal status");
    assert.equal(finalized!.summary, "device finished early");
    assert.equal((await store.getMcpApprovalOutbox(txId))?.delivery_status, "delivered");
  }
});

test("invalid outbox decision/delivery_status fail closed on read", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  // Bypass type system to inject invalid row.
  (store as unknown as { mcpApprovalOutbox: Map<string, unknown> }).mcpApprovalOutbox.set("bad", {
    id: "bad",
    operation_id: "op",
    principal_id: "p",
    tenant_id: "t",
    decision: "maybe",
    correlation_id: "c",
    delivery_status: "pending",
    attempts: 0,
    last_error: null,
    created_at: "now",
    delivered_at: null,
  });
  assert.equal(await store.getMcpApprovalOutbox("bad"), null);

  (store as unknown as { mcpApprovalOutbox: Map<string, unknown> }).mcpApprovalOutbox.set("bad2", {
    id: "bad2",
    operation_id: "op2",
    principal_id: "p",
    tenant_id: "t",
    decision: "approve",
    correlation_id: "c",
    delivery_status: "shipped",
    attempts: 0,
    last_error: null,
    created_at: "now",
    delivered_at: null,
  });
  assert.equal(await store.getMcpApprovalOutbox("bad2"), null);
});

test("/approve POST bearer requires write or exec scope; read-only rejected", async () => {
  const store = new MemoryStore();
  const readTok = await seed(store, "ownmesh.read");
  const writeTok = await seed(store, "ownmesh.write");
  const execTok = await seed(store, "ownmesh.exec");
  const noneTok = await seed(store, "");
  const deviceId = "dev_scope_apr_01abcdefab";
  await putDevice(store, deviceId);
  const opId = randomId("op_");
  await store.putMcpOperation(approvalOp(opId, deviceId));

  __setTestStore(store);
  const ctx = {
    waitUntil() {},
    passThroughOnException() {},
  } as unknown as ExecutionContext;

  try {
    // GET with read-only still allowed (form render).
    const getRead = await worker.fetch(
      new Request(`https://cp.test/approve?operation_id=${opId}`, {
        headers: { authorization: `Bearer ${readTok.access_token}` },
      }),
      {},
      ctx,
    );
    assert.equal(getRead.status, 200);

    const html = await getRead.text();
    const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
    assert.ok(tx && csrf);

    const postWith = (token: string) =>
      worker.fetch(
        new Request(`https://cp.test/approve?operation_id=${opId}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "application/json",
            authorization: `Bearer ${token}`,
            origin: "https://cp.test",
          },
          body: JSON.stringify({
            decision: "approve",
            transaction_id: tx,
            csrf_token: csrf,
            operation_id: opId,
          }),
        }),
        {},
        ctx,
      );

    // Worker-level scope gate (before delivery).
    const readDenied = await postWith(readTok.access_token);
    assert.equal(readDenied.status, 403);
    const readBody = (await readDenied.json()) as { error?: string };
    assert.equal(readBody.error, "insufficient_scope");

    const noneDenied = await postWith(noneTok.access_token);
    assert.equal(noneDenied.status, 403);
    assert.equal(((await noneDenied.json()) as { error?: string }).error, "insufficient_scope");

    // write/exec may decide via handleApprove (mock route; worker needs DEVICE_ROOM).
    const routeToDevice = async () => ({ status: "routed_to_device" as const, detail: {} });

    const get2 = await handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId}`, {
        headers: { authorization: `Bearer ${writeTok.access_token}` },
      }),
      store,
      { principal: { id: "prin_dev", tenant_id: "ten_default" }, routeToDevice },
    );
    assert.equal(get2.status, 200);
    const html2 = await get2.text();
    const tx2 = /name="transaction_id" value="([^"]+)"/.exec(html2)?.[1];
    const csrf2 = /name="csrf_token" value="([^"]+)"/.exec(html2)?.[1];
    assert.ok(tx2 && csrf2);

    const writeOk = await handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${writeTok.access_token}`,
          origin: "https://cp.test",
        },
        body: JSON.stringify({
          decision: "deny",
          transaction_id: tx2,
          csrf_token: csrf2,
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
    assert.equal(writeOk.status, 200, await writeOk.clone().text());
    assert.equal((await store.getMcpOperation(opId))?.status, "denied");

    // exec scope also permitted on a new op.
    const opId2 = randomId("op_");
    await store.putMcpOperation(approvalOp(opId2, deviceId));
    const get3 = await handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId2}`, {
        headers: { authorization: `Bearer ${execTok.access_token}` },
      }),
      store,
      { principal: { id: "prin_dev", tenant_id: "ten_default" }, routeToDevice },
    );
    const html3 = await get3.text();
    const tx3 = /name="transaction_id" value="([^"]+)"/.exec(html3)?.[1];
    const csrf3 = /name="csrf_token" value="([^"]+)"/.exec(html3)?.[1];
    const execOk = await handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId2}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${execTok.access_token}`,
          origin: "https://cp.test",
        },
        body: JSON.stringify({
          decision: "deny",
          transaction_id: tx3,
          csrf_token: csrf3,
          operation_id: opId2,
        }),
      }),
      store,
      {
        principal: { id: "prin_dev", tenant_id: "ten_default" },
        originAllowed: true,
        routeToDevice,
      },
    );
    assert.equal(execOk.status, 200, await execOk.clone().text());

    // Worker gate still accepts write-scoped bearer (scope check passes; may 503 without DO).
    const opId3 = randomId("op_");
    await store.putMcpOperation(approvalOp(opId3, deviceId));
    const getW = await worker.fetch(
      new Request(`https://cp.test/approve?operation_id=${opId3}`, {
        headers: { authorization: `Bearer ${writeTok.access_token}` },
      }),
      {},
      ctx,
    );
    const htmlW = await getW.text();
    const txW = /name="transaction_id" value="([^"]+)"/.exec(htmlW)?.[1];
    const csrfW = /name="csrf_token" value="([^"]+)"/.exec(htmlW)?.[1];
    const writeScoped = await worker.fetch(
      new Request(`https://cp.test/approve?operation_id=${opId3}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${writeTok.access_token}`,
          origin: "https://cp.test",
        },
        body: JSON.stringify({
          decision: "approve",
          transaction_id: txW,
          csrf_token: csrfW,
          operation_id: opId3,
        }),
      }),
      {},
      ctx,
    );
    // Must not be insufficient_scope (403); delivery may fail without DEVICE_ROOM.
    assert.notEqual(writeScoped.status, 403);
    assert.notEqual(
      ((await writeScoped.clone().json()) as { error?: string }).error,
      "insufficient_scope",
    );
  } finally {
    __setTestStore(null);
  }
});
