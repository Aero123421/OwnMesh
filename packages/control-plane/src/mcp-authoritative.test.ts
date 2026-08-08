/**
 * Authoritative MCP operation/result/approval persistence (D1/sql + Memory).
 * OperationTracker is cache-only; store survives "isolate empty" restarts.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  OperationTracker,
  handleApprove,
  handleMcp,
  createHarnessRouter,
} from "./mcp.ts";
import {
  MemoryStore,
  SqlStore,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { applyMcpOperationResult, DeviceRoomHarness } from "./device-room.ts";
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
      const out: T[] = [];
      for (const s of statements) out.push((await s.run()) as T);
      return out;
    },
  };
}

function openSqlStore(): SqlStore {
  return openSqlStoreWithDb().store;
}

function openSqlStoreWithDb(): { db: DatabaseSync; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  for (const f of readdirSync(migrationsDir).filter((x) => x.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  return { db, store: new SqlStore(adaptSqlite(db), "sqlite") };
}

async function seedAuthed(store: MemoryStore | SqlStore, principal = "prin_dev") {
  await store.ensureBootstrap();
  if (store.kind !== "memory") {
    // SqlStore bootstrap already has prin_dev; ensure client
    await store.putClient({
      client_id: "client_mcp",
      tenant_id: "ten_default",
      client_name: "mcp",
      redirect_uris: ["http://127.0.0.1/cb"],
      created_at: new Date().toISOString(),
    });
  } else {
    await store.putClient({
      client_id: "client_mcp",
      tenant_id: "ten_default",
      client_name: "mcp",
      redirect_uris: ["http://127.0.0.1/cb"],
      created_at: new Date().toISOString(),
    });
  }
  const tok = await store.issueTokens(
    "client_mcp",
    principal,
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device",
  );
  return tok;
}

async function putActiveDevice(
  store: MemoryStore | SqlStore,
  id: string,
  principal = "prin_dev",
) {
  await store.putDevice({
    id,
    tenant_id: "ten_default",
    principal_id: principal,
    name: id,
    hostname: id,
    os: "test",
    arch: "x64",
    agent_version: "1",
    protocol_version: "ownmesh.device/1.0",
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  });
}

function rpc(name: string, args: Record<string, unknown>, token: string): Request {
  return new Request("https://cp.test/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
}

const ctx = {
  waitUntil() {},
  passThroughOnException() {},
  props: {},
} as unknown as ExecutionContext;

test("migration 0005 creates mcp_operations, mcp_approval_transactions, and outbox", () => {
  const db = new DatabaseSync(":memory:");
  for (const f of readdirSync(migrationsDir).filter((x) => x.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  const tables = db
    .prepare(`SELECT name FROM sqlite_master WHERE type='table' ORDER BY name`)
    .all() as { name: string }[];
  const names = tables.map((t) => t.name);
  assert.ok(names.includes("mcp_operations"));
  assert.ok(names.includes("mcp_approval_transactions"));
  assert.ok(names.includes("mcp_approval_outbox"));
  // Idempotent re-apply
  db.exec(readFileSync(join(migrationsDir, "0005_mcp_operations.sql"), "utf8"));
});

test("schemaReadiness tracks 0005 MCP objects for both store kinds", async () => {
  const mem = new MemoryStore();
  const memR = await mem.schemaReadiness();
  assert.equal(memR.schema_ready, true);
  assert.equal(memR.checks.mcp_operations, true);
  assert.equal(memR.checks.mcp_approval_transactions, true);
  assert.equal(memR.checks.mcp_approval_outbox, true);

  const sql = openSqlStore();
  const sqlR = await sql.schemaReadiness();
  assert.equal(sqlR.schema_ready, true);
  assert.equal(sqlR.checks.mcp_operations, true);
  assert.equal(sqlR.checks.mcp_approval_transactions, true);
  assert.equal(sqlR.checks.mcp_approval_outbox, true);
});

test("store is authoritative: empty tracker still polls after isolate restart", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_auth_persist_01abcdef";
  await putActiveDevice(store, deviceId);

  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  room.router.sessions.get(agent)!.phase = "ready";
  room.router.sessions.get(agent)!.remote_routing_enabled = true;

  const tracker1 = new OperationTracker();
  const router = createHarnessRouter({
    inject: (_id, op) => {
      const r = room.router.injectOperation(op);
      if (r.status !== "routed_to_device") return r;
      return {
        status: "routed_to_device",
        detail: {
          status: "pending",
          operation_id: op.payload.operation_id,
        },
      };
    },
  });

  const createRes = await handleMcp(
    rpc("ownmesh_command_run", { device_id: deviceId, program: "echo", args: ["hi"], async: true, idempotency_key: "idem_auth_cmd" }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { issuer: "https://cp.test", tracker: tracker1 },
  );
  const created = (await createRes.json()) as {
    result: { structuredContent: { operation_id: string; status: string } };
  };
  const opId = created.result.structuredContent.operation_id;
  assert.ok(opId);
  assert.equal((await store.getMcpOperation(opId))?.status, "pending");

  // Simulate Worker isolate restart: brand-new tracker (empty Map), same store.
  const tracker2 = new OperationTracker();
  assert.equal(tracker2.get(opId), undefined);

  const pollRes = await handleMcp(
    rpc("ownmesh_get_operation", { operation_id: opId }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { issuer: "https://cp.test", tracker: tracker2 },
  );
  const polled = (await pollRes.json()) as {
    result: { structuredContent: { operation_id: string; status: string } };
  };
  assert.equal(polled.result.structuredContent.operation_id, opId);
  assert.equal(polled.result.structuredContent.status, "pending");
});

test("SqlStore put/get/update MCP operation + result apply", async () => {
  const store = openSqlStore();
  await store.ensureBootstrap();
  const opId = randomId("op_");
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: "dev_sql_01",
    tool: "ownmesh_fs_list",
    status: "pending",
    summary: "routed",
    data: { tool: "ownmesh_fs_list" },
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "cor_sql_1",
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  const got = await store.getMcpOperation(opId);
  assert.equal(got?.status, "pending");
  assert.equal((await store.getMcpOperationByCorrelation("cor_sql_1"))?.operation_id, opId);

  const applied = await applyMcpOperationResult(store, {
    correlationId: "cor_sql_1",
    payload: { status: "completed", summary: "done", result: { entries: ["a"] } },
    deviceId: "dev_sql_01",
  });
  assert.equal(applied.ok, true);
  assert.ok(applied.ok && applied.record);
  assert.equal(applied.ok && applied.record?.status, "completed");
  assert.deepEqual(applied.ok && applied.record?.data, { entries: ["a"] });
});

test("poll/cancel reject foreign principal (owner check)", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.putClient({
    client_id: "c",
    tenant_id: "ten_default",
    client_name: "c",
    redirect_uris: ["http://127.0.0.1/cb"],
    created_at: new Date().toISOString(),
  });
  const owner = await store.issueTokens("c", "owner", "ownmesh.read ownmesh.exec");
  const attacker = await store.issueTokens("c", "attacker", "ownmesh.read ownmesh.exec");
  const opId = "op_secret_owner";
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "owner",
    device_id: "dev_x",
    tool: "x",
    status: "pending",
    summary: "secret",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  for (const name of ["ownmesh_get_operation", "ownmesh_cancel_operation"] as const) {
    const res = await handleMcp(
      rpc(name, { operation_id: opId }, attacker.access_token),
      store,
      new URL("https://cp.test/mcp"),
    );
    const body = await res.json() as { result?: { structuredContent?: { summary?: string } }; error?: unknown };
    const text = JSON.stringify(body);
    assert.match(text, /unknown operation|not found/i);
  }
  assert.equal((await store.getMcpOperation(opId))?.status, "pending");
  assert.ok(owner.access_token);
});

test("revoked/expired device credential fails create/poll/cancel (MCP path)", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_cred_gate_01abcdef01";
  await putActiveDevice(store, deviceId);
  const device = (await store.getDevice(deviceId))!;
  const cred = await store.issueDeviceCredential(device, 60_000);

  // Create succeeds while credential valid
  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  room.router.sessions.get(agent)!.phase = "ready";
  room.router.sessions.get(agent)!.remote_routing_enabled = true;
  const router = createHarnessRouter({
    inject: (_id, op) => room.router.injectOperation(op),
  });
  const tracker = new OperationTracker();
  const created = await handleMcp(
    rpc("ownmesh_fs_list", { device_id: deviceId, path: "/", async: true }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { tracker, issuer: "https://cp.test" },
  );
  const createdBody = (await created.json()) as {
    result?: { structuredContent?: { operation_id?: string } };
    error?: { message?: string };
  };
  assert.ok(createdBody.result?.structuredContent?.operation_id);
  const opId = createdBody.result!.structuredContent!.operation_id!;

  // Revoke credential (and ensure no other valid ones)
  const hash = await sha256Hex(cred.token);
  const rec = store.deviceCredentials.get(hash)!;
  rec.revoked = true;
  store.deviceCredentials.set(hash, rec);

  // New create rejected
  const create2 = await handleMcp(
    rpc("ownmesh_fs_list", { device_id: deviceId, path: "/" }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { tracker, issuer: "https://cp.test" },
  );
  const c2 = (await create2.json()) as { error?: { message?: string } };
  assert.equal(c2.error?.message, "device_credential_revoked");

  // Poll rejected
  const poll = await handleMcp(
    rpc("ownmesh_get_operation", { operation_id: opId }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { tracker, issuer: "https://cp.test" },
  );
  const p = (await poll.json()) as { error?: { message?: string } };
  assert.equal(p.error?.message, "device_credential_revoked");

  // Cancel rejected
  const cancel = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { tracker, issuer: "https://cp.test" },
  );
  const k = (await cancel.json()) as { error?: { message?: string } };
  assert.equal(k.error?.message, "device_credential_revoked");

  // Expired credential also fails create
  rec.revoked = false;
  rec.expires_at = Date.now() - 1000;
  store.deviceCredentials.set(hash, rec);
  const create3 = await handleMcp(
    rpc("ownmesh_fs_read", { device_id: deviceId, path: "/x" }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    { routeToDevice: async () => ({ status: "should_not_run" }) },
    { tracker, issuer: "https://cp.test" },
  );
  const c3 = (await create3.json()) as { error?: { message?: string } };
  assert.equal(c3.error?.message, "device_credential_revoked");
});

test("/approve auth+CSRF+one-time delivers decision to DeviceRoom; double approve rejected", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_approve_flow_01abcdef";
  await putActiveDevice(store, deviceId);

  const opId = randomId("op_");
  const corr = randomId("cor_");
  await store.putMcpOperation({
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
    correlation_id: corr,
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const deliveries: Array<{ type: string; payload: Record<string, unknown> }> = [];
  const routeToDevice = async (
    _deviceId: string,
    operation: { type: string; payload: Record<string, unknown>; correlation_id: string },
  ) => {
    deliveries.push({ type: operation.type, payload: operation.payload });
    return { status: "routed_to_device", detail: { recipients: 1 } };
  };

  // Unregistered principal fail-closed
  const unauth = await handleApprove(
    new Request(`https://cp.test/approve?operation_id=${opId}`),
    store,
    {
      principal: { id: "nope", tenant_id: "ten_default" },
      authSource: "browser",
    },
  );
  assert.equal(unauth.status, 403);

  // Wrong registered human must not see foreign op.
  await store.ensurePrincipal("prin_other", "Other", "human", "ten_default");
  const wrong = await handleApprove(
    new Request(`https://cp.test/approve?operation_id=${opId}`),
    store,
    {
      principal: { id: "prin_other", tenant_id: "ten_default" },
      authSource: "browser",
    },
  );
  assert.equal(wrong.status, 404);

  // Creator bearer path rejected inside handler.
  const bearerDenied = await handleApprove(
    new Request(`https://cp.test/approve?operation_id=${opId}`, {
      headers: { authorization: `Bearer ${tok.access_token}` },
    }),
    store,
    {
      issuer: "https://cp.test",
      principal: { id: "prin_dev", tenant_id: "ten_default" },
      authSource: "bearer",
      routeToDevice,
    },
  );
  assert.equal(bearerDenied.status, 403);

  const getRes = await handleApprove(
    new Request(`https://cp.test/approve?operation_id=${opId}`),
    store,
    {
      issuer: "https://cp.test",
      principal: { id: "prin_dev", tenant_id: "ten_default" },
      authSource: "browser",
      routeToDevice,
    },
  );
  assert.equal(getRes.status, 200);
  const html = await getRes.text();
  const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(tx && csrf);

  const postOnce = () =>
    handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          origin: "https://cp.test",
        },
        body: JSON.stringify({
          decision: "approve",
          transaction_id: tx,
          csrf_token: csrf,
          operation_id: opId,
        }),
      }),
      store,
      {
        issuer: "https://cp.test",
        principal: { id: "prin_dev", tenant_id: "ten_default" },
        authSource: "browser",
        originAllowed: true,
        routeToDevice,
      },
    );

  const first = await postOnce();
  assert.equal(first.status, 200, await first.clone().text());
  const firstBody = (await first.json()) as { ok: boolean; decision: string; status: string };
  assert.equal(firstBody.ok, true);
  assert.equal(firstBody.decision, "approve");
  assert.equal(firstBody.status, "pending");
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0]!.type, "approval.decision");
  assert.equal(deliveries[0]!.payload.decision, "approve");
  // Decision frame has its own operation_id; original op is target_operation_id.
  assert.equal(
    deliveries[0]!.payload.target_operation_id ||
      (deliveries[0]!.payload.arguments as { target_operation_id?: string } | undefined)
        ?.target_operation_id,
    opId,
  );

  // Double approve with same tx rejected (already delivered)
  const second = await postOnce();
  assert.equal(second.status, 400);

  // Fresh GET while no longer approval_required → conflict
  const get2 = await handleApprove(
    new Request(`https://cp.test/approve?operation_id=${opId}`),
    store,
    {
      principal: { id: "prin_dev", tenant_id: "ten_default" },
      authSource: "browser",
      routeToDevice,
    },
  );
  assert.equal(get2.status, 409);
});

test("/approve delivery failure is retryable non-success; retry delivers exactly once", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await store.ensureBootstrap();
    const tok = await seedAuthed(store);
    const deviceId = `dev_approve_retry_${store.kind}`.padEnd(24, "a").slice(0, 24);
    await putActiveDevice(store, deviceId);

    const opId = randomId("op_");
    const corr = randomId("cor_");
    await store.putMcpOperation({
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
      correlation_id: corr,
      policy_authority: "ownmesh_device",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });

    let failNext = true;
    const deliveries: Array<{ type: string; payload: Record<string, unknown> }> = [];
    const routeToDevice = async (
      _deviceId: string,
      operation: { type: string; payload: Record<string, unknown>; correlation_id: string },
    ) => {
      if (failNext) {
        failNext = false;
        return { status: "device_offline", detail: { reason: "simulated" } };
      }
      deliveries.push({ type: operation.type, payload: operation.payload });
      return { status: "routed_to_device", detail: { recipients: 1 } };
    };

    const getRes = await handleApprove(
      new Request(`https://cp.test/approve?operation_id=${opId}`),
      store,
      {
        issuer: "https://cp.test",
        principal: { id: "prin_dev", tenant_id: "ten_default" },
        authSource: "browser",
        routeToDevice,
      },
    );
    assert.equal(getRes.status, 200);
    const html = await getRes.text();
    const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
    assert.ok(tx && csrf);
    void tok; // creator bearer intentionally unused for approval

    const postOnce = () =>
      handleApprove(
        new Request(`https://cp.test/approve?operation_id=${opId}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "application/json",
            origin: "https://cp.test",
          },
          body: JSON.stringify({
            decision: "approve",
            transaction_id: tx,
            csrf_token: csrf,
            operation_id: opId,
          }),
        }),
        store,
        {
          issuer: "https://cp.test",
          principal: { id: "prin_dev", tenant_id: "ten_default" },
          authSource: "browser",
          originAllowed: true,
          routeToDevice,
        },
      );

    const failed = await postOnce();
    assert.equal(failed.status, 503, await failed.clone().text());
    const failBody = (await failed.json()) as {
      ok?: boolean;
      error: string;
      retryable?: boolean;
      delivery_status?: string;
    };
    assert.notEqual(failBody.ok, true);
    assert.equal(failBody.error, "delivery_failed");
    assert.equal(failBody.retryable, true);
    assert.equal(failBody.delivery_status, "pending");
    // Operation must NOT be irreversibly transitioned on delivery failure.
    const mid = await store.getMcpOperation(opId);
    assert.equal(mid?.status, "approval_required");
    assert.equal(mid?.approval_required, true);
    assert.equal(deliveries.length, 0);

    // Decision durable in outbox
    const outbox = await store.getMcpApprovalOutbox(tx!);
    assert.ok(outbox);
    assert.equal(outbox!.delivery_status, "pending");
    assert.equal(outbox!.decision, "approve");
    assert.ok(outbox!.attempts >= 1);

    // Retry with same one-time tx delivers exactly once and CAS-transitions.
    const retry = await postOnce();
    assert.equal(retry.status, 200, await retry.clone().text());
    const retryBody = (await retry.json()) as { ok: boolean; status: string };
    assert.equal(retryBody.ok, true);
    assert.equal(retryBody.status, "pending");
    assert.equal(deliveries.length, 1);
    assert.equal(
      deliveries[0]!.payload.target_operation_id ||
        (deliveries[0]!.payload.arguments as { target_operation_id?: string } | undefined)
          ?.target_operation_id,
      opId,
    );

    const after = await store.getMcpOperation(opId);
    assert.equal(after?.status, "pending");
    assert.equal(after?.approval_required, false);

    const delivered = await store.getMcpApprovalOutbox(tx!);
    assert.equal(delivered?.delivery_status, "delivered");

    // Further retry does not re-deliver
    const third = await postOnce();
    assert.equal(third.status, 400);
    assert.equal(deliveries.length, 1);
  }
});

test("assertDeviceOperableForMcp fails closed on missing/broken credential schema", async () => {
  // Full migrations then drop/break credentials table — must not treat as "no credentials".
  const { db, store } = openSqlStoreWithDb();
  await store.ensureBootstrap();
  const deviceId = "dev_schema_fail_01abcdef";
  await putActiveDevice(store, deviceId);

  // Sanity: operable when schema is intact and no credentials issued.
  const okGate = await store.assertDeviceOperableForMcp(deviceId, "prin_dev", "ten_default");
  assert.equal(okGate.ok, true);

  db.exec(`DROP TABLE device_credentials`);
  const gate = await store.assertDeviceOperableForMcp(deviceId, "prin_dev", "ten_default");
  assert.equal(gate.ok, false);
  if (!gate.ok) {
    assert.equal(gate.error, "device_credentials_unavailable");
  }

  // Broken projection (table exists but required columns missing) also fails closed.
  db.exec(`CREATE TABLE device_credentials (credential_hash TEXT PRIMARY KEY)`);
  const gate2 = await store.assertDeviceOperableForMcp(deviceId, "prin_dev", "ten_default");
  assert.equal(gate2.ok, false);
  if (!gate2.ok) {
    assert.equal(gate2.error, "device_credentials_unavailable");
  }
});

test("worker /approve no longer returns 501; requires auth", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  __setTestStore(store);
  const authProvider = {
    fetch: async () =>
      Response.json({ principal_id: "prin_dev", tenant_id: "ten_default" }),
  } as unknown as Fetcher;
  try {
    const unauth = await worker.fetch(new Request("https://cp.test/approve"), {}, ctx);
    assert.equal(unauth.status, 401);

    // Creator bearer cannot act as human approval session.
    const bearerDenied = await worker.fetch(
      new Request("https://cp.test/approve", {
        headers: { authorization: `Bearer ${tok.access_token}` },
      }),
      { AUTH_PROVIDER: authProvider },
      ctx,
    );
    assert.equal(bearerDenied.status, 403);

    const authNoOp = await worker.fetch(
      new Request("https://cp.test/approve"),
      { AUTH_PROVIDER: authProvider },
      ctx,
    );
    // Implemented: missing operation_id → 400 (not 501 stub)
    assert.equal(authNoOp.status, 400);
    assert.notEqual(authNoOp.status, 501);
  } finally {
    __setTestStore(null);
  }
});

test("DeviceRoom operation.result updates authoritative MCP store state", async () => {
  const store = openSqlStore();
  await store.ensureBootstrap();
  const deviceId = "dev_result_do_01abcdef";
  await putActiveDevice(store, deviceId);
  const opId = randomId("op_");
  const corr = randomId("cor_");
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_list",
    status: "pending",
    summary: "routed",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: corr,
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  // Direct apply path (same helper DeviceRoom uses)
  const updated = await applyMcpOperationResult(store, {
    operationId: opId,
    correlationId: corr,
    payload: {
      status: "completed",
      operation_id: opId,
      summary: "listed",
      result: { entries: ["README.md"] },
    },
    deviceId,
  });
  assert.equal(updated.ok, true);
  assert.equal(updated.ok && updated.record?.status, "completed");
  assert.equal((await store.getMcpOperation(opId))?.status, "completed");
});

test("loadOp has no tracker fallback: tracker-only ops are invisible", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const tracker = new OperationTracker();
  const ghostId = "op_ghost_tracker_only";
  tracker.put({
    operation_id: ghostId,
    status: "completed",
    summary: "ghost",
    data: { leaked: true },
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    policy_authority: "ownmesh_device",
    tool: "ownmesh_fs_list",
    principal: "prin_dev",
    tenant_id: "ten_default",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });
  const res = await handleMcp(
    rpc("ownmesh_get_operation", { operation_id: ghostId }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    undefined,
    { tracker },
  );
  const body = await res.json() as { result?: { structuredContent?: { summary?: string; data?: unknown } } };
  assert.match(JSON.stringify(body), /unknown operation|not found/i);
  assert.ok(!JSON.stringify(body).includes("leaked"));
});

test("cancel owner path updates store and is CAS-safe", async () => {
  const store = new MemoryStore();
  const tok = await seedAuthed(store);
  const deviceId = "dev_cancel_cas_01abcdef";
  await putActiveDevice(store, deviceId);
  const opId = randomId("op_");
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_command_run",
    status: "running",
    summary: "running",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: randomId("cor_"),
    policy_authority: "ownmesh_device",
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const routed: string[] = [];
  const res = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: async (id, op) => {
        routed.push(`${id}:${op.type}`);
        return { status: "routed_to_device" };
      },
    },
    { tracker: new OperationTracker() },
  );
  const body = (await res.json()) as { result: { structuredContent: { status: string } } };
  // Device-bound cancel only advances to cancel_requested after successful route.
  assert.equal(body.result.structuredContent.status, "cancel_requested");
  assert.equal((await store.getMcpOperation(opId))?.status, "cancel_requested");
  assert.ok(
    routed[0]?.includes("cancel") || routed[0]?.includes("ownmesh_cancel_operation"),
    `cancel route type should be cancel action, got ${routed[0]}`,
  );

  // Second cancel: durable claim replay — no second device route, target stays cancel_requested.
  let secondRoutes = 0;
  const res2 = await handleMcp(
    rpc("ownmesh_cancel_operation", { operation_id: opId }, tok.access_token),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: async () => {
        secondRoutes += 1;
        return { status: "should_not" };
      },
    },
    { tracker: new OperationTracker() },
  );
  const body2 = (await res2.json()) as {
    result: { structuredContent: { status: string; summary: string } };
  };
  assert.equal(body2.result.structuredContent.status, "cancel_requested");
  assert.equal(secondRoutes, 0, "idempotent cancel claim must not re-route");
  assert.equal((await store.getMcpOperation(opId))?.status, "cancel_requested");
});
