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
  await store.putWorkspace({
    workspace_id: "ws_default",
    tenant_id: "ten_default",
    device_id: id,
    owner_principal_id: principal,
    version: 1,
    local_generation: "wsg_00000000000000000000000000000001",
    active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
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
  assert.equal(memR.checks.device_workspaces, true);
  assert.equal(memR.checks.device_workspace_members, true);

  const sql = openSqlStore();
  const sqlR = await sql.schemaReadiness();
  assert.equal(sqlR.schema_ready, true);
  assert.equal(sqlR.checks.mcp_operations, true);
  assert.equal(sqlR.checks.mcp_approval_transactions, true);
  assert.equal(sqlR.checks.mcp_approval_outbox, true);
  assert.equal(sqlR.checks.device_workspaces, true);
  assert.equal(sqlR.checks.device_workspace_members, true);
});

test("public MCP workspace custody denies a tenant member and binds owner action version", async () => {
  const store = new MemoryStore();
  const owner = await seedAuthed(store);
  await store.ensurePrincipal("prin_member", "Member", "human", "ten_default");
  const member = await seedAuthed(store, "prin_member");
  const deviceId = "dev_workspace_acl_01abcdef";
  await putActiveDevice(store, deviceId);
  await store.putTenantMember("ten_default", "prin_member", "member");
  await store.putWorkspace({
    workspace_id: "owner-root",
    tenant_id: "ten_default",
    device_id: deviceId,
    owner_principal_id: "prin_dev",
    version: 7,
    local_generation: "wsg_77777777777777777777777777777777",
    active: true,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  let memberRoutes = 0;
  const denied = await handleMcp(
    rpc("ownmesh_fs_list", { device_id: deviceId, workspace_id: "owner-root", idempotency_key: "member-read" }, member.access_token),
    store, new URL("https://cp.test/mcp"),
    { routeToDevice: async () => { memberRoutes += 1; return { status: "routed_to_device" }; } },
    { tracker: new OperationTracker() },
  );
  assert.equal(denied.status, 200);
  assert.equal(memberRoutes, 0, "ACL denial must happen before DeviceRoom routing");
  assert.match(await denied.text(), /workspace_not_available/);

  let bound: Record<string, unknown> | undefined;
  const ownerResult = await handleMcp(
    rpc("ownmesh_fs_list", { device_id: deviceId, workspace_id: "owner-root", idempotency_key: "owner-read" }, owner.access_token),
    store, new URL("https://cp.test/mcp"),
    { routeToDevice: async (_id, op) => { bound = ((op.payload.authorization as { bound_action?: Record<string, unknown> })?.bound_action); return { status: "routed_to_device" }; } },
    { tracker: new OperationTracker() },
  );
  assert.equal(ownerResult.status, 200);
  assert.equal(bound?.workspace_id, "owner-root");
  assert.equal(bound?.workspace_version, 7);
});

test("workspace custody is device-scoped and ready reconciliation is fail-closed", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await seedAuthed(store);
    const first = "dev_same_default_a_01";
    const second = "dev_same_default_b_01";
    await putActiveDevice(store, first);
    await putActiveDevice(store, second);

    const firstDefault = { id: "ws_default", generation: "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" };
    const secondDefault = { id: "ws_default", generation: "wsg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" };
    await store.syncDeviceWorkspaces(first, [firstDefault]);
    await store.syncDeviceWorkspaces(second, [secondDefault]);
    assert.equal((await store.getWorkspace(first, "ws_default"))?.device_id, first);
    assert.equal((await store.getWorkspace(second, "ws_default"))?.device_id, second);
    assert.equal(
      (await store.assertWorkspaceOperableForMcp(
        "ws_default",
        second,
        "prin_dev",
        "ten_default",
      )).ok,
      true,
    );

    const cli = { id: "ws_cli", generation: "wsg_cccccccccccccccccccccccccccccccc" };
    await store.syncDeviceWorkspaces(first, [firstDefault, cli]);
    assert.equal((await store.getWorkspace(first, "ws_cli"))?.active, true);
    assert.equal(await store.getWorkspace(second, "ws_cli"), null);

    await store.putWorkspace({
      workspace_id: "ws_legacy",
      tenant_id: "ten_default",
      device_id: first,
      owner_principal_id: "prin_dev",
      version: 7,
      active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    await store.syncDeviceWorkspaces(first, [
      firstDefault,
      cli,
      { id: "ws_legacy", generation: "wsg_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" },
    ]);
    const upgradedLegacy = await store.getWorkspace(first, "ws_legacy");
    assert.equal(upgradedLegacy?.version, 8);
    assert.equal(upgradedLegacy?.local_generation, "wsg_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

    // Missing from one ready snapshot must not cancel a cloud reservation that
    // may be waiting for reconnect delivery.
    await store.syncDeviceWorkspaces(first, [firstDefault]);
    assert.equal((await store.getWorkspace(first, "ws_cli"))?.version, 1);
    await store.syncDeviceWorkspaces(first, [
      firstDefault,
      { ...cli, generation: "wsg_dddddddddddddddddddddddddddddddd" },
    ]);
    assert.equal((await store.getWorkspace(first, "ws_cli"))?.version, 2);
    const inactive = await store.getWorkspace(first, "ws_cli");
    assert.ok(inactive);
    await store.putWorkspace({ ...inactive, active: false });
    await store.syncDeviceWorkspaces(first, [
      firstDefault,
      { ...cli, generation: "wsg_dddddddddddddddddddddddddddddddd" },
    ]);
    assert.equal((await store.getWorkspace(first, "ws_cli"))?.version, 3);

    await store.putWorkspace({
      workspace_id: "ws_pending_ready",
      tenant_id: "ten_default",
      device_id: first,
      owner_principal_id: "prin_dev",
      version: 1,
      active: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    await store.syncDeviceWorkspaces(first, [
      firstDefault,
      { id: "ws_pending_ready", generation: "wsg_ffffffffffffffffffffffffffffffff" },
    ]);
    const reconnected = await store.getWorkspace(first, "ws_pending_ready");
    assert.equal(reconnected?.active, true);
    assert.equal(reconnected?.local_generation, "wsg_ffffffffffffffffffffffffffffffff");
  }
});

test("default workspace reservation is idempotent after a partial enrollment retry", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await seedAuthed(store);
    const deviceId = `dev_enroll_retry_${store.kind}`;
    const createdAt = new Date().toISOString();
    await store.putDevice({
      id: deviceId,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      name: deviceId,
      hostname: deviceId,
      os: "test",
      arch: "x64",
      agent_version: "1",
      protocol_version: "ownmesh.device/1.0",
      public_key: "ab".repeat(32),
      revoked: false,
      created_at: createdAt,
      status: "pending",
    });
    const reservation = {
      workspace_id: "ws_default",
      tenant_id: "ten_default",
      device_id: deviceId,
      owner_principal_id: "prin_dev",
      version: 1,
      active: false,
      created_at: createdAt,
      updated_at: createdAt,
    };
    await store.putWorkspace(reservation);
    await store.putWorkspace(reservation);
    assert.deepEqual(await store.getWorkspace(deviceId, "ws_default"), reservation);
  }
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
    rpc("ownmesh_command_run", { device_id: deviceId, workspace_id: "ws_default", program: "echo", args: ["hi"], async: true, idempotency_key: "idem_auth_cmd" }, tok.access_token),
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

test("approval decision result cannot substitute its exact-bound target or decision", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const deviceId = "dev_decision_binding_01abcdef";
  const now = new Date().toISOString();
  const putTarget = async (operationId: string, transactionId: string, approvalId: string) =>
    store.putMcpOperation({
      operation_id: operationId,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_fs_write",
      status: "approval_required",
      summary: "awaiting exact decision",
      data: {
        approval_decision: "approve",
        approval_transaction_id: transactionId,
        approval_device_id: approvalId,
      },
      truncated: false,
      next_cursor: null,
      approval_required: true,
      approval_id: approvalId,
      warnings: [],
      correlation_id: operationId,
      policy_authority: "ownmesh_device",
      created_at: now,
      updated_at: now,
    });
  await putTarget("op_bound_target_a", "apr_TxA", "apr_DeviceA");
  await putTarget("op_bound_target_b", "apr_TxB", "apr_DeviceB");
  const expected = {
    target_operation_id: "op_bound_target_a",
    decision: "approve" as const,
    approval_id: "apr_DeviceA",
    transaction_id: "apr_TxA",
  };
  const applyDecision = (target: string, decision: "approve" | "deny") =>
    applyMcpOperationResult(store, {
      operationId: "op_decision_control",
      correlationId: "op_decision_control",
      deviceId,
      expectedApprovalDecision: expected,
      payload: {
        status: "completed",
        operation_id: "op_decision_control",
        result: {
          approval_decision_applied: true,
          target_operation_id: target,
          approval_id: "apr_DeviceA",
          decision,
          result: { ok: true },
        },
      },
    });

  const swappedTarget = await applyDecision("op_bound_target_b", "approve");
  assert.equal(swappedTarget.ok, false);
  assert.equal(!swappedTarget.ok && swappedTarget.error, "approval_decision_binding_mismatch");
  const swappedDecision = await applyDecision("op_bound_target_a", "deny");
  assert.equal(swappedDecision.ok, false);
  assert.equal(!swappedDecision.ok && swappedDecision.error, "approval_decision_binding_mismatch");
  assert.equal((await store.getMcpOperation("op_bound_target_a"))?.status, "approval_required");
  assert.equal((await store.getMcpOperation("op_bound_target_b"))?.status, "approval_required");

  const exact = await applyDecision("op_bound_target_a", "approve");
  assert.equal(exact.ok, true);
  assert.equal((await store.getMcpOperation("op_bound_target_a"))?.status, "completed");
  assert.equal((await store.getMcpOperation("op_bound_target_b"))?.status, "approval_required");
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
    rpc("ownmesh_fs_list", { device_id: deviceId, workspace_id: null, path: "/", async: true }, tok.access_token),
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
    rpc("ownmesh_fs_list", { device_id: deviceId, workspace_id: null, path: "/" }, tok.access_token),
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
    rpc("ownmesh_fs_read", { device_id: deviceId, workspace_id: null, path: "/x" }, tok.access_token),
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
  const targetExpires = new Date(Date.now() + 5 * 60_000).toISOString();
  const targetHash = "a".repeat(64);
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
    payload_hash: targetHash,
    expires_at: targetExpires,
    claim_version: 1,
    action: {
      capability: "filesystem.write",
      action: "fs.write",
      tool: "ownmesh_fs_write",
      path: "secret.txt",
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const deliveries: Array<{
    type: string;
    payload: Record<string, unknown>;
    expires_at?: string;
  }> = [];
  const routeToDevice = async (
    _deviceId: string,
    operation: {
      type: string;
      payload: Record<string, unknown>;
      correlation_id: string;
      expires_at?: string;
    },
  ) => {
    deliveries.push({
      type: operation.type,
      payload: operation.payload,
      expires_at: operation.expires_at,
    });
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
  assert.equal(firstBody.status, "approval_required");
  assert.equal(deliveries.length, 1);
  assert.equal(deliveries[0]!.type, "approval.decision");
  // Strict ownmesh.operation/1.0 nests decision under arguments (not flat payload).
  const decisionArgs = deliveries[0]!.payload.arguments as
    | {
        decision?: string;
        target_operation_id?: string;
        action?: string;
        approval_id?: string;
      }
    | undefined;
  assert.equal(decisionArgs?.decision, "approve");
  assert.equal(decisionArgs?.action, "approval.decision");
  // Decision frame has its own operation_id; original op is target_operation_id.
  assert.equal(
    deliveries[0]!.payload.target_operation_id || decisionArgs?.target_operation_id,
    opId,
  );
  // E3: recovery decision must carry server-bound exact-action authorization.
  assert.equal(deliveries[0]!.payload.capability, "approval.decision");
  assert.ok(
    typeof deliveries[0]!.payload.payload_hash === "string" &&
      String(deliveries[0]!.payload.payload_hash).length === 64,
    "approval.decision must include server payload_hash",
  );
  const auth = deliveries[0]!.payload.authorization as
    | { bound_action?: Record<string, unknown> }
    | undefined;
  assert.ok(auth?.bound_action && typeof auth.bound_action === "object");
  assert.equal(auth!.bound_action!.action, "approval.decision");
  assert.equal(auth!.bound_action!.principal_id, "prin_dev");
  assert.equal(
    (auth!.bound_action!.facts as { decision?: string } | undefined)?.decision,
    "approve",
  );
  assert.ok(
    typeof deliveries[0]!.expires_at === "string" ||
      typeof auth!.bound_action!.expires_at === "string",
    "decision must bind expires_at",
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

test("admin approval renders only safe local preview and rechecks role before delivery", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.ensurePrincipal("prin_admin_review", "Admin", "human", "ten_default");
  await store.putTenantMember("ten_default", "prin_admin_review", "admin");
  const deviceId = "dev_admin_review_01abcdef";
  await putActiveDevice(store, deviceId, "prin_device_owner");
  const opId = randomId("op_");
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_admin_review",
    device_id: deviceId,
    tool: "ownmesh_request_approval",
    status: "approval_required",
    summary: "local approval bridge",
    data: {
      error: {
        details: {
          target_preview: {
            approval_id: "apr_Local1",
            operation_id: "op_local_write_1",
            capability: "filesystem.write",
            reason: "write requested",
            path: "<img src=x onerror=alert(1)>",
            secret: "TOP_SECRET_MUST_NOT_RENDER",
          },
        },
      },
    },
    truncated: false,
    next_cursor: null,
    approval_required: true,
    approval_id: "apr_BridgeOuter1",
    approval_url: `https://cp.test/approve?operation_id=${opId}`,
    warnings: [],
    correlation_id: opId,
    policy_authority: "ownmesh_device",
    payload_hash: "c".repeat(64),
    expires_at: new Date(Date.now() + 5 * 60_000).toISOString(),
    claim_version: 1,
    action: {
      capability: "admin.approval.bridge",
      approval_id: "apr_Local1",
      requested_decision: "approve",
      temporary_grant: false,
    },
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const getRes = await handleApprove(
    new Request(`https://cp.test/approve?operation_id=${opId}`),
    store,
    {
      issuer: "https://cp.test",
      principal: { id: "prin_admin_review", tenant_id: "ten_default" },
      authSource: "browser",
    },
  );
  assert.equal(getRes.status, 200);
  const html = await getRes.text();
  assert.match(html, /Local target/);
  assert.match(html, /filesystem\.write/);
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
  assert.ok(!html.includes("<img src=x onerror=alert(1)>"));
  assert.ok(!html.includes("TOP_SECRET_MUST_NOT_RENDER"));
  const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(tx && csrf);

  // A principal demoted after GET may remain a tenant member, but must lose
  // administrative mutation authority before the exact decision is routed.
  await store.putTenantMember("ten_default", "prin_admin_review", "member");
  let routes = 0;
  const post = await handleApprove(
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
      principal: { id: "prin_admin_review", tenant_id: "ten_default" },
      authSource: "browser",
      originAllowed: true,
      routeToDevice: async () => {
        routes += 1;
        return { status: "routed_to_device" };
      },
    },
  );
  assert.equal(post.status, 403);
  assert.match(await post.text(), /device_admin_required/);
  assert.equal(routes, 0);
  assert.equal((await store.getMcpApprovalOutbox(tx!))?.delivery_status, "pending");
  const unchanged = await store.getMcpOperation(opId);
  assert.equal(unchanged?.status, "approval_required");
  assert.equal(unchanged?.data.approval_transaction_id, undefined);
});

test("/approve rejects expired target operation (no decision delivery)", async () => {
  const store = new MemoryStore();
  await seedAuthed(store);
  const deviceId = "dev_approve_expired_01ab";
  await putActiveDevice(store, deviceId);
  const opId = randomId("op_");
  const past = new Date(Date.now() - 60_000).toISOString();
  await store.putMcpOperation({
    operation_id: opId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_fs_write",
    status: "approval_required",
    summary: "stale",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: true,
    approval_url: `https://cp.test/approve?operation_id=${opId}`,
    warnings: [],
    correlation_id: randomId("cor_"),
    policy_authority: "ownmesh_device",
    payload_hash: "b".repeat(64),
    expires_at: past,
    claim_version: 1,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  });

  const deliveries: unknown[] = [];
  const getRes = await handleApprove(
    new Request(`https://cp.test/approve?operation_id=${opId}`),
    store,
    {
      issuer: "https://cp.test",
      principal: { id: "prin_dev", tenant_id: "ten_default" },
      authSource: "browser",
      routeToDevice: async () => {
        deliveries.push("should_not_run");
        return { status: "routed_to_device" };
      },
    },
  );
  assert.equal(getRes.status, 409, await getRes.clone().text());
  assert.equal(
    ((await getRes.json()) as { error?: string }).error,
    "expired",
  );
  assert.equal(deliveries.length, 0);
  assert.equal((await store.getMcpOperation(opId))?.status, "approval_required");
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
    assert.equal(retryBody.status, "approval_required");
    assert.equal(deliveries.length, 1);
    assert.equal(
      deliveries[0]!.payload.target_operation_id ||
        (deliveries[0]!.payload.arguments as { target_operation_id?: string } | undefined)
          ?.target_operation_id,
      opId,
    );

    const after = await store.getMcpOperation(opId);
    assert.equal(after?.status, "approval_required");
    assert.equal(after?.approval_required, true);

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

test("newly created workspace is not executable until Agent generation is observed", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    const owner = await seedAuthed(store);
    const deviceId = `dev_pending_ws_${store.kind}`;
    await putActiveDevice(store, deviceId);
    const createdAt = new Date().toISOString();
    await store.putWorkspace({
      workspace_id: "ws_dev",
      tenant_id: "ten_default",
      device_id: deviceId,
      owner_principal_id: "prin_dev",
      version: 1,
      active: false,
      created_at: createdAt,
      updated_at: createdAt,
    });

    const listed = await store.getWorkspace(deviceId, "ws_dev");
    assert.equal(listed?.active, false);
    assert.equal(listed?.local_generation, undefined);

    let routes = 0;
    const denied = await handleMcp(
      rpc("ownmesh_fs_list", { device_id: deviceId, workspace_id: "ws_dev", idempotency_key: "pending-read" }, owner.access_token),
      store, new URL("https://cp.test/mcp"),
      { routeToDevice: async () => { routes += 1; return { status: "routed_to_device" }; } },
      { tracker: new OperationTracker() },
    );
    assert.equal(denied.status, 200);
    assert.equal(routes, 0);
    const deniedBody = await denied.json() as { error?: { message?: string; data?: Record<string, unknown> } };
    assert.equal(deniedBody.error?.message, "workspace_not_available");
    assert.equal(deniedBody.error?.data?.cause, "pending_activation");
    assert.equal(deniedBody.error?.data?.next_action, "retry_activation");
    assert.equal(deniedBody.error?.data?.code, "OWNMESH_E_WORKSPACE_PENDING_ACTIVATION");

    const observed = await store.observeWorkspaceGeneration(
      deviceId,
      "ws_dev",
      "wsg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );
    assert.equal(observed?.active, true);
    assert.equal(observed?.local_generation, "wsg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    const operable = await store.assertWorkspaceOperableForMcp("ws_dev", deviceId, "prin_dev", "ten_default");
    assert.equal(operable.ok, true);
  }
});

test("workspace add result observes generation and does not report active before that", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await seedAuthed(store);
    const deviceId = `dev_ws_add_result_${store.kind}`;
    await putActiveDevice(store, deviceId);
    const createdAt = new Date().toISOString();
    await store.putWorkspace({
      workspace_id: "ws_dev",
      tenant_id: "ten_default",
      device_id: deviceId,
      owner_principal_id: "prin_dev",
      version: 1,
      active: false,
      created_at: createdAt,
      updated_at: createdAt,
    });
    const pendingOp = `op_ws_add_pending_${store.kind}`;
    await store.putMcpOperation({
      operation_id: pendingOp,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_workspace_add",
      status: "pending",
      summary: "routing",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: pendingOp,
      workspace_id: "ws_dev",
      policy_authority: "ownmesh_device",
      created_at: createdAt,
      updated_at: createdAt,
    });

    const before = await applyMcpOperationResult(store, {
      operationId: pendingOp,
      correlationId: pendingOp,
      deviceId,
      payload: {
        status: "completed",
        operation_id: pendingOp,
        result: { id: "ws_dev", root: "/home/tonakai/Dev", created: true },
      },
    });
    assert.equal(before.ok, true);
    assert.equal((await store.getWorkspace(deviceId, "ws_dev"))?.active, false);
    assert.equal(before.ok && before.record?.data?.activation_state, "pending_activation");

    const readyOp = `op_ws_add_ready_${store.kind}`;
    await store.putMcpOperation({
      operation_id: readyOp,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_workspace_add",
      status: "pending",
      summary: "routing",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: readyOp,
      workspace_id: "ws_dev",
      policy_authority: "ownmesh_device",
      created_at: createdAt,
      updated_at: createdAt,
    });
    const after = await applyMcpOperationResult(store, {
      operationId: readyOp,
      correlationId: readyOp,
      deviceId,
      payload: {
        status: "completed",
        operation_id: readyOp,
        result: {
          id: "ws_dev",
          root: "/home/tonakai/Dev",
          created: true,
          generation: "wsg_cccccccccccccccccccccccccccccccc",
        },
      },
    });
    assert.equal(after.ok, true);
    const activated = await store.getWorkspace(deviceId, "ws_dev");
    assert.equal(activated?.active, true);
    assert.equal(activated?.local_generation, "wsg_cccccccccccccccccccccccccccccccc");
    assert.equal(after.ok && after.record?.data?.activation_state, "active");
    assert.equal(after.ok && after.record?.data?.generation, undefined);
  }
});

test("fresh-passkey approval_required always persists a same-origin approval_url", async () => {
  const store = new MemoryStore();
  await seedAuthed(store);
  const deviceId = "dev_approval_url_01abcdef";
  await putActiveDevice(store, deviceId);
  const createdAt = new Date().toISOString();
  await store.putMcpOperation({
    operation_id: "op_47485e58d8c9411e9cbc10",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_policy_preset",
    status: "pending",
    summary: "routing",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "op_47485e58d8c9411e9cbc10",
    policy_authority: "ownmesh_device",
    created_at: createdAt,
    updated_at: createdAt,
  });

  const applied = await applyMcpOperationResult(store, {
    operationId: "op_47485e58d8c9411e9cbc10",
    correlationId: "op_47485e58d8c9411e9cbc10",
    deviceId,
    issuer: "https://cp.test",
    payload: {
      status: "failed",
      operation_id: "op_47485e58d8c9411e9cbc10",
      error: {
        code: "OWNMESH_E_APPROVAL_REQUIRED",
        message: "fresh passkey required",
        details: { approval_id: "apr_policy", reason: "policy preset" },
      },
    },
  });
  assert.equal(applied.ok, true);
  assert.equal(applied.ok && applied.record?.status, "approval_required");
  assert.equal(applied.ok && applied.record?.approval_required, true);
  assert.equal(
    applied.ok && applied.record?.approval_url,
    "https://cp.test/approve?operation_id=op_47485e58d8c9411e9cbc10",
  );
});

test("policy observation updates workspace_root_enforcement independently of access_preset", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await seedAuthed(store);
    const deviceId = `dev_policy_enforcement_${store.kind}`;
    await putActiveDevice(store, deviceId);
    await store.recordDeviceReadyConnection(deviceId, {
      protocol_version: "ownmesh.device/1.0",
      last_seen_at: new Date().toISOString(),
      enforce_workspace: true,
    });
    assert.equal((await store.getDevice(deviceId))?.enforce_workspace, true);
    await store.recordObservedWorkspaceEnforcement(deviceId, false);
    assert.equal((await store.getDevice(deviceId))?.enforce_workspace, false);
  }
});

test("stale workspace list cannot revive a removed generation", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await seedAuthed(store);
    const deviceId = `dev_ws_tombstone_${store.kind}`;
    await putActiveDevice(store, deviceId);
    const createdAt = new Date().toISOString();
    const generation = "wsg_dddddddddddddddddddddddddddddddd";
    await store.putWorkspace({
      workspace_id: "ws_dev",
      tenant_id: "ten_default",
      device_id: deviceId,
      owner_principal_id: "prin_dev",
      version: 2,
      local_generation: generation,
      active: true,
      created_at: createdAt,
      updated_at: createdAt,
    });
    const removeOp = `op_ws_remove_${store.kind}`;
    await store.putMcpOperation({
      operation_id: removeOp,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_workspace_remove",
      status: "pending",
      summary: "routing",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: removeOp,
      workspace_id: "ws_dev",
      policy_authority: "ownmesh_device",
      created_at: createdAt,
      updated_at: createdAt,
    });
    const removed = await applyMcpOperationResult(store, {
      operationId: removeOp,
      correlationId: removeOp,
      deviceId,
      payload: {
        status: "completed",
        operation_id: removeOp,
        result: { id: "ws_dev", removed: true },
      },
    });
    assert.equal(removed.ok, true);
    assert.equal((await store.getWorkspace(deviceId, "ws_dev"))?.active, false);

    const listOp = `op_ws_stale_list_${store.kind}`;
    await store.putMcpOperation({
      operation_id: listOp,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_workspace_list",
      status: "pending",
      summary: "routing",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: listOp,
      policy_authority: "ownmesh_device",
      created_at: createdAt,
      updated_at: createdAt,
    });
    const stale = await applyMcpOperationResult(store, {
      operationId: listOp,
      correlationId: listOp,
      deviceId,
      payload: {
        status: "completed",
        operation_id: listOp,
        result: {
          workspaces: [
            { id: "ws_dev", root: "/home/tonakai/Dev", generation },
          ],
        },
      },
    });
    assert.equal(stale.ok, true);
    const after = await store.getWorkspace(deviceId, "ws_dev");
    assert.equal(after?.active, false);
    assert.equal(after?.local_generation, generation);
    assert.equal(
      stale.ok &&
        Array.isArray(stale.record?.data?.workspaces) &&
        (stale.record.data.workspaces[0] as { activation_state?: string }).activation_state,
      "unavailable",
    );
  }
});

test("workspace add result cannot activate a different id than the reserved binding", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await seedAuthed(store);
    const deviceId = `dev_ws_id_bind_${store.kind}`;
    await putActiveDevice(store, deviceId);
    const createdAt = new Date().toISOString();
    await store.putWorkspace({
      workspace_id: "ws_dev",
      tenant_id: "ten_default",
      device_id: deviceId,
      owner_principal_id: "prin_dev",
      version: 1,
      active: false,
      created_at: createdAt,
      updated_at: createdAt,
    });
    const addOp = `op_ws_add_mismatch_${store.kind}`;
    await store.putMcpOperation({
      operation_id: addOp,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_workspace_add",
      status: "pending",
      summary: "routing",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: addOp,
      workspace_id: "ws_dev",
      policy_authority: "ownmesh_device",
      created_at: createdAt,
      updated_at: createdAt,
    });
    const applied = await applyMcpOperationResult(store, {
      operationId: addOp,
      correlationId: addOp,
      deviceId,
      payload: {
        status: "completed",
        operation_id: addOp,
        result: {
          id: "ws_other",
          root: "/tmp/other",
          created: true,
          generation: "wsg_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        },
      },
    });
    assert.equal(applied.ok, true);
    assert.equal(await store.getWorkspace(deviceId, "ws_other"), null);
    const reserved = await store.getWorkspace(deviceId, "ws_dev");
    assert.equal(reserved?.active, false);
    assert.equal(reserved?.local_generation, undefined);
  }
});

test("workspace add requires admin even when id is omitted", async () => {
  const store = new MemoryStore();
  await seedAuthed(store);
  await store.ensurePrincipal("prin_member", "Member", "human", "ten_default");
  const member = await seedAuthed(store, "prin_member");
  const deviceId = "dev_ws_add_no_id_acl";
  await putActiveDevice(store, deviceId);
  await store.putTenantMember("ten_default", "prin_member", "member");
  let routes = 0;
  const denied = await handleMcp(
    rpc(
      "ownmesh_workspace_add",
      { device_id: deviceId, path: "/home/tonakai/Dev", idempotency_key: "member-add" },
      member.access_token,
    ),
    store,
    new URL("https://cp.test/mcp"),
    {
      routeToDevice: async () => {
        routes += 1;
        return { status: "routed_to_device" };
      },
    },
    { tracker: new OperationTracker() },
  );
  assert.equal(denied.status, 200);
  assert.equal(routes, 0, "member add without id must not reach DeviceRoom");
  const body = (await denied.json()) as { error?: { data?: Record<string, unknown> } };
  assert.equal(body.error?.data?.code, "OWNMESH_E_WORKSPACE_ADMIN_REQUIRED");
});

test("removed workspace id can be re-registered after a new Agent generation", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    const owner = await seedAuthed(store);
    const deviceId = `dev_ws_reregister_${store.kind}`;
    await putActiveDevice(store, deviceId);
    const createdAt = new Date().toISOString();
    const oldGeneration = "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    await store.putWorkspace({
      workspace_id: "ws_dev",
      tenant_id: "ten_default",
      device_id: deviceId,
      owner_principal_id: "prin_dev",
      version: 2,
      local_generation: oldGeneration,
      active: false,
      created_at: createdAt,
      updated_at: createdAt,
    });

    let routes = 0;
    const added = await handleMcp(
      rpc(
        "ownmesh_workspace_add",
        {
          device_id: deviceId,
          id: "ws_dev",
          path: "/home/tonakai/Dev",
          idempotency_key: `reregister-${store.kind}`,
        },
        owner.access_token,
      ),
      store,
      new URL("https://cp.test/mcp"),
      {
        routeToDevice: async () => {
          routes += 1;
          return { status: "routed_to_device" };
        },
      },
      { tracker: new OperationTracker() },
    );
    assert.equal(added.status, 200);
    assert.equal(routes, 1, "inactive tombstone must not conflict on re-add");
    const addedBody = (await added.json()) as { error?: { data?: { code?: string } } };
    assert.equal(addedBody.error?.data?.code, undefined);

    const addOp = `op_ws_reregister_${store.kind}`;
    await store.putMcpOperation({
      operation_id: addOp,
      tenant_id: "ten_default",
      principal_id: "prin_dev",
      device_id: deviceId,
      tool: "ownmesh_workspace_add",
      status: "pending",
      summary: "routing",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: false,
      warnings: [],
      correlation_id: addOp,
      workspace_id: "ws_dev",
      policy_authority: "ownmesh_device",
      created_at: createdAt,
      updated_at: createdAt,
    });
    const applied = await applyMcpOperationResult(store, {
      operationId: addOp,
      correlationId: addOp,
      deviceId,
      payload: {
        status: "completed",
        operation_id: addOp,
        result: {
          id: "ws_dev",
          root: "/home/tonakai/Dev",
          created: true,
          generation: "wsg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        },
      },
    });
    assert.equal(applied.ok, true);
    const revived = await store.getWorkspace(deviceId, "ws_dev");
    assert.equal(revived?.active, true);
    assert.equal(revived?.local_generation, "wsg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert.equal(
      (await store.assertWorkspaceOperableForMcp("ws_dev", deviceId, "prin_dev", "ten_default")).ok,
      true,
    );
  }
});

test("approval_required without issuer does not persist a relative approval_url", async () => {
  const store = new MemoryStore();
  await seedAuthed(store);
  const deviceId = "dev_approval_no_issuer";
  await putActiveDevice(store, deviceId);
  const createdAt = new Date().toISOString();
  await store.putMcpOperation({
    operation_id: "op_approval_no_issuer01",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: deviceId,
    tool: "ownmesh_policy_preset",
    status: "pending",
    summary: "routing",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "op_approval_no_issuer01",
    policy_authority: "ownmesh_device",
    created_at: createdAt,
    updated_at: createdAt,
  });
  const applied = await applyMcpOperationResult(store, {
    operationId: "op_approval_no_issuer01",
    correlationId: "op_approval_no_issuer01",
    deviceId,
    payload: {
      status: "failed",
      operation_id: "op_approval_no_issuer01",
      error: {
        code: "OWNMESH_E_APPROVAL_REQUIRED",
        message: "fresh passkey required",
        details: { approval_id: "apr_policy", reason: "policy preset" },
      },
    },
  });
  assert.equal(applied.ok, true);
  assert.equal(applied.ok && applied.record?.approval_required, true);
  assert.equal(applied.ok && applied.record?.approval_url, undefined);
});

