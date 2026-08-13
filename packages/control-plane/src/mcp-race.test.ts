/**
 * MCP route/result race + create-only put + pollable local tools.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  OperationTracker,
  handleMcp,
  type OperationRouter,
} from "./mcp.ts";
import {
  MemoryStore,
  SqlStore,
  type McpOperationRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import { applyMcpOperationResult } from "./device-room.ts";

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
  const db = new DatabaseSync(":memory:");
  for (const f of readdirSync(migrationsDir).filter((x) => x.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  return new SqlStore(adaptSqlite(db), "sqlite");
}

function sampleOp(id: string, status = "pending"): McpOperationRecord {
  const now = new Date().toISOString();
  return {
    operation_id: id,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: "dev_race_01abcdef01",
    tool: "ownmesh_fs_list",
    status,
    summary: "seed",
    data: { seed: true },
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: `cor_${id}`,
    policy_authority: "ownmesh_device",
    created_at: now,
    updated_at: now,
  };
}

async function authed(store: MemoryStore | SqlStore) {
  await store.ensureBootstrap();
  const tok = await store.issueTokens(
    "client_mcp",
    "prin_dev",
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device",
  );
  return tok.access_token;
}

function rpc(method: string, params: Record<string, unknown>, token: string): Request {
  return new Request("https://cp.test/mcp", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
}

async function ensureDevice(store: MemoryStore | SqlStore, deviceId: string) {
  if (await store.getDevice(deviceId)) return;
  await store.putDevice({
    id: deviceId,
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    name: deviceId,
    hostname: deviceId,
    os: "test",
    arch: "test",
    agent_version: "test",
    protocol_version: "ownmesh.device/1.0",
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  });
}

async function callTool(
  store: MemoryStore | SqlStore,
  token: string,
  name: string,
  args: Record<string, unknown>,
  router?: OperationRouter,
  tracker?: OperationTracker,
) {
  if (typeof args.device_id === "string") {
    await ensureDevice(store, args.device_id);
  }
  const res = await handleMcp(
    rpc("tools/call", { name, arguments: args }, token),
    store,
    new URL("https://cp.test/mcp"),
    router,
    { issuer: "https://cp.test", tracker: tracker || new OperationTracker() },
  );
  const body = (await res.json()) as {
    result?: {
      content: { type: string; text: string }[];
      structuredContent?: Record<string, unknown>;
      isError?: boolean;
    };
    error?: { code: number; message: string };
  };
  return { res, body };
}

test("Memory+SQL putMcpOperation is create-only (conflict does not overwrite)", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await store.ensureBootstrap();
    const op = sampleOp(`op_create_only_${store.kind || "memory"}`);
    await store.putMcpOperation(op);

    await assert.rejects(
      () => store.putMcpOperation({ ...op, status: "completed", summary: "overwrite-attempt" }),
      /mcp_operation_exists/,
    );

    const got = await store.getMcpOperation(op.operation_id);
    assert.equal(got?.status, "pending");
    assert.equal(got?.summary, "seed");
    assert.equal(got?.data?.seed, true);
  }
});

test("Memory+SQL exact-data CAS rejects a stale metadata snapshot", async () => {
  for (const store of [new MemoryStore(), openSqlStore()] as const) {
    await store.ensureBootstrap();
    const op = sampleOp(`op_data_cas_${store.kind || "memory"}`);
    await store.putMcpOperation(op);
    const snapshot = (await store.getMcpOperation(op.operation_id))!.data;
    const winner = await store.updateMcpOperation(
      op.operation_id,
      { status: "running", data: { transfer: { cleanup_generation: 1, owner: "winner" } } },
      ["pending"],
      snapshot,
    );
    assert.ok(winner);
    const stale = await store.updateMcpOperation(
      op.operation_id,
      { data: { transfer: { cleanup_generation: 1, owner: "stale" } } },
      ["pending", "running"],
      snapshot,
    );
    assert.equal(stale, null, "status still matches, but stale parent data must lose");
    const retained = (await store.getMcpOperation(op.operation_id))?.data.transfer as Record<string, unknown> | undefined;
    assert.equal(retained?.owner, "winner");
  }
});

test("fast DO terminal result is not overwritten by late route persist (CAS loss returns current)", async () => {
  const store = new MemoryStore();
  const token = await authed(store);
  const deviceId = "dev_race_fast_do_01ab";
  await ensureDevice(store, deviceId);
  const tracker = new OperationTracker();

  const router: OperationRouter = {
    async routeToDevice(deviceIdArg, operation) {
      const payload = (operation.payload || {}) as Record<string, unknown>;
      const opId = String(payload.operation_id || "");
      const corr = operation.correlation_id ? String(operation.correlation_id) : undefined;
      // Simulate DO finishing (and CAS-updating store) before route handler finalizes.
      const applied = await applyMcpOperationResult(store, {
        operationId: opId,
        correlationId: corr,
        deviceId: deviceIdArg,
        payload: {
          operation_id: opId,
          status: "completed",
          summary: "fast DO terminal result",
          result: {
            winner: "device",
            marker: "do-first",
            workspace_id: null,
            workspace_version: null,
          },
        },
      });
      assert.equal(applied.ok, true, "DO CAS apply must succeed against pending/running");
      // Route path would otherwise try to write device_offline / failed.
      return {
        status: "device_offline" as const,
        detail: { note: "stale route observation" },
      };
    },
  };

  const { body } = await callTool(
    store,
    token,
    "ownmesh_fs_list",
    { device_id: deviceId, workspace_id: null, path: "/" },
    router,
    tracker,
  );

  const sc = body.result!.structuredContent!;
  assert.equal(sc.status, "completed", "response must surface authoritative DO result");
  assert.equal(sc.summary, "fast DO terminal result");
  assert.equal((sc.data as { winner?: string }).winner, "device");
  assert.equal((sc.data as { marker?: string }).marker, "do-first");

  const opId = String(sc.operation_id);
  const stored = await store.getMcpOperation(opId);
  assert.ok(stored);
  assert.equal(stored.status, "completed");
  assert.equal(stored.summary, "fast DO terminal result");
  assert.equal((stored.data as { marker?: string }).marker, "do-first");

  // Empty tracker (simulated isolate restart) still polls the DO result.
  const poll = await callTool(
    store,
    token,
    "ownmesh_get_operation",
    { operation_id: opId },
    undefined,
    new OperationTracker(),
  );
  assert.equal(poll.body.result!.structuredContent!.status, "completed");
  assert.equal(
    (poll.body.result!.structuredContent!.data as { marker?: string }).marker,
    "do-first",
  );
});

test("SQL store: late unconditional-style update cannot clobber via put; CAS from pending loses to terminal", async () => {
  const store = openSqlStore();
  await store.ensureBootstrap();
  const op = sampleOp("op_sql_cas_race_01");
  await store.putMcpOperation(op);

  const terminal = await store.updateMcpOperation(
    op.operation_id,
    { status: "completed", summary: "do-won", data: { winner: "do" } },
    ["pending", "running"],
  );
  assert.equal(terminal?.status, "completed");

  const lost = await store.updateMcpOperation(
    op.operation_id,
    { status: "device_offline", summary: "stale-route", data: { winner: "route" } },
    ["pending", "running"],
  );
  assert.equal(lost, null, "CAS from pending must lose once terminal");

  const current = await store.getMcpOperation(op.operation_id);
  assert.equal(current?.status, "completed");
  assert.equal(current?.summary, "do-won");
  assert.equal((current?.data as { winner?: string }).winner, "do");

  // put remains create-only even after terminal state
  await assert.rejects(
    () => store.putMcpOperation({ ...op, status: "failed", summary: "replace?" }),
    /mcp_operation_exists/,
  );
  assert.equal((await store.getMcpOperation(op.operation_id))?.status, "completed");
});

test("get_device success+not-found and list_profiles ops are pollable after simulated restart", async () => {
  const store = new MemoryStore();
  const token = await authed(store);
  const deviceId = "dev_race_local_poll_01";
  await ensureDevice(store, deviceId);

  const getOk = await callTool(store, token, "ownmesh_get_device", { device_id: deviceId });
  const getOkSc = getOk.body.result!.structuredContent!;
  assert.equal(getOkSc.status, "completed");
  const getOkId = String(getOkSc.operation_id);
  assert.ok(getOkId.startsWith("op_"));

  // Do not use callTool helper (it auto-seeds devices); exercise true not-found.
  const getMissRes = await handleMcp(
    rpc(
      "tools/call",
      { name: "ownmesh_get_device", arguments: { device_id: "dev_does_not_exist_zz" } },
      token,
    ),
    store,
    new URL("https://cp.test/mcp"),
    undefined,
    { issuer: "https://cp.test", tracker: new OperationTracker() },
  );
  const getMissBody = (await getMissRes.json()) as {
    result?: { structuredContent?: Record<string, unknown> };
  };
  const getMissSc = getMissBody.result!.structuredContent!;
  assert.equal(getMissSc.status, "failed");
  const getMissId = String(getMissSc.operation_id);

  const profiles = await callTool(store, token, "ownmesh_list_profiles", {});
  const profilesSc = profiles.body.result!.structuredContent!;
  assert.equal(profilesSc.status, "completed");
  const profilesId = String(profilesSc.operation_id);

  // Simulated Worker isolate restart: empty tracker, same store.
  const fresh = new OperationTracker();
  for (const [opId, expectStatus] of [
    [getOkId, "completed"],
    [getMissId, "failed"],
    [profilesId, "completed"],
  ] as const) {
    assert.ok(await store.getMcpOperation(opId), `store must hold ${opId}`);
    const poll = await callTool(
      store,
      token,
      "ownmesh_get_operation",
      { operation_id: opId },
      undefined,
      fresh,
    );
    assert.equal(poll.body.result!.structuredContent!.operation_id, opId);
    assert.equal(poll.body.result!.structuredContent!.status, expectStatus);
  }
});
