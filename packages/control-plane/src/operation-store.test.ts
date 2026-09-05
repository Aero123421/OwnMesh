/**
 * Issue #224 plan F (P2): operation authority facade, tenant-sharded durable
 * log, hybrid cutover fallback, and the OperationRoom endpoint.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { DeviceOperationLog, InMemoryDeviceOpStorage } from "./device-op-store.ts";
import {
  D1OperationStore,
  HybridOperationStore,
  OperationRoomStore,
  createOperationStoreResolver,
  resolveOperationStoreMode,
} from "./operation-store.ts";
import { MemoryStore } from "./store.ts";
import { internalDoHeaders } from "./util.ts";
import { OperationRoom } from "./device-room.ts";

const OP_SECRET = "test-session-secret-for-op-room-00000000";

function makeOp(id: string, key = `idem_${id}`) {
  const stamp = new Date().toISOString();
  return {
    operation_id: id,
    tenant_id: "ten_ops",
    principal_id: "prin_ops",
    device_id: "dev_ops",
    tool: "ownmesh_command_run",
    status: "pending",
    summary: "probe",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: id,
    payload_hash: "ph_ops",
    idempotency_key: key,
    policy_authority: "ownmesh_device" as const,
    created_at: stamp,
    updated_at: stamp,
  };
}

test("resolveOperationStoreMode fails safe to d1", () => {
  assert.equal(resolveOperationStoreMode({}), "d1");
  assert.equal(resolveOperationStoreMode({ OWNMESH_OPERATION_STORE: "device_do" }), "device_do");
  assert.equal(resolveOperationStoreMode({ OWNMESH_OPERATION_STORE: "DEVICE_DO" }), "d1");
  assert.equal(resolveOperationStoreMode({ OWNMESH_OPERATION_STORE: "bogus" }), "d1");
});

test("D1OperationStore mirrors the base store exactly", async () => {
  const base = new MemoryStore();
  await base.ensureBootstrap();
  const ops = new D1OperationStore(base);
  assert.equal(ops.backend, "d1");
  await ops.put(makeOp("op_d1_1"));
  assert.equal((await ops.get("op_d1_1"))?.status, "pending");
  const claimed = await ops.claim(makeOp("op_d1_2"));
  assert.equal(claimed.outcome, "created");
  const again = await ops.claim(makeOp("op_d1_2"));
  assert.equal(again.outcome, "existing");
  const terminal = await ops.transition("op_d1_2", { status: "completed", summary: "done" }, ["pending"]);
  assert.equal(terminal?.status, "completed");
  assert.equal(await ops.transition("op_d1_2", { status: "failed" }, ["pending"]), null);
  const byIdem = await ops.getByIdempotency({
    principalId: "prin_ops",
    tenantId: "ten_ops",
    deviceId: "dev_ops",
    idempotencyKey: "idem_op_d1_2",
  });
  assert.equal(byIdem?.operation_id, "op_d1_2");
  assert.equal((await ops.getByCorrelation("op_d1_2"))?.operation_id, "op_d1_2");
  const wide = await ops.update("op_d1_1", { summary: "wide", device_id: "dev_ops" }, ["pending"]);
  assert.equal(wide?.summary, "wide");
});

test("DeviceOperationLog enforces claim, CAS, quota, and tombstones", async () => {
  const storage = new InMemoryDeviceOpStorage();
  const log = new DeviceOperationLog(storage, 2);
  const created = await log.claim(makeOp("op_do_1"));
  assert.equal(created.outcome, "created");
  const existing = await log.claim(makeOp("op_do_1"));
  assert.equal(existing.outcome, "existing");
  assert.equal(existing.op.operation_id, "op_do_1");
  // Second key fills the quota of 2.
  await log.claim(makeOp("op_do_2"));
  await assert.rejects(log.claim(makeOp("op_do_3")), /mcp_operation_quota_exceeded/);
  // Narrow CAS wins once, then loses.
  const terminal = await log.transition("op_do_1", "ten_ops", { status: "completed" }, ["pending"]);
  assert.equal(terminal?.status, "completed");
  assert.equal(await log.transition("op_do_1", "ten_ops", { status: "failed" }, ["pending"]), null);
  assert.equal(await log.transition("op_missing", "ten_ops", { status: "failed" }), null);
  // Identity binding survives transitions.
  assert.equal((await log.get("op_do_1", "ten_ops"))?.idempotency_key, "idem_op_do_1");
  // put() is create-only.
  await assert.rejects(log.put(makeOp("op_do_1")), /mcp_operation_exists/);
});

test("DeviceOperationLog prune mirrors retention semantics", async () => {
  const storage = new InMemoryDeviceOpStorage();
  const log = new DeviceOperationLog(storage, 100);
  const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
  // Expired keyed terminal -> tombstone receipt.
  await log.put({ ...makeOp("op_old_keyed"), status: "completed", created_at: old, updated_at: old });
  // Expired keyless terminal -> deleted.
  await log.put({
    ...makeOp("op_old_keyless", ""),
    status: "failed",
    created_at: old,
    updated_at: old,
    idempotency_key: null,
  });
  // Fresh row untouched.
  await log.put(makeOp("op_fresh"));
  const stats = await log.prune("ten_ops");
  assert.equal(stats.compacted, 1);
  assert.equal(stats.deleted, 1);
  assert.equal((await log.get("op_old_keyed", "ten_ops"))?.status, "tombstone");
  assert.equal(await log.get("op_old_keyless", "ten_ops"), null);
  assert.equal((await log.get("op_fresh", "ten_ops"))?.status, "pending");
  // Closed-window tombstone no longer owns its key.
  const aged = (await log.get("op_old_keyed", "ten_ops"))!;
  assert.ok(aged.idempotency_key);
  // Expire the tombstone itself, then prune again.
  storage.rows.set(`dxop:v1:ten_ops:op_old_keyed`, {
    ...aged,
    updated_at: new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString(),
  });
  const second = await log.prune("ten_ops");
  assert.equal(second.deleted, 1);
  assert.equal(
    await log.getByIdempotency({
      principalId: "prin_ops",
      tenantId: "ten_ops",
      deviceId: "dev_ops",
      idempotencyKey: aged.idempotency_key!,
    }),
    null,
  );
});

test("HybridOperationStore falls back to D1 for pre-cutover rows", async () => {
  const base = new MemoryStore();
  await base.ensureBootstrap();
  await base.putMcpOperation(makeOp("op_legacy_1"));
  const d1 = new D1OperationStore(base);
  const roomStorage = new InMemoryDeviceOpStorage();
  const roomLog = new DeviceOperationLog(roomStorage, 100);
  // Fake primary that only speaks the room log for one tenant.
  const primary = {
    backend: "operation-room" as const,
    claim: (op: ReturnType<typeof makeOp>) => roomLog.claim(op),
    get: (id: string) => roomLog.get(id, "ten_ops"),
    getByIdempotency: (opts: { principalId: string; tenantId: string; deviceId: string; idempotencyKey: string }) =>
      roomLog.getByIdempotency(opts),
    getByCorrelation: (correlationId: string) => roomLog.getByCorrelation(correlationId, "ten_ops"),
    put: (op: ReturnType<typeof makeOp>) => roomLog.put(op),
    transition: (
      id: string,
      transition: { status: string },
      from?: string[],
    ) => roomLog.transition(id, "ten_ops", transition, from),
    update: (
      id: string,
      patch: Partial<ReturnType<typeof makeOp>>,
      from?: string[],
      expected?: Record<string, unknown>,
    ) => roomLog.update(id, "ten_ops", patch, from, expected),
  };
  const hybrid = new HybridOperationStore(primary, d1);
  // Pre-cutover row visible through the hybrid.
  assert.equal((await hybrid.get("op_legacy_1"))?.status, "pending");
  // Claim with a D1-owned key converges without a room write.
  const converged = await hybrid.claim(makeOp("op_legacy_1"));
  assert.equal(converged.outcome, "existing");
  assert.equal(converged.op.operation_id, "op_legacy_1");
  assert.equal(roomStorage.rows.size, 0);
  // In-flight terminal write at cutover time lands on D1 via fallback.
  const terminal = await hybrid.transition("op_legacy_1", { status: "completed" }, ["pending"]);
  assert.equal(terminal?.status, "completed");
  // New keys go to the room.
  const created = await hybrid.claim(makeOp("op_room_1"));
  assert.equal(created.outcome, "created");
  assert.ok(roomStorage.rows.size > 0);
});

test("resolver routes by mode, bindings, and cutover cursor", async () => {
  const base = new MemoryStore();
  const d1Only = createOperationStoreResolver({}, base);
  assert.equal(d1Only.mode, "d1");
  assert.equal((await d1Only.forTenant("ten_ops", "prin_ops")).auditCovered, false);

  const noBindings = createOperationStoreResolver({ OWNMESH_OPERATION_STORE: "device_do" }, base);
  assert.equal(noBindings.mode, "device_do");
  // No OPERATION_ROOM/SESSION_SECRET -> safe D1 fallback.
  assert.equal((await noBindings.forTenant("ten_ops", "prin_ops")).auditCovered, false);

  const fakeRoom = { idFromName: () => ({}), get: () => ({ fetch: async () => new Response("{}") }) };
  const roomEnv = {
    OWNMESH_OPERATION_STORE: "device_do",
    OPERATION_ROOM: fakeRoom,
    SESSION_SECRET: OP_SECRET,
  };
  const resolver = createOperationStoreResolver(roomEnv, base);
  // No cutover cursor -> D1 authority.
  const before = await resolver.forTenant("ten_ops", "prin_ops");
  assert.equal(before.ops.backend, "d1");
  assert.equal(before.auditCovered, false);
  // Cutover cursor routes to the room (fresh tenant avoids the 60s isolate cache).
  await base.setOperationStoreCutover("ten_cut", new Date().toISOString());
  const after = await resolver.forTenant("ten_cut", "prin_ops");
  assert.equal(after.ops.backend, "operation-room");
  assert.equal(after.auditCovered, true);
  // Explicit per-tenant escape hatch back to D1.
  await base.setOperationStoreCutover("ten_escape", "d1");
  const escaped = await resolver.forTenant("ten_escape", "prin_ops");
  assert.equal(escaped.ops.backend, "d1");
  assert.equal(escaped.auditCovered, false);
});

function fakeDoState() {
  const rows = new Map<string, unknown>();
  return {
    rows,
    storage: {
      get: async (key: string) => rows.get(key),
      put: async (key: string, value: unknown) => {
        rows.set(key, value);
      },
      delete: async (key: string) => rows.delete(key),
      list: async (opts: { prefix: string; limit?: number }) => {
        const out = new Map<string, unknown>();
        for (const key of [...rows.keys()].sort()) {
          if (key.startsWith(opts.prefix)) {
            out.set(key, rows.get(key));
            if (out.size >= (opts.limit ?? 128)) break;
          }
        }
        return out;
      },
    },
    blockConcurrencyWhile: async (fn: () => Promise<void>) => {
      await fn();
    },
  };
}

async function opRoomCall(
  room: OperationRoom,
  tenantId: string,
  action: string,
  body: Record<string, unknown>,
  secret = OP_SECRET,
  claimsTenant = tenantId,
): Promise<{ status: number; json: Record<string, unknown> }> {
  const raw = JSON.stringify({ action, ...body });
  const { sha256Hex } = await import("./util.ts");
  const headers = await internalDoHeaders(secret, {
    op: "op_store",
    device_id: "",
    principal_id: "prin_ops",
    tenant_id: claimsTenant,
    correlation_id: "",
    method: "POST",
    path: "/op-store",
    body_sha256: await sha256Hex(raw),
  });
  const res = await room.fetch(
    new Request(`https://operation-room/op-store?tenant_id=${encodeURIComponent(tenantId)}`, {
      method: "POST",
      headers,
      body: raw,
    }),
  );
  return { status: res.status, json: (await res.json()) as Record<string, unknown> };
}

test("OperationRoom endpoint round-trips claims with tenant-bound auth", async () => {
  const state = fakeDoState();
  const room = new OperationRoom(
    state as unknown as DurableObjectState,
    { SESSION_SECRET: OP_SECRET, MCP_OPS_MAX_PER_TENANT: "100" },
  );
  const claimed = await opRoomCall(room, "ten_ops", "claim", { op: makeOp("op_ep_1") });
  assert.equal(claimed.status, 200);
  assert.equal(claimed.json.outcome, "created");
  const again = await opRoomCall(room, "ten_ops", "claim", { op: makeOp("op_ep_1") });
  assert.equal(again.json.outcome, "existing");
  const got = await opRoomCall(room, "ten_ops", "get", { operation_id: "op_ep_1" });
  assert.equal((got.json.op as { status: string }).status, "pending");
  const terminal = await opRoomCall(room, "ten_ops", "transition", {
    operation_id: "op_ep_1",
    transition: { status: "completed", summary: "done" },
    from_statuses: ["pending"],
  });
  assert.equal((terminal.json.op as { status: string }).status, "completed");
  const byIdem = await opRoomCall(room, "ten_ops", "get_by_idempotency", {
    principal_id: "prin_ops",
    device_id: "dev_ops",
    idempotency_key: "idem_op_ep_1",
  });
  assert.equal((byIdem.json.op as { operation_id: string }).operation_id, "op_ep_1");

  // Wrong secret, foreign tenant, and malformed records fail closed.
  const badSecret = await opRoomCall(room, "ten_ops", "get", { operation_id: "op_ep_1" }, "wrong-secret");
  assert.equal(badSecret.status, 401);
  const foreign = await opRoomCall(room, "ten_other", "get", { operation_id: "op_ep_1" }, OP_SECRET, "ten_ops");
  assert.equal(foreign.status, 403);
  const invalid = await opRoomCall(room, "ten_ops", "claim", { op: { operation_id: "" } });
  assert.equal(invalid.status, 400);

  // TTL prune runs on alarm without throwing.
  await room.alarm();
  assert.equal(((await opRoomCall(room, "ten_ops", "get", { operation_id: "op_ep_1" })).json.op as {
    status: string;
  }).status, "completed");
});

test("OperationRoomStore client surfaces room errors without inventing state", async () => {
  const calls: Array<{ tenant: string; action: string }> = [];
  const env = {
    SESSION_SECRET: OP_SECRET,
    OPERATION_ROOM: {
      idFromName: (name: string) => ({ name }),
      get: (_id: unknown) => ({
        fetch: async (request: Request) => {
          const body = (await request.json()) as { action: string };
          const url = new URL(request.url);
          calls.push({ tenant: url.searchParams.get("tenant_id") || "", action: body.action });
          if (body.action === "get") return new Response(JSON.stringify({ op: null }));
          return new Response(JSON.stringify({ error: "boom" }), { status: 500 });
        },
      }),
    },
  };
  const client = new OperationRoomStore(env, "ten_ops", "prin_ops");
  assert.equal(await client.get("op_missing"), null);
  await assert.rejects(client.claim(makeOp("op_x")), /operation_room_500/);
  assert.deepEqual(calls[0], { tenant: "ten_ops", action: "get" });
});
