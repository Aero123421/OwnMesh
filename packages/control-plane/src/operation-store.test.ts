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
  type OperationStore,
} from "./operation-store.ts";
import { MemoryStore, MCP_OPS_RESULT_TTL_MS } from "./store.ts";
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
  // Issue #243: no OPERATION_ROOM/SESSION_SECRET -> unknown authority -> fail
  // closed instead of silently degrading to D1.
  await assert.rejects(
    noBindings.forTenant("ten_ops", "prin_ops"),
    /operation_authority_temporarily_unavailable:binding_missing/,
  );

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
  // Cutover cursor routes to the room.
  await base.setOperationStoreCutover("ten_cut", new Date().toISOString());
  const after = await resolver.forTenant("ten_cut", "prin_ops");
  assert.equal(after.ops.backend, "operation-room");
  assert.equal(after.auditCovered, true);
  // Explicit per-tenant escape hatch with an empty room -> D1 authority.
  await base.setOperationStoreCutover("ten_escape", "d1");
  const escaped = await resolver.forTenant("ten_escape", "prin_ops");
  assert.equal(escaped.ops.backend, "d1");
  assert.equal(escaped.auditCovered, false);
});

class UnreadableCutoverStore extends MemoryStore {
  override async getOperationStoreCutover(_tenantId: string): Promise<string | null> {
    throw new Error("D1_ERROR: database temporarily unavailable");
  }
}

function makeOpFor(tenantId: string, id: string, key = `idem_${id}`) {
  return { ...makeOp(id, key), tenant_id: tenantId };
}

function fakeOperationStore(overrides: Partial<OperationStore>): OperationStore {
  const base: OperationStore = {
    backend: "d1",
    claim: async () => {
      throw new Error("claim_unused");
    },
    get: async () => null,
    getByIdempotency: async () => null,
    getByCorrelation: async () => null,
    put: async () => {},
    transition: async () => null,
    update: async () => null,
  };
  return { ...base, ...overrides };
}

function fakeRoomNamespace(room: OperationRoom) {
  return {
    idFromName: (name: string) => ({ name }),
    get: (_id: unknown) => ({
      fetch: (request: Request) => room.fetch(request),
    }),
  };
}

test("resolver fails closed when the cutover cursor cannot be read", async () => {
  const base = new UnreadableCutoverStore();
  const env = {
    OWNMESH_OPERATION_STORE: "device_do",
    OPERATION_ROOM: {
      idFromName: () => ({}),
      get: () => ({ fetch: async () => new Response("{}") }),
    },
    SESSION_SECRET: OP_SECRET,
  };
  const resolver = createOperationStoreResolver(env, base);
  await assert.rejects(
    resolver.forTenant("ten_ops", "prin_ops"),
    /operation_authority_temporarily_unavailable:cutover_unreadable/,
  );
});

test("rollback with room rows blocks claims but keeps DO reads and transitions", async () => {
  const state = fakeDoState();
  const room = new OperationRoom(
    state as unknown as DurableObjectState,
    { SESSION_SECRET: OP_SECRET, MCP_OPS_MAX_PER_TENANT: "100" },
  );
  const namespace = fakeRoomNamespace(room);
  const base = new MemoryStore();
  await base.ensureBootstrap();
  // Cut over, claim a room-only row, then roll the cursor back to 'd1'.
  await base.setOperationStoreCutover("ten_roll", new Date().toISOString());
  const roomStore = new OperationRoomStore(
    { OPERATION_ROOM: namespace, SESSION_SECRET: OP_SECRET },
    "ten_roll",
    "prin_ops",
  );
  const claimed = await roomStore.claim(makeOpFor("ten_roll", "op_roll_1"));
  assert.equal(claimed.outcome, "created");
  await base.setOperationStoreCutover("ten_roll", "d1");

  const resolver = createOperationStoreResolver(
    { OWNMESH_OPERATION_STORE: "device_do", OPERATION_ROOM: namespace, SESSION_SECRET: OP_SECRET },
    base,
  );
  const resolved = await resolver.forTenant("ten_roll", "prin_ops");
  assert.equal(resolved.ops.backend, "d1");
  assert.equal(resolved.auditCovered, false);
  // DO-only rows stay readable.
  assert.equal((await resolved.ops.get("op_roll_1"))?.status, "pending");
  assert.equal(
    (await resolved.ops.getByIdempotency({
      principalId: "prin_ops",
      tenantId: "ten_roll",
      deviceId: "dev_ops",
      idempotencyKey: "idem_op_roll_1",
    }))?.operation_id,
    "op_roll_1",
  );
  // New ownership fails closed until the room is drained/reconciled.
  await assert.rejects(
    resolved.ops.claim(makeOpFor("ten_roll", "op_roll_2")),
    /operation_authority_temporarily_unavailable:rollback_pending/,
  );
  // In-flight terminal transitions still reach the room row.
  const terminal = await resolved.ops.transition("op_roll_1", { status: "completed" }, ["pending"]);
  assert.equal(terminal?.status, "completed");
  assert.equal((await roomStore.get("op_roll_1"))?.status, "completed");
});

test("claim fence rejects a store resolved before a cutover lands", async () => {
  const base = new MemoryStore();
  await base.ensureBootstrap();
  const env = {
    OWNMESH_OPERATION_STORE: "device_do",
    OPERATION_ROOM: {
      idFromName: () => ({}),
      get: () => ({
        fetch: async () => new Response(JSON.stringify({ has_rows: false })),
      }),
    },
    SESSION_SECRET: OP_SECRET,
  };
  const resolver = createOperationStoreResolver(env, base);
  const resolved = await resolver.forTenant("ten_fence", "prin_ops");
  assert.equal(resolved.ops.backend, "d1");
  // Cut over after resolution: the cached store must not claim to D1.
  await base.setOperationStoreCutover("ten_fence", new Date().toISOString());
  await assert.rejects(
    resolved.ops.claim(makeOpFor("ten_fence", "op_fence_1")),
    /operation_authority_temporarily_unavailable:authority_changed/,
  );
});

test("Hybrid dual ownership is detected instead of silently resolved", async () => {
  const roomOp = makeOpFor("ten_conf", "op_owner_room");
  const d1Op = makeOpFor("ten_conf", "op_owner_d1");
  const primary = fakeOperationStore({
    backend: "operation-room",
    claim: async () => ({ outcome: "created" as const, op: roomOp }),
    get: async () => roomOp,
    getByIdempotency: async () => roomOp,
    getByCorrelation: async () => roomOp,
  });
  let fallbackLookups = 0;
  const fallback = fakeOperationStore({
    claim: async () => ({ outcome: "created" as const, op: d1Op }),
    get: async () => null,
    getByIdempotency: async () => {
      fallbackLookups += 1;
      // Pre-claim check misses; post-create fence observes the concurrent
      // D1 owner that landed during cutover propagation.
      return fallbackLookups === 1 ? null : d1Op;
    },
  });
  const hybrid = new HybridOperationStore(primary, fallback);
  await assert.rejects(hybrid.claim(roomOp), /operation_authority_conflict:claim/);

  const dualPrimary = fakeOperationStore({
    backend: "operation-room",
    getByIdempotency: async () => roomOp,
  });
  const dualFallback = fakeOperationStore({
    getByIdempotency: async () => d1Op,
  });
  await assert.rejects(
    new HybridOperationStore(dualPrimary, dualFallback).getByIdempotency({
      principalId: "prin_ops",
      tenantId: "ten_conf",
      deviceId: "dev_ops",
      idempotencyKey: "idem_op_owner_room",
    }),
    /operation_authority_conflict:idempotency/,
  );
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

/** Issue #244: fake SQLite-backed DO state with durable alarm support. */
function fakeDoStateWithAlarms() {
  const rows = new Map<string, unknown>();
  let alarmAt: number | null = null;
  const storage = {
    get: async (key: string) => rows.get(key),
    put: async (key: string, value: unknown) => {
      rows.set(key, value);
    },
    delete: async (key: string) => rows.delete(key),
    list: async (opts: { prefix: string; limit?: number; startAfter?: string }) => {
      const out = new Map<string, unknown>();
      for (const key of [...rows.keys()].sort()) {
        if (!key.startsWith(opts.prefix)) continue;
        if (opts.startAfter && key <= opts.startAfter) continue;
        out.set(key, rows.get(key));
        if (out.size >= (opts.limit ?? 128)) break;
      }
      return out;
    },
    setAlarm: async (at: number) => {
      alarmAt = at;
    },
    getAlarm: async () => alarmAt,
    deleteAlarm: async () => {
      alarmAt = null;
    },
  };
  return {
    rows,
    storage,
    get alarmAt() {
      return alarmAt;
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

test("OperationRoomStore client surfaces room errors without inventing state", async () => {  const calls: Array<{ tenant: string; action: string }> = [];
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

test("Hybrid over a real OperationRoom covers claim, poll, and terminal flows", async () => {
  const state = fakeDoState();
  const room = new OperationRoom(
    state as unknown as DurableObjectState,
    { SESSION_SECRET: OP_SECRET, MCP_OPS_MAX_PER_TENANT: "100" },
  );
  // In-process DO wiring: the namespace stub calls room.fetch directly, so
  // auth, validation, and storage all run for real.
  const namespace = {
    idFromName: (name: string) => ({ name }),
    get: (_id: unknown) => ({
      fetch: (request: Request) => room.fetch(request),
    }),
  };
  const base = new MemoryStore();
  await base.ensureBootstrap();
  const d1 = new D1OperationStore(base);
  const hybrid = new HybridOperationStore(
    new OperationRoomStore(
      { OPERATION_ROOM: namespace, SESSION_SECRET: OP_SECRET },
      "ten_ops",
      "prin_ops",
    ),
    d1,
  );

  // Claim a new key: D1 has no owner, the room creates it.
  const created = await hybrid.claim(makeOp("op_e2e_1"));
  assert.equal(created.outcome, "created");
  assert.equal(created.op.operation_id, "op_e2e_1");

  // Poll by id and by correlation through the hybrid.
  assert.equal((await hybrid.get("op_e2e_1"))?.status, "pending");
  assert.equal((await hybrid.getByCorrelation("op_e2e_1"))?.operation_id, "op_e2e_1");

  // Terminalize through the hybrid (room primary).
  const terminal = await hybrid.transition("op_e2e_1", { status: "completed", summary: "done" }, ["pending"]);
  assert.equal(terminal?.status, "completed");
  assert.equal(terminal?.summary, "done");

  // Wide update falls back correctly and stays visible.
  const wide = await hybrid.update("op_e2e_1", { summary: "wide-write" }, ["completed"]);
  assert.equal(wide?.summary, "wide-write");

  // A pre-cutover D1 row stays readable and terminalizable through the same handle.
  await base.putMcpOperation(makeOp("op_legacy_e2e"));
  assert.equal((await hybrid.get("op_legacy_e2e"))?.status, "pending");
  const legacyTerminal = await hybrid.transition("op_legacy_e2e", { status: "failed", summary: "late result" }, ["pending"]);
  assert.equal(legacyTerminal?.status, "failed");

  // Duplicate put across authorities is refused instead of shadowing.
  await assert.rejects(hybrid.put(makeOp("op_legacy_e2e")), /mcp_operation_exists/);
});

test("prune advances past the front page to reach later expiries", async () => {
  const storage = new InMemoryDeviceOpStorage();
  const log = new DeviceOperationLog(storage, 100);
  const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
  await log.put(makeOp("a_live_1"));
  await log.put(makeOp("a_live_2"));
  await log.put({
    ...makeOp("z_expired", ""),
    status: "failed",
    idempotency_key: null,
    created_at: old,
    updated_at: old,
  });
  let deleted = 0;
  let passes = 0;
  // Batch smaller than the live prefix: only cursors can reach the back.
  while (deleted === 0 && passes < 5) {
    const stats = await log.prune("ten_ops", Date.now(), 2);
    deleted += stats.deleted;
    passes += 1;
  }
  assert.equal(deleted, 1);
  assert.equal(await log.get("z_expired", "ten_ops"), null);
  // Live rows survive with intact occupancy.
  assert.ok(await log.get("a_live_1", "ten_ops"));
  assert.ok(await log.get("a_live_2", "ten_ops"));
});

test("prune compacts front-page terminals and still reaches the back", async () => {
  const storage = new InMemoryDeviceOpStorage();
  const log = new DeviceOperationLog(storage, 100);
  const old = new Date(Date.now() - 40 * 24 * 60 * 60 * 1000).toISOString();
  // Keyed expired terminal compacts to a tombstone in the front page.
  await log.put({ ...makeOp("a_keyed_terminal"), status: "completed", created_at: old, updated_at: old });
  await log.put({
    ...makeOp("z_keyless_terminal", ""),
    status: "failed",
    idempotency_key: null,
    created_at: old,
    updated_at: old,
  });
  let deleted = 0;
  let compacted = 0;
  for (let pass = 0; pass < 4 && deleted === 0; pass += 1) {
    const stats = await log.prune("ten_ops", Date.now(), 1);
    deleted += stats.deleted;
    compacted += stats.compacted;
  }
  assert.equal(compacted, 1);
  assert.equal(deleted, 1);
  assert.equal((await log.get("a_keyed_terminal", "ten_ops"))?.status, "tombstone");
  assert.equal(await log.get("z_keyless_terminal", "ten_ops"), null);
});

test("orphan correlation index is reaped despite healthy idempotency entries", async () => {
  const storage = new InMemoryDeviceOpStorage();
  const log = new DeviceOperationLog(storage, 1000);
  // More healthy idempotency entries than the old shared 64-check budget, so
  // the pre-fix scanner starves correlation cleanup on every pass.
  for (let i = 0; i < 70; i += 1) {
    await log.put(makeOp(`op_idem_${String(i).padStart(2, "0")}`));
  }
  await storage.put("dxcorr:v1:ten_ops:cor_orphan", "op_missing");
  let reaped = 0;
  for (let pass = 0; pass < 3 && reaped === 0; pass += 1) {
    reaped += (await log.prune("ten_ops")).indexesReaped;
  }
  assert.equal(reaped, 1);
  assert.equal(await storage.get("dxcorr:v1:ten_ops:cor_orphan"), undefined);
});

test("prune carries the cycle's next expiry across pages", async () => {
  const storage = new InMemoryDeviceOpStorage();
  const log = new DeviceOperationLog(storage, 100);
  const soon = new Date(Date.now() - MCP_OPS_RESULT_TTL_MS + 10 * 60_000).toISOString();
  await log.put({
    ...makeOp("a_terminal", ""),
    status: "completed",
    idempotency_key: null,
    created_at: soon,
    updated_at: soon,
  });
  await log.put(makeOp("b_live"));
  await log.put(makeOp("c_live"));
  const expected = Date.parse(soon) + MCP_OPS_RESULT_TTL_MS;
  const first = await log.prune("ten_ops", Date.now(), 2);
  assert.equal(first.hasMore, true);
  assert.equal(first.nextExpiryMs, null, "mid-cycle pages must not arm the alarm");
  const second = await log.prune("ten_ops", Date.now(), 2);
  assert.equal(second.hasMore, false);
  assert.equal(
    second.nextExpiryMs,
    expected,
    "the wrapped cycle must remember the early page's expiry",
  );
  assert.equal(await storage.get("dxnext:v1:ten_ops"), undefined);
});

test("alarm reschedules at the next expiry after a zero-deletion pass", async () => {
  const state = fakeDoStateWithAlarms();
  const room = new OperationRoom(
    state as unknown as DurableObjectState,
    { SESSION_SECRET: OP_SECRET, MCP_OPS_MAX_PER_TENANT: "100" },
  );
  const claimed = await opRoomCall(room, "ten_alarm", "claim", {
    op: makeOpFor("ten_alarm", "op_alarm_1", ""),
  });
  assert.equal(claimed.json.outcome, "created");
  const rowKey = "dxop:v1:ten_alarm:op_alarm_1";
  const row = state.rows.get(rowKey) as Record<string, unknown>;
  state.rows.set(rowKey, {
    ...row,
    status: "failed",
    idempotency_key: null,
    updated_at: new Date(Date.now() - MCP_OPS_RESULT_TTL_MS + 60_000).toISOString(),
  });
  await room.alarm();
  // Nothing prunable yet, but the next expiry must be on the schedule.
  assert.ok((state.rows.get(rowKey) as Record<string, unknown>));
  const scheduled = state.alarmAt;
  assert.ok(scheduled !== null, "alarm must be rescheduled at the next expiry");
  const delta = scheduled! - Date.now();
  assert.ok(delta > 30_000 && delta <= 61_000, `unexpected alarm delta ${delta}`);
  // Expiry reached: the next alarm deletes it without any new request.
  state.rows.set(rowKey, {
    ...(state.rows.get(rowKey) as Record<string, unknown>),
    updated_at: new Date(Date.now() - MCP_OPS_RESULT_TTL_MS - 1_000).toISOString(),
  });
  await room.alarm();
  assert.equal(state.rows.get(rowKey), undefined);
});

test("alarm retries with bounded backoff after a transient prune failure", async () => {
  const state = fakeDoStateWithAlarms();
  const room = new OperationRoom(
    state as unknown as DurableObjectState,
    { SESSION_SECRET: OP_SECRET, MCP_OPS_MAX_PER_TENANT: "100" },
  );
  await opRoomCall(room, "ten_retry", "get", { operation_id: "op_none" });
  const originalList = state.storage.list;
  let failures = 1;
  state.storage.list = async (opts) => {
    if (failures > 0) {
      failures -= 1;
      throw new Error("D1_ERROR: database temporarily unavailable");
    }
    return originalList(opts);
  };
  await room.alarm();
  assert.ok(state.alarmAt !== null, "transient failure must schedule a retry");
  const delta = state.alarmAt! - Date.now();
  assert.ok(delta > 60_000 && delta <= 121_000, `unexpected retry delta ${delta}`);
  // Recovery: the next alarm runs the prune without throwing.
  await room.alarm();
});

test("alarm arms the carried cycle expiry and resets the carry", async () => {
  const state = fakeDoStateWithAlarms();
  const room = new OperationRoom(
    state as unknown as DurableObjectState,
    { SESSION_SECRET: OP_SECRET, MCP_OPS_MAX_PER_TENANT: "100" },
  );
  await opRoomCall(room, "ten_carry", "get", { operation_id: "op_none" });
  // Simulate a mid-cycle page that saw a future expiry, then wrapped.
  const expiry = Date.now() + 90_000;
  state.rows.set("dxnext:v1:ten_carry", expiry);
  await room.alarm();
  assert.ok(state.alarmAt !== null, "carried expiry must arm the next alarm");
  assert.ok(
    Math.abs(state.alarmAt! - expiry) < 5_000,
    `expected alarm near the carried expiry, got delta ${state.alarmAt! - Date.now()}`,
  );
  assert.equal(state.rows.get("dxnext:v1:ten_carry"), undefined, "cycle carry resets");
});

test("empty room schedules no alarm and a terminal transition schedules one", async () => {
  const state = fakeDoStateWithAlarms();
  const room = new OperationRoom(
    state as unknown as DurableObjectState,
    { SESSION_SECRET: OP_SECRET, MCP_OPS_MAX_PER_TENANT: "100" },
  );
  await opRoomCall(room, "ten_idle", "get", { operation_id: "op_none" });
  await room.alarm();
  assert.equal(state.alarmAt, null);
  const claimed = await opRoomCall(room, "ten_idle", "claim", {
    op: makeOpFor("ten_idle", "op_idle_1"),
  });
  await state.storage.deleteAlarm();
  assert.equal(claimed.json.outcome, "created");  const terminal = await opRoomCall(room, "ten_idle", "transition", {
    operation_id: "op_idle_1",
    transition: { status: "completed", summary: "done" },
    from_statuses: ["pending"],
  });
  assert.equal((terminal.json.op as { status: string }).status, "completed");
  // The terminal write itself must schedule retention so its result TTL is
  // enforced even if no further request touches the tenant.
  assert.ok(state.alarmAt !== null, "terminal transition must schedule a prune");
});
