/**
 * DeviceRoom race/durability: prepare→persist→dispatch operation injection,
 * and room-level durable internal-context nonce replay across hibernation.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import {
  DeviceRoom,
  DeviceRoomRouter,
  ROOM_STATE_STORAGE_KEY,
  type PersistedRoomState,
  type SessionAttachment,
} from "./device-room.ts";
import {
  DEFAULT_TENANT,
  SqlStore,
  type DeviceRecord,
  type SqlDatabase,
  type SqlStatement,
} from "./store.ts";
import {
  defaultInternalContextReplayGuard,
  internalDoHeaders,
  randomId,
  sha256Hex,
  signInternalContext,
  verifyInternalContext,
} from "./util.ts";

const SESSION_SECRET = "test-device-room-race-session-secret";
const PROTOCOL = "ownmesh.device/1.0";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

function openSqliteAdapter(): { adapter: SqlDatabase; store: SqlStore } {
  const db = new DatabaseSync(":memory:");
  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const f of files) {
    db.exec(readFileSync(join(migrationsDir, f), "utf8"));
  }
  type SqlVal = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
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
          const rows = stmt.all(...bound) as T[];
          return { results: rows };
        },
      };
      return api;
    },
    exec(query: string) {
      db.exec(query);
    },
    async batch<T>(statements: SqlStatement[]): Promise<T[]> {
      const run = async (): Promise<T[]> => {
        db.exec("BEGIN IMMEDIATE");
        try {
          const results: unknown[] = [];
          for (const statement of statements) results.push(await statement.run());
          db.exec("COMMIT");
          return results as T[];
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      };
      const result = batchTail.then(run, run);
      batchTail = result.then(
        () => undefined,
        () => undefined,
      );
      return result;
    },
  };
  return { adapter, store: new SqlStore(adapter, "sqlite") };
}

async function seedActiveDevice(store: SqlStore, deviceId: string): Promise<void> {
  await store.ensureBootstrap();
  const device: DeviceRecord = {
    id: deviceId,
    tenant_id: DEFAULT_TENANT,
    principal_id: "prin_dev",
    name: "test-device",
    hostname: "host",
    os: "test",
    arch: "x64",
    agent_version: "0",
    protocol_version: PROTOCOL,
    public_key: "ab".repeat(32),
    revoked: false,
    created_at: new Date().toISOString(),
    status: "active",
  };
  await store.putDevice(device);
}

function mockDOState(opts?: {
  storage?: Map<string, unknown>;
  sockets?: unknown[];
}): DurableObjectState {
  const map = opts?.storage || new Map<string, unknown>();
  const sockets = opts?.sockets || [];
  return {
    id: { toString: () => "do_race", equals: () => false, name: undefined } as DurableObjectId,
    storage: {
      get: async (key: string) => map.get(key),
      put: async (key: string, value: unknown) => {
        map.set(key, structuredClone(value));
      },
      delete: async (key: string) => map.delete(key),
      list: async () => new Map(map),
      deleteAll: async () => {
        map.clear();
      },
      transaction: async (fn: (txn: unknown) => Promise<unknown>) => fn({}),
      getAlarm: async () => null,
      setAlarm: async () => undefined,
      deleteAlarm: async () => undefined,
      sync: async () => undefined,
      sql: undefined,
    },
    getWebSockets: () => sockets as unknown as WebSocket[],
    acceptWebSocket: (ws: WebSocket) => {
      sockets.push(ws);
    },
    setWebSocketAutoResponse: () => undefined,
    getWebSocketAutoResponse: () => null,
    getWebSocketAutoResponseTimestamp: () => null,
    setHibernatableWebSocketEventTimeout: () => undefined,
    getHibernatableWebSocketEventTimeout: () => null,
    getTags: () => [],
    abort: () => undefined,
    waitUntil: () => undefined,
    blockConcurrencyWhile: async <T>(fn: () => Promise<T>) => fn(),
  } as unknown as DurableObjectState;
}

/** Mint internal DO /operation headers with method/path/body bind + fixed nonce. */
async function operationHeaders(
  deviceId: string,
  body: unknown,
  extra?: {
    principal_id?: string;
    tenant_id?: string;
    correlation_id?: string;
    nonce?: string;
  },
): Promise<{ headers: Headers; bodyText: string; nonce: string }> {
  const bodyText = JSON.stringify(body);
  const body_sha256 = await sha256Hex(bodyText);
  const nonce = extra?.nonce || randomId("n_");
  const token = await signInternalContext(SESSION_SECRET, {
    op: "operation",
    device_id: deviceId,
    principal_id: extra?.principal_id || "prin_dev",
    tenant_id: extra?.tenant_id || DEFAULT_TENANT,
    correlation_id: extra?.correlation_id,
    method: "POST",
    path: "/operation",
    body_sha256,
    nonce,
  });
  const headers = new Headers({
    "content-type": "application/json",
    "x-ownmesh-internal-context": token,
  });
  return { headers, bodyText, nonce };
}

test("persist failure before dispatch: zero sends, no pending mutation, 503", async () => {
  const deviceId = "dev_race_persist_fail_01";
  const { adapter, store } = openSqliteAdapter();
  await seedActiveDevice(store, deviceId);

  const map = new Map<string, unknown>();
  let failPut = false;
  const state = mockDOState({ storage: map });
  const origPut = state.storage.put.bind(state.storage);
  (state.storage as { put: (k: string, v: unknown) => Promise<void> }).put = async (k, v) => {
    if (failPut) throw new Error("quota_exceeded");
    return origPut(k, v);
  };

  const room = new DeviceRoom(state, {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;

  room.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: "ags_race_pf",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  } satisfies SessionAttachment);

  let sendCount = 0;
  room.router.sendToSession = () => {
    sendCount += 1;
    return true;
  };

  const corr = "op_race_pf_01";
  const pendingBefore = room.router.pending.size;
  const seqBefore = room.router.seqOut;

  failPut = true;
  const payload = { type: "ownmesh_fs_list", correlation_id: corr, payload: { path: "/" } };
  const { headers, bodyText } = await operationHeaders(deviceId, payload, { correlation_id: corr });
  const res = await room.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers,
      body: bodyText,
    }),
  );

  assert.equal(res.status, 503);
  assert.equal(((await res.json()) as { error: string }).error, "storage_unavailable");
  assert.equal(sendCount, 0, "must not send to any agent before durable persist");
  assert.equal(room.router.pending.has(corr), false, "pending must not remain after failed persist");
  assert.equal(room.router.pending.size, pendingBefore);
  // seqOut may have been reserved during prepare; pending must not stick.
  assert.ok(room.router.seqOut >= seqBefore);
  assert.equal(room.isStorageBroken, true);
});

test("prepare+dispatch: successful path persists pending+nonce before send", async () => {
  const deviceId = "dev_race_ok_order_01ab";
  const { adapter, store } = openSqliteAdapter();
  await seedActiveDevice(store, deviceId);

  const map = new Map<string, unknown>();
  const putOrder: string[] = [];
  const state = mockDOState({ storage: map });
  const origPut = state.storage.put.bind(state.storage);
  (state.storage as { put: (k: string, v: unknown) => Promise<void> }).put = async (k, v) => {
    putOrder.push(k);
    return origPut(k, v);
  };

  const room = new DeviceRoom(state, {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  room.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: "ags_race_ok",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });

  const events: string[] = [];
  room.router.sendToSession = () => {
    events.push("send");
    // At send time, durable snapshot must already include pending + nonce.
    const snap = map.get(ROOM_STATE_STORAGE_KEY) as PersistedRoomState | undefined;
    assert.ok(snap, "storage must hold room state before any send");
    assert.ok(
      snap.pending.some((p) => p.correlation_id === "op_race_ok_01"),
      "pending persisted before send",
    );
    assert.ok(snap.consumedNonces && Object.keys(snap.consumedNonces).length > 0, "nonce persisted before send");
    return true;
  };

  const corr = "op_race_ok_01";
  const payload = { type: "ownmesh_fs_list", correlation_id: corr, payload: { path: "/" } };
  const { headers, bodyText, nonce } = await operationHeaders(deviceId, payload, {
    correlation_id: corr,
  });
  const res = await room.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers,
      body: bodyText,
    }),
  );
  assert.equal(res.status, 200);
  assert.deepEqual(events, ["send"]);
  assert.ok(putOrder.includes(ROOM_STATE_STORAGE_KEY));
  assert.equal(room.router.hasInternalNonce(nonce), true);
  assert.equal(room.router.pending.has(corr), true);
});

test("hibernation restore: same internal-context nonce rejected (room-level, util guard disabled)", async () => {
  const deviceId = "dev_race_nonce_hiber_01";
  const { adapter, store } = openSqliteAdapter();
  await seedActiveDevice(store, deviceId);

  const storage = new Map<string, unknown>();
  const room1 = new DeviceRoom(mockDOState({ storage }), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room1.ready;
  room1.deviceId = deviceId;
  room1.router.deviceId = deviceId;
  room1.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: "ags_nonce_h1",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  room1.router.sendToSession = () => true;

  const fixedNonce = "n_fixed_hibernate_replay_001";
  const corr = "op_nonce_hiber_01";
  const payload = { type: "ownmesh_fs_list", correlation_id: corr, payload: { path: "/" } };
  const { headers, bodyText } = await operationHeaders(deviceId, payload, {
    correlation_id: corr,
    nonce: fixedNonce,
  });

  // Clear process-local guard so it cannot be the authority for this test.
  defaultInternalContextReplayGuard.clear();

  const res1 = await room1.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers,
      body: bodyText,
    }),
  );
  assert.equal(res1.status, 200, await res1.clone().text());
  assert.equal(room1.router.hasInternalNonce(fixedNonce), true);

  const stored = storage.get(ROOM_STATE_STORAGE_KEY) as PersistedRoomState;
  assert.ok(stored?.consumedNonces?.[fixedNonce], "nonce must be in durable snapshot");

  // Hibernate wake: fresh isolate, empty process-local guard, same DO storage.
  defaultInternalContextReplayGuard.clear();
  assert.equal(defaultInternalContextReplayGuard.size, 0);

  const room2 = new DeviceRoom(mockDOState({ storage }), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
  });
  await room2.ready;
  room2.deviceId = deviceId;
  room2.router.deviceId = deviceId;
  room2.router.registerSession({
    role: "agent",
    device_id: deviceId,
    session_id: "ags_nonce_h2",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });
  let sendsAfterRestore = 0;
  room2.router.sendToSession = () => {
    sendsAfterRestore += 1;
    return true;
  };

  assert.equal(room2.router.hasInternalNonce(fixedNonce), true, "nonce restored from DO storage");

  // Re-present the exact same signed token (same nonce) after hibernation.
  const res2 = await room2.fetch(
    new Request("https://device-room/operation?device_id=" + deviceId, {
      method: "POST",
      headers,
      body: bodyText,
    }),
  );
  assert.equal(res2.status, 401);
  assert.equal(((await res2.json()) as { error: string }).error, "replay");
  assert.equal(sendsAfterRestore, 0, "replay must not dispatch");

  // Crypto still verifies with replayGuard:null — room is the sole authority.
  const verified = await verifyInternalContext(
    SESSION_SECRET,
    headers.get("x-ownmesh-internal-context"),
    {
      op: "operation",
      device_id: deviceId,
      method: "POST",
      path: "/operation",
      body_sha256: await sha256Hex(bodyText),
      replayGuard: null,
    },
  );
  assert.equal(verified.ok, true, "signature valid; rejection is room nonce, not HMAC");
});

test("router prepare rolls back without dispatch; injectOperation still prepare+dispatch", () => {
  const router = new DeviceRoomRouter("dev_race_router_01", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });
  router.registerSession({
    role: "agent",
    device_id: "dev_race_router_01",
    session_id: "ags_r",
    connected_at: Date.now(),
    phase: "ready",
    remote_routing_enabled: true,
  });

  let sends = 0;
  router.sendToSession = () => {
    sends += 1;
    return true;
  };

  const prep = router.prepareInjectOperation({
    type: "ownmesh_fs_list",
    payload: { path: "/" },
    correlation_id: "c_prep_1",
  });
  assert.equal(prep.ok, true);
  if (!prep.ok) return;
  assert.equal(router.pending.has("c_prep_1"), true);
  assert.equal(sends, 0, "prepare must not send");

  router.rollbackPreparedInject(prep.prepared);
  assert.equal(router.pending.has("c_prep_1"), false);

  const r = router.injectOperation({
    type: "ownmesh_fs_list",
    payload: { path: "/" },
    correlation_id: "c_inj_1",
  });
  assert.equal(r.status, "routed_to_device");
  assert.equal(sends, 1);
});

test("nonce store TTL and cap are pruned on export", () => {
  const router = new DeviceRoomRouter("dev_race_nonce_prune", {
    sendToSession: () => true,
    sendToRole: () => 0,
  });
  const now = Date.now();
  // Expired
  assert.equal(router.consumeInternalNonce("n_old", now - 1000, now), true);
  // Fresh
  assert.equal(router.consumeInternalNonce("n_fresh", now + 60_000, now), true);
  router.pruneConsumedNonces(now);
  assert.equal(router.hasInternalNonce("n_old"), false);
  assert.equal(router.hasInternalNonce("n_fresh"), true);

  const snap = router.exportState();
  assert.equal(snap.consumedNonces?.["n_old"], undefined);
  assert.ok(snap.consumedNonces?.["n_fresh"]);
});

test("internalDoHeaders helper still mints bound operation contexts", async () => {
  // Sanity: production helper path remains compatible with room verify (replayGuard null).
  const bodyText = JSON.stringify({ type: "ownmesh_fs_list", correlation_id: "c1" });
  const body_sha256 = await sha256Hex(bodyText);
  const headers = await internalDoHeaders(SESSION_SECRET, {
    op: "operation",
    device_id: "dev_x",
    principal_id: "p",
    tenant_id: DEFAULT_TENANT,
    method: "POST",
    path: "/operation",
    body_sha256,
    correlation_id: "c1",
  });
  const v = await verifyInternalContext(SESSION_SECRET, headers.get("x-ownmesh-internal-context"), {
    op: "operation",
    device_id: "dev_x",
    method: "POST",
    path: "/operation",
    body_sha256,
    correlation_id: "c1",
    replayGuard: null,
  });
  assert.equal(v.ok, true);
});
