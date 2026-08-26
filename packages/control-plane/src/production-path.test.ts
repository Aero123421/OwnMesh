/**
 * Production-path security tests: worker.fetch against SqlStore on node:sqlite
 * with a transaction-capable batch adapter (same pattern as persistence-races).
 *
 * Covers authorize+consent-tx+PKCE, device-code, enroll→proof→activate with a
 * real WebCrypto Ed25519 keypair, and fail-closed security negatives.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { DatabaseSync } from "node:sqlite";
import worker, { __setTestStore } from "./index.ts";
import { MCP_SYNC_WAIT_MS } from "./mcp.ts";
import {
  DeviceRoom,
  PROTOCOL,
  type DeviceEnvelope,
  type SessionAttachment,
} from "./device-room.ts";
import { MemoryStore, SqlStore, type SqlDatabase, type SqlStatement } from "./store.ts";
import { internalDoHeaders, randomId, sha256Hex } from "./util.ts";

const ctx = {} as ExecutionContext;
const ISSUER = "https://cp.test";
const REDIRECT = "http://127.0.0.1:8750/callback";
const CLIENT = "client_ownmesh_cli";
const PRINCIPAL_ID = "prin_dev";
const TENANT_ID = "ten_default";
const SESSION_SECRET = "test-session-secret-production-path";

const here = dirname(fileURLToPath(import.meta.url));
const migrationsDir = join(here, "..", "migrations");

/** Transaction-capable node:sqlite adapter (BEGIN IMMEDIATE + serialized batch). */
function openSqlBackend(): { store: SqlStore; adapter: SqlDatabase } {
  const db = new DatabaseSync(":memory:");
  // Match D1 foreign-key enforcement so unprovisioned tenant INSERTs fail closed.
  db.exec("PRAGMA foreign_keys = ON");
  for (const file of readdirSync(migrationsDir).filter((f) => f.endsWith(".sql")).sort()) {
    db.exec(readFileSync(join(migrationsDir, file), "utf8"));
  }
  type V = null | number | string | bigint | Uint8Array;
  let batchTail: Promise<void> = Promise.resolve();
  const adapter: SqlDatabase = {
    prepare(query: string): SqlStatement {
      const statement = db.prepare(query);
      let values: V[] = [];
      const api: SqlStatement = {
        bind(...input: unknown[]) {
          values = input.map((v) => (v === undefined ? null : (v as V)));
          return api;
        },
        async first<T>(column?: string) {
          const row = statement.get(...values) as Record<string, unknown> | undefined;
          return row ? (column ? (row[column] as T) : (row as T)) : null;
        },
        async run() {
          const info = statement.run(...values) as { changes: number };
          return { success: true, meta: { changes: info.changes } };
        },
        async all<T>() {
          return { results: statement.all(...values) as T[] };
        },
      };
      return api;
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
  return { store: new SqlStore(adapter, "sqlite"), adapter };
}

function openSqlStore(): SqlStore {
  return openSqlBackend().store;
}

function authProvider(
  principalId = PRINCIPAL_ID,
  tenantId = TENANT_ID,
  fresh = false,
): Fetcher {
  return {
    fetch: async () =>
      Response.json({
        principal_id: principalId,
        tenant_id: tenantId,
        display_name: principalId,
        fresh,
      }),
  } as unknown as Fetcher;
}

function env(_store: SqlStore, extra: Record<string, unknown> = {}) {
  return {
    AUTH_PROVIDER: authProvider(),
    OAUTH_ISSUER: ISSUER,
    ...extra,
  };
}

async function withStore<T>(fn: (store: SqlStore) => Promise<T>): Promise<T> {
  const store = openSqlStore();
  await store.ensureBootstrap();
  __setTestStore(store);
  try {
    return await fn(store);
  } finally {
    __setTestStore(null);
  }
}

async function withStoreAndAdapter<T>(
  fn: (store: SqlStore, adapter: SqlDatabase) => Promise<T>,
): Promise<T> {
  const { store, adapter } = openSqlBackend();
  await store.ensureBootstrap();
  __setTestStore(store);
  try {
    return await fn(store, adapter);
  } finally {
    __setTestStore(null);
  }
}

async function makePkce(): Promise<{ verifier: string; challenge: string }> {
  const verifier = "0123456789012345678901234567890123456789013";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const bytes = new Uint8Array(digest);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const challenge = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return { verifier, challenge };
}

function parseConsentForm(html: string): { tx: string; csrf: string } {
  const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
  const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
  assert.ok(tx && csrf, "consent form must include transaction_id and csrf_token");
  return { tx: tx!, csrf: csrf! };
}

async function ed25519Keypair(): Promise<{ publicKeyHex: string; privateKey: CryptoKey }> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicBytes = new Uint8Array(
    (await crypto.subtle.exportKey("raw", keyPair.publicKey)) as ArrayBuffer,
  );
  const publicKeyHex = [...publicBytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return { publicKeyHex, privateKey: keyPair.privateKey };
}

async function signHex(privateKey: CryptoKey, message: string): Promise<string> {
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(message)),
  );
  return [...signatureBytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Real DeviceRoom DO test doubles (mock DurableObjectState + WebSocketPair)
// ---------------------------------------------------------------------------

type MockSocket = {
  attachment: SessionAttachment | null;
  closed: { code: number; reason: string } | null;
  sent: string[];
  readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  serializeAttachment(att: unknown): void;
  deserializeAttachment(): SessionAttachment | null;
  accept?(): void;
};

function mockSocket(att: SessionAttachment | null = null): MockSocket {
  const s: MockSocket = {
    attachment: att,
    closed: null,
    sent: [],
    readyState: 1,
    send(data: string) {
      if (s.closed) throw new Error("closed");
      s.sent.push(data);
    },
    close(code = 1000, reason = "") {
      s.closed = { code, reason };
      s.readyState = 3;
    },
    serializeAttachment(attValue: unknown) {
      s.attachment = attValue as SessionAttachment;
    },
    deserializeAttachment() {
      return s.attachment;
    },
    accept() {
      /* no-op for tests */
    },
  };
  return s;
}

function mockDOState(opts?: {
  sockets?: MockSocket[];
  storage?: Map<string, unknown>;
}): DurableObjectState {
  const map = opts?.storage || new Map<string, unknown>();
  const sockets = opts?.sockets || [];
  return {
    id: { toString: () => "do_test", equals: () => false, name: undefined } as DurableObjectId,
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
      sockets.push(ws as unknown as MockSocket);
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

/** Minimal WebSocketPair so DeviceRoom WS upgrade works outside workerd. */
function installWebSocketPairGlobal(): void {
  const g = globalThis as typeof globalThis & {
    WebSocketPair?: new () => { 0: MockSocket; 1: MockSocket };
    WebSocketRequestResponsePair?: new (req: string, res: string) => unknown;
  };
  if (!g.WebSocketPair) {
    g.WebSocketPair = class WebSocketPair {
      0: MockSocket;
      1: MockSocket;
      constructor() {
        this[0] = mockSocket();
        this[1] = mockSocket();
      }
    };
  }
  if (!g.WebSocketRequestResponsePair) {
    g.WebSocketRequestResponsePair = class WebSocketRequestResponsePair {
      constructor(_req: string, _res: string) {
        /* no-op */
      }
    };
  }
}

/** DEVICE_ROOM namespace that resolves every id to one real DeviceRoom instance. */
function deviceRoomNamespace(room: DeviceRoom): DurableObjectNamespace {
  return {
    idFromName: (name: string) =>
      ({
        toString: () => name,
        equals: () => false,
        name,
      }) as DurableObjectId,
    get: () => room as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function workerEnv(
  adapter: SqlDatabase,
  room: DeviceRoom,
  extra: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    AUTH_PROVIDER: authProvider(),
    OAUTH_ISSUER: ISSUER,
    SESSION_SECRET,
    DB: adapter as unknown as D1Database,
    DEVICE_ROOM: deviceRoomNamespace(room),
    ...extra,
  };
}

function drainSocket(sock: MockSocket): DeviceEnvelope[] {
  const out = sock.sent.map((s) => JSON.parse(s) as DeviceEnvelope);
  sock.sent.length = 0;
  return out;
}

/**
 * Upgrade via real DeviceRoom.fetch, then drive hello→challenge→proof→ready
 * through webSocketMessage. Never mutates session.phase directly.
 */
async function connectAgentReady(opts: {
  room: DeviceRoom;
  deviceId: string;
  deviceCredential: string;
  privateKey: CryptoKey;
}): Promise<{ agentWs: MockSocket; agentSessionId: string; nextSeq: () => number }> {
  installWebSocketPairGlobal();
  const { room, deviceId, deviceCredential, privateKey } = opts;

  const headers = await internalDoHeaders(
    SESSION_SECRET,
    {
      op: "ws",
      device_id: deviceId,
      principal_id: PRINCIPAL_ID,
      tenant_id: TENANT_ID,
      role: "agent",
      method: "GET",
      path: "/ws",
    },
    {
      Upgrade: "websocket",
      origin: ISSUER,
      authorization: `Bearer ${deviceCredential}`,
      "x-ownmesh-allowed-origin": ISSUER,
    },
  );
  // Node's undici Response rejects status 101; workerd allows it for WS upgrade.
  // DeviceRoom.acceptWebSocket + session registration run before Response is built,
  // so a 101 construction error still leaves a live hibernation socket to drive.
  let upgradeStatus: number | null = null;
  try {
    const upgrade = await room.fetch(
      new Request(`https://device-room/ws?device_id=${encodeURIComponent(deviceId)}&role=agent`, {
        headers,
      }),
    );
    upgradeStatus = upgrade.status;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (!/status.*101|range of 200 to 599/i.test(msg)) throw err;
    upgradeStatus = 101;
  }
  assert.equal(upgradeStatus, 101, "WS upgrade must complete (101)");

  const agentWs = [...room.wsSessions.keys()][0] as unknown as MockSocket;
  assert.ok(agentWs, "DeviceRoom must accept hibernation websocket");
  const agentSessionId = room.wsSessions.get(agentWs as unknown as WebSocket);
  assert.ok(agentSessionId);
  assert.equal(room.router.sessions.get(agentSessionId)?.phase, "connected");

  let seq = 0;
  const nextSeq = () => {
    seq += 1;
    return seq;
  };
  const frame = (
    type: string,
    payload: Record<string, unknown> = {},
    correlation?: string,
  ): DeviceEnvelope => {
    const envl: DeviceEnvelope = {
      protocol: PROTOCOL,
      message_id: randomId("msg_"),
      type,
      device_id: deviceId,
      seq: nextSeq(),
      sent_at: new Date().toISOString(),
      payload,
    };
    if (correlation) envl.correlation_id = correlation;
    return envl;
  };

  await room.webSocketMessage(
    agentWs as unknown as WebSocket,
    JSON.stringify(frame("hello", { protocols: [PROTOCOL] })),
  );
  const challengeMsgs = drainSocket(agentWs);
  assert.equal(challengeMsgs[0]?.type, "challenge");
  const challengeMessage = String(challengeMsgs[0]?.payload.message || "");
  assert.match(challengeMessage, /ownmesh-device-challenge/);
  assert.equal(room.router.sessions.get(agentSessionId)?.phase, "challenged");

  const signature = await signHex(privateKey, challengeMessage);
  await room.webSocketMessage(
    agentWs as unknown as WebSocket,
    JSON.stringify(
      frame("proof", {
        signature,
        connection_id: challengeMsgs[0]?.payload.connection_id,
      }),
    ),
  );
  assert.equal(drainSocket(agentWs)[0]?.type, "accepted");
  assert.equal(room.router.sessions.get(agentSessionId)?.phase, "proven");

  await room.webSocketMessage(
    agentWs as unknown as WebSocket,
    JSON.stringify(
      frame("ready", {
        capabilities: ["filesystem.read", "filesystem.write", "command.run"],
        remote_routing_enabled: true,
      }),
    ),
  );
  assert.equal(drainSocket(agentWs)[0]?.type, "ready.ack");
  // Phase ready only via handshake above — never assigned in the test.
  assert.equal(room.router.sessions.get(agentSessionId)?.phase, "ready");

  return { agentWs, agentSessionId, nextSeq };
}

async function enrollActivatedDevice(
  store: SqlStore,
  adapter: SqlDatabase,
  privateKey: CryptoKey,
  publicKeyHex: string,
  name: string,
): Promise<{ deviceId: string; deviceCredential: string; accessToken: string; room: DeviceRoom }> {
  const human = await store.issueTokens(
    CLIENT,
    PRINCIPAL_ID,
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device",
  );
  const e = env(store);
  const enrollRes = await worker.fetch(
    new Request(`${ISSUER}/v1/devices/enroll`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${human.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name,
        hostname: `${name}.local`,
        os: "linux",
        arch: "x64",
        agent_version: "1.0.1",
        protocol_version: "ownmesh.device/1.0",
        public_key: publicKeyHex,
      }),
    }),
    e,
    ctx,
  );
  assert.equal(enrollRes.status, 201);
  const enrolled = (await enrollRes.json()) as {
    device_id: string;
    challenge: { id: string; message: string };
  };
  const enrollSig = await signHex(privateKey, enrolled.challenge.message);
  const proofRes = await worker.fetch(
    new Request(`${ISSUER}/v1/devices/enroll/proof`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${human.access_token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        device_id: enrolled.device_id,
        challenge_id: enrolled.challenge.id,
        signature: enrollSig,
      }),
    }),
    e,
    ctx,
  );
  assert.equal(proofRes.status, 200);
  const proof = (await proofRes.json()) as { device_credential: string; status: string };
  assert.equal(proof.status, "active");
  assert.ok(proof.device_credential.startsWith("dcred_"));

  installWebSocketPairGlobal();
  const room = new DeviceRoom(mockDOState({ storage: new Map() }), {
    DB: adapter as unknown as D1Database,
    SESSION_SECRET,
    OAUTH_ISSUER: ISSUER,
  });
  await room.ready;

  return {
    deviceId: enrolled.device_id,
    deviceCredential: proof.device_credential,
    accessToken: human.access_token,
    room,
  };
}

function mcpRpc(
  name: string,
  args: Record<string, unknown>,
  token: string,
): Request {
  return new Request(`${ISSUER}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
      origin: ISSUER,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name, arguments: args },
    }),
  });
}

// ---------------------------------------------------------------------------
// Happy paths on SqlStore + worker
// ---------------------------------------------------------------------------

test("production-path: delayed AUTH_PROVIDER cannot extend consent expiry past GET receipt", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  await store.putClient({
    client_id: CLIENT,
    tenant_id: TENANT_ID,
    client_name: "receipt-boundary",
    redirect_uris: [REDIRECT],
    created_at: new Date().toISOString(),
  });
  __setTestStore(store);
  let providerStartedAt = 0;
  try {
    const response = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          "&code_challenge=receipt_boundary&code_challenge_method=S256&scope=ownmesh.read",
      ),
      {
        OAUTH_ISSUER: ISSUER,
        AUTH_PROVIDER: {
          fetch: async () => {
            providerStartedAt = Date.now();
            await new Promise<void>((resolve) => setTimeout(resolve, 150));
            return Response.json({
              principal_id: PRINCIPAL_ID,
              tenant_id: TENANT_ID,
              display_name: PRINCIPAL_ID,
            });
          },
        } as unknown as Fetcher,
      },
      ctx,
    );
    assert.equal(response.status, 200);
    const { tx } = parseConsentForm(await response.text());
    const stored = store.authorizeTransactions.get(tx);
    assert.ok(stored, "worker must persist the consent transaction");
    assert.ok(providerStartedAt > 0, "delayed AUTH_PROVIDER must have run");
    assert.ok(
      stored!.expires_at <= providerStartedAt + 5 * 60 * 1000,
      "consent expiry must be anchored before the delayed AUTH_PROVIDER call",
    );
  } finally {
    __setTestStore(null);
  }
});

test("production-path: authorize consent-tx + PKCE exchange via worker + SqlStore", async () => {
  await withStore(async (store) => {
    const { verifier, challenge } = await makePkce();
    const e = env(store);

    const getRes = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256` +
          `&scope=ownmesh.read%20offline_access&state=st_prod`,
      ),
      e,
      ctx,
    );
    assert.equal(getRes.status, 200);
    const { tx, csrf } = parseConsentForm(await getRes.text());

    const postRes = await worker.fetch(
      new Request(`${ISSUER}/oauth/authorize`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: tx,
          csrf_token: csrf,
          decision: "approve",
          // attacker-controlled params must be ignored
          scope: "ownmesh.exec",
          redirect_uri: "https://evil.example/cb",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(postRes.status, 302);
    const loc = new URL(postRes.headers.get("location")!);
    assert.equal(loc.origin + loc.pathname, REDIRECT);
    assert.equal(loc.searchParams.get("state"), "st_prod");
    const code = loc.searchParams.get("code");
    assert.ok(code?.startsWith("ac_"));

    const tokRes = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "authorization_code",
          code: code!,
          redirect_uri: REDIRECT,
          client_id: CLIENT,
          code_verifier: verifier,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(tokRes.status, 200);
    const tok = (await tokRes.json()) as {
      access_token: string;
      refresh_token?: string;
      token_type: string;
    };
    assert.ok(tok.access_token.startsWith("atk_"));
    assert.ok(tok.refresh_token?.startsWith("rtk_"));
    assert.ok(await store.getAccess(tok.access_token));
  });
});

test("production-path: device-code flow via worker + SqlStore (GET consent → POST approve → token)", async () => {
  await withStore(async (store) => {
    const e = env(store);

    const issued = await worker.fetch(
      new Request(`${ISSUER}/oauth/device_authorization`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_id: CLIENT, scope: "ownmesh.read" }),
      }),
      e,
      ctx,
    );
    assert.equal(issued.status, 200);
    const dc = (await issued.json()) as {
      device_code: string;
      user_code: string;
    };
    assert.ok(dc.device_code);
    assert.match(dc.user_code, /^[A-Z]{4}-[A-Z]{4}$/);

    const pending = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: dc.device_code,
          client_id: CLIENT,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(pending.status, 400);
    assert.equal(((await pending.json()) as { error: string }).error, "authorization_pending");

    const page = await worker.fetch(
      new Request(`${ISSUER}/oauth/device?user_code=${encodeURIComponent(dc.user_code)}`),
      e,
      ctx,
    );
    assert.equal(page.status, 200);
    const { tx, csrf } = parseConsentForm(await page.text());

    const approve = await worker.fetch(
      new Request(`${ISSUER}/oauth/device`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: tx,
          csrf_token: csrf,
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(approve.status, 200);

    const done = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: dc.device_code,
          client_id: CLIENT,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(done.status, 200);
    const tok = (await done.json()) as { access_token: string };
    assert.ok(await store.getAccess(tok.access_token));

    // Second poll must fail closed (code consumed)
    const reuse = await worker.fetch(
      new Request(`${ISSUER}/oauth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: dc.device_code,
          client_id: CLIENT,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(reuse.status, 400);
  });
});

test("production-path: enroll → real Ed25519 proof → activate via worker + SqlStore", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.device ownmesh.read");
    const { publicKeyHex, privateKey } = await ed25519Keypair();

    const enrollRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "prod-agent",
          hostname: "prod.local",
          os: "linux",
          arch: "x64",
          agent_version: "1.0.1",
          protocol_version: "ownmesh.device/1.0",
          public_key: publicKeyHex,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(enrollRes.status, 201);
    const enrolled = (await enrollRes.json()) as {
      device_id: string;
      challenge: { id: string; message: string };
    };
    assert.match(enrolled.device_id, /^dev_/);
    assert.equal((await store.getDevice(enrolled.device_id))?.status, "pending");

    const signature = await signHex(privateKey, enrolled.challenge.message);
    const proofRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(proofRes.status, 200);
    const proof = (await proofRes.json()) as {
      ok: boolean;
      status: string;
      device_credential: string;
    };
    assert.equal(proof.ok, true);
    assert.equal(proof.status, "active");
    assert.ok(proof.device_credential.startsWith("dcred_"));
    assert.equal((await store.getDevice(enrolled.device_id))?.status, "active");
    assert.ok(await store.getDeviceCredential(proof.device_credential));

    // Challenge one-time: reuse fails closed
    const reuse = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature,
        }),
      }),
      e,
      ctx,
    );
    assert.ok(reuse.status === 409 || reuse.status === 400);
  });
});

// ---------------------------------------------------------------------------
// Security negatives (fail closed)
// ---------------------------------------------------------------------------

test("production-path negatives: bad Ed25519 signature leaves device pending", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.device");
    const { publicKeyHex } = await ed25519Keypair();

    const enrollRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "bad-sig",
          hostname: "bad.local",
          os: "linux",
          arch: "x64",
          agent_version: "1.0.1",
          protocol_version: "ownmesh.device/1.0",
          public_key: publicKeyHex,
        }),
      }),
      e,
      ctx,
    );
    const enrolled = (await enrollRes.json()) as {
      device_id: string;
      challenge: { id: string };
    };

    const bad = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature: "00".repeat(64),
        }),
      }),
      e,
      ctx,
    );
    assert.equal(bad.status, 400);
    assert.equal((await store.getDevice(enrolled.device_id))?.status, "pending");
  });
});

test("production-path negatives: CSRF replay rejected on authorize and device verification", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const { challenge } = await makePkce();

    // --- authorize consent replay ---
    const getAuth = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256&scope=ownmesh.read&state=s`,
      ),
      e,
      ctx,
    );
    const authForm = parseConsentForm(await getAuth.text());
    const approveOnce = () =>
      worker.fetch(
        new Request(`${ISSUER}/oauth/authorize`, {
          method: "POST",
          headers: {
            origin: ISSUER,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            transaction_id: authForm.tx,
            csrf_token: authForm.csrf,
            decision: "approve",
          }),
        }),
        e,
        ctx,
      );
    assert.equal((await approveOnce()).status, 302);
    assert.equal((await approveOnce()).status, 400);

    // wrong CSRF on a fresh tx
    const getAuth2 = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256&scope=ownmesh.read`,
      ),
      e,
      ctx,
    );
    const authForm2 = parseConsentForm(await getAuth2.text());
    const wrongCsrf = await worker.fetch(
      new Request(`${ISSUER}/oauth/authorize`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: authForm2.tx,
          csrf_token: "csrf_forged_token_value",
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(wrongCsrf.status, 400);

    // --- device verification CSRF replay ---
    const da = await worker.fetch(
      new Request(`${ISSUER}/oauth/device_authorization`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ client_id: CLIENT, scope: "ownmesh.read" }),
      }),
      e,
      ctx,
    );
    const dc = (await da.json()) as { user_code: string };
    const page = await worker.fetch(
      new Request(`${ISSUER}/oauth/device?user_code=${encodeURIComponent(dc.user_code)}`),
      e,
      ctx,
    );
    const devForm = parseConsentForm(await page.text());
    const approveDev = () =>
      worker.fetch(
        new Request(`${ISSUER}/oauth/device`, {
          method: "POST",
          headers: {
            origin: ISSUER,
            "content-type": "application/x-www-form-urlencoded",
          },
          body: new URLSearchParams({
            transaction_id: devForm.tx,
            csrf_token: devForm.csrf,
            decision: "approve",
          }),
        }),
        e,
        ctx,
      );
    assert.equal((await approveDev()).status, 200);
    assert.equal((await approveDev()).status, 400);
  });
});

test("production-path negatives: expired authorize and device-verification transactions fail closed", async () => {
  await withStore(async (store) => {
    const e = env(store);

    // Expired authorize transaction (inserted directly; worker POST must reject)
    const csrfAuth = "csrf_expired_auth_token";
    const authTxId = "atz_expired_prod";
    await store.putAuthorizeTransaction({
      id: authTxId,
      csrf_hash: await sha256Hex(csrfAuth),
      principal_id: PRINCIPAL_ID,
      tenant_id: TENANT_ID,
      client_id: CLIENT,
      redirect_uri: REDIRECT,
      scope: "ownmesh.read",
      state: "expired",
      code_challenge: "ch_expired",
      code_challenge_method: "S256",
      expires_at: Date.now() - 1_000,
      consumed: false,
    });
    const expiredAuth = await worker.fetch(
      new Request(`${ISSUER}/oauth/authorize`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: authTxId,
          csrf_token: csrfAuth,
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(expiredAuth.status, 400);

    // Expired device verification transaction
    await store.putDeviceCode({
      device_code: "dcode_expired_vtx",
      user_code: "XPDF-CDFG",
      client_id: CLIENT,
      scope: "ownmesh.read",
      verification_uri: `${ISSUER}/oauth/device`,
      interval_sec: 5,
      expires_at: Date.now() + 60_000,
      status: "pending",
    });
    const csrfDev = "csrf_expired_dev_token";
    const vtxId = "dvt_expired_prod";
    await store.putDeviceVerificationTransaction({
      id: vtxId,
      csrf_hash: await sha256Hex(csrfDev),
      user_code: "XPDF-CDFG",
      principal_id: PRINCIPAL_ID,
      client_id: CLIENT,
      scope: "ownmesh.read",
      expires_at: Date.now() - 1_000,
      consumed: false,
    });
    const expiredDev = await worker.fetch(
      new Request(`${ISSUER}/oauth/device`, {
        method: "POST",
        headers: {
          origin: ISSUER,
          "content-type": "application/x-www-form-urlencoded",
        },
        body: new URLSearchParams({
          transaction_id: vtxId,
          csrf_token: csrfDev,
          decision: "approve",
        }),
      }),
      e,
      ctx,
    );
    assert.equal(expiredDev.status, 400);
    assert.equal((await store.getDeviceCode("dcode_expired_vtx"))?.status, "pending");
  });
});

test("production-path: AUTH_PROVIDER unknown tenant fails closed (401/403) on authorize + device; tenants unchanged", async () => {
  await withStore(async (store) => {
    const unknownTenant = "ten_unprovisioned_xyz";
    const unknownPrincipal = "prin_stranger";
    const e = env(store, {
      AUTH_PROVIDER: authProvider(unknownPrincipal, unknownTenant),
    });

    assert.equal(await store.tenantExists(TENANT_ID), true);
    assert.equal(await store.tenantExists(unknownTenant), false);

    const { challenge } = await makePkce();
    const authorizeRes = await worker.fetch(
      new Request(
        `${ISSUER}/oauth/authorize?response_type=code&client_id=${CLIENT}` +
          `&redirect_uri=${encodeURIComponent(REDIRECT)}` +
          `&code_challenge=${challenge}&code_challenge_method=S256` +
          `&scope=ownmesh.read%20offline_access&state=st_unknown_tenant`,
      ),
      e,
      ctx,
    );
    assert.ok(
      authorizeRes.status === 401 || authorizeRes.status === 403,
      `authorize must fail closed, got ${authorizeRes.status}`,
    );
    assert.notEqual(authorizeRes.status, 500);
    const authorizeBody = (await authorizeRes.json()) as { error?: string };
    assert.equal(authorizeBody.error, "unknown_tenant");

    const deviceRes = await worker.fetch(
      new Request(`${ISSUER}/oauth/device?user_code=BCDF-JKLM`),
      e,
      ctx,
    );
    assert.ok(
      deviceRes.status === 401 || deviceRes.status === 403,
      `device must fail closed, got ${deviceRes.status}`,
    );
    assert.notEqual(deviceRes.status, 500);
    const deviceBody = (await deviceRes.json()) as { error?: string };
    assert.equal(deviceBody.error, "unknown_tenant");

    // No tenant auto-created from provider claims.
    assert.equal(await store.tenantExists(unknownTenant), false);
    // Known principal must not have been inserted under the unknown tenant path either.
    assert.equal(await store.getPrincipal(unknownPrincipal), null);

    // Known tenant still works with the default AUTH_PROVIDER.
    const knownEnv = env(store);
    const knownPage = await worker.fetch(
      new Request(`${ISSUER}/oauth/device`),
      knownEnv,
      ctx,
    );
    assert.equal(knownPage.status, 200);
    assert.match(await knownPage.text(), /user_code|OwnMesh/i);
  });
});

test("production-path negatives: revoked device credential rejected on agent connect", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.device ownmesh.read");
    const { publicKeyHex, privateKey } = await ed25519Keypair();

    const enrollRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "rev-agent",
          hostname: "rev.local",
          os: "linux",
          arch: "x64",
          agent_version: "1.0.1",
          protocol_version: "ownmesh.device/1.0",
          public_key: publicKeyHex,
        }),
      }),
      e,
      ctx,
    );
    const enrolled = (await enrollRes.json()) as {
      device_id: string;
      challenge: { id: string; message: string };
    };
    const signature = await signHex(privateKey, enrolled.challenge.message);
    const proofRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature,
        }),
      }),
      e,
      ctx,
    );
    const proof = (await proofRes.json()) as { device_credential: string };
    assert.ok(proof.device_credential);

    const rev = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/revoke`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ id: enrolled.device_id }),
      }),
      e,
      ctx,
    );
    assert.equal(rev.status, 200);

    // Credential must not validate after revoke
    const hash = await sha256Hex(proof.device_credential);
    assert.equal(
      await store.validateDeviceSession(hash, "agent", enrolled.device_id),
      false,
    );

    // Agent connect must fail closed for revoked device BEFORE any DO hop.
    // No always-204 DEVICE_ROOM stub: omit binding entirely so a leak past
    // auth would surface as 503 (device_room_unbound), not a silent 204.
    const connect = await worker.fetch(
      new Request(
        `${ISSUER}/agent/connect?device_id=${enrolled.device_id}&role=agent`,
        {
          headers: {
            upgrade: "websocket",
            origin: ISSUER,
            authorization: `Bearer ${proof.device_credential}`,
          },
        },
      ),
      e,
      ctx,
    );
    assert.ok(
      connect.status === 403 || connect.status === 401,
      `revoked device must be rejected at auth, got ${connect.status}`,
    );
    assert.notEqual(connect.status, 204);
    assert.notEqual(connect.status, 101);
    assert.notEqual(connect.status, 426);
    const connectBody = (await connect.json()) as { error?: string };
    assert.ok(
      connectBody.error === "device_not_active" ||
        connectBody.error === "invalid_device_credential",
      `expected device_not_active|invalid_device_credential, got ${connectBody.error}`,
    );
  });
});

// ---------------------------------------------------------------------------
// Real DeviceRoom + MCP operation.result + /approve production path
// (no phase 直書き, no tracker.update, no always-204 stubs)
// ---------------------------------------------------------------------------

test("production-path: DEVICE_ROOM missing fails closed 503 on agent connect (valid device)", async () => {
  await withStore(async (store) => {
    const e = env(store);
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.device ownmesh.read");
    const { publicKeyHex, privateKey } = await ed25519Keypair();

    const enrollRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name: "no-do-agent",
          hostname: "nodo.local",
          os: "linux",
          arch: "x64",
          agent_version: "1.0.1",
          protocol_version: "ownmesh.device/1.0",
          public_key: publicKeyHex,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(enrollRes.status, 201);
    const enrolled = (await enrollRes.json()) as {
      device_id: string;
      challenge: { id: string; message: string };
    };
    const signature = await signHex(privateKey, enrolled.challenge.message);
    const proofRes = await worker.fetch(
      new Request(`${ISSUER}/v1/devices/enroll/proof`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${human.access_token}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          device_id: enrolled.device_id,
          challenge_id: enrolled.challenge.id,
          signature,
        }),
      }),
      e,
      ctx,
    );
    assert.equal(proofRes.status, 200);
    const proof = (await proofRes.json()) as { device_credential: string };
    assert.ok(proof.device_credential.startsWith("dcred_"));

    // Valid device + credential, but no DEVICE_ROOM binding → explicit 503.
    const connect = await worker.fetch(
      new Request(
        `${ISSUER}/agent/connect?device_id=${enrolled.device_id}&role=agent`,
        {
          headers: {
            upgrade: "websocket",
            origin: ISSUER,
            authorization: `Bearer ${proof.device_credential}`,
          },
        },
      ),
      e,
      ctx,
    );
    assert.equal(connect.status, 503);
    const body = (await connect.json()) as { error?: string };
    assert.equal(body.error, "device_room_unbound");
  });
});

test("production-path: DeviceRoom handshake → MCP inject → operation.result updates store → poll", async () => {
  await withStoreAndAdapter(async (store, adapter) => {
    const { publicKeyHex, privateKey } = await ed25519Keypair();
    const { deviceId, deviceCredential, accessToken, room } = await enrollActivatedDevice(
      store,
      adapter,
      privateKey,
      publicKeyHex,
      "prod-do-agent",
    );

    const { agentWs, nextSeq } = await connectAgentReady({
      room,
      deviceId,
      deviceCredential,
      privateKey,
    });

    // worker.fetch /mcp → signed internal /operation on real DeviceRoom (no harness).
    const wenv = workerEnv(adapter, room);
    const createRes = await worker.fetch(
      mcpRpc(
        "ownmesh_fs_list",
        { device_id: deviceId, workspace_id: null, path: "/workspace", async: true },
        accessToken,
      ),
      wenv,
      ctx,
    );
    assert.equal(createRes.status, 200, await createRes.clone().text());
    const created = (await createRes.json()) as {
      result?: {
        structuredContent?: {
          operation_id?: string;
          status?: string;
          correlation_id?: string;
        };
      };
      error?: unknown;
    };
    assert.equal(created.error, undefined);
    const opId = created.result?.structuredContent?.operation_id;
    assert.ok(opId, "operation_id required");
    assert.ok(
      created.result?.structuredContent?.status === "pending" ||
        created.result?.structuredContent?.status === "running",
    );

    const storedPending = await store.getMcpOperation(opId!);
    assert.ok(storedPending);
    assert.equal(storedPending!.device_id, deviceId);
    const correlation =
      storedPending!.correlation_id ||
      created.result?.structuredContent?.correlation_id;
    assert.ok(correlation);
    assert.ok(room.router.pending.has(correlation!), "DO pending must hold correlation");

    // Agent receives operation.request delivered by real DeviceRoom /operation inject.
    const agentInbox = drainSocket(agentWs);
    assert.ok(
      agentInbox.some((m) => m.type === "operation.request"),
      `agent must receive operation.request, got ${JSON.stringify(agentInbox.map((m) => m.type))}`,
    );
    const reqMsg = agentInbox.find((m) => m.type === "operation.request")!;
    assert.equal(reqMsg.correlation_id, correlation);

    // Agent completes via real DO webSocketMessage → applyMcpOperationResult runtime path.
    const resultFrame: DeviceEnvelope = {
      protocol: PROTOCOL,
      message_id: randomId("msg_"),
      type: "operation.result",
      device_id: deviceId,
      seq: nextSeq(),
      sent_at: new Date().toISOString(),
      correlation_id: correlation!,
      payload: {
        status: "completed",
        operation_id: opId,
        summary: "listed",
        result: {
          entries: ["README.md", "src/"],
          workspace_id: null,
          workspace_version: null,
        },
      },
    };
    await room.webSocketMessage(
      agentWs as unknown as WebSocket,
      JSON.stringify(resultFrame),
    );

    // D1/SqlStore row updated only via DeviceRoom runtime path (no manual apply helper).
    const completed = await store.getMcpOperation(opId!);
    assert.equal(completed?.status, "completed");
    assert.deepEqual((completed?.data as { entries?: string[] }).entries, ["README.md", "src/"]);
    assert.equal((completed?.data as { workspace_id?: unknown }).workspace_id, null);
    assert.equal((completed?.data as { workspace_version?: unknown }).workspace_version, null);
    assert.equal(
      room.router.pending.has(correlation!),
      false,
      "pending cleared only after authoritative CAS",
    );

    // Poll through worker /mcp — store is sole authority (fresh process has no tracker state).
    const pollRes = await worker.fetch(
      mcpRpc("ownmesh_get_operation", { operation_id: opId }, accessToken),
      wenv,
      ctx,
    );
    assert.equal(pollRes.status, 200);
    const polled = (await pollRes.json()) as {
      result?: {
        structuredContent?: {
          status?: string;
          operation_id?: string;
          data?: { entries?: string[] };
        };
      };
    };
    assert.equal(polled.result?.structuredContent?.operation_id, opId);
    assert.equal(polled.result?.structuredContent?.status, "completed");
    assert.deepEqual(polled.result?.structuredContent?.data?.entries, ["README.md", "src/"]);
  });
});

test("production-path: synchronous MCP uses a bounded authoritative fast path", async () => {
  await withStoreAndAdapter(async (store, adapter) => {
    const { publicKeyHex, privateKey } = await ed25519Keypair();
    const { deviceId, deviceCredential, accessToken, room } = await enrollActivatedDevice(
      store,
      adapter,
      privateKey,
      publicKeyHex,
      "prod-sync-wait-agent",
    );
    const { agentWs, nextSeq } = await connectAgentReady({
      room,
      deviceId,
      deviceCredential,
      privateKey,
    });
    const wenv = workerEnv(adapter, room);

    const takeRequest = async (): Promise<DeviceEnvelope> => {
      const deadline = Date.now() + 2_000;
      while (Date.now() < deadline) {
        const request = drainSocket(agentWs).find((message) => message.type === "operation.request");
        if (request) return request;
        await new Promise<void>((resolve) => setTimeout(resolve, 5));
      }
      throw new Error("timed out waiting for operation.request");
    };
    const complete = async (request: DeviceEnvelope, summary: string): Promise<void> => {
      await room.webSocketMessage(
        agentWs as unknown as WebSocket,
        JSON.stringify({
          protocol: PROTOCOL,
          message_id: randomId("msg_"),
          type: "operation.result",
          device_id: deviceId,
          seq: nextSeq(),
          sent_at: new Date().toISOString(),
          correlation_id: request.correlation_id,
          payload: {
            status: "completed",
            operation_id: request.payload.operation_id,
            summary,
            // Mirror the Agent's exact absolute-path workspace receipt.
            result: { entries: [summary], workspace_id: null, workspace_version: null },
          },
        } satisfies DeviceEnvelope),
      );
    };
    const content = async (response: Response) => {
      assert.equal(response.status, 200, await response.clone().text());
      const body = (await response.json()) as {
        result?: { structuredContent?: Record<string, unknown> };
        error?: unknown;
      };
      assert.equal(body.error, undefined);
      return body.result?.structuredContent || {};
    };

    // A result arriving shortly after durable dispatch completes in this call.
    const fastResponder = (async () => {
      const request = await takeRequest();
      await new Promise<void>((resolve) => setTimeout(resolve, 25));
      await complete(request, "fast");
    })();
    const fastStarted = Date.now();
    const fastResponse = await worker.fetch(
      mcpRpc(
        "ownmesh_fs_list",
        { device_id: deviceId, workspace_id: null, path: "/fast", idempotency_key: "sync-fast" },
        accessToken,
      ),
      wenv,
      ctx,
    );
    await fastResponder;
    const fast = await content(fastResponse);
    assert.equal(fast.status, "completed");
    assert.equal(fast.phase, "completed");
    assert.match(String(fast.phase_updated_at), /^\d{4}-\d{2}-\d{2}T/);
    assert.ok(Date.now() - fastStarted < MCP_SYNC_WAIT_MS + 500);

    // No result within the fixed window remains durable, pollable pending.
    const timeoutStarted = Date.now();
    const timeout = await content(await worker.fetch(
      mcpRpc(
        "ownmesh_fs_list",
        { device_id: deviceId, workspace_id: null, path: "/slow", idempotency_key: "sync-timeout" },
        accessToken,
      ),
      wenv,
      ctx,
    ));
    const timeoutElapsed = Date.now() - timeoutStarted;
    assert.equal(timeout.status, "pending");
    assert.equal(timeout.phase, "dispatched");
    assert.ok(timeoutElapsed >= MCP_SYNC_WAIT_MS - 100, `waited only ${timeoutElapsed}ms`);
    assert.ok(timeoutElapsed < MCP_SYNC_WAIT_MS + 1_000, `waited ${timeoutElapsed}ms`);
    assert.ok(await store.getMcpOperation(String(timeout.operation_id)));
    drainSocket(agentWs);

    // If the device wins before the Worker writes its pending route receipt,
    // the terminal CAS winner must be returned and never overwritten.
    let raced = false;
    const racingStub = {
      fetch: async (request: Request) => {
        const response = await room.fetch(request);
        const operationRequest = drainSocket(agentWs).find(
          (message) => message.type === "operation.request",
        );
        assert.ok(operationRequest);
        await complete(operationRequest!, "race-winner");
        raced = true;
        return response;
      },
    } as unknown as DurableObjectStub;
    const racingNamespace = {
      idFromName: (name: string) => ({ toString: () => name, equals: () => false, name }),
      get: () => racingStub,
    } as unknown as DurableObjectNamespace;
    const race = await content(await worker.fetch(
      mcpRpc(
        "ownmesh_fs_list",
        { device_id: deviceId, workspace_id: null, path: "/race", idempotency_key: "sync-race" },
        accessToken,
      ),
      { ...wenv, DEVICE_ROOM: racingNamespace },
      ctx,
    ));
    assert.equal(raced, true);
    assert.equal(race.status, "completed");
    assert.equal(race.phase, "completed");
  });
});

test("production-path: /approve auth+CSRF+one-time delivers decision via real DeviceRoom", async () => {
  await withStoreAndAdapter(async (store, adapter) => {
    const { publicKeyHex, privateKey } = await ed25519Keypair();
    const { deviceId, deviceCredential, accessToken, room } = await enrollActivatedDevice(
      store,
      adapter,
      privateKey,
      publicKeyHex,
      "prod-approve-agent",
    );
    const { agentWs } = await connectAgentReady({
      room,
      deviceId,
      deviceCredential,
      privateKey,
    });
    const wenv = workerEnv(adapter, room, {
      AUTH_PROVIDER: authProvider(PRINCIPAL_ID, TENANT_ID, true),
    });

    const opId = randomId("op_");
    const corr = randomId("cor_");
    const targetExpires = new Date(Date.now() + 5 * 60_000).toISOString();
    const targetHash = "c".repeat(64);
    await store.putMcpOperation({
      operation_id: opId,
      tenant_id: TENANT_ID,
      principal_id: PRINCIPAL_ID,
      device_id: deviceId,
      tool: "ownmesh_fs_write",
      status: "approval_required",
      summary: "needs human",
      data: { tool: "ownmesh_fs_write", path: "secret.txt" },
      truncated: false,
      next_cursor: null,
      approval_required: true,
      approval_url: `${ISSUER}/approve?operation_id=${opId}`,
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

    // Creator/MCP bearer must not self-approve (fail-closed).
    const creatorBearer = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId}`, {
        headers: { authorization: `Bearer ${accessToken}` },
      }),
      wenv,
      ctx,
    );
    assert.equal(creatorBearer.status, 403, await creatorBearer.clone().text());
    assert.equal(
      ((await creatorBearer.json()) as { error?: string }).error,
      "self_approval_forbidden",
    );
    assert.equal((await store.getMcpOperation(opId))?.status, "approval_required");

    // Wrong human principal via AUTH_PROVIDER → not found / forbidden (no leak).
    await store.ensurePrincipal("prin_other", "Other", "human", TENANT_ID);
    const wrongPrin = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId}`),
      { ...wenv, AUTH_PROVIDER: authProvider("prin_other", TENANT_ID, true) },
      ctx,
    );
    assert.ok(
      wrongPrin.status === 404 || wrongPrin.status === 403,
      `foreign principal must not see op, got ${wrongPrin.status}`,
    );

    // Non-human principal cannot approve.
    await store.ensurePrincipal("prin_service", "Svc", "service", TENANT_ID);
    const servicePrin = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId}`),
      { ...wenv, AUTH_PROVIDER: authProvider("prin_service", TENANT_ID, true) },
      ctx,
    );
    assert.equal(servicePrin.status, 403, await servicePrin.clone().text());
    assert.match(
      String(((await servicePrin.json()) as { error_description?: string }).error_description || ""),
      /human/i,
    );

    // Tenant mismatch fail-closed: AUTH_PROVIDER claims owner id but wrong tenant.
    const tenantMismatch = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId}`),
      { ...wenv, AUTH_PROVIDER: authProvider(PRINCIPAL_ID, "ten_other", true) },
      ctx,
    );
    assert.equal(tenantMismatch.status, 403, await tenantMismatch.clone().text());
    assert.match(
      String(((await tenantMismatch.json()) as { error_description?: string }).error_description || ""),
      /tenant/i,
    );

    // GET approval page through worker via independent human browser auth.
    const getRes = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId}`),
      wenv,
      ctx,
    );
    assert.equal(getRes.status, 200, await getRes.clone().text());
    const html = await getRes.text();
    const tx = /name="transaction_id" value="([^"]+)"/.exec(html)?.[1];
    const csrf = /name="csrf_token" value="([^"]+)"/.exec(html)?.[1];
    assert.ok(tx && csrf, "approval form must include transaction_id and csrf_token");

    // Client-supplied approver identity must be ignored (auth principal wins).
    const postBody = {
      decision: "approve",
      transaction_id: tx!,
      csrf_token: csrf!,
      operation_id: opId,
      approver_principal_id: "prin_attacker",
      principal_id: "prin_attacker",
    };
    const postOnce = () =>
      worker.fetch(
        new Request(`${ISSUER}/approve?operation_id=${opId}`, {
          method: "POST",
          headers: {
            "content-type": "application/json",
            accept: "application/json",
            origin: ISSUER,
          },
          body: JSON.stringify(postBody),
        }),
        wenv,
        ctx,
      );

    // Bearer POST still forbidden even with a valid browser-minted tx id in body.
    const bearerPost = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          authorization: `Bearer ${accessToken}`,
          origin: ISSUER,
        },
        body: JSON.stringify(postBody),
      }),
      wenv,
      ctx,
    );
    assert.equal(bearerPost.status, 403);
    assert.equal(
      ((await bearerPost.json()) as { error?: string }).error,
      "self_approval_forbidden",
    );
    assert.equal((await store.getMcpOperation(opId))?.status, "approval_required");

    const first = await postOnce();
    assert.equal(first.status, 200, await first.clone().text());
    const firstBody = (await first.json()) as {
      ok: boolean;
      decision: string;
      status: string;
      route?: { status: string };
    };
    assert.equal(firstBody.ok, true);
    assert.equal(firstBody.decision, "approve");
    assert.equal(firstBody.status, "approval_required");
    assert.equal(firstBody.route?.status, "routed_to_device");

    // Real DeviceRoom delivered bound approval.decision to the agent frame.
    const agentInbox = drainSocket(agentWs);
    const decisionFrame = agentInbox.find(
      (m) =>
        m.type === "operation.request" &&
        (m.payload.capability === "approval.decision" ||
          (m.payload.arguments as { action?: string } | undefined)?.action ===
            "approval.decision"),
    );
    assert.ok(
      decisionFrame,
      `agent must receive approval.decision, got ${JSON.stringify(
        agentInbox.map(
          (m) =>
            m.type +
            ":" +
            String(m.payload.capability || m.payload.op || m.payload.decision || ""),
        ),
      )}`,
    );
    assert.equal(
      (decisionFrame!.payload.arguments as { decision?: string } | undefined)?.decision,
      "approve",
    );
    assert.ok(
      typeof decisionFrame!.payload.payload_hash === "string" &&
        String(decisionFrame!.payload.payload_hash).length === 64,
      "decision frame must carry server payload_hash",
    );
    const bound = (
      decisionFrame!.payload.authorization as
        | { bound_action?: Record<string, unknown> }
        | undefined
    )?.bound_action;
    assert.ok(bound && typeof bound === "object", "decision must carry bound_action");
    assert.equal(bound!.action, "approval.decision");
    assert.equal(bound!.principal_id, PRINCIPAL_ID);
    assert.equal(
      (bound!.facts as { target_payload_hash?: string } | undefined)?.target_payload_hash,
      targetHash,
    );

    // Delivery alone is not execution. The operation remains nonterminal until
    // the Agent returns the authoritative result for this exact decision.
    assert.equal((await store.getMcpOperation(opId))?.status, "approval_required");
    assert.equal((await store.getMcpOperation(opId))?.approval_required, true);

    // One-time: same transaction rejected (replay/TOCTOU).
    const second = await postOnce();
    assert.equal(second.status, 400);

    // CSRF forgery on a fresh approval_required op is rejected.
    const opId2 = randomId("op_");
    await store.putMcpOperation({
      operation_id: opId2,
      tenant_id: TENANT_ID,
      principal_id: PRINCIPAL_ID,
      device_id: deviceId,
      tool: "ownmesh_fs_write",
      status: "approval_required",
      summary: "needs human again",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: true,
      approval_url: `${ISSUER}/approve?operation_id=${opId2}`,
      warnings: [],
      correlation_id: randomId("cor_"),
      policy_authority: "ownmesh_device",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    const get2 = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId2}`),
      wenv,
      ctx,
    );
    assert.equal(get2.status, 200);
    const html2 = await get2.text();
    const tx2 = /name="transaction_id" value="([^"]+)"/.exec(html2)?.[1];
    assert.ok(tx2);
    const forged = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId2}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          origin: ISSUER,
        },
        body: JSON.stringify({
          decision: "approve",
          transaction_id: tx2,
          csrf_token: "csrf_forged_token_value",
          operation_id: opId2,
        }),
      }),
      wenv,
      ctx,
    );
    assert.equal(forged.status, 400);
    assert.equal((await store.getMcpOperation(opId2))?.status, "approval_required");

    // Delivery-failure: device offline → retryable non-success; op stays approval_required.
    const offlineRoom = new DeviceRoom(mockDOState({ storage: new Map() }), {
      DB: adapter as unknown as D1Database,
      SESSION_SECRET,
      OAUTH_ISSUER: ISSUER,
    });
    await offlineRoom.ready;
    const offlineEnv = workerEnv(adapter, offlineRoom, {
      AUTH_PROVIDER: authProvider(PRINCIPAL_ID, TENANT_ID, true),
    });
    const opId3 = randomId("op_");
    await store.putMcpOperation({
      operation_id: opId3,
      tenant_id: TENANT_ID,
      principal_id: PRINCIPAL_ID,
      device_id: deviceId,
      tool: "ownmesh_fs_write",
      status: "approval_required",
      summary: "offline delivery",
      data: {},
      truncated: false,
      next_cursor: null,
      approval_required: true,
      approval_url: `${ISSUER}/approve?operation_id=${opId3}`,
      warnings: [],
      correlation_id: randomId("cor_"),
      policy_authority: "ownmesh_device",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    });
    const get3 = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId3}`),
      offlineEnv,
      ctx,
    );
    assert.equal(get3.status, 200);
    const html3 = await get3.text();
    const tx3 = /name="transaction_id" value="([^"]+)"/.exec(html3)?.[1];
    const csrf3 = /name="csrf_token" value="([^"]+)"/.exec(html3)?.[1];
    assert.ok(tx3 && csrf3);
    const failDelivery = await worker.fetch(
      new Request(`${ISSUER}/approve?operation_id=${opId3}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          accept: "application/json",
          origin: ISSUER,
        },
        body: JSON.stringify({
          decision: "approve",
          transaction_id: tx3,
          csrf_token: csrf3,
          operation_id: opId3,
        }),
      }),
      offlineEnv,
      ctx,
    );
    assert.equal(failDelivery.status, 503, await failDelivery.clone().text());
    const failBody = (await failDelivery.json()) as {
      ok?: boolean;
      error?: string;
      retryable?: boolean;
      delivery_status?: string;
      route?: { status?: string };
    };
    assert.notEqual(failBody.ok, true);
    assert.equal(failBody.error, "delivery_failed");
    assert.equal(failBody.retryable, true);
    assert.equal(failBody.delivery_status, "pending");
    assert.equal(failBody.route?.status, "device_offline");
    // Authoritative transition must NOT have run on delivery failure.
    assert.equal((await store.getMcpOperation(opId3))?.status, "approval_required");
    assert.equal((await store.getMcpOperation(opId3))?.approval_required, true);
  });
});

test("production-path: worker /approve is implemented (auth required, not 501)", async () => {
  await withStore(async (store) => {
    // No AUTH_PROVIDER → unauthorized (not a 501 stub).
    const unauth = await worker.fetch(
      new Request(`${ISSUER}/approve`),
      { OAUTH_ISSUER: ISSUER },
      ctx,
    );
    assert.equal(unauth.status, 401);
    assert.notEqual(unauth.status, 501);

    // Creator bearer rejected (not treated as human approval session).
    const human = await store.issueTokens(CLIENT, PRINCIPAL_ID, "ownmesh.read ownmesh.exec");
    const bearerDenied = await worker.fetch(
      new Request(`${ISSUER}/approve`, {
        headers: { authorization: `Bearer ${human.access_token}` },
      }),
      env(store),
      ctx,
    );
    assert.equal(bearerDenied.status, 403);
    assert.equal(
      ((await bearerDenied.json()) as { error?: string }).error,
      "self_approval_forbidden",
    );

    // Independent human browser auth, no operation_id → pending inbox (handler is live).
    const authNoOp = await worker.fetch(
      new Request(`${ISSUER}/approve`),
      env(store),
      ctx,
    );
    assert.equal(authNoOp.status, 200);
    assert.match(await authNoOp.text(), /Review pending operations/);
    assert.notEqual(authNoOp.status, 501);
  });
});
