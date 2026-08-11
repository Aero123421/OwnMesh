/**
 * DeviceRoom security-negative tests with real Ed25519 verification.
 *
 * - hello → challenge → proof → ready completed via real WebCrypto signatures
 * - forged proofs rejected (no always-true verifyProof)
 * - security-negative states reached through the protocol, never by mutating phase
 */
import assert from "node:assert/strict";
import test from "node:test";
import {
  DeviceRoomHarness,
  PROTOCOL,
  type DeviceEnvelope,
} from "./device-room.ts";
import {
  randomId,
  verifyEd25519Hex,
  internalContextHeaderName,
  signInternalContext,
  verifyInternalContext,
  sha256Hex,
  INTERNAL_CONTEXT_TTL_MS,
  InternalContextReplayGuard,
  defaultInternalContextReplayGuard,
} from "./util.ts";
import worker, { __setTestStore, __test, DeviceRoom } from "./index.ts";
import { MemoryStore } from "./store.ts";
import fs from "node:fs";

/** Per-session monotonic inbound seq counters. */
const sessionSeq = new Map<string, number>();

function nextSeq(sessionKey: string): number {
  const n = (sessionSeq.get(sessionKey) || 0) + 1;
  sessionSeq.set(sessionKey, n);
  return n;
}

function envFor(
  sessionId: string,
  type: string,
  deviceId: string,
  payload: Record<string, unknown> = {},
  correlation?: string,
  opts?: {
    seq?: number;
    message_id?: string;
    expires_at?: string;
  },
): DeviceEnvelope {
  const e: DeviceEnvelope = {
    protocol: PROTOCOL,
    message_id: opts?.message_id || randomId("msg_"),
    type,
    device_id: deviceId,
    seq: opts?.seq ?? nextSeq(sessionId),
    sent_at: new Date().toISOString(),
    payload,
  };
  if (correlation) e.correlation_id = correlation;
  if (opts?.expires_at) e.expires_at = opts.expires_at;
  return e;
}

async function generateEd25519(): Promise<{
  publicKeyHex: string;
  privateKey: CryptoKey;
  verify: (deviceId: string, message: string, signature: string) => Promise<boolean>;
}> {
  const keyPair = (await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const publicBytes = new Uint8Array(
    (await crypto.subtle.exportKey("raw", keyPair.publicKey)) as ArrayBuffer,
  );
  const publicKeyHex = [...publicBytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return {
    publicKeyHex,
    privateKey: keyPair.privateKey,
    verify: (_deviceId, message, signature) =>
      verifyEd25519Hex(publicKeyHex, message, signature),
  };
}

async function signMessage(privateKey: CryptoKey, message: string): Promise<string> {
  const signatureBytes = new Uint8Array(
    await crypto.subtle.sign("Ed25519", privateKey, new TextEncoder().encode(message)),
  );
  return [...signatureBytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Drive agent through hello → challenge (no phase mutation). */
async function helloToChallenge(
  room: DeviceRoomHarness,
  agent: string,
  deviceId: string,
): Promise<DeviceEnvelope> {
  const hello = await room.send(
    agent,
    envFor(agent, "hello", deviceId, { protocols: [PROTOCOL] }),
  );
  assert.equal(hello.ok, true, "hello must succeed");
  const replies = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(replies[0]?.type, "challenge");
  assert.ok(String(replies[0]?.payload.message || "").includes("ownmesh-device-challenge"));
  assert.equal(room.router.sessions.get(agent)?.phase, "challenged");
  return replies[0]!;
}

test("ws-security: real Ed25519 hello→challenge→proof→ready completes without phase mutation", async () => {
  const deviceId = "dev_wssec_ready01abcdef";
  const { privateKey, verify } = await generateEd25519();
  const room = new DeviceRoomHarness(deviceId, verify);
  const agent = room.connect("agent");

  // Start at connected (harness default) — never force phase.
  assert.equal(room.router.sessions.get(agent)?.phase, "connected");

  const challenge = await helloToChallenge(room, agent, deviceId);
  const message = String(challenge.payload.message);
  const signature = await signMessage(privateKey, message);

  const proofResult = await room.send(
    agent,
    envFor(agent, "proof", deviceId, {
      signature,
      connection_id: challenge.payload.connection_id,
    }),
  );
  assert.equal(proofResult.ok, true);
  assert.equal(room.router.sessions.get(agent)?.phase, "proven");
  const accepted = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(accepted[0]?.type, "accepted");

  const readyResult = await room.send(
    agent,
    envFor(agent, "ready", deviceId, {
      capabilities: ["filesystem.read"],
      remote_routing_enabled: true,
    }),
  );
  assert.equal(readyResult.ok, true);
  assert.equal(room.router.sessions.get(agent)?.phase, "ready");
  const ack = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(ack[0]?.type, "ready.ack");

  // Ready agent can receive injected operations
  const corr = randomId("op_");
  const route = room.router.injectOperation({
    type: "ownmesh_fs_list",
    payload: { path: "/" },
    correlation_id: corr,
  });
  assert.equal(route.status, "routed_to_device");
  const inbox = room.drain(agent).map((s) => JSON.parse(s) as DeviceEnvelope);
  assert.equal(inbox[0]?.type, "operation.request");
  assert.equal(inbox[0]?.correlation_id, corr);
});

test("ws-security: forged proof rejected; session stays challenged (no always-true verifier)", async () => {
  const deviceId = "dev_wssec_forge01abcdef";
  const { verify } = await generateEd25519();
  // Real verifier only — forged hex must fail.
  const room = new DeviceRoomHarness(deviceId, verify);
  const agent = room.connect("agent");

  const challenge = await helloToChallenge(room, agent, deviceId);

  const forged = await room.send(
    agent,
    envFor(agent, "proof", deviceId, {
      signature: "ab".repeat(64),
      connection_id: challenge.payload.connection_id,
    }),
  );
  assert.equal(forged.ok, false);
  assert.equal(forged.error, "invalid_proof");
  // Must remain challenged — never jump to ready/proven without valid proof
  assert.equal(room.router.sessions.get(agent)?.phase, "challenged");
  assert.equal(room.drain(agent).length, 0);

  // Zero-signature also rejected
  const zero = await room.send(
    agent,
    envFor(agent, "proof", deviceId, {
      signature: "00".repeat(64),
      connection_id: challenge.payload.connection_id,
    }),
  );
  assert.equal(zero.ok, false);
  assert.equal(zero.error, "invalid_proof");
  assert.equal(room.router.sessions.get(agent)?.phase, "challenged");
});

test("ws-security: wrong-key signature rejected; valid key can still complete after failed forge", async () => {
  const deviceId = "dev_wssec_wrongkey01abc";
  const device = await generateEd25519();
  const attacker = await generateEd25519();
  const room = new DeviceRoomHarness(deviceId, device.verify);
  const agent = room.connect("agent");

  const challenge = await helloToChallenge(room, agent, deviceId);
  const message = String(challenge.payload.message);

  // Attacker signs with a different keypair
  const badSig = await signMessage(attacker.privateKey, message);
  const bad = await room.send(
    agent,
    envFor(agent, "proof", deviceId, {
      signature: badSig,
      connection_id: challenge.payload.connection_id,
    }),
  );
  assert.equal(bad.ok, false);
  assert.equal(bad.error, "invalid_proof");
  assert.equal(room.router.sessions.get(agent)?.phase, "challenged");

  // Legitimate device key still works on the same challenged session
  const goodSig = await signMessage(device.privateKey, message);
  const good = await room.send(
    agent,
    envFor(agent, "proof", deviceId, {
      signature: goodSig,
      connection_id: challenge.payload.connection_id,
    }),
  );
  assert.equal(good.ok, true);
  assert.equal(room.router.sessions.get(agent)?.phase, "proven");
  assert.equal(
    (JSON.parse(room.drain(agent)[0]!) as DeviceEnvelope).type,
    "accepted",
  );

  // Complete ready without mutating phase
  const ready = await room.send(
    agent,
    envFor(agent, "ready", deviceId, { capabilities: [] }),
  );
  assert.equal(ready.ok, true);
  assert.equal(room.router.sessions.get(agent)?.phase, "ready");
});

test("ws-security: ready/proof out of order rejected without phase shortcuts", async () => {
  const deviceId = "dev_wssec_order01abcdef";
  const { privateKey, verify } = await generateEd25519();
  const room = new DeviceRoomHarness(deviceId, verify);
  const agent = room.connect("agent");

  // ready before hello
  const earlyReady = await room.send(
    agent,
    envFor(agent, "ready", deviceId, { capabilities: [] }),
  );
  assert.equal(earlyReady.ok, false);
  assert.equal(earlyReady.error, "invalid_state");
  assert.equal(room.router.sessions.get(agent)?.phase, "connected");

  // proof before hello
  const earlyProof = await room.send(
    agent,
    envFor(agent, "proof", deviceId, { signature: "11".repeat(64) }),
  );
  assert.equal(earlyProof.ok, false);
  assert.equal(earlyProof.error, "invalid_state");
  assert.equal(room.router.sessions.get(agent)?.phase, "connected");

  // injectOperation must not route while not ready
  const offline = room.router.injectOperation({
    type: "ownmesh_fs_read",
    payload: { path: "/x" },
    correlation_id: randomId("op_"),
  });
  assert.equal(offline.status, "device_offline");

  // Complete proper handshake
  const challenge = await helloToChallenge(room, agent, deviceId);
  const signature = await signMessage(privateKey, String(challenge.payload.message));
  assert.equal(
    (
      await room.send(
        agent,
        envFor(agent, "proof", deviceId, {
          signature,
          connection_id: challenge.payload.connection_id,
        }),
      )
    ).ok,
    true,
  );
  room.drain(agent);
  // ready before proven is impossible here — already proven; skip extra ready-before-proven case
  assert.equal(room.router.sessions.get(agent)?.phase, "proven");
  assert.equal(
    (await room.send(agent, envFor(agent, "ready", deviceId, {}))).ok,
    true,
  );
  assert.equal(room.router.sessions.get(agent)?.phase, "ready");
});

test("ws-security: default harness verifier fails closed (no implicit always-true)", async () => {
  const deviceId = "dev_wssec_default01abcd";
  // No verifyProof argument → DeviceRoomRouter defaults to () => false
  const room = new DeviceRoomHarness(deviceId);
  const agent = room.connect("agent");
  const challenge = await helloToChallenge(room, agent, deviceId);

  // Even a well-formed 64-byte hex signature is rejected without a real verifier
  const result = await room.send(
    agent,
    envFor(agent, "proof", deviceId, {
      signature: "cd".repeat(64),
      connection_id: challenge.payload.connection_id,
    }),
  );
  assert.equal(result.ok, false);
  assert.equal(result.error, "invalid_proof");
  assert.equal(room.router.sessions.get(agent)?.phase, "challenged");
});

const TEST_SECRET = "test-session-secret-for-internal-context-only";
const wsTestCtx = {} as ExecutionContext;

function mockDoState(): DurableObjectState {
  const storage = new Map<string, unknown>();
  return {
    storage: {
      get: async (key: string) => storage.get(key),
      put: async (key: string, value: unknown) => { storage.set(key, value); },
      delete: async (key: string) => storage.delete(key),
    },
    getWebSockets: () => [] as WebSocket[],
    acceptWebSocket: () => undefined,
    blockConcurrencyWhile: async <T>(fn: () => Promise<T>) => fn(),
    setWebSocketAutoResponse: () => undefined,
  } as unknown as DurableObjectState;
}

test("internal context: sign/verify binds principal/tenant/device/op and rejects bad tokens", async () => {
  const guard = new InternalContextReplayGuard();
  const token = await signInternalContext(TEST_SECRET, {
    op: "operation", device_id: "dev_ctx_bind_01", principal_id: "prin_a", tenant_id: "ten_a", correlation_id: "op_1",
  });
  const ok = await verifyInternalContext(TEST_SECRET, token, {
    op: "operation", device_id: "dev_ctx_bind_01", principal_id: "prin_a", tenant_id: "ten_a", correlation_id: "op_1",
    replayGuard: guard,
  });
  assert.equal(ok.ok, true);
  const wrongDevice = await verifyInternalContext(TEST_SECRET, token, {
    op: "operation", device_id: "dev_other", replayGuard: guard,
  });
  assert.equal(wrongDevice.ok, false);
  if (!wrongDevice.ok) { assert.equal(wrongDevice.status, 403); assert.equal(wrongDevice.error, "binding_mismatch"); }
  const wrongOp = await verifyInternalContext(TEST_SECRET, token, {
    op: "ws", device_id: "dev_ctx_bind_01", replayGuard: guard,
  });
  assert.equal(wrongOp.ok, false);
  if (!wrongOp.ok) assert.equal(wrongOp.status, 403);
  const expired = await signInternalContext(TEST_SECRET, { op: "operation", device_id: "dev_ctx_bind_01", principal_id: "prin_a", tenant_id: "ten_a", exp: Date.now() - 1000 });
  const expRes = await verifyInternalContext(TEST_SECRET, expired, {
    op: "operation", device_id: "dev_ctx_bind_01", replayGuard: guard,
  });
  assert.equal(expRes.ok, false);
  if (!expRes.ok) { assert.equal(expRes.status, 401); assert.equal(expRes.error, "context_expired"); }
  const bad = await verifyInternalContext(TEST_SECRET, token.slice(0, -4) + "aaaa", {
    op: "operation", device_id: "dev_ctx_bind_01", replayGuard: guard,
  });
  assert.equal(bad.ok, false);
  if (!bad.ok) assert.equal(bad.status, 401);
});

test("internal context: replay of same nonce rejected; method/path/body_sha256 bound; max TTL enforced", async () => {
  const guard = new InternalContextReplayGuard();
  const body = JSON.stringify({ type: "ownmesh_fs_list", correlation_id: "op_replay_1", payload: { path: "/" } });
  const bodyHash = await sha256Hex(body);
  const token = await signInternalContext(TEST_SECRET, {
    op: "operation",
    device_id: "dev_ctx_replay_01",
    principal_id: "prin_a",
    tenant_id: "ten_a",
    correlation_id: "op_replay_1",
    method: "POST",
    path: "/operation",
    body_sha256: bodyHash,
    nonce: "n_fixed_replay_nonce_001",
  });

  const first = await verifyInternalContext(TEST_SECRET, token, {
    op: "operation",
    device_id: "dev_ctx_replay_01",
    principal_id: "prin_a",
    tenant_id: "ten_a",
    correlation_id: "op_replay_1",
    method: "POST",
    path: "/operation",
    body_sha256: bodyHash,
    replayGuard: guard,
  });
  assert.equal(first.ok, true);
  if (first.ok) {
    assert.equal(first.claims.method, "POST");
    assert.equal(first.claims.path, "/operation");
    assert.equal(first.claims.body_sha256, bodyHash);
  }

  // Second use of the exact same signed token/nonce must fail closed.
  const replay = await verifyInternalContext(TEST_SECRET, token, {
    op: "operation",
    device_id: "dev_ctx_replay_01",
    principal_id: "prin_a",
    tenant_id: "ten_a",
    correlation_id: "op_replay_1",
    method: "POST",
    path: "/operation",
    body_sha256: bodyHash,
    replayGuard: guard,
  });
  assert.equal(replay.ok, false);
  if (!replay.ok) {
    assert.equal(replay.status, 401);
    assert.equal(replay.error, "replay");
  }

  // Mismatched method / path / body hash rejected (fresh nonce each time).
  const baseClaims = {
    op: "operation" as const,
    device_id: "dev_ctx_replay_01",
    principal_id: "prin_a",
    tenant_id: "ten_a",
    correlation_id: "op_bind_m",
    method: "POST",
    path: "/operation",
    body_sha256: bodyHash,
  };
  const tokMethod = await signInternalContext(TEST_SECRET, { ...baseClaims, nonce: "n_method_mismatch_01" });
  const badMethod = await verifyInternalContext(TEST_SECRET, tokMethod, {
    ...baseClaims,
    method: "PUT",
    replayGuard: guard,
  });
  assert.equal(badMethod.ok, false);
  if (!badMethod.ok) {
    assert.equal(badMethod.status, 403);
    assert.equal(badMethod.error, "binding_mismatch");
  }

  const tokPath = await signInternalContext(TEST_SECRET, { ...baseClaims, nonce: "n_path_mismatch_01" });
  const badPath = await verifyInternalContext(TEST_SECRET, tokPath, {
    ...baseClaims,
    path: "/other",
    replayGuard: guard,
  });
  assert.equal(badPath.ok, false);
  if (!badPath.ok) {
    assert.equal(badPath.status, 403);
    assert.equal(badPath.error, "binding_mismatch");
  }

  const otherHash = await sha256Hex(body + "x");
  const tokBody = await signInternalContext(TEST_SECRET, { ...baseClaims, nonce: "n_body_mismatch_01" });
  const badBody = await verifyInternalContext(TEST_SECRET, tokBody, {
    ...baseClaims,
    body_sha256: otherHash,
    replayGuard: guard,
  });
  assert.equal(badBody.ok, false);
  if (!badBody.ok) {
    assert.equal(badBody.status, 403);
    assert.equal(badBody.error, "binding_mismatch");
  }

  // ttlMs over cap rejected at sign time.
  await assert.rejects(
    () =>
      signInternalContext(TEST_SECRET, {
        op: "operation",
        device_id: "dev_ctx_replay_01",
        principal_id: "prin_a",
        tenant_id: "ten_a",
        ttlMs: INTERNAL_CONTEXT_TTL_MS + 1,
      }),
    (err: unknown) => err instanceof Error && err.message === "ttl_exceeds_max",
  );

  // Explicit exp beyond max TTL rejected at sign time.
  await assert.rejects(
    () =>
      signInternalContext(TEST_SECRET, {
        op: "operation",
        device_id: "dev_ctx_replay_01",
        principal_id: "prin_a",
        tenant_id: "ten_a",
        exp: Date.now() + INTERNAL_CONTEXT_TTL_MS + 60_000,
      }),
    (err: unknown) => err instanceof Error && err.message === "exp_exceeds_max_ttl",
  );

  // Verify-time: token whose exp is further than max TTL from "now" is rejected.
  // Build a valid short-lived token, then verify with a clock far before exp window end
  // such that exp - nowMs > INTERNAL_CONTEXT_TTL_MS.
  const shortTok = await signInternalContext(TEST_SECRET, {
    op: "operation",
    device_id: "dev_ctx_replay_01",
    principal_id: "prin_a",
    tenant_id: "ten_a",
    ttlMs: INTERNAL_CONTEXT_TTL_MS,
    nonce: "n_ttl_verify_cap_01",
  });
  const farPast = Date.now() - INTERNAL_CONTEXT_TTL_MS - 5_000;
  const ttlVerify = await verifyInternalContext(TEST_SECRET, shortTok, {
    op: "operation",
    device_id: "dev_ctx_replay_01",
    nowMs: farPast,
    replayGuard: guard,
  });
  assert.equal(ttlVerify.ok, false);
  if (!ttlVerify.ok) {
    assert.equal(ttlVerify.status, 401);
    assert.equal(ttlVerify.error, "context_ttl_exceeded");
  }

  // Replay guard is bounded + TTL-pruned.
  const bounded = new InternalContextReplayGuard();
  const now = Date.now();
  assert.equal(bounded.remember("n1", now + 1000, now), true);
  assert.equal(bounded.remember("n1", now + 1000, now), false, "duplicate nonce");
  assert.equal(bounded.size, 1);
  // Expired entry pruned on next remember.
  assert.equal(bounded.remember("n2", now + 1000, now + 2000), true);
  assert.equal(bounded.has("n1"), false);
  assert.ok(bounded.size <= 4096);
  // Default singleton is the exported process guard (smoke).
  assert.ok(defaultInternalContextReplayGuard instanceof InternalContextReplayGuard);
});

test("routeToDeviceRoom signs method/path/sha256 of exact body bytes (single serialization)", async () => {
  const deviceId = "dev_route_bind_01abcd";
  const operation = {
    type: "ownmesh_fs_list",
    payload: { path: "/tmp" },
    correlation_id: "op_route_bind_1",
  };
  type Captured = { method: string; path: string; body: string; token: string | null };
  const box: { current: Captured | null } = { current: null };
  const room = {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: async (req: Request) => {
          box.current = {
            method: req.method,
            path: new URL(req.url).pathname,
            body: await req.text(),
            token: req.headers.get(internalContextHeaderName()),
          };
          return Response.json({ status: "routed_to_device" });
        },
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;

  const routed = await __test.routeToDeviceRoom(
    { DEVICE_ROOM: room, SESSION_SECRET: TEST_SECRET },
    deviceId,
    operation,
    { principal_id: "prin_dev", tenant_id: "ten_default" },
  );
  assert.equal(routed.status, "routed_to_device");
  assert.ok(box.current);
  const cap = box.current as Captured;
  assert.equal(cap.method, "POST");
  assert.equal(cap.path, "/operation");
  const expectedBody = JSON.stringify(operation);
  assert.equal(cap.body, expectedBody, "body bytes must match single serialization source");
  assert.ok(cap.token);
  const bodyHash = await sha256Hex(expectedBody);
  const verified = await verifyInternalContext(TEST_SECRET, cap.token, {
    op: "operation",
    device_id: deviceId,
    principal_id: "prin_dev",
    tenant_id: "ten_default",
    correlation_id: operation.correlation_id,
    method: "POST",
    path: "/operation",
    body_sha256: bodyHash,
    replayGuard: new InternalContextReplayGuard(),
  });
  assert.equal(verified.ok, true);
  if (verified.ok) {
    assert.equal(verified.claims.body_sha256, bodyHash);
    assert.equal(verified.claims.method, "POST");
    assert.equal(verified.claims.path, "/operation");
  }
  const tampered = await verifyInternalContext(TEST_SECRET, cap.token, {
    op: "operation",
    device_id: deviceId,
    method: "POST",
    path: "/operation",
    body_sha256: await sha256Hex(expectedBody + "-tamper"),
    replayGuard: new InternalContextReplayGuard(),
  });
  assert.equal(tampered.ok, false);
});

test("DeviceRoom rejects unsigned, legacy constant header, expired, and binding mismatch", async () => {
  const deviceId = "dev_do_auth_01abcdef";
  const room = new DeviceRoom(mockDoState(), { SESSION_SECRET: TEST_SECRET, OAUTH_ISSUER: "https://cp.test" });
  await room.ready;
  room.deviceId = deviceId;
  room.router.deviceId = deviceId;
  const unsigned = await room.fetch(new Request("https://device-room/operation?device_id=" + deviceId, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "ownmesh_fs_list", correlation_id: "op_u" }) }));
  assert.equal(unsigned.status, 401);
  const legacy = await room.fetch(new Request("https://device-room/operation?device_id=" + deviceId, { method: "POST", headers: { "content-type": "application/json", "x-ownmesh-edge-authorized": "1" }, body: JSON.stringify({ type: "ownmesh_fs_list", correlation_id: "op_l" }) }));
  assert.equal(legacy.status, 401, "legacy constant header must not authorize");
  const expiredTok = await signInternalContext(TEST_SECRET, { op: "operation", device_id: deviceId, principal_id: "prin_dev", tenant_id: "ten_default", correlation_id: "op_e", exp: Date.now() - 5000 });
  const expiredRes = await room.fetch(new Request("https://device-room/operation?device_id=" + deviceId, { method: "POST", headers: { "content-type": "application/json", [internalContextHeaderName()]: expiredTok }, body: JSON.stringify({ type: "ownmesh_fs_list", correlation_id: "op_e" }) }));
  assert.equal(expiredRes.status, 401);
  const wrongDeviceTok = await signInternalContext(TEST_SECRET, { op: "operation", device_id: "dev_other_device_xx", principal_id: "prin_dev", tenant_id: "ten_default", correlation_id: "op_w" });
  const mismatch = await room.fetch(new Request("https://device-room/operation?device_id=" + deviceId, { method: "POST", headers: { "content-type": "application/json", [internalContextHeaderName()]: wrongDeviceTok }, body: JSON.stringify({ type: "ownmesh_fs_list", correlation_id: "op_w" }) }));
  assert.equal(mismatch.status, 403);
  const otherSecretTok = await signInternalContext("other-secret-not-configured", { op: "operation", device_id: deviceId, principal_id: "prin_dev", tenant_id: "ten_default", correlation_id: "op_s" });
  const wrongSecret = await room.fetch(new Request("https://device-room/operation?device_id=" + deviceId, { method: "POST", headers: { "content-type": "application/json", [internalContextHeaderName()]: otherSecretTok }, body: JSON.stringify({ type: "ownmesh_fs_list", correlation_id: "op_s" }) }));
  assert.equal(wrongSecret.status, 401);
});

test("GET /v1/devices/:id/ws is not swallowed by broad /v1/devices route", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const device = { id: "dev_ws_route_01abcdef", tenant_id: "ten_default", principal_id: "prin_dev", name: "agent", hostname: "agent", os: "x", arch: "x", agent_version: "x", protocol_version: "ownmesh.device/1.0", public_key: "ab".repeat(32), revoked: false, created_at: new Date().toISOString(), status: "active" as const };
  await store.putDevice(device);
  const credential = await store.issueDeviceCredential(device);
  __setTestStore(store);
  let sawUpgrade = false;
  let sawPath = "";
  let sawInternal = false;
  const room = { idFromName: () => ({}) as DurableObjectId, get: () => ({ fetch: async (req: Request) => { sawUpgrade = true; sawPath = new URL(req.url).pathname; sawInternal = Boolean(req.headers.get(internalContextHeaderName())); return new Response(null, { status: 204 }); } }) as unknown as DurableObjectStub } as unknown as DurableObjectNamespace;
  const res = await worker.fetch(new Request("https://cp.test/v1/devices/dev_ws_route_01abcdef/ws?role=agent", { headers: { upgrade: "websocket", origin: "https://cp.test", authorization: "Bearer " + credential.token } }), { DEVICE_ROOM: room, SESSION_SECRET: TEST_SECRET, OAUTH_ISSUER: "https://cp.test" }, wsTestCtx);
  assert.equal(sawUpgrade, true, "DO stub must receive the WS route");
  assert.equal(sawPath, "/ws");
  assert.equal(sawInternal, true, "signed internal context must be attached");
  assert.equal(res.status, 204);
  __setTestStore(null);
});

test("/mcp rejects disallowed Origin and allows issuer Origin", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const token = await store.issueTokens("client_test", "prin_dev", "ownmesh.read");
  __setTestStore(store);
  const evil = await worker.fetch(new Request("https://cp.test/mcp", { method: "POST", headers: { origin: "https://evil.test", authorization: "Bearer " + token.access_token, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }) }), { OAUTH_ISSUER: "https://cp.test", OWNMESH_ALLOWED_ORIGINS: "" }, wsTestCtx);
  assert.equal(evil.status, 403);
  assert.equal(((await evil.json()) as { error: string }).error, "origin_not_allowed");
  const good = await worker.fetch(new Request("https://cp.test/mcp", { method: "POST", headers: { origin: "https://cp.test", authorization: "Bearer " + token.access_token, "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: {} }) }), { OAUTH_ISSUER: "https://cp.test" }, wsTestCtx);
  assert.notEqual(good.status, 403);
  __setTestStore(null);
});

test("legacy x-ownmesh-edge-authorized constant is not set by Worker edge code", () => {
  const indexSrc = fs.readFileSync(new URL("./index.ts", import.meta.url), "utf8");
  const deviceSrc = fs.readFileSync(new URL("./device-room.ts", import.meta.url), "utf8");
  assert.equal(indexSrc.includes("set(\"x-ownmesh-edge-authorized\""), false);
  assert.equal(deviceSrc.includes("get(\"x-ownmesh-edge-authorized\""), false);
  assert.equal(deviceSrc.includes("x-ownmesh-edge-authorized") && deviceSrc.includes("=== \"1\""), false);
});
