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
import { randomId, verifyEd25519Hex } from "./util.ts";

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
    envFor(agent, "ready", deviceId, { capabilities: ["fs"] }),
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
