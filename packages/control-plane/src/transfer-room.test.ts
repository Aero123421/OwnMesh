import assert from "node:assert/strict";
import test from "node:test";
import { canonicalTransferEphemeralProof, issueTransferTerminalControl, issueTransferTicket, TransferRoom, TransferRoomRouter, TRANSFER_PROTOCOL, validateTransferAttachment, verifyTransferEphemeralProof, verifyTransferTicket, type TransferAttachment, type TransferMetadata, type TransferTicketClaims } from "./transfer-room.ts";

const digest = "a".repeat(64);
function meta(): TransferMetadata { return { version: 1, transfer_id: "xfer_test", tenant_id: "ten_a", source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", plan_sha256: digest, transfer_expires_at: Date.now() + 10 * 60_000, max_bytes: 128 * 1024, epoch: 1, fence: 7, state: "prepared", contiguous_ack_sequence: null, contiguous_ack_offset: 0 }; }
function frame(type: string, fields: Record<string, unknown> = {}) { return JSON.stringify({ protocol: TRANSFER_PROTOCOL, type, transfer_id: "xfer_test", epoch: 1, fence: 7, plan_sha256: digest, ...fields }); }
function encrypted(length: number): string { return btoa("x".repeat(length + 16)); }
function ticket(role: "source" | "destination"): TransferTicketClaims { return { v: 1, jti: `jti_${role}`, session_nonce: `nonce_${role}`, transfer_id: "xfer_test", tenant_id: "ten_a", principal_id: "prin_a", device_id: role === "source" ? "dev_source" : "dev_destination", role, source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", plan_sha256: digest, epoch: 1, fence: 7, max_bytes: 128 * 1024, ticket_exp: Date.now() + 20_000, transfer_expires_at: Date.now() + 10 * 60_000, source_device_public_key: "01".repeat(32), destination_device_public_key: "02".repeat(32), source_ephemeral_public_key: "03".repeat(32), destination_ephemeral_public_key: "04".repeat(32), source_ephemeral_signature: "05".repeat(64), destination_ephemeral_signature: "06".repeat(64) }; }

type TransferMockSocket = {
  attachment: unknown; accepted: boolean; closed: boolean; sent: string[];
  send(data: string): void; close(): void;
  serializeAttachment(value: unknown): void; deserializeAttachment(): unknown;
};
function transferMockSocket(): TransferMockSocket {
  const socket: TransferMockSocket = {
    attachment: null, accepted: false, closed: false, sent: [],
    send(data) { if (!socket.accepted) throw new Error("send before acceptWebSocket"); socket.sent.push(data); }, close() { socket.closed = true; },
    serializeAttachment(value) { socket.attachment = value; },
    deserializeAttachment() { return socket.attachment; },
  };
  return socket;
}
function installTransferWebSocketPair(): void {
  const target = globalThis as typeof globalThis & { WebSocketPair?: new () => { 0: TransferMockSocket; 1: TransferMockSocket } };
  if (!target.WebSocketPair) target.WebSocketPair = class WebSocketPair {
    0 = transferMockSocket(); 1 = transferMockSocket();
  };
}
function transferState(
  storage: Map<string, unknown>, sockets: TransferMockSocket[] = [],
  beforePut?: (key: string, value: unknown) => Promise<void>,
  beforeDelete?: (key: string) => Promise<void>,
): DurableObjectState {
  return {
    id: { toString: () => "xfer_test", equals: () => false, name: "xfer_test" } as DurableObjectId,
    storage: {
      get: async (key: string) => structuredClone(storage.get(key)),
      put: async (key: string, value: unknown) => { await beforePut?.(key, value); storage.set(key, structuredClone(value)); },
      delete: async (key: string) => { await beforeDelete?.(key); return storage.delete(key); },
      setAlarm: async () => undefined,
    },
    getWebSockets: () => sockets as unknown as WebSocket[],
    acceptWebSocket: (socket: WebSocket) => { const accepted = socket as unknown as TransferMockSocket; accepted.accepted = true; sockets.push(accepted); },
  } as unknown as DurableObjectState;
}
async function transferUpgrade(room: TransferRoom, encoded: string): Promise<number> {
  try {
    return (await room.fetch(new Request("https://room.invalid/", {
      headers: { Upgrade: "websocket", "x-ownmesh-transfer-ticket": encoded },
    }))).status;
  } catch (error) {
    // Node's Response rejects status 101 after the DO has accepted the socket.
    const message = error instanceof Error ? error.message : String(error);
    if (/status.*101|range of 200 to 599/i.test(message)) return 101;
    throw error;
  }
}

test("transfer tickets are short lived and bind role, device, tenant, plan and session nonce", async () => {
  const secret = "test-secret"; const source = ticket("source");
  const encoded = await issueTransferTicket(secret, source);
  assert.deepEqual(await verifyTransferTicket(secret, encoded), source);
  assert.equal(await verifyTransferTicket("wrong", encoded), null);
  await assert.rejects(issueTransferTicket(secret, { ...source, role: "source", device_id: "dev_destination" }));
  await assert.rejects(issueTransferTicket(secret, { ...source, ticket_exp: Date.now() - 1 }));
  await assert.rejects(issueTransferTicket(secret, { ...source, transfer_expires_at: source.ticket_exp - 1 }));
});

test("TransferRoom persists only a transfer-bound JTI hash and rejects replay after hibernation", async () => {
  installTransferWebSocketPair();
  const secret = "replay-ledger-secret";
  const rawJti = "jti_distinctive_raw_value_must_not_survive";
  const claims = { ...ticket("source"), jti: rawJti };
  const encoded = await issueTransferTicket(secret, claims);
  const storage = new Map<string, unknown>();
  assert.equal(await transferUpgrade(new TransferRoom(transferState(storage), { SESSION_SECRET: secret }), encoded), 101);

  const ledger = storage.get("ownmesh:transfer:tickets:v1");
  assert.ok(Array.isArray(ledger));
  assert.equal(ledger.length, 1);
  assert.match(String(ledger[0]?.[0]), /^[a-f0-9]{64}$/);
  assert.notEqual(ledger[0]?.[0], rawJti, "raw JTI must never be the durable replay key");
  assert.equal(JSON.stringify([...storage.entries()]).includes(rawJti), false);
  assert.equal(JSON.stringify([...storage.entries()]).includes(encoded), false);

  // A fresh object has no in-memory ledger, so this proves restore from the
  // actual storage key retains replay denial across hibernation/eviction.
  const restored = new TransferRoom(transferState(storage), { SESSION_SECRET: secret });
  assert.equal(await transferUpgrade(restored, encoded), 409);

  // Restore is strict: legacy/raw identifiers cannot be silently accepted as
  // replay state and malformed/future entries do not bypass the cap/TTL rules.
  const invalid = new Map<string, unknown>([["ownmesh:transfer:tickets:v1", [[rawJti, Date.now() + 10_000]]]]);
  await assert.rejects(
    transferUpgrade(new TransferRoom(transferState(invalid), { SESSION_SECRET: secret }), encoded),
    /invalid transfer replay ledger/,
  );
});

test("TransferRoom accepts both DO sockets before second-role ready sends", async () => {
  installTransferWebSocketPair();
  const secret = "accept-before-ready-secret";
  const storage = new Map<string, unknown>();
  const sockets: TransferMockSocket[] = [];
  const room = new TransferRoom(transferState(storage, sockets), { SESSION_SECRET: secret });
  const source = ticket("source");
  const destination = { ...ticket("destination"), transfer_expires_at: source.transfer_expires_at };
  assert.equal(await transferUpgrade(room, await issueTransferTicket(secret, source)), 101);
  assert.equal(await transferUpgrade(room, await issueTransferTicket(secret, destination)), 101);
  assert.equal(sockets.length, 2);
  assert.ok(sockets.every((socket) => socket.accepted));
  assert.ok(sockets.every((socket) => socket.sent.some((raw) => raw.includes('"type":"ready"'))));
});

test("TransferRoom serializes concurrent two-role generation advance", async () => {
  installTransferWebSocketPair();
  const secret = "concurrent-generation-secret";
  const current = meta();
  const storage = new Map<string, unknown>([["ownmesh:transfer:metadata:v1", current]]);
  const sockets: TransferMockSocket[] = [];
  let advancePuts = 0;
  let releaseFirst!: () => void;
  const firstAdvanceBlocked = new Promise<void>((resolve) => { releaseFirst = resolve; });
  let markFirstStarted!: () => void;
  const firstAdvanceStarted = new Promise<void>((resolve) => { markFirstStarted = resolve; });
  const room = new TransferRoom(transferState(storage, sockets, async (key, value) => {
    if (key !== "ownmesh:transfer:metadata:v1"
      || Number((value as TransferMetadata).epoch) !== current.epoch + 1) return;
    advancePuts += 1;
    if (advancePuts === 1) { markFirstStarted(); await firstAdvanceBlocked; }
  }), { SESSION_SECRET: secret });
  const source = {
    ...ticket("source"), epoch: current.epoch + 1, fence: current.fence + 1,
    transfer_expires_at: current.transfer_expires_at, max_bytes: current.max_bytes,
    jti: "jti_source_generation_2",
  };
  const sourceUpgrade = transferUpgrade(room, await issueTransferTicket(secret, source));
  await firstAdvanceStarted;
  const destinationUpgrades: Array<Promise<number>> = [];
  for (let index = 0; index < 16; index += 1) {
    const destination = {
      ...ticket("destination"), epoch: current.epoch + 1, fence: current.fence + 1,
      transfer_expires_at: current.transfer_expires_at, max_bytes: current.max_bytes,
      jti: `jti_destination_generation_2_${index}`,
    };
    destinationUpgrades.push(transferUpgrade(room, await issueTransferTicket(secret, destination)));
  }
  const overflowStatus = await Promise.race([
    Promise.any(destinationUpgrades.map(async (upgrade) => {
      const status = await upgrade;
      if (status !== 429) throw new Error("not overflow");
      return status;
    })),
    new Promise<never>((_, reject) => setTimeout(() => reject(new Error("admission queue was not bounded")), 1_000)),
  ]);
  assert.equal(overflowStatus, 429);
  releaseFirst();
  assert.equal(await sourceUpgrade, 101);
  const destinationStatuses = await Promise.all(destinationUpgrades);
  assert.equal(destinationStatuses.filter((status) => status === 101).length, 1);
  assert.equal(destinationStatuses.filter((status) => status === 409).length, 14);
  assert.equal(destinationStatuses.filter((status) => status === 429).length, 1);
  assert.equal(advancePuts, 1, "exactly one role may commit the epoch advance");
  assert.equal(sockets.length, 2);
  assert.ok(sockets.every((socket) => !socket.closed));
  assert.ok(sockets.every((socket) => socket.sent.some((raw) => raw.includes('"type":"ready"'))));
  const ledger = storage.get("ownmesh:transfer:tickets:v1");
  assert.equal(Array.isArray(ledger) ? ledger.length : -1, 2, "overflow admission must not consume a ticket");
});

test("service-HMAC terminal control completes a prepared Room without persisting the receipt digest", async () => {
  installTransferWebSocketPair();
  const secret = "terminal-control-secret";
  const storage = new Map<string, unknown>();
  const sockets: TransferMockSocket[] = [];
  const room = new TransferRoom(transferState(storage, sockets), { SESSION_SECRET: secret });
  const source = ticket("source");
  const destination = { ...ticket("destination"), transfer_expires_at: source.transfer_expires_at };
  assert.equal(await transferUpgrade(room, await issueTransferTicket(secret, source)), 101);
  assert.equal(await transferUpgrade(room, await issueTransferTicket(secret, destination)), 101);
  const artifactSha256 = "d".repeat(64);
  const signed = await issueTransferTerminalControl(secret, {
    v: 1, transfer_id: source.transfer_id, plan_sha256: source.plan_sha256,
    epoch: source.epoch, fence: source.fence, artifact_sha256: artifactSha256,
  });
  const terminalRequest = (body: string, signature: string, headers: Record<string, string> = {}) => new Request("https://room.invalid/terminal", {
    method: "POST", headers: {
      "content-type": "application/json",
      "content-length": String(new TextEncoder().encode(body).byteLength),
      "x-ownmesh-transfer-control": signature,
      ...headers,
    }, body,
  });
  const invalid = await room.fetch(new Request("https://room.invalid/terminal", {
    method: "POST", headers: {
      "content-type": "application/json", "content-length": String(signed.body.length),
      "x-ownmesh-transfer-control": "invalid",
    }, body: signed.body,
  }));
  assert.equal(invalid.status, 401);
  assert.equal((await room.fetch(new Request("https://room.invalid/terminal", {
    method: "POST", headers: { "content-type": "application/json", "x-ownmesh-transfer-control": signed.signature }, body: signed.body,
  }))).status, 411, "missing content length must fail closed");
  assert.equal((await room.fetch(terminalRequest(signed.body, signed.signature, { "content-length": String(signed.body.length + 1) }))).status, 400, "spoofed content length must fail closed");
  assert.equal((await room.fetch(terminalRequest(`${signed.body}${" ".repeat(1025)}`, signed.signature, { "content-length": String(signed.body.length) }))).status, 400, "streamed body beyond the declared bound must fail closed");
  assert.equal((await room.fetch(terminalRequest(signed.body, signed.signature, { "content-length": "-1" }))).status, 400);
  assert.equal((await room.fetch(terminalRequest(signed.body, signed.signature, { "content-length": "NaN" }))).status, 400);
  assert.equal((await room.fetch(terminalRequest(signed.body, signed.signature, { "content-length": `0${signed.body.length}` }))).status, 400, "content length must be canonical decimal");
  assert.equal((await room.fetch(terminalRequest(signed.body, signed.signature, { "content-length": "1025" }))).status, 413, "declared overflow must fail before reading the body");
  assert.equal((await room.fetch(terminalRequest(`${signed.body}${" ".repeat(1025)}`, signed.signature))).status, 413, "actual overflow must fail closed");
  assert.equal((await room.fetch(terminalRequest(signed.body, signed.signature, { "content-type": "application/json; charset=utf-8" }))).status, 415, "content type must be exact");
  const completed = await room.fetch(terminalRequest(signed.body, signed.signature));
  assert.equal(completed.status, 200);
  assert.equal((storage.get("ownmesh:transfer:metadata:v1") as TransferMetadata).state, "completed");
  assert.equal(storage.has("ownmesh:transfer:tickets:v1"), false);
  assert.ok(sockets.every((socket) => socket.closed));
  assert.equal(JSON.stringify([...storage.entries()]).includes(artifactSha256), false);
  const replay = new TransferRoom(transferState(storage), { SESSION_SECRET: secret });
  assert.equal((await replay.fetch(terminalRequest(signed.body, signed.signature))).status, 200);
});

test("terminal control retries replay-ledger deletion after completed metadata was persisted", async () => {
  installTransferWebSocketPair();
  const secret = "terminal-delete-retry-secret";
  const current = meta();
  const storage = new Map<string, unknown>([
    ["ownmesh:transfer:metadata:v1", current],
    ["ownmesh:transfer:tickets:v1", [["b".repeat(64), Date.now() + 10_000]]],
  ]);
  let deleteAttempts = 0;
  const room = new TransferRoom(transferState(storage, [], undefined, async (key) => {
    if (key === "ownmesh:transfer:tickets:v1" && ++deleteAttempts === 1) throw new Error("injected delete failure");
  }), { SESSION_SECRET: secret });
  const signed = await issueTransferTerminalControl(secret, {
    v: 1, transfer_id: current.transfer_id, plan_sha256: current.plan_sha256,
    epoch: current.epoch, fence: current.fence, artifact_sha256: "e".repeat(64),
  });
  const request = () => new Request("https://room.invalid/terminal", {
    method: "POST", headers: {
      "content-type": "application/json", "content-length": String(signed.body.length),
      "x-ownmesh-transfer-control": signed.signature,
    }, body: signed.body,
  });
  assert.equal((await room.fetch(request())).status, 503);
  assert.equal((storage.get("ownmesh:transfer:metadata:v1") as TransferMetadata).state, "completed");
  assert.equal(storage.has("ownmesh:transfer:tickets:v1"), true);
  assert.equal((await room.fetch(request())).status, 200);
  assert.equal(storage.has("ownmesh:transfer:tickets:v1"), false);
  assert.equal(deleteAttempts, 2);
});

test("ephemeral proof binds the exact key, role, and immutable transfer facts", async () => {
  const generated = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  if (!("publicKey" in generated)) throw new Error("Ed25519 key pair unavailable");
  const key = generated as CryptoKeyPair;
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", key.publicKey) as ArrayBuffer);
  const hex = (bytes: Uint8Array) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
  const claims = ticket("source");
  claims.source_device_public_key = hex(publicKey);
  claims.destination_device_public_key = hex(publicKey);
  claims.source_ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, canonicalTransferEphemeralProof(claims, "source"))));
  claims.destination_ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, canonicalTransferEphemeralProof(claims, "destination"))));
  assert.equal(await verifyTransferEphemeralProof(claims, "source", claims.source_device_public_key), true);
  assert.equal(await verifyTransferEphemeralProof({ ...claims, source_ephemeral_public_key: "ff".repeat(32) }, "source", claims.source_device_public_key), false);
  assert.equal(await verifyTransferEphemeralProof({ ...claims, epoch: 2 }, "source", claims.source_device_public_key), false);
});

test("ephemeral proof golden vector is length-delimited for punctuation-bearing IDs", () => {
  const claims = ticket("source");
  Object.assign(claims, {
    transfer_id: "x|=fer", tenant_id: "t=|", source_device_id: "dev|=",
    source_workspace_id: "ws=|", plan_sha256: "00".repeat(32),
    source_ephemeral_public_key: "11".repeat(32), epoch: 0x0102_0304,
    fence: 0x0102_0304_0506, session_nonce: "n|=", transfer_expires_at: 1_700_000_000_000,
  });
  const u32 = (n: number) => Uint8Array.of(0, 0, 0, n);
  const u64 = (n: bigint) => {
    const bytes = new Uint8Array(8); new DataView(bytes.buffer).setBigUint64(0, n, false); return bytes;
  };
  const text = (value: string) => [u32(value.length), new TextEncoder().encode(value)];
  const expectedParts = [
    ...text("ownmesh-transfer-ephemeral-v1"), ...text("x|=fer"), ...text("t=|"), Uint8Array.of(1),
    ...text("dev|="), ...text("ws=|"), new Uint8Array(32), Uint8Array.of(1, 2, 3, 4),
    u64(0x0102_0304_0506n), ...text("n|="), new Uint8Array(32).fill(0x11),
    Uint8Array.of(0, 0, 1, 0x8b, 0xcf, 0xe5, 0x68, 0),
  ];
  const expected = new Uint8Array(expectedParts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0; for (const part of expectedParts) { expected.set(part, offset); offset += part.length; }
  assert.deepEqual(canonicalTransferEphemeralProof(claims, "source"), expected);
  const different = { ...claims, transfer_id: "x", tenant_id: "=fer|t=|" };
  assert.notDeepEqual(canonicalTransferEphemeralProof(claims, "source"), canonicalTransferEphemeralProof(different, "source"));
});

test("TransferRoom forwards one opaque chunk and persists only contiguous ACK metadata", async () => {
  const saved: TransferMetadata[] = []; const destination: string[] = []; const source: string[] = [];
  const room = new TransferRoomRouter(meta(), async (m) => { saved.push(m); });
  const src = { id: "src", role: "source" as const, device_id: "dev_source", send: (v: string) => source.push(v) };
  const dst = { id: "dst", role: "destination" as const, device_id: "dev_destination", send: (v: string) => destination.push(v) };
  assert.equal(room.attach(src), "new"); assert.equal(room.attach(dst), "new");
  source.length = 0; destination.length = 0;
  const chunk = frame("chunk", { sequence: 0, offset: 0, length: 3, ciphertext_base64: encrypted(3), chunk_sha256: digest });
  assert.deepEqual(await room.handle(src, chunk), { ok: true });
  assert.equal(destination[0], chunk); assert.equal(saved.length, 0);
  assert.deepEqual(await room.handle(dst, frame("ack", { sequence: 0, next_offset: 3 })), { ok: true });
  assert.equal(saved.length, 1); assert.equal(saved[0].contiguous_ack_offset, 3); assert.equal(JSON.stringify(saved[0]).includes(encrypted(3)), false);
  assert.match(source[0], /"next_offset":3/);
});

test("TransferRoom drops in-flight bytes on disconnect and rejects duplicate/gap/fence substitution", async () => {
  const room = new TransferRoomRouter(meta(), async () => {}); const received: string[] = [];
  const src = { id: "src", role: "source" as const, device_id: "dev_source", send: () => {} };
  const dst = { id: "dst", role: "destination" as const, device_id: "dev_destination", send: (v: string) => received.push(v) };
  room.attach(src); room.attach(dst);
  received.length = 0;
  assert.equal((await room.handle(src, frame("chunk", { sequence: 1, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }))).error, "non_contiguous_or_busy");
  assert.equal((await room.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest, extra: true }))).error, "bad_chunk");
  assert.equal((await room.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }))).ok, true);
  room.detach("destination", "dst");
  const dst2 = { ...dst, id: "dst2" }; room.attach(dst2);
  received.length = 1; // discard only the resumed destination's ready cursor
  // Same cursor is retransmittable because the prior in-flight ciphertext was dropped.
  assert.equal((await room.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }))).ok, true);
  assert.equal(received.length, 2);
  assert.equal((await room.handle(dst2, frame("ack", { sequence: 0, next_offset: 2 }))).error, "ack_mismatch");
  assert.equal((await room.handle(src, frame("cancel", { fence: 8 }))).error, "binding_mismatch");
});

test("TransferRoom does not ACK source when metadata persistence fails", async () => {
  const source: string[] = []; const destination: string[] = [];
  const room = new TransferRoomRouter(meta(), async () => { throw new Error("storage"); });
  const src = { id: "src", role: "source" as const, device_id: "dev_source", send: (v: string) => source.push(v) };
  const dst = { id: "dst", role: "destination" as const, device_id: "dev_destination", send: (v: string) => destination.push(v) };
  room.attach(src); room.attach(dst);
  source.length = 0; destination.length = 0;
  await room.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }));
  assert.equal(destination.length, 1);
  assert.equal((await room.handle(dst, frame("ack", { sequence: 0, next_offset: 1 }))).error, "persist_failed");
  assert.equal(source.length, 0);
});

test("hibernation attachments are strict non-bearer bindings and reconstruct both live peers", async () => {
  const m = meta(); const sent: string[] = [];
  const attachment = (role: "source" | "destination"): TransferAttachment => ({ v: 1, peer_id: `${role}-peer`, role, device_id: role === "source" ? m.source_device_id : m.destination_device_id, transfer_id: m.transfer_id, epoch: m.epoch, fence: m.fence, plan_sha256: m.plan_sha256, transfer_expires_at: m.transfer_expires_at });
  const sourceAttachment = attachment("source"); const destinationAttachment = attachment("destination");
  assert.equal(JSON.stringify(sourceAttachment).includes("ticket"), false);
  assert.equal(JSON.stringify(sourceAttachment).includes("ciphertext"), false);
  assert.deepEqual(validateTransferAttachment(sourceAttachment, m), sourceAttachment);
  assert.equal(validateTransferAttachment({ ...sourceAttachment, ticket: "bearer" }, m), null);
  assert.equal(validateTransferAttachment({ ...sourceAttachment, device_id: "dev_destination" }, m), null);
  // Simulate an evicted DO: reconstruct a fresh router from durable metadata
  // and the two still-live socket attachments before either sends a frame.
  const restored = new TransferRoomRouter(structuredClone(m), async () => {});
  const src = { id: sourceAttachment.peer_id, role: "source" as const, device_id: sourceAttachment.device_id, send: () => {} };
  const dst = { id: destinationAttachment.peer_id, role: "destination" as const, device_id: destinationAttachment.device_id, send: (raw: string) => sent.push(raw) };
  assert.equal(restored.attach(src), "new"); assert.equal(restored.attach(dst), "new");
  sent.length = 0;
  assert.equal((await restored.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }))).ok, true);
  assert.equal(sent.length, 1);
});

test("same-role attach is race-safe and cannot replace a live source", async () => {
  const room = new TransferRoomRouter(meta(), async () => {});
  const source = { id: "source-1", role: "source" as const, device_id: "dev_source", send: () => {} };
  assert.equal(room.attach(source), "new");
  assert.equal(room.attach({ ...source, id: "source-2" }), "reject");
  // A duplicate restore/message for the exact same socket is harmless.
  assert.equal(room.attach(source), "existing");
});

test("exact error detach accepts a fresh peer without evicting a live role", () => {
  const room = new TransferRoomRouter(meta(), async () => {});
  const source = { id: "source-1", role: "source" as const, device_id: "dev_source", send: () => {} };
  room.attach(source);
  // A malformed attachment cannot name the live peer, so its detach is inert.
  room.detach("source", "malformed-peer");
  assert.equal(room.attach({ ...source, id: "source-2" }), "reject");
  room.detach("source", "source-1");
  assert.equal(room.attach({ ...source, id: "source-2" }), "new");
});

test("ready is emitted only after both peers attach and never on ordinary reattach", () => {
  const sourceFirst: string[] = []; const destinationFirst: string[] = [];
  const room = new TransferRoomRouter(meta(), async () => {});
  const source = { id: "source", role: "source" as const, device_id: "dev_source", send: (raw: string) => sourceFirst.push(raw) };
  const destination = { id: "destination", role: "destination" as const, device_id: "dev_destination", send: (raw: string) => destinationFirst.push(raw) };
  assert.equal(room.attach(source), "new");
  assert.equal(sourceFirst.length, 0);
  assert.equal(room.attach(destination), "new");
  assert.equal(sourceFirst.length, 1); assert.equal(destinationFirst.length, 1);
  const ready = JSON.parse(sourceFirst[0]) as Record<string, unknown>;
  assert.deepEqual(JSON.parse(destinationFirst[0]), ready);
  assert.deepEqual({ type: ready.type, next_sequence: ready.next_sequence, next_offset: ready.next_offset, epoch: ready.epoch, fence: ready.fence, plan_sha256: ready.plan_sha256 }, { type: "ready", next_sequence: 0, next_offset: 0, epoch: 1, fence: 7, plan_sha256: digest });
  assert.equal(room.attach(source), "existing");
  assert.equal(sourceFirst.length, 1); assert.equal(destinationFirst.length, 1);
  const secondSource: string[] = []; const secondDestination: string[] = [];
  const destinationFirstRoom = new TransferRoomRouter(meta(), async () => {});
  const secondSrc = { ...source, id: "source-2", send: (raw: string) => secondSource.push(raw) };
  const secondDst = { ...destination, id: "destination-2", send: (raw: string) => secondDestination.push(raw) };
  assert.equal(destinationFirstRoom.attach(secondDst), "new");
  assert.equal(secondDestination.length, 0);
  assert.equal(destinationFirstRoom.attach(secondSrc), "new");
  assert.equal(secondSource.length, 1); assert.equal(secondDestination.length, 1);
});

test("zero-byte transfer finishes only after destination finish acknowledgement is durable", async () => {
  const persisted: TransferMetadata[] = []; const source: string[] = []; const destination: string[] = [];
  const room = new TransferRoomRouter({ ...meta(), max_bytes: 0 }, async (m) => { persisted.push(m); });
  const src = { id: "source", role: "source" as const, device_id: "dev_source", send: (raw: string) => source.push(raw) };
  const dst = { id: "destination", role: "destination" as const, device_id: "dev_destination", send: (raw: string) => destination.push(raw) };
  room.attach(src); room.attach(dst); source.length = 0; destination.length = 0;
  assert.deepEqual(await room.handle(src, frame("finish")), { ok: true });
  assert.match(destination[0], /"type":"finish"/);
  assert.deepEqual(await room.handle(dst, frame("finish_ack")), { ok: true });
  assert.equal(room.snapshot().state, "completed");
  assert.equal(persisted.at(-1)?.state, "completed");
  assert.match(source[0], /"type":"finish_ack"/);
});

test("cancel persistence failure breaks the room and never forwards a cancel", async () => {
  const destination: string[] = [];
  const room = new TransferRoomRouter(meta(), async () => { throw new Error("storage"); });
  const source = { id: "src", role: "source" as const, device_id: "dev_source", send: () => {} };
  const dest = { id: "dst", role: "destination" as const, device_id: "dev_destination", send: (raw: string) => destination.push(raw) };
  room.attach(source); room.attach(dest);
  destination.length = 0;
  assert.deepEqual(await room.handle(source, frame("cancel")), { ok: false, error: "persist_failed" });
  assert.equal(room.isBroken, true);
  assert.equal(destination.length, 0);
  assert.equal((await room.handle(source, frame("cancel"))).error, "peer_unavailable");
});
