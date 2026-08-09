import assert from "node:assert/strict";
import test from "node:test";
import { canonicalTransferEphemeralProof, issueTransferTicket, TransferRoomRouter, TRANSFER_PROTOCOL, verifyTransferEphemeralProof, verifyTransferTicket, type TransferMetadata, type TransferTicketClaims } from "./transfer-room.ts";

const digest = "a".repeat(64);
function meta(): TransferMetadata { return { version: 1, transfer_id: "xfer_test", tenant_id: "ten_a", source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", plan_sha256: digest, expires_at: Date.now() + 60_000, max_bytes: 128 * 1024, epoch: 1, fence: 7, state: "prepared", contiguous_ack_sequence: null, contiguous_ack_offset: 0 }; }
function frame(type: string, fields: Record<string, unknown> = {}) { return JSON.stringify({ protocol: TRANSFER_PROTOCOL, type, transfer_id: "xfer_test", epoch: 1, fence: 7, plan_sha256: digest, ...fields }); }
function encrypted(length: number): string { return btoa("x".repeat(length + 16)); }
function ticket(role: "source" | "destination"): TransferTicketClaims { return { v: 1, jti: `jti_${role}`, session_nonce: `nonce_${role}`, transfer_id: "xfer_test", tenant_id: "ten_a", principal_id: "prin_a", device_id: role === "source" ? "dev_source" : "dev_destination", role, source_device_id: "dev_source", destination_device_id: "dev_destination", source_workspace_id: "ws_source", destination_workspace_id: "ws_destination", plan_sha256: digest, epoch: 1, fence: 7, max_bytes: 128 * 1024, exp: Date.now() + 20_000, source_device_public_key: "01".repeat(32), destination_device_public_key: "02".repeat(32), source_ephemeral_public_key: "03".repeat(32), destination_ephemeral_public_key: "04".repeat(32), source_ephemeral_signature: "05".repeat(64), destination_ephemeral_signature: "06".repeat(64) }; }

test("transfer tickets are short lived and bind role, device, tenant, plan and session nonce", async () => {
  const secret = "test-secret"; const source = ticket("source");
  const encoded = await issueTransferTicket(secret, source);
  assert.deepEqual(await verifyTransferTicket(secret, encoded), source);
  assert.equal(await verifyTransferTicket("wrong", encoded), null);
  await assert.rejects(issueTransferTicket(secret, { ...source, role: "source", device_id: "dev_destination" }));
  await assert.rejects(issueTransferTicket(secret, { ...source, exp: Date.now() - 1 }));
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
  claims.source_ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, new TextEncoder().encode(canonicalTransferEphemeralProof(claims, "source")))));
  claims.destination_ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, new TextEncoder().encode(canonicalTransferEphemeralProof(claims, "destination")))));
  assert.equal(await verifyTransferEphemeralProof(claims, "source", claims.source_device_public_key), true);
  assert.equal(await verifyTransferEphemeralProof({ ...claims, source_ephemeral_public_key: "ff".repeat(32) }, "source", claims.source_device_public_key), false);
  assert.equal(await verifyTransferEphemeralProof({ ...claims, epoch: 2 }, "source", claims.source_device_public_key), false);
});

test("TransferRoom forwards one opaque chunk and persists only contiguous ACK metadata", async () => {
  const saved: TransferMetadata[] = []; const destination: string[] = []; const source: string[] = [];
  const room = new TransferRoomRouter(meta(), async (m) => { saved.push(m); });
  const src = { id: "src", role: "source" as const, device_id: "dev_source", send: (v: string) => source.push(v) };
  const dst = { id: "dst", role: "destination" as const, device_id: "dev_destination", send: (v: string) => destination.push(v) };
  assert.equal(room.attach(src), true); assert.equal(room.attach(dst), true);
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
  assert.equal((await room.handle(src, frame("chunk", { sequence: 1, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }))).error, "non_contiguous_or_busy");
  assert.equal((await room.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest, extra: true }))).error, "bad_chunk");
  assert.equal((await room.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }))).ok, true);
  room.detach("destination", "dst");
  const dst2 = { ...dst, id: "dst2" }; room.attach(dst2);
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
  await room.handle(src, frame("chunk", { sequence: 0, offset: 0, length: 1, ciphertext_base64: encrypted(1), chunk_sha256: digest }));
  assert.equal(destination.length, 1);
  assert.equal((await room.handle(dst, frame("ack", { sequence: 0, next_offset: 1 }))).error, "persist_failed");
  assert.equal(source.length, 0);
});
