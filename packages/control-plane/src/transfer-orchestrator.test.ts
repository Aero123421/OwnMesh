import assert from "node:assert/strict";
import test from "node:test";
import { canonicalTransferEphemeralProof, verifyTransferTicket, type TransferTicketClaims } from "./transfer-room.ts";
import { mintTransferTicketPair, parseTransferPreflightResult, type AgentEphemeralReply, type TransferServerBinding } from "./transfer-orchestrator.ts";

const hex = (bytes: Uint8Array) => [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

test("ticket coordinator accepts only exact Agent proofs and returns metadata without payloads", async () => {
  const sourceKey = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const destinationKey = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  if (!("publicKey" in sourceKey) || !("publicKey" in destinationKey)) throw new Error("Ed25519 unavailable");
  const transferExpiresAt = Date.now() + 5 * 60_000;
  const binding: TransferServerBinding = {
    transfer_id: "xfer_1", tenant_id: "ten_1", principal_id: "prin_1", source_device_id: "dev_s", destination_device_id: "dev_d",
    source_workspace_id: "ws_s", destination_workspace_id: "ws_d", plan_sha256: "a".repeat(64), max_bytes: 131_072,
    epoch: 1, fence: 1, ticket_exp: Date.now() + 30_000, transfer_expires_at: transferExpiresAt,
    source_device_public_key: hex(new Uint8Array(await crypto.subtle.exportKey("raw", sourceKey.publicKey) as ArrayBuffer)),
    destination_device_public_key: hex(new Uint8Array(await crypto.subtle.exportKey("raw", destinationKey.publicKey) as ArrayBuffer)),
  };
  const source: AgentEphemeralReply = { role: "source", transfer_id: binding.transfer_id, tenant_id: binding.tenant_id, device_id: binding.source_device_id, workspace_id: binding.source_workspace_id, plan_sha256: binding.plan_sha256, epoch: 1, fence: 1, session_nonce: "session_1", transfer_expires_at: transferExpiresAt, ephemeral_public_key: "11".repeat(32), ephemeral_signature: "" };
  const destination: AgentEphemeralReply = { role: "destination", transfer_id: binding.transfer_id, tenant_id: binding.tenant_id, device_id: binding.destination_device_id, workspace_id: binding.destination_workspace_id, plan_sha256: binding.plan_sha256, epoch: 1, fence: 1, session_nonce: "session_1", transfer_expires_at: transferExpiresAt, ephemeral_public_key: "22".repeat(32), ephemeral_signature: "" };
  const claims = (role: "source" | "destination"): TransferTicketClaims => ({
    v: 1, jti: "jti_test", session_nonce: "session_1", transfer_id: binding.transfer_id, tenant_id: binding.tenant_id, principal_id: binding.principal_id,
    device_id: role === "source" ? binding.source_device_id : binding.destination_device_id, role,
    source_device_id: binding.source_device_id, destination_device_id: binding.destination_device_id, source_workspace_id: binding.source_workspace_id, destination_workspace_id: binding.destination_workspace_id,
    plan_sha256: binding.plan_sha256, epoch: 1, fence: 1, max_bytes: binding.max_bytes, ticket_exp: Date.now() + 30_000, transfer_expires_at: transferExpiresAt,
    source_device_public_key: binding.source_device_public_key, destination_device_public_key: binding.destination_device_public_key,
    source_ephemeral_public_key: source.ephemeral_public_key, destination_ephemeral_public_key: destination.ephemeral_public_key,
    source_ephemeral_signature: source.ephemeral_signature, destination_ephemeral_signature: destination.ephemeral_signature,
  });
  source.ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", sourceKey.privateKey, canonicalTransferEphemeralProof(claims("source"), "source"))));
  destination.ephemeral_signature = hex(new Uint8Array(await crypto.subtle.sign("Ed25519", destinationKey.privateKey, canonicalTransferEphemeralProof(claims("destination"), "destination"))));
  const pair = await mintTransferTicketPair("secret", binding, source, destination, "session_1", "jti_source", "jti_destination");
  assert.equal((await verifyTransferTicket("secret", pair.source_ticket))?.role, "source");
  assert.equal((await verifyTransferTicket("secret", pair.destination_ticket))?.role, "destination");
  assert.equal(JSON.stringify(pair.metadata).includes("ephemeral"), false);
  await assert.rejects(mintTransferTicketPair("secret", binding, { ...source, plan_sha256: "b".repeat(64) }, destination, "session_1", "jti_2", "jti_3"));
  await assert.rejects(mintTransferTicketPair("secret", binding, source, { ...destination, ephemeral_public_key: "33".repeat(32) }, "session_1", "jti_4", "jti_5"));
});

test("preflight result parser rejects bytes, unknown fields, and correlation substitution", () => {
  const expected = { role: "source" as const, transfer_id: "xfer_1", tenant_id: "ten_1", plan_sha256: "a".repeat(64), epoch: 1, fence: 2, transfer_expires_at: Date.now() + 10_000, device_id: "dev_s", workspace_id: "ws_s", session_nonce: "nonce_1" };
  const value = { ...expected, ephemeral_public_key: "11".repeat(32), ephemeral_signature: "22".repeat(64) };
  assert.deepEqual(parseTransferPreflightResult(value, expected), value);
  assert.equal(parseTransferPreflightResult({ ...value, ciphertext_base64: "forbidden" }, expected), null);
  assert.equal(parseTransferPreflightResult({ ...value, fence: 3 }, expected), null);
  assert.equal(parseTransferPreflightResult({ ...value, role: "destination" }, expected), null);
});
