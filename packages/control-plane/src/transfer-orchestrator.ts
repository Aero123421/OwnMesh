/**
 * Metadata-only transfer ticket coordinator.
 *
 * This module is deliberately not an MCP surface by itself. Its inputs are
 * server-derived device/workspace/grant facts and authenticated Agent replies;
 * it refuses client-selected identities, hashes, grants, relay configuration,
 * or file bytes. The eventual MCP handler may expose a transfer only by first
 * obtaining these facts from the source/destination Agents.
 */

import {
  issueTransferTicket,
  verifyTransferEphemeralProof,
  type TransferRole,
  type TransferTicketClaims,
} from "./transfer-room.ts";

export type TransferServerBinding = Readonly<{
  transfer_id: string;
  tenant_id: string;
  principal_id: string;
  source_device_id: string;
  destination_device_id: string;
  source_workspace_id: string;
  destination_workspace_id: string;
  plan_sha256: string;
  max_bytes: number;
  epoch: number;
  fence: number;
  /** Short connection authority; minted exact-bound by the coordinator. */
  ticket_exp: number;
  /** Immutable plan deadline, distinct from ticket_exp. */
  transfer_expires_at: number;
  source_device_public_key: string;
  destination_device_public_key: string;
}>;

/** Exact reply accepted only from an authenticated Agent operation. */
export type AgentEphemeralReply = {
  role: TransferRole;
  transfer_id: string;
  tenant_id: string;
  device_id: string;
  workspace_id: string;
  plan_sha256: string;
  epoch: number;
  fence: number;
  session_nonce: string;
  /** Millisecond expiry of the preflight proof; matches the Rust wire field. */
  expires_at: number;
  ephemeral_public_key: string;
  ephemeral_signature: string;
};

/** Parse the bounded `operation.result.result.transfer_preflight` payload.
 * This is intentionally metadata-only and is the only shape a future
 * DeviceRoom correlation path may hand to the coordinator. */
export function parseTransferPreflightResult(
  value: unknown,
  expected: Pick<TransferServerBinding, "transfer_id" | "tenant_id" | "plan_sha256" | "epoch" | "fence"> & { role: TransferRole; device_id: string; workspace_id: string; session_nonce: string; expires_at: number },
): AgentEphemeralReply | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const obj = value as Record<string, unknown>;
  const allowed = ["role", "transfer_id", "tenant_id", "device_id", "workspace_id", "plan_sha256", "epoch", "fence", "session_nonce", "expires_at", "ephemeral_public_key", "ephemeral_signature"];
  if (Object.keys(obj).some((name) => !allowed.includes(name))) return null;
  const text = (name: string) => typeof obj[name] === "string" ? obj[name] : null;
  const integer = (name: string) => typeof obj[name] === "number" && Number.isSafeInteger(obj[name]) ? obj[name] as number : null;
  const reply: AgentEphemeralReply = {
    role: text("role") as TransferRole, transfer_id: text("transfer_id") || "", tenant_id: text("tenant_id") || "",
    device_id: text("device_id") || "", workspace_id: text("workspace_id") || "", plan_sha256: text("plan_sha256") || "",
    epoch: integer("epoch") ?? 0, fence: integer("fence") ?? 0, session_nonce: text("session_nonce") || "",
    expires_at: integer("expires_at") ?? 0, ephemeral_public_key: text("ephemeral_public_key") || "", ephemeral_signature: text("ephemeral_signature") || "",
  };
  return reply.role === expected.role && reply.transfer_id === expected.transfer_id && reply.tenant_id === expected.tenant_id
    && reply.device_id === expected.device_id && reply.workspace_id === expected.workspace_id
    // Source planning is the one place where the server cannot know the
    // immutable content hash yet. An empty expected hash is therefore allowed
    // only for the source preflight; the coordinator CAS-binds the returned
    // lower-case SHA-256 before it can dispatch destination preflight/start.
    && (expected.plan_sha256 === "" && expected.role === "source" ? hash(reply.plan_sha256) : reply.plan_sha256 === expected.plan_sha256)
    && reply.epoch === expected.epoch && reply.fence === expected.fence
    && reply.session_nonce === expected.session_nonce && reply.expires_at === expected.expires_at
    && key(reply.ephemeral_public_key, 32) && key(reply.ephemeral_signature, 64) ? reply : null;
}

export type TransferTicketPair = Readonly<{
  source_ticket: string;
  destination_ticket: string;
  /** Durable transfer metadata: no raw/ciphertext/key values are returned. */
  metadata: Readonly<{
    transfer_id: string;
    tenant_id: string;
    source_device_id: string;
    destination_device_id: string;
    source_workspace_id: string;
    destination_workspace_id: string;
    plan_sha256: string;
    epoch: number;
    fence: number;
    transfer_expires_at: number;
    max_bytes: number;
  }>;
}>;

function identifier(value: string): boolean {
  return value.length > 0 && value.length <= 256 && !/[\x00-\x1f]/.test(value);
}
function hash(value: string): boolean { return /^[a-f0-9]{64}$/.test(value); }
function key(value: string, bytes: number): boolean { return new RegExp(`^[a-f0-9]{${bytes * 2}}$`).test(value); }

/**
 * Produces a single session's two short-lived tickets after both Agent
 * signatures are proved against the server's registered public identities.
 * The returned metadata intentionally excludes ephemeral public keys,
 * signatures, bearer tickets, and all transfer bytes.
 */
export async function mintTransferTicketPair(
  secret: string,
  binding: TransferServerBinding,
  source: AgentEphemeralReply,
  destination: AgentEphemeralReply,
  nonce: string,
  sourceJti: string,
  destinationJti: string,
): Promise<TransferTicketPair> {
  if (!secret || !identifier(nonce) || !identifier(sourceJti) || !identifier(destinationJti)
    || sourceJti === destinationJti || !identifier(binding.transfer_id) || !identifier(binding.tenant_id)
    || !identifier(binding.principal_id) || !identifier(binding.source_device_id)
    || !identifier(binding.destination_device_id) || !identifier(binding.source_workspace_id)
    || !identifier(binding.destination_workspace_id) || !hash(binding.plan_sha256)
    || !key(binding.source_device_public_key, 32) || !key(binding.destination_device_public_key, 32)
    || !Number.isSafeInteger(binding.epoch) || binding.epoch < 1
    || !Number.isSafeInteger(binding.fence) || binding.fence < 1
    || !Number.isSafeInteger(binding.max_bytes) || binding.max_bytes < 0
    || !Number.isSafeInteger(binding.ticket_exp) || binding.ticket_exp <= Date.now() || binding.ticket_exp > Date.now() + 60_000
    || !Number.isSafeInteger(binding.transfer_expires_at) || binding.transfer_expires_at < binding.ticket_exp) {
    throw new Error("invalid_transfer_server_binding");
  }
  const matchReply = (reply: AgentEphemeralReply, role: TransferRole): boolean =>
    reply.role === role && reply.transfer_id === binding.transfer_id && reply.tenant_id === binding.tenant_id
    && reply.device_id === (role === "source" ? binding.source_device_id : binding.destination_device_id)
    && reply.workspace_id === (role === "source" ? binding.source_workspace_id : binding.destination_workspace_id)
    && reply.plan_sha256 === binding.plan_sha256 && reply.epoch === binding.epoch
    && reply.fence === binding.fence && reply.session_nonce === nonce && reply.expires_at === binding.transfer_expires_at
    && key(reply.ephemeral_public_key, 32) && key(reply.ephemeral_signature, 64);
  if (!matchReply(source, "source") || !matchReply(destination, "destination")) {
    throw new Error("agent_ephemeral_reply_binding_mismatch");
  }
  const claims = (role: TransferRole, jti: string): TransferTicketClaims => ({
    v: 1, jti, session_nonce: nonce, transfer_id: binding.transfer_id, tenant_id: binding.tenant_id,
    principal_id: binding.principal_id, device_id: role === "source" ? binding.source_device_id : binding.destination_device_id,
    role, source_device_id: binding.source_device_id, destination_device_id: binding.destination_device_id,
    source_workspace_id: binding.source_workspace_id, destination_workspace_id: binding.destination_workspace_id,
    plan_sha256: binding.plan_sha256, epoch: binding.epoch, fence: binding.fence,
    max_bytes: binding.max_bytes,
    ticket_exp: binding.ticket_exp,
    transfer_expires_at: binding.transfer_expires_at,
    source_device_public_key: binding.source_device_public_key,
    destination_device_public_key: binding.destination_device_public_key,
    source_ephemeral_public_key: source.ephemeral_public_key,
    destination_ephemeral_public_key: destination.ephemeral_public_key,
    source_ephemeral_signature: source.ephemeral_signature,
    destination_ephemeral_signature: destination.ephemeral_signature,
  });
  const sourceClaims = claims("source", sourceJti);
  const destinationClaims = claims("destination", destinationJti);
  if (!(await verifyTransferEphemeralProof(sourceClaims, "source", binding.source_device_public_key))
    || !(await verifyTransferEphemeralProof(sourceClaims, "destination", binding.destination_device_public_key))) {
    throw new Error("agent_ephemeral_signature_invalid");
  }
  const [source_ticket, destination_ticket] = await Promise.all([
    issueTransferTicket(secret, sourceClaims), issueTransferTicket(secret, destinationClaims),
  ]);
  return {
    source_ticket, destination_ticket,
    metadata: {
      transfer_id: binding.transfer_id, tenant_id: binding.tenant_id,
      source_device_id: binding.source_device_id, destination_device_id: binding.destination_device_id,
      source_workspace_id: binding.source_workspace_id, destination_workspace_id: binding.destination_workspace_id,
      plan_sha256: binding.plan_sha256, epoch: binding.epoch, fence: binding.fence,
      transfer_expires_at: binding.transfer_expires_at, max_bytes: binding.max_bytes,
    },
  };
}
