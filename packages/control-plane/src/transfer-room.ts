/**
 * Ephemeral, one-in-flight encrypted transfer relay.
 *
 * This room deliberately never stores a chunk body. Durable state is limited to
 * immutable binding metadata plus the contiguous destination ACK cursor. A
 * source retransmits after a disconnect from that cursor; a room restart never
 * has plaintext/ciphertext to replay.
 */

export const TRANSFER_PROTOCOL = "ownmesh.transfer/1.0";
export const MAX_TRANSFER_CHUNK_BYTES = 64 * 1024;
export const MAX_TRANSFER_FRAME_BYTES = 96 * 1024;
/** AES-GCM / ChaCha20-Poly1305 authentication tag length. */
export const AEAD_TAG_BYTES = 16;

export type TransferRole = "source" | "destination";
export type TransferState = "prepared" | "active" | "cancelled" | "expired";

export type TransferMetadata = {
  version: 1;
  transfer_id: string;
  tenant_id: string;
  source_device_id: string;
  destination_device_id: string;
  source_workspace_id: string;
  destination_workspace_id: string;
  plan_sha256: string;
  expires_at: number;
  max_bytes: number;
  epoch: number;
  fence: number;
  state: TransferState;
  contiguous_ack_sequence: number | null;
  contiguous_ack_offset: number;
};

export type TransferPeer = {
  id: string;
  role: TransferRole;
  device_id: string;
  send(raw: string): void;
};

type InFlight = { sequence: number; offset: number; length: number };

function object(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function exactlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every((key) => keys.includes(key));
}

function id(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 256 && !/[\x00-\x1f]/.test(value);
}

function hash(value: unknown): value is string {
  return typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
}

function b64(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_TRANSFER_FRAME_BYTES && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

/** Testable policy core; Durable Object wiring supplies peer sockets/persistence. */
export class TransferRoomRouter {
  private peers = new Map<TransferRole, TransferPeer>();
  private inFlight: InFlight | null = null;
  private metadata: TransferMetadata;
  private readonly persist: (metadata: TransferMetadata) => Promise<void>;
  private broken = false;

  constructor(metadata: TransferMetadata, persist: (metadata: TransferMetadata) => Promise<void>) {
    this.metadata = metadata;
    this.persist = persist;
  }

  snapshot(): TransferMetadata {
    return structuredClone(this.metadata);
  }

  attach(peer: TransferPeer): boolean {
    const expected = peer.role === "source" ? this.metadata.source_device_id : this.metadata.destination_device_id;
    if (this.broken || peer.device_id !== expected || this.metadata.state === "cancelled" || this.expired()) return false;
    this.peers.set(peer.role, peer);
    return true;
  }

  detach(role: TransferRole, peerId: string): void {
    if (this.peers.get(role)?.id === peerId) this.peers.delete(role);
    // Never retain bytes across a disconnect. The persisted ACK is the only
    // resume cursor, so an unacknowledged frame must be resent by its source.
    this.inFlight = null;
  }

  private expired(): boolean {
    if (this.metadata.expires_at > Date.now()) return false;
    this.metadata.state = "expired";
    return true;
  }

  async handle(peer: TransferPeer, raw: string): Promise<{ ok: boolean; error?: string }> {
    if (new TextEncoder().encode(raw).byteLength > MAX_TRANSFER_FRAME_BYTES) return { ok: false, error: "frame_too_large" };
    if (this.broken || this.peers.get(peer.role)?.id !== peer.id || this.expired()) return { ok: false, error: "peer_unavailable" };
    let frame: Record<string, unknown> | null;
    try { frame = object(JSON.parse(raw)); } catch { frame = null; }
    if (!frame || frame.protocol !== TRANSFER_PROTOCOL || frame.transfer_id !== this.metadata.transfer_id || !id(frame.type)) return { ok: false, error: "bad_frame" };
    if (frame.type === "chunk") return this.chunk(peer, frame, raw);
    if (frame.type === "ack") return this.ack(peer, frame);
    if (frame.type === "cancel") return this.cancel(peer, frame);
    return { ok: false, error: "unsupported_type" };
  }

  private bound(frame: Record<string, unknown>): boolean {
    return frame.epoch === this.metadata.epoch && frame.fence === this.metadata.fence && frame.plan_sha256 === this.metadata.plan_sha256;
  }

  private async chunk(peer: TransferPeer, frame: Record<string, unknown>, raw: string): Promise<{ ok: boolean; error?: string }> {
    if (peer.role !== "source" || this.metadata.state === "cancelled" || !this.bound(frame)) return { ok: false, error: "binding_mismatch" };
    if (!exactlyKeys(frame, ["protocol", "type", "transfer_id", "epoch", "fence", "plan_sha256", "sequence", "offset", "length", "ciphertext_base64", "chunk_sha256"]) || !hash(frame.chunk_sha256) || !b64(frame.ciphertext_base64)) return { ok: false, error: "bad_chunk" };
    const sequence = Number(frame.sequence); const offset = Number(frame.offset); const length = Number(frame.length);
    const expectedSequence = this.metadata.contiguous_ack_sequence === null ? 0 : this.metadata.contiguous_ack_sequence + 1;
    const ciphertextBytes = decodedBase64Bytes(String(frame.ciphertext_base64));
    if (!Number.isSafeInteger(sequence) || !Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || sequence !== expectedSequence || offset !== this.metadata.contiguous_ack_offset || length < 1 || length > MAX_TRANSFER_CHUNK_BYTES || offset + length > this.metadata.max_bytes || ciphertextBytes !== length + AEAD_TAG_BYTES || this.inFlight) return { ok: false, error: "non_contiguous_or_busy" };
    const destination = this.peers.get("destination");
    if (!destination) return { ok: false, error: "destination_offline" };
    this.metadata.state = "active";
    this.inFlight = { sequence, offset, length };
    // `raw` is forwarded directly and intentionally not captured in audit/state.
    destination.send(raw);
    return { ok: true };
  }

  private async ack(peer: TransferPeer, frame: Record<string, unknown>): Promise<{ ok: boolean; error?: string }> {
    if (peer.role !== "destination" || !this.bound(frame) || !this.inFlight || !exactlyKeys(frame, ["protocol", "type", "transfer_id", "epoch", "fence", "plan_sha256", "sequence", "next_offset"])) return { ok: false, error: "bad_ack" };
    const sequence = Number(frame.sequence); const next = Number(frame.next_offset);
    if (!Number.isSafeInteger(sequence) || !Number.isSafeInteger(next) || sequence !== this.inFlight.sequence || next !== this.inFlight.offset + this.inFlight.length) return { ok: false, error: "ack_mismatch" };
    const before = this.snapshot();
    this.metadata.contiguous_ack_sequence = sequence;
    this.metadata.contiguous_ack_offset = next;
    this.inFlight = null;
    try {
      await this.persist(this.snapshot());
    } catch {
      // Source must never observe an ACK that did not cross the durable
      // metadata barrier. Drop both sockets and leave the source to retry from
      // its last known ACK after reconnect.
      this.metadata = before;
      this.broken = true;
      this.peers.clear();
      return { ok: false, error: "persist_failed" };
    }
    this.peers.get("source")?.send(JSON.stringify({ protocol: TRANSFER_PROTOCOL, type: "ack", transfer_id: this.metadata.transfer_id, epoch: this.metadata.epoch, fence: this.metadata.fence, plan_sha256: this.metadata.plan_sha256, sequence, next_offset: next }));
    return { ok: true };
  }

  private async cancel(peer: TransferPeer, frame: Record<string, unknown>): Promise<{ ok: boolean; error?: string }> {
    if (!this.bound(frame) || !exactlyKeys(frame, ["protocol", "type", "transfer_id", "epoch", "fence", "plan_sha256"])) return { ok: false, error: "binding_mismatch" };
    this.metadata.state = "cancelled";
    this.inFlight = null;
    await this.persist(this.snapshot());
    const other = peer.role === "source" ? "destination" : "source";
    this.peers.get(other)?.send(JSON.stringify({ protocol: TRANSFER_PROTOCOL, type: "cancel", transfer_id: this.metadata.transfer_id, epoch: this.metadata.epoch, fence: this.metadata.fence, plan_sha256: this.metadata.plan_sha256 }));
    return { ok: true };
  }
}

/** Strictly decode only bounded canonical Base64 and return raw byte length. */
function decodedBase64Bytes(value: string): number | null {
  try {
    const decoded = atob(value);
    if (btoa(decoded) !== value) return null;
    return decoded.length;
  } catch {
    return null;
  }
}
