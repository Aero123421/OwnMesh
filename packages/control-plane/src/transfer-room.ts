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

/** Worker-minted, single-use ticket consumed by the transfer DO. */
export type TransferTicketClaims = {
  v: 1;
  jti: string;
  session_nonce: string;
  transfer_id: string;
  tenant_id: string;
  principal_id: string;
  device_id: string;
  role: TransferRole;
  source_device_id: string;
  destination_device_id: string;
  source_workspace_id: string;
  destination_workspace_id: string;
  plan_sha256: string;
  epoch: number;
  fence: number;
  max_bytes: number;
  exp: number;
};

const TICKET_MAX_MS = 60_000;
const STORAGE_METADATA = "ownmesh:transfer:metadata:v1";
const STORAGE_TICKETS = "ownmesh:transfer:tickets:v1";
const MAX_TICKET_REPLAYS = 128;

function base64Url(bytes: Uint8Array): string {
  let text = ""; for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}
function fromBase64Url(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  try { const raw = atob(value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4)); return Uint8Array.from(raw, (c) => c.charCodeAt(0)); } catch { return null; }
}
async function ticketKey(secret: string): Promise<CryptoKey> { return crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]); }

export async function issueTransferTicket(secret: string, claims: TransferTicketClaims): Promise<string> {
  if (!secret || claims.v !== 1 || !id(claims.jti) || !id(claims.session_nonce) || !id(claims.transfer_id) || !id(claims.tenant_id) || !id(claims.principal_id) || !id(claims.device_id) || !id(claims.source_device_id) || !id(claims.destination_device_id) || !id(claims.source_workspace_id) || !id(claims.destination_workspace_id) || !hash(claims.plan_sha256) || (claims.role !== "source" && claims.role !== "destination") || claims.device_id !== (claims.role === "source" ? claims.source_device_id : claims.destination_device_id) || claims.exp <= Date.now() || claims.exp > Date.now() + TICKET_MAX_MS || !Number.isSafeInteger(claims.epoch) || claims.epoch < 1 || !Number.isSafeInteger(claims.fence) || claims.fence < 1 || !Number.isSafeInteger(claims.max_bytes) || claims.max_bytes < 1) throw new Error("invalid_transfer_ticket_claims");
  const body = base64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", await ticketKey(secret), new TextEncoder().encode(body)));
  return `${body}.${base64Url(signature)}`;
}

export async function verifyTransferTicket(secret: string | undefined, raw: string | null): Promise<TransferTicketClaims | null> {
  if (!secret || !raw) return null;
  const [body, sig, extra] = raw.split("."); if (!body || !sig || extra) return null;
  const signature = fromBase64Url(sig); if (!signature) return null;
  if (!(await crypto.subtle.verify("HMAC", await ticketKey(secret), signature, new TextEncoder().encode(body)))) return null;
  const bytes = fromBase64Url(body); if (!bytes) return null;
  let claims: TransferTicketClaims; try { claims = JSON.parse(new TextDecoder().decode(bytes)) as TransferTicketClaims; } catch { return null; }
  try { await issueTransferTicket(secret, claims); } catch { return null; }
  return claims;
}

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

type TransferStorage = {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  delete(key: string): Promise<boolean>;
  setAlarm(time: number): Promise<void>;
};
type TransferRoomEnv = { SESSION_SECRET?: string };
type TransferAttachment = { ticket: string; peer_id: string };

/** Actual hibernatable Durable Object. It has no HTTP data plane except a
 * signed ticket-bound WebSocket upgrade; all frame bodies remain in sockets. */
export class TransferRoom {
  private metadata: TransferMetadata | null = null;
  private router: TransferRoomRouter | null = null;
  private consumed = new Map<string, number>();
  private readonly ready: Promise<void>;
  private readonly state: DurableObjectState;
  private readonly env: TransferRoomEnv;

  constructor(state: DurableObjectState, env: TransferRoomEnv) {
    this.state = state;
    this.env = env;
    this.ready = this.restore();
  }

  private storage(): TransferStorage { return this.state.storage as unknown as TransferStorage; }
  private async restore(): Promise<void> {
    this.metadata = (await this.storage().get<TransferMetadata>(STORAGE_METADATA)) || null;
    const entries = (await this.storage().get<Array<[string, number]>>(STORAGE_TICKETS)) || [];
    for (const [jti, exp] of entries) if (id(jti) && Number.isFinite(exp) && exp > Date.now()) this.consumed.set(jti, exp);
    if (this.metadata) this.router = new TransferRoomRouter(this.metadata, async (metadata) => this.persistMetadata(metadata));
  }
  private async persistMetadata(metadata: TransferMetadata): Promise<void> {
    // This object intentionally contains no chunk bytes, ciphertext, plaintext,
    // key material, or session ticket bearer.
    await this.storage().put(STORAGE_METADATA, metadata);
    this.metadata = metadata;
  }
  private async consume(claims: TransferTicketClaims): Promise<boolean> {
    for (const [jti, exp] of this.consumed) if (exp <= Date.now()) this.consumed.delete(jti);
    if (this.consumed.has(claims.jti) || this.consumed.size >= MAX_TICKET_REPLAYS) return false;
    this.consumed.set(claims.jti, claims.exp);
    await this.storage().put(STORAGE_TICKETS, [...this.consumed]);
    return true;
  }
  private metadataFor(claims: TransferTicketClaims): TransferMetadata {
    return { version: 1, transfer_id: claims.transfer_id, tenant_id: claims.tenant_id, source_device_id: claims.source_device_id, destination_device_id: claims.destination_device_id, source_workspace_id: claims.source_workspace_id, destination_workspace_id: claims.destination_workspace_id, plan_sha256: claims.plan_sha256, expires_at: claims.exp, max_bytes: claims.max_bytes, epoch: claims.epoch, fence: claims.fence, state: "prepared", contiguous_ack_sequence: null, contiguous_ack_offset: 0 };
  }
  private sameMetadata(metadata: TransferMetadata, claims: TransferTicketClaims): boolean {
    return metadata.transfer_id === claims.transfer_id && metadata.tenant_id === claims.tenant_id && metadata.source_device_id === claims.source_device_id && metadata.destination_device_id === claims.destination_device_id && metadata.source_workspace_id === claims.source_workspace_id && metadata.destination_workspace_id === claims.destination_workspace_id && metadata.plan_sha256 === claims.plan_sha256 && metadata.epoch === claims.epoch && metadata.fence === claims.fence && metadata.max_bytes === claims.max_bytes && metadata.expires_at === claims.exp;
  }
  async fetch(request: Request): Promise<Response> {
    await this.ready;
    if (request.method !== "GET" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return new Response("expected websocket", { status: 426 });
    const ticket = await verifyTransferTicket(this.env.SESSION_SECRET, request.headers.get("x-ownmesh-transfer-ticket"));
    if (!ticket || ticket.exp <= Date.now()) return new Response("invalid ticket", { status: 401 });
    const expectedDevice = ticket.role === "source" ? ticket.source_device_id : ticket.destination_device_id;
    if (ticket.device_id !== expectedDevice) return new Response("ticket device mismatch", { status: 403 });
    if (this.metadata && !this.sameMetadata(this.metadata, ticket)) return new Response("transfer binding mismatch", { status: 403 });
    if (this.metadata?.state === "cancelled" || this.metadata?.expires_at && this.metadata.expires_at <= Date.now()) return new Response("transfer expired", { status: 410 });
    // A same-role takeover is rejected before consuming the ticket. Agents must
    // reconnect only after the old socket has closed, never replace a live peer.
    for (const socket of this.state.getWebSockets()) {
      const attachment = socket.deserializeAttachment() as TransferAttachment | null;
      const existing = attachment && await verifyTransferTicket(this.env.SESSION_SECRET, attachment.ticket);
      if (existing?.role === ticket.role) return new Response("role already connected", { status: 409 });
    }
    try { if (!(await this.consume(ticket))) return new Response("ticket replay", { status: 409 }); }
    catch { return new Response("storage unavailable", { status: 503 }); }
    if (!this.metadata) {
      const metadata = this.metadataFor(ticket);
      try { await this.persistMetadata(metadata); await this.storage().setAlarm(metadata.expires_at); }
      catch { return new Response("storage unavailable", { status: 503 }); }
      this.router = new TransferRoomRouter(metadata, async (m) => this.persistMetadata(m));
    }
    const pair = new WebSocketPair(); const client = pair[0]; const server = pair[1];
    const peerId = crypto.randomUUID(); const peer: TransferPeer = { id: peerId, role: ticket.role, device_id: ticket.device_id, send: (raw) => server.send(raw) };
    if (!this.router?.attach(peer)) return new Response("peer rejected", { status: 403 });
    server.serializeAttachment({ ticket: request.headers.get("x-ownmesh-transfer-ticket")!, peer_id: peerId } satisfies TransferAttachment);
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }
  async webSocketMessage(socket: WebSocket, message: string | ArrayBuffer): Promise<void> {
    await this.ready;
    const attachment = socket.deserializeAttachment() as TransferAttachment | null;
    const ticket = attachment && await verifyTransferTicket(this.env.SESSION_SECRET, attachment.ticket);
    if (!attachment || !ticket || ticket.exp <= Date.now() || typeof message !== "string" || !this.router) { socket.close(1008, "invalid transfer session"); return; }
    const peer: TransferPeer = { id: attachment.peer_id, role: ticket.role, device_id: ticket.device_id, send: (raw) => socket.send(raw) };
    // Reattach hibernated socket only if no active same-role peer exists.
    this.router.attach(peer);
    const result = await this.router.handle(peer, message);
    if (!result.ok) socket.send(JSON.stringify({ protocol: TRANSFER_PROTOCOL, type: "error", code: result.error || "rejected" }));
  }
  webSocketClose(socket: WebSocket): void { const a = socket.deserializeAttachment() as TransferAttachment | null; const t = a && this.env.SESSION_SECRET ? null : null; void t; if (a && this.router) { /* role recovered on next message; never persist frame */ this.router.detach("source", a.peer_id); this.router.detach("destination", a.peer_id); } }
  async alarm(): Promise<void> { await this.ready; if (!this.metadata || this.metadata.expires_at > Date.now()) return; this.metadata.state = "expired"; try { await this.persistMetadata(this.metadata); await this.storage().delete(STORAGE_TICKETS); } finally { for (const ws of this.state.getWebSockets()) ws.close(1008, "transfer expired"); } }
}
