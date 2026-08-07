/** Shared helpers for the OwnMesh control plane. */

export const SERVICE_NAME = "ownmesh-control-plane";
export const SERVICE_VERSION = "1.1.2";

/** OAuth/token/device responses must not be stored by shared caches (RFC 9700). */
export const NO_STORE_CACHE_CONTROL = "no-store, no-cache";

export type JsonInit = ResponseInit & { noStore?: boolean };

/** Merge Cache-Control: no-store, no-cache (+ Pragma) onto headers. */
export function applyNoStore(headers: HeadersInit | Headers = {}): Headers {
  const h = headers instanceof Headers ? headers : new Headers(headers);
  h.set("cache-control", NO_STORE_CACHE_CONTROL);
  h.set("pragma", "no-cache");
  return h;
}

export function json(data: unknown, init: JsonInit = {}): Response {
  const { noStore, headers: initHeaders, ...rest } = init;
  const headers = new Headers(initHeaders);
  headers.set("content-type", "application/json; charset=utf-8");
  if (noStore) applyNoStore(headers);
  return new Response(JSON.stringify(data, null, 0), { ...rest, headers });
}

/** HTML helper with optional no-store (consent / device verification pages). */
export function html(body: string, init: JsonInit = {}): Response {
  const { noStore, headers: initHeaders, ...rest } = init;
  const headers = new Headers(initHeaders);
  if (!headers.has("content-type")) {
    headers.set("content-type", "text/html; charset=utf-8");
  }
  if (noStore) applyNoStore(headers);
  return new Response(body, { ...rest, headers });
}

export function nowIso(ms: number = Date.now()): string {
  return new Date(ms).toISOString();
}

export function randomToken(prefix: string): string {
  return `${prefix}${crypto.randomUUID().replace(/-/g, "")}`;
}

export function randomId(prefix: string): string {
  return `${prefix}${crypto.randomUUID().replace(/-/g, "").slice(0, 22)}`;
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** RFC 7636 S256 code_challenge verification. */
export async function verifyPkceS256(
  verifier: string,
  challenge: string,
): Promise<boolean> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  // base64url without padding
  const bytes = new Uint8Array(digest);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return b64 === challenge;
}

export function bearer(req: Request): string | null {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

export async function readBody(req: Request): Promise<Record<string, string>> {
  const ct = req.headers.get("content-type") || "";
  const out: Record<string, string> = {};
  if (ct.includes("application/json")) {
    const body = (await req.json()) as Record<string, unknown>;
    for (const [k, v] of Object.entries(body)) {
      if (v === undefined || v === null) continue;
      out[k] = typeof v === "string" ? v : JSON.stringify(v);
    }
    return out;
  }
  const form = await req.formData();
  form.forEach((v, k) => {
    out[k] = String(v);
  });
  return out;
}

export function parseScope(scope: string): Set<string> {
  return new Set(scope.split(/\s+/).filter(Boolean));
}

export function requireScope(scope: string, need: string): boolean {
  const scopes = parseScope(scope);
  if (scopes.has(need)) return true;
  // Write may include reading the same resource, but it must never imply command
  // execution or interactive-session authority.
  if (need === "ownmesh.read" && scopes.has("ownmesh.write")) return true;
  return false;
}

export function constantTimeEqual(a: string, b: string): boolean {
  const aa = new TextEncoder().encode(a);
  const bb = new TextEncoder().encode(b);
  if (aa.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < aa.length; i++) diff |= aa[i]! ^ bb[i]!;
  return diff === 0;
}

export function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-f]+$/i.test(hex) || hex.length % 2 !== 0) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export async function verifyEd25519Hex(
  publicKeyHex: string,
  message: string,
  signatureHex: string,
): Promise<boolean> {
  const publicKey = hexToBytes(publicKeyHex);
  const signature = hexToBytes(signatureHex);
  if (!publicKey || publicKey.length !== 32 || !signature || signature.length !== 64) return false;
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
    return crypto.subtle.verify("Ed25519", key, signature, new TextEncoder().encode(message));
  } catch {
    return false;
  }
}

/** Generate a human-friendly user_code like ABCD-EFGH. */
export function generateUserCode(): string {
  const alphabet = "BCDFGHJKLMNPQRSTVWXZ";
  const pick = () => alphabet[Math.floor(Math.random() * alphabet.length)]!;
  let s = "";
  for (let i = 0; i < 8; i++) s += pick();
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}

// ---------------------------------------------------------------------------
// Signed short-lived internal context (Worker → DeviceRoom DO)
// ---------------------------------------------------------------------------

/** Internal ops that the edge Worker may invoke on a DeviceRoom. */
export type InternalContextOp = "ws" | "operation";

/**
 * Claims bound into `x-ownmesh-internal-context`.
 * HMAC-SHA256 over the canonical payload; secret is env SESSION_SECRET only.
 */
export type InternalContextClaims = {
  v: 1;
  /** Expiry as Unix epoch milliseconds. */
  exp: number;
  /** Unique per-request nonce (replay resistance within TTL window). */
  nonce: string;
  op: InternalContextOp;
  device_id: string;
  principal_id: string;
  tenant_id: string;
  /** Optional role for ws upgrades. */
  role?: string;
  /** Optional correlation id for operation routing. */
  correlation_id?: string;
  /** HTTP method bound into the signature (e.g. POST). */
  method?: string;
  /** Request path bound into the signature (e.g. /operation). */
  path?: string;
  /** Hex SHA-256 of the exact request body bytes sent with this context. */
  body_sha256?: string;
};

/** Default / maximum internal-context lifetime (short-lived). */
export const INTERNAL_CONTEXT_TTL_MS = 30_000;

/** Hard cap on remembered nonces (after TTL prune). */
export const INTERNAL_CONTEXT_REPLAY_MAX = 4096;

/**
 * Drop expired nonce→expMs entries only (TTL prune).
 * Does not evict live entries for capacity — callers must reject inserts when full.
 * Shared by process-local InternalContextReplayGuard and Durable Object room state.
 *
 * `max` is retained for call-site compatibility and is intentionally unused:
 * capacity is enforced by refusing new nonces in rememberNonceInMap, not by FIFO eviction.
 */
export function pruneNonceExpMap(
  seen: Map<string, number>,
  nowMs: number = Date.now(),
  _max: number = INTERNAL_CONTEXT_REPLAY_MAX,
): void {
  for (const [nonce, exp] of seen) {
    if (exp < nowMs) seen.delete(nonce);
  }
}

/**
 * Record nonce if unseen. Returns true when fresh; false on replay or when at capacity.
 * Prunes expired entries first. When still at/over `max`, rejects the new nonce
 * without deleting any live (unexpired) entries — never opens a replay window via eviction.
 */
export function rememberNonceInMap(
  seen: Map<string, number>,
  nonce: string,
  expMs: number,
  nowMs: number = Date.now(),
  max: number = INTERNAL_CONTEXT_REPLAY_MAX,
): boolean {
  pruneNonceExpMap(seen, nowMs, max);
  if (seen.has(nonce)) return false;
  if (seen.size >= max) return false;
  seen.set(nonce, expMs);
  return true;
}

/**
 * Bounded, TTL-pruned nonce replay guard for signed internal context tokens.
 * Callers (or verifyInternalContext) record a nonce on first successful use;
 * a second presentation of the same nonce is rejected until expiry prune.
 *
 * NOTE: DeviceRoom Durable Objects must NOT rely on the process-local singleton
 * as authority across hibernation — they persist nonces via room storage and
 * call verifyInternalContext with `replayGuard: null` after durable consume.
 */
export class InternalContextReplayGuard {
  private readonly seen = new Map<string, number>(); // nonce -> expMs

  get size(): number {
    return this.seen.size;
  }

  clear(): void {
    this.seen.clear();
  }

  /** Drop entries whose exp has passed (no live-entry eviction). */
  prune(nowMs: number = Date.now()): void {
    pruneNonceExpMap(this.seen, nowMs, INTERNAL_CONTEXT_REPLAY_MAX);
  }

  /**
   * Record nonce if unseen. Returns true when fresh; false on replay or capacity.
   * Prunes expired entries first; rejects new nonces at INTERNAL_CONTEXT_REPLAY_MAX
   * without evicting live entries.
   */
  remember(nonce: string, expMs: number, nowMs: number = Date.now()): boolean {
    return rememberNonceInMap(this.seen, nonce, expMs, nowMs, INTERNAL_CONTEXT_REPLAY_MAX);
  }

  has(nonce: string): boolean {
    return this.seen.has(nonce);
  }
}

/** Process-local default guard used by verifyInternalContext when none is supplied. */
export const defaultInternalContextReplayGuard = new InternalContextReplayGuard();

const INTERNAL_CONTEXT_HEADER = "x-ownmesh-internal-context";

export function internalContextHeaderName(): string {
  return INTERNAL_CONTEXT_HEADER;
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(s: string): Uint8Array | null {
  if (!s || /[^A-Za-z0-9_-]/.test(s)) return null;
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function canonicalInternalPayload(claims: InternalContextClaims): string {
  // Stable field order — do not JSON.stringify unordered object keys.
  const parts = [
    `v=${claims.v}`,
    `exp=${claims.exp}`,
    `nonce=${claims.nonce}`,
    `op=${claims.op}`,
    `device_id=${claims.device_id}`,
    `principal_id=${claims.principal_id}`,
    `tenant_id=${claims.tenant_id}`,
  ];
  if (claims.role) parts.push(`role=${claims.role}`);
  if (claims.correlation_id) parts.push(`correlation_id=${claims.correlation_id}`);
  if (claims.method) parts.push(`method=${claims.method}`);
  if (claims.path) parts.push(`path=${claims.path}`);
  if (claims.body_sha256) parts.push(`body_sha256=${claims.body_sha256}`);
  return parts.join("|");
}

async function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/**
 * Mint a signed internal context token for Worker→DO calls.
 * `secret` MUST come from env (SESSION_SECRET); never hardcode.
 * Rejects ttlMs / exp beyond INTERNAL_CONTEXT_TTL_MS (no silent clamp).
 */
export async function signInternalContext(
  secret: string,
  claims: Omit<InternalContextClaims, "v" | "exp" | "nonce"> & {
    exp?: number;
    nonce?: string;
    ttlMs?: number;
  },
): Promise<string> {
  if (!secret) throw new Error("session_secret_required");
  const now = Date.now();
  if (claims.ttlMs !== undefined) {
    if (!Number.isFinite(claims.ttlMs) || claims.ttlMs <= 0) {
      throw new Error("ttl_invalid");
    }
    if (claims.ttlMs > INTERNAL_CONTEXT_TTL_MS) {
      throw new Error("ttl_exceeds_max");
    }
  }
  const exp = claims.exp ?? now + (claims.ttlMs ?? INTERNAL_CONTEXT_TTL_MS);
  if (!Number.isFinite(exp)) throw new Error("exp_invalid");
  // Enforce short maximum lifetime at sign time (explicit exp or derived).
  if (exp > now + INTERNAL_CONTEXT_TTL_MS) {
    throw new Error("exp_exceeds_max_ttl");
  }
  const full: InternalContextClaims = {
    v: 1,
    exp,
    nonce: claims.nonce ?? randomToken("n_"),
    op: claims.op,
    device_id: claims.device_id,
    principal_id: claims.principal_id,
    tenant_id: claims.tenant_id,
    role: claims.role,
    correlation_id: claims.correlation_id,
    method: claims.method,
    path: claims.path,
    body_sha256: claims.body_sha256,
  };
  const payload = canonicalInternalPayload(full);
  const key = await hmacKey(secret);
  const sig = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload)),
  );
  const body = bytesToBase64Url(new TextEncoder().encode(payload));
  const signature = bytesToBase64Url(sig);
  return `${body}.${signature}`;
}

export type InternalContextExpectation = {
  op: InternalContextOp;
  device_id: string;
  /** When set, principal must match exactly. */
  principal_id?: string;
  /** When set, tenant must match exactly. */
  tenant_id?: string;
  /** When set, role claim must match (ws). */
  role?: string;
  /** When set, correlation_id claim must match (operation). */
  correlation_id?: string;
  /** When set, HTTP method claim must match. */
  method?: string;
  /** When set, path claim must match. */
  path?: string;
  /** When set, body_sha256 claim must match (hex SHA-256 of exact body bytes). */
  body_sha256?: string;
  /** Override "now" for tests (ms). */
  nowMs?: number;
  /**
   * Replay guard instance. Defaults to process-local singleton.
   * Pass a fresh guard in tests to isolate nonce state.
   * Set to `null` to skip replay tracking (not recommended in production paths).
   */
  replayGuard?: InternalContextReplayGuard | null;
};

export type VerifyInternalContextResult =
  | { ok: true; claims: InternalContextClaims }
  | { ok: false; error: string; status: number };

/**
 * Verify HMAC, expiry, and binding expectations for an internal context token.
 * Constant-time signature compare. Does NOT accept legacy edge-authorized headers.
 */
export async function verifyInternalContext(
  secret: string | undefined,
  token: string | null | undefined,
  expect: InternalContextExpectation,
): Promise<VerifyInternalContextResult> {
  if (!secret) return { ok: false, error: "session_secret_unbound", status: 503 };
  if (!token) return { ok: false, error: "unauthorized", status: 401 };

  const parts = token.split(".");
  if (parts.length !== 2) return { ok: false, error: "unauthorized", status: 401 };
  const [bodyB64, sigB64] = parts as [string, string];
  const bodyBytes = base64UrlToBytes(bodyB64);
  const sigBytes = base64UrlToBytes(sigB64);
  if (!bodyBytes || !sigBytes) return { ok: false, error: "unauthorized", status: 401 };

  let payload: string;
  try {
    payload = new TextDecoder().decode(bodyBytes);
  } catch {
    return { ok: false, error: "unauthorized", status: 401 };
  }

  const key = await hmacKey(secret);
  let validSig = false;
  try {
    validSig = await crypto.subtle.verify("HMAC", key, sigBytes, new TextEncoder().encode(payload));
  } catch {
    validSig = false;
  }
  if (!validSig) return { ok: false, error: "unauthorized", status: 401 };

  const map = new Map<string, string>();
  for (const part of payload.split("|")) {
    const eq = part.indexOf("=");
    if (eq <= 0) continue;
    map.set(part.slice(0, eq), part.slice(eq + 1));
  }

  const v = map.get("v");
  const expRaw = map.get("exp");
  const nonce = map.get("nonce");
  const op = map.get("op") as InternalContextOp | undefined;
  const device_id = map.get("device_id");
  const principal_id = map.get("principal_id");
  const tenant_id = map.get("tenant_id");
  if (v !== "1" || !expRaw || !nonce || !op || !device_id || principal_id === undefined || tenant_id === undefined) {
    return { ok: false, error: "unauthorized", status: 401 };
  }
  const exp = Number(expRaw);
  if (!Number.isFinite(exp)) return { ok: false, error: "unauthorized", status: 401 };

  const now = expect.nowMs ?? Date.now();
  if (now > exp) return { ok: false, error: "context_expired", status: 401 };

  if (op !== expect.op) return { ok: false, error: "binding_mismatch", status: 403 };
  if (device_id !== expect.device_id) return { ok: false, error: "binding_mismatch", status: 403 };
  if (expect.principal_id !== undefined && principal_id !== expect.principal_id) {
    return { ok: false, error: "binding_mismatch", status: 403 };
  }
  if (expect.tenant_id !== undefined && tenant_id !== expect.tenant_id) {
    return { ok: false, error: "binding_mismatch", status: 403 };
  }
  const role = map.get("role");
  if (expect.role !== undefined && role !== expect.role) {
    return { ok: false, error: "binding_mismatch", status: 403 };
  }
  const correlation_id = map.get("correlation_id");
  if (expect.correlation_id !== undefined && correlation_id !== expect.correlation_id) {
    return { ok: false, error: "binding_mismatch", status: 403 };
  }
  const method = map.get("method");
  if (expect.method !== undefined && method !== expect.method) {
    return { ok: false, error: "binding_mismatch", status: 403 };
  }
  const path = map.get("path");
  if (expect.path !== undefined && path !== expect.path) {
    return { ok: false, error: "binding_mismatch", status: 403 };
  }
  const body_sha256 = map.get("body_sha256");
  if (expect.body_sha256 !== undefined && body_sha256 !== expect.body_sha256) {
    return { ok: false, error: "binding_mismatch", status: 403 };
  }

  // Reject tokens whose remaining/absolute lifetime exceeds the short max TTL
  // (signed with an over-long exp even if not yet expired).
  if (exp - now > INTERNAL_CONTEXT_TTL_MS) {
    return { ok: false, error: "context_ttl_exceeded", status: 401 };
  }

  // Re-canonicalize and ensure signature covered the exact structured form
  // (defense in depth against ambiguous payload encodings).
  const claims: InternalContextClaims = {
    v: 1,
    exp,
    nonce,
    op,
    device_id,
    principal_id,
    tenant_id,
    role,
    correlation_id,
    method,
    path,
    body_sha256,
  };
  if (canonicalInternalPayload(claims) !== payload) {
    return { ok: false, error: "unauthorized", status: 401 };
  }

  // Replay: same nonce rejected on second successful verification.
  const guard =
    expect.replayGuard === null
      ? null
      : (expect.replayGuard ?? defaultInternalContextReplayGuard);
  if (guard && !guard.remember(nonce, exp, now)) {
    return { ok: false, error: "replay", status: 401 };
  }

  return { ok: true, claims };
}

/**
 * Build headers for a Worker→DO internal request (signed context + JSON content-type).
 */
export async function internalDoHeaders(
  secret: string,
  claims: Omit<InternalContextClaims, "v" | "exp" | "nonce"> & {
    exp?: number;
    nonce?: string;
    ttlMs?: number;
  },
  base?: HeadersInit,
): Promise<Headers> {
  const headers = new Headers(base);
  if (!headers.has("content-type")) headers.set("content-type", "application/json");
  headers.set(INTERNAL_CONTEXT_HEADER, await signInternalContext(secret, claims));
  // Never set legacy constant auth header as an authority signal.
  headers.delete("x-ownmesh-edge-authorized");
  return headers;
}
