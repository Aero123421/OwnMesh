/** Shared helpers for the OwnMesh control plane. */

export const SERVICE_NAME = "ownmesh-control-plane";
export const SERVICE_VERSION = "1.0.1";

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
