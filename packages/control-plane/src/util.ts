/** Shared helpers for the OwnMesh control plane. */

export const SERVICE_NAME = "ownmesh-control-plane";
export const SERVICE_VERSION = "1.0.2";

export function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("access-control-allow-origin", "*");
  headers.set(
    "access-control-allow-headers",
    "authorization, content-type, mcp-session-id",
  );
  headers.set("access-control-allow-methods", "GET, POST, OPTIONS, DELETE");
  return new Response(JSON.stringify(data, null, 0), { ...init, headers });
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
  if (need === "ownmesh.read" && scopes.has("ownmesh.write")) return true;
  if (
    scopes.has("ownmesh.write") &&
    ["ownmesh.read", "ownmesh.exec", "ownmesh.session"].includes(need)
  ) {
    return true;
  }
  return false;
}

/** Generate a human-friendly user_code like ABCD-EFGH. */
export function generateUserCode(): string {
  const alphabet = "BCDFGHJKLMNPQRSTVWXZ";
  const pick = () => alphabet[Math.floor(Math.random() * alphabet.length)]!;
  let s = "";
  for (let i = 0; i < 8; i++) s += pick();
  return `${s.slice(0, 4)}-${s.slice(4)}`;
}
