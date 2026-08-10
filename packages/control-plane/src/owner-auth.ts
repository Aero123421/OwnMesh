import type { ControlPlaneStore } from "./store.ts";
import {
  constantTimeEqual,
  html,
  json,
  nowIso,
  randomToken,
  sha256Hex,
} from "./util.ts";

export type OwnerAuthEnv = {
  SESSION_SECRET?: string;
  OWNER_TOKEN_HASH?: string;
};

export type OwnerPrincipal = {
  id: string;
  tenant_id: string;
  display_name: string;
};

const OWNER_ID = "prin_owner";
const OWNER_TENANT = "ten_default";
const SESSION_COOKIE = "__Host-ownmesh_owner";
const CSRF_COOKIE = "__Host-ownmesh_csrf";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const MAX_FORM_BYTES = 8 * 1024;

type SessionClaims = {
  v: 1;
  sub: string;
  tenant: string;
  aud: string;
  exp: number;
  nonce: string;
};

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBytes(value: string): Uint8Array | null {
  if (!value || /[^A-Za-z0-9_-]/.test(value)) return null;
  const padding = value.length % 4 === 0 ? "" : "=".repeat(4 - (value.length % 4));
  try {
    const binary = atob(value.replace(/-/g, "+").replace(/_/g, "/") + padding);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  } catch {
    return null;
  }
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

function cookieValue(request: Request, name: string): string | null {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const index = part.indexOf("=");
    if (index < 1) continue;
    if (part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}

function cookie(name: string, value: string, maxAge: number, sameSite: "Lax" | "Strict"): string {
  return `${name}=${value}; Path=/; Secure; HttpOnly; SameSite=${sameSite}; Max-Age=${maxAge}`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeReturnTo(raw: string | null, issuer: string, fallback = "/connect/chatgpt"): string {
  if (!raw || raw.length > 4096 || raw.startsWith("//")) return fallback;
  try {
    const base = new URL(issuer);
    const target = new URL(raw, base);
    if (target.origin !== base.origin) return fallback;
    return `${target.pathname}${target.search}`;
  } catch {
    return fallback;
  }
}

function sameOriginPost(request: Request, issuer: string): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  try {
    return new URL(origin).origin === new URL(issuer).origin;
  } catch {
    return false;
  }
}

async function boundedForm(request: Request): Promise<URLSearchParams | null> {
  if (!(request.headers.get("content-type") || "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    return null;
  }
  const declared = Number(request.headers.get("content-length") || "0");
  if (Number.isFinite(declared) && declared > MAX_FORM_BYTES) return null;
  const body = await request.text();
  if (new TextEncoder().encode(body).byteLength > MAX_FORM_BYTES) return null;
  return new URLSearchParams(body);
}

export function ownerAuthConfigured(env: OwnerAuthEnv): boolean {
  return Boolean(
    env.SESSION_SECRET &&
      new TextEncoder().encode(env.SESSION_SECRET).byteLength >= 32 &&
      env.OWNER_TOKEN_HASH &&
      /^[0-9a-f]{64}$/.test(env.OWNER_TOKEN_HASH),
  );
}

async function issueSession(secret: string, issuer: string): Promise<string> {
  const claims: SessionClaims = {
    v: 1,
    sub: OWNER_ID,
    tenant: OWNER_TENANT,
    aud: new URL(issuer).origin,
    exp: Date.now() + SESSION_TTL_SECONDS * 1000,
    nonce: randomToken("s_").slice(0, 40),
  };
  const body = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(body)),
  );
  return `${body}.${bytesToBase64Url(signature)}`;
}

export async function ownerPrincipalFromRequest(
  request: Request,
  env: OwnerAuthEnv,
  issuer: string,
): Promise<OwnerPrincipal | null> {
  if (!ownerAuthConfigured(env)) return null;
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token || token.length > 2048) return null;
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra !== undefined) return null;
  const signatureBytes = base64UrlToBytes(signature);
  const bodyBytes = base64UrlToBytes(body);
  if (!signatureBytes || !bodyBytes) return null;
  const valid = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(env.SESSION_SECRET!),
    signatureBytes,
    new TextEncoder().encode(body),
  );
  if (!valid) return null;
  try {
    const claims = JSON.parse(new TextDecoder().decode(bodyBytes)) as Partial<SessionClaims>;
    if (
      claims.v !== 1 ||
      claims.sub !== OWNER_ID ||
      claims.tenant !== OWNER_TENANT ||
      claims.aud !== new URL(issuer).origin ||
      typeof claims.exp !== "number" ||
      claims.exp <= Date.now() ||
      claims.exp > Date.now() + SESSION_TTL_SECONDS * 1000 + 60_000 ||
      typeof claims.nonce !== "string" ||
      claims.nonce.length < 16
    ) {
      return null;
    }
    return { id: OWNER_ID, tenant_id: OWNER_TENANT, display_name: "Owner" };
  } catch {
    return null;
  }
}

export function ownerLoginRedirect(request: Request, issuer: string): Response {
  const current = new URL(request.url);
  const login = new URL("/login", issuer);
  login.searchParams.set("return_to", `${current.pathname}${current.search}`);
  return new Response(null, { status: 302, headers: { location: login.toString() } });
}

function loginPage(issuer: string, returnTo: string, failed = false): Response {
  const message = failed
    ? '<p class="error">The owner code was not accepted.</p>'
    : "<p>Enter the one-time owner code created during deployment.</p>";
  return html(
    `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>OwnMesh sign in</title>
<style>:root{color-scheme:dark}body{margin:0;background:#0d0f12;color:#d9dde3;font:15px ui-monospace,SFMono-Regular,Consolas,monospace}.box{max-width:30rem;margin:12vh auto;padding:2rem;border:1px solid #30343a;background:#15181d}.mark{letter-spacing:.08em;color:#f0f2f4}p{color:#9ba3ad;line-height:1.55}.error{color:#f2a6a6}label{display:block;margin:1.5rem 0 .5rem}input,button{box-sizing:border-box;width:100%;padding:.8rem;border:1px solid #3a4048;background:#0d0f12;color:#f0f2f4;font:inherit}button{margin-top:1rem;background:#d9dde3;color:#111418;cursor:pointer;font-weight:700}small{display:block;margin-top:1.25rem;color:#737b86}</style></head>
<body><main class="box"><h1 class="mark">OWNMESH</h1><h2>Owner sign in</h2>${message}
<form method="post" action="/login"><input type="hidden" name="return_to" value="${escapeHtml(returnTo)}"><label for="owner_code">Owner code</label><input id="owner_code" name="owner_code" type="password" autocomplete="current-password" minlength="20" maxlength="128" required autofocus><button type="submit">Sign in</button></form>
<small>Self-hosted instance: ${escapeHtml(new URL(issuer).host)}. The code is checked locally by your Worker and is never stored in D1.</small></main></body></html>`,
    { status: failed ? 401 : 200, noStore: true },
  );
}

export async function handleOwnerLogin(
  request: Request,
  store: ControlPlaneStore,
  issuer: string,
  env: OwnerAuthEnv,
): Promise<Response> {
  if (!ownerAuthConfigured(env)) {
    return json({ error: "owner_auth_unavailable" }, { status: 503, noStore: true });
  }
  const url = new URL(request.url);
  const returnTo = safeReturnTo(url.searchParams.get("return_to"), issuer);
  if (request.method === "GET") {
    if (await ownerPrincipalFromRequest(request, env, issuer)) {
      return new Response(null, { status: 302, headers: { location: returnTo } });
    }
    return loginPage(issuer, returnTo);
  }
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, { status: 405, noStore: true });
  }
  if (!sameOriginPost(request, issuer)) {
    return json({ error: "origin_not_allowed" }, { status: 403, noStore: true });
  }
  const form = await boundedForm(request);
  if (!form) return json({ error: "invalid_request" }, { status: 400, noStore: true });
  const submittedReturnTo = safeReturnTo(form.get("return_to"), issuer);
  const ownerCode = (form.get("owner_code") || "").trim();
  if (ownerCode.length < 20 || ownerCode.length > 128) return loginPage(issuer, submittedReturnTo, true);
  const digest = await sha256Hex(ownerCode);
  if (!constantTimeEqual(digest, env.OWNER_TOKEN_HASH!)) {
    return loginPage(issuer, submittedReturnTo, true);
  }
  await store.ensureBootstrap();
  if (!(await store.tenantExists(OWNER_TENANT))) {
    return json({ error: "owner_tenant_unavailable" }, { status: 503, noStore: true });
  }
  await store.ensurePrincipal(OWNER_ID, "Owner", "human", OWNER_TENANT);
  const token = await issueSession(env.SESSION_SECRET!, issuer);
  return new Response(null, {
    status: 303,
    headers: {
      location: submittedReturnTo,
      "set-cookie": cookie(SESSION_COOKIE, token, SESSION_TTL_SECONDS, "Lax"),
      "cache-control": "no-store, no-cache",
      pragma: "no-cache",
    },
  });
}

export async function handleOwnerLogout(request: Request, issuer: string): Promise<Response> {
  if (request.method !== "POST" || !sameOriginPost(request, issuer)) {
    return json({ error: "origin_not_allowed" }, { status: 403, noStore: true });
  }
  return new Response(null, {
    status: 303,
    headers: {
      location: "/login",
      "set-cookie": cookie(SESSION_COOKIE, "", 0, "Lax"),
      "cache-control": "no-store, no-cache",
    },
  });
}

export function chatGptOAuthPair(clientId: string, redirectUri: string): boolean {
  if (!/^client_chatgpt_[a-z0-9_-]{8,64}$/.test(clientId)) return false;
  try {
    const redirect = new URL(redirectUri);
    if (
      redirect.protocol !== "https:" ||
      redirect.hostname !== "chatgpt.com" ||
      redirect.username ||
      redirect.password ||
      redirect.search ||
      redirect.hash
    ) {
      return false;
    }
    const match = /^\/connector\/oauth\/([A-Za-z0-9_-]{8,64})$/.exec(redirect.pathname);
    return Boolean(match && clientId === `client_chatgpt_${match[1]!.toLowerCase()}`);
  } catch {
    return false;
  }
}

export async function handleChatGptConnector(
  request: Request,
  store: ControlPlaneStore,
  issuer: string,
  principal: OwnerPrincipal,
): Promise<Response> {
  if (request.method === "GET") {
    const csrf = randomToken("csrf_");
    const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect ChatGPT — OwnMesh</title>
<style>:root{color-scheme:dark}body{margin:0;background:#0d0f12;color:#d9dde3;font:15px ui-monospace,SFMono-Regular,Consolas,monospace}.box{max-width:38rem;margin:8vh auto;padding:2rem;border:1px solid #30343a;background:#15181d}p,li{color:#9ba3ad;line-height:1.55}code{color:#edf0f3}input,button{box-sizing:border-box;width:100%;padding:.8rem;border:1px solid #3a4048;background:#0d0f12;color:#f0f2f4;font:inherit}button{margin-top:1rem;background:#d9dde3;color:#111418;cursor:pointer;font-weight:700}</style></head>
<body><main class="box"><h1>OWNMESH</h1><h2>Connect ChatGPT</h2><ol><li>In ChatGPT, create a custom MCP app with <code>${escapeHtml(issuer)}/mcp</code>.</li><li>Copy its callback URL and paste it below.</li><li>Copy the generated client ID back to ChatGPT.</li></ol>
<form method="post" action="/connect/chatgpt"><input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}"><label for="callback">ChatGPT callback URL</label><input id="callback" name="callback" type="url" placeholder="https://chatgpt.com/connector/oauth/..." maxlength="256" required autofocus><button type="submit">Create OAuth client</button></form></main></body></html>`;
    const headers = new Headers(html(page, { noStore: true }).headers);
    headers.append("set-cookie", cookie(CSRF_COOKIE, csrf, 600, "Strict"));
    return new Response(page, { status: 200, headers });
  }
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, { status: 405, noStore: true });
  }
  if (!sameOriginPost(request, issuer)) {
    return json({ error: "origin_not_allowed" }, { status: 403, noStore: true });
  }
  const form = await boundedForm(request);
  if (!form) return json({ error: "invalid_request" }, { status: 400, noStore: true });
  const csrf = form.get("csrf_token") || "";
  const csrfCookie = cookieValue(request, CSRF_COOKIE) || "";
  if (!csrf || !csrfCookie || !constantTimeEqual(csrf, csrfCookie)) {
    return json({ error: "csrf_failed" }, { status: 403, noStore: true });
  }
  const callback = (form.get("callback") || "").trim();
  let slug = "";
  try {
    const parsed = new URL(callback);
    slug = /^\/connector\/oauth\/([A-Za-z0-9_-]{8,64})$/.exec(parsed.pathname)?.[1] || "";
  } catch {
    slug = "";
  }
  const clientId = slug ? `client_chatgpt_${slug.toLowerCase()}` : "";
  if (!chatGptOAuthPair(clientId, callback)) {
    return json(
      { error: "invalid_chatgpt_callback", error_description: "Use the exact callback URL shown by ChatGPT." },
      { status: 400, noStore: true },
    );
  }
  await store.putClient({
    client_id: clientId,
    tenant_id: principal.tenant_id,
    client_name: "ChatGPT",
    redirect_uris: [callback],
    created_at: nowIso(),
  });
  const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ChatGPT client ready — OwnMesh</title></head><body style="margin:3rem auto;max-width:42rem;background:#0d0f12;color:#d9dde3;font:15px ui-monospace,Consolas,monospace"><h1>ChatGPT client ready</h1><p>Paste this OAuth client ID into ChatGPT:</p><pre style="padding:1rem;border:1px solid #3a4048;overflow:auto">${escapeHtml(clientId)}</pre><p>MCP server URL:</p><pre style="padding:1rem;border:1px solid #3a4048;overflow:auto">${escapeHtml(issuer)}/mcp</pre><p>Authentication: OAuth. The next ChatGPT prompt opens OwnMesh consent.</p></body></html>`;
  return html(page, { status: 201, noStore: true });
}
