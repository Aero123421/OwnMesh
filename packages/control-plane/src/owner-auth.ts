import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type AuthenticatorTransportFuture,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import type { ControlPlaneStore, OwnerAuthChallenge } from "./store.ts";
import {
  AUTH_PAGE_CSP,
  authLocale,
  authPage,
  authText,
  type AuthLocale,
} from "./auth-ui.ts";
import {
  BodyTooLargeError,
  constantTimeEqual,
  html,
  json,
  nowIso,
  randomToken,
  readRequestJsonLimited,
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
const PASSKEY_CHALLENGE_COOKIE = "__Host-ownmesh_passkey";
const PRESENCE_COOKIE = "__Host-ownmesh_presence";
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const PRESENCE_TTL_SECONDS = 5 * 60;
const PASSKEY_CHALLENGE_TTL_MS = 5 * 60 * 1000;
const MAX_FORM_BYTES = 8 * 1024;
const MAX_PASSKEY_BODY_BYTES = 64 * 1024;
const REGISTRATION_CHALLENGE_ID = "owner_registration";
const ALLOWED_TRANSPORTS = new Set<AuthenticatorTransportFuture>([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

type SessionClaims = {
  v: 1;
  sub: string;
  tenant: string;
  aud: string;
  exp: number;
  nonce: string;
};

type PresenceClaims = {
  v: 1;
  purpose: "approve";
  sub: string;
  tenant: string;
  aud: string;
  operation_id: string;
  exp: number;
  nonce: string;
};

type PresenceClaimsV2 = {
  v: 2;
  purpose: "approve";
  sub: string;
  tenant: string;
  aud: string;
  commitment: string;
  exp: number;
  nonce: string;
};

const PRESENCE_SIGNING_CONTEXT = "ownmesh.owner.presence.v1:";
const PRESENCE_SIGNING_CONTEXT_V2 = "ownmesh.owner.presence.v2:";
const APPROVE_LIST_CSRF_COOKIE = "__Host-ownmesh_approve_list";
const APPROVE_LIST_CSRF_TTL_SECONDS = 10 * 60;
const PAYLOAD_HASH_RE = /^[0-9a-f]{64}$/i;

/** Hard cap on one passkey-bound approval set. */
export const MAX_BATCH_APPROVAL_IDS = 32;

export type ApprovalSelection =
  | { kind: "list" }
  | { kind: "single"; operationId: string }
  | { kind: "batch"; operationIds: string[] }
  | { kind: "invalid"; error: string };

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

function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(new ArrayBuffer(length));
  crypto.getRandomValues(bytes);
  return bytes;
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

function validOperationId(value: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$/.test(value);
}

/** Canonical lowercase SHA-256 hex, or null when the value is not a payload hash. */
export function payloadHashForCommitment(value: unknown): string | null {
  if (typeof value !== "string" || !PAYLOAD_HASH_RE.test(value)) return null;
  return value.toLowerCase();
}

/**
 * Parse `/approve` query selection.
 * `operation_id` (exactly one) and `ids` are mutually exclusive. Duplicate `ids`
 * are collapsed; order is sorted for the v2 commitment.
 */
export function parseApprovalSelection(url: URL): ApprovalSelection {
  const singles = url.searchParams.getAll("operation_id").filter((value) => value.length > 0);
  const rawIds = url.searchParams.getAll("ids").filter((value) => value.length > 0);
  if (singles.length > 0 && rawIds.length > 0) {
    return { kind: "invalid", error: "operation_id and ids are mutually exclusive" };
  }
  if (singles.length > 1) {
    return { kind: "invalid", error: "exactly one operation_id allowed" };
  }
  if (singles.length === 1) {
    return validOperationId(singles[0]!)
      ? { kind: "single", operationId: singles[0]! }
      : { kind: "invalid", error: "invalid operation_id" };
  }
  if (rawIds.length === 0) return { kind: "list" };
  const seen = new Set<string>();
  const operationIds: string[] = [];
  for (const id of rawIds) {
    if (!validOperationId(id)) return { kind: "invalid", error: "invalid ids" };
    if (seen.has(id)) continue;
    seen.add(id);
    operationIds.push(id);
  }
  if (operationIds.length > MAX_BATCH_APPROVAL_IDS) {
    return { kind: "invalid", error: `ids exceeds ${MAX_BATCH_APPROVAL_IDS}` };
  }
  operationIds.sort();
  return { kind: "batch", operationIds };
}

function parseApprovalTarget(target: string, issuer: string): ApprovalSelection | null {
  try {
    const url = new URL(target, issuer);
    if (url.origin !== new URL(issuer).origin || url.pathname !== "/approve") return null;
    const selection = parseApprovalSelection(url);
    return selection.kind === "invalid" ? null : selection;
  } catch {
    return null;
  }
}

export function approvalSelectionReturnTo(selection: Extract<ApprovalSelection, { kind: "single" | "batch" | "list" }>): string {
  if (selection.kind === "single") {
    return `/approve?operation_id=${encodeURIComponent(selection.operationId)}`;
  }
  if (selection.kind === "batch") {
    return `/approve?${selection.operationIds.map((id) => `ids=${encodeURIComponent(id)}`).join("&")}`;
  }
  return "/approve";
}

/**
 * SHA-256 of sorted `operation_id:payload_hash` lines. Hashes must be server-looked-up
 * 64-char hex; the client must not supply them.
 */
export async function approvalSetCommitment(
  entries: Array<{ operation_id: string; payload_hash: string }>,
): Promise<string | null> {
  if (entries.length < 1 || entries.length > MAX_BATCH_APPROVAL_IDS) return null;
  const lines: string[] = [];
  const seen = new Set<string>();
  for (const entry of entries) {
    if (!validOperationId(entry.operation_id) || seen.has(entry.operation_id)) return null;
    const hash = payloadHashForCommitment(entry.payload_hash);
    if (!hash) return null;
    seen.add(entry.operation_id);
    lines.push(`${entry.operation_id}:${hash}`);
  }
  lines.sort();
  return sha256Hex(lines.join("\n"));
}

export async function approvalCommitmentForIds(
  store: ControlPlaneStore,
  operationIds: string[],
): Promise<string | null> {
  if (operationIds.length < 1 || operationIds.length > MAX_BATCH_APPROVAL_IDS) return null;
  const entries: Array<{ operation_id: string; payload_hash: string }> = [];
  for (const operationId of operationIds) {
    const op = await store.getMcpOperation(operationId);
    const hash = payloadHashForCommitment(op?.payload_hash);
    if (!op || op.status !== "approval_required" || !hash) return null;
    entries.push({ operation_id: operationId, payload_hash: hash });
  }
  return approvalSetCommitment(entries);
}

export function issueApproveListCsrf(): { token: string; header: string } {
  const token = randomToken("csrf_");
  return {
    token,
    header: cookie(APPROVE_LIST_CSRF_COOKIE, token, APPROVE_LIST_CSRF_TTL_SECONDS, "Strict"),
  };
}

export function verifyApproveListCsrf(request: Request, token: string): boolean {
  const cookieToken = cookieValue(request, APPROVE_LIST_CSRF_COOKIE) || "";
  return Boolean(token && cookieToken && constantTimeEqual(token, cookieToken));
}

export function sameOriginBrowserPost(request: Request, issuer: string): boolean {
  const expected = new URL(issuer).origin;
  const origin = request.headers.get("origin");
  if (origin) {
    try {
      return new URL(origin).origin === expected;
    } catch {
      return false;
    }
  }

  // Some browser form submissions omit Origin, and OwnMesh intentionally uses
  // Referrer-Policy: no-referrer. Sec-Fetch-Site is browser-controlled and is
  // therefore the primary fallback for these exact same-origin submissions.
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite === "same-origin") return true;
  if (fetchSite) return false;

  // Older clients without Fetch Metadata may fall back to an exact Referer.
  const referer = request.headers.get("referer");
  if (!referer) return false;
  try {
    return new URL(referer).origin === expected;
  } catch {
    return false;
  }
}

function rpId(issuer: string): string {
  return new URL(issuer).hostname;
}

function origin(issuer: string): string {
  return new URL(issuer).origin;
}

function passkeyChallengeId(request: Request): string | null {
  const id = cookieValue(request, PASSKEY_CHALLENGE_COOKIE);
  return id && /^[A-Za-z0-9_-]{8,128}$/.test(id) ? id : null;
}

function passkeyChallengeCookie(id: string, maxAge = 300): string {
  return cookie(PASSKEY_CHALLENGE_COOKIE, id, maxAge, "Strict");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function boundedText(value: unknown, max: number): string | null {
  if (typeof value !== "string" || value.length < 1 || value.length > max) return null;
  return value;
}

function base64UrlText(value: unknown, max: number): string | null {
  const text = boundedText(value, max);
  return text && /^[A-Za-z0-9_-]+$/.test(text) ? text : null;
}

function parseTransports(value: unknown): AuthenticatorTransportFuture[] | undefined {
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || value.length > 8) return undefined;
  const transports: AuthenticatorTransportFuture[] = [];
  for (const item of value) {
    if (typeof item === "string" && ALLOWED_TRANSPORTS.has(item as AuthenticatorTransportFuture)) {
      transports.push(item as AuthenticatorTransportFuture);
    }
  }
  return transports;
}

function registrationResponse(value: unknown): RegistrationResponseJSON | null {
  if (!isRecord(value) || !isRecord(value.response)) return null;
  const id = base64UrlText(value.id, 1024);
  const rawId = base64UrlText(value.rawId, 1024);
  const clientDataJSON = base64UrlText(value.response.clientDataJSON, 8192);
  const attestationObject = base64UrlText(value.response.attestationObject, 48 * 1024);
  if (!id || !rawId || !clientDataJSON || !attestationObject || value.type !== "public-key") return null;
  const authenticatorAttachment = value.authenticatorAttachment === "platform" || value.authenticatorAttachment === "cross-platform"
    ? value.authenticatorAttachment
    : undefined;
  return {
    id,
    rawId,
    type: "public-key",
    authenticatorAttachment,
    clientExtensionResults: {},
    response: {
      clientDataJSON,
      attestationObject,
      transports: parseTransports(value.response.transports),
    },
  };
}

function authenticationResponse(value: unknown): AuthenticationResponseJSON | null {
  if (!isRecord(value) || !isRecord(value.response)) return null;
  const id = base64UrlText(value.id, 1024);
  const rawId = base64UrlText(value.rawId, 1024);
  const clientDataJSON = base64UrlText(value.response.clientDataJSON, 8192);
  const authenticatorData = base64UrlText(value.response.authenticatorData, 8192);
  const signature = base64UrlText(value.response.signature, 8192);
  const userHandle = value.response.userHandle == null
    ? undefined
    : base64UrlText(value.response.userHandle, 1024) ?? undefined;
  if (!id || !rawId || !clientDataJSON || !authenticatorData || !signature || value.type !== "public-key") {
    return null;
  }
  const authenticatorAttachment = value.authenticatorAttachment === "platform" || value.authenticatorAttachment === "cross-platform"
    ? value.authenticatorAttachment
    : undefined;
  return {
    id,
    rawId,
    type: "public-key",
    authenticatorAttachment,
    clientExtensionResults: {},
    response: { clientDataJSON, authenticatorData, signature, userHandle },
  };
}

async function passkeyJson(request: Request): Promise<Record<string, unknown> | null> {
  if (!(request.headers.get("content-type") || "").toLowerCase().startsWith("application/json")) return null;
  try {
    const value = await readRequestJsonLimited<unknown>(request, MAX_PASSKEY_BODY_BYTES);
    return isRecord(value) ? value : null;
  } catch (error) {
    if (error instanceof BodyTooLargeError) throw error;
    return null;
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

/**
 * Mint a short-lived, purpose-separated proof of recent user verification.
 * The resulting cookie is useful only for the exact approval operation.
 */
export async function issueOwnerPresenceForOperation(
  env: OwnerAuthEnv,
  issuer: string,
  principal: OwnerPrincipal,
  operationId: string,
): Promise<string | null> {
  if (
    !ownerAuthConfigured(env) ||
    principal.id !== OWNER_ID ||
    principal.tenant_id !== OWNER_TENANT ||
    !validOperationId(operationId)
  ) {
    return null;
  }
  const claims: PresenceClaims = {
    v: 1,
    purpose: "approve",
    sub: principal.id,
    tenant: principal.tenant_id,
    aud: new URL(issuer).origin,
    operation_id: operationId,
    exp: Date.now() + PRESENCE_TTL_SECONDS * 1000,
    nonce: randomToken("p_").slice(0, 40),
  };
  const body = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const signed = `${PRESENCE_SIGNING_CONTEXT}${body}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", await hmacKey(env.SESSION_SECRET!), new TextEncoder().encode(signed)),
  );
  return cookie(PRESENCE_COOKIE, `${body}.${bytesToBase64Url(signature)}`, PRESENCE_TTL_SECONDS, "Strict");
}

/**
 * Mint a short-lived v2 presence cookie bound to a set commitment
 * (`SHA-256` of sorted `operation_id:payload_hash` lines). Distinct HMAC
 * context from v1 so a v1 verifier cannot accept this cookie.
 */
export async function issueOwnerPresenceForCommitment(
  env: OwnerAuthEnv,
  issuer: string,
  principal: OwnerPrincipal,
  commitment: string,
): Promise<string | null> {
  const bound = payloadHashForCommitment(commitment);
  if (
    !ownerAuthConfigured(env) ||
    principal.id !== OWNER_ID ||
    principal.tenant_id !== OWNER_TENANT ||
    !bound
  ) {
    return null;
  }
  const claims: PresenceClaimsV2 = {
    v: 2,
    purpose: "approve",
    sub: principal.id,
    tenant: principal.tenant_id,
    aud: new URL(issuer).origin,
    commitment: bound,
    exp: Date.now() + PRESENCE_TTL_SECONDS * 1000,
    nonce: randomToken("p_").slice(0, 40),
  };
  const body = bytesToBase64Url(new TextEncoder().encode(JSON.stringify(claims)));
  const signed = `${PRESENCE_SIGNING_CONTEXT_V2}${body}`;
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", await hmacKey(env.SESSION_SECRET!), new TextEncoder().encode(signed)),
  );
  return cookie(PRESENCE_COOKIE, `${body}.${bytesToBase64Url(signature)}`, PRESENCE_TTL_SECONDS, "Strict");
}

export async function ownerPresenceForOperation(
  request: Request,
  env: OwnerAuthEnv,
  issuer: string,
  principal: OwnerPrincipal,
  operationId: string,
): Promise<boolean> {
  if (
    !ownerAuthConfigured(env) ||
    principal.id !== OWNER_ID ||
    principal.tenant_id !== OWNER_TENANT ||
    !validOperationId(operationId)
  ) {
    return false;
  }
  const token = cookieValue(request, PRESENCE_COOKIE);
  if (!token || token.length > 2048) return false;
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra !== undefined) return false;
  const bodyBytes = base64UrlToBytes(body);
  const signatureBytes = base64UrlToBytes(signature);
  if (!bodyBytes || !signatureBytes) return false;
  const valid = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(env.SESSION_SECRET!),
    signatureBytes,
    new TextEncoder().encode(`${PRESENCE_SIGNING_CONTEXT}${body}`),
  );
  if (!valid) return false;
  try {
    const claims = JSON.parse(new TextDecoder().decode(bodyBytes)) as Partial<PresenceClaims>;
    const now = Date.now();
    return (
      claims.v === 1 &&
      claims.purpose === "approve" &&
      claims.sub === principal.id &&
      claims.tenant === principal.tenant_id &&
      claims.aud === new URL(issuer).origin &&
      claims.operation_id === operationId &&
      typeof claims.exp === "number" &&
      claims.exp > now &&
      claims.exp <= now + PRESENCE_TTL_SECONDS * 1000 + 60_000 &&
      typeof claims.nonce === "string" &&
      claims.nonce.length >= 16
    );
  } catch {
    return false;
  }
}

export async function ownerPresenceForCommitment(
  request: Request,
  env: OwnerAuthEnv,
  issuer: string,
  principal: OwnerPrincipal,
  commitment: string,
): Promise<boolean> {
  const bound = payloadHashForCommitment(commitment);
  if (
    !ownerAuthConfigured(env) ||
    principal.id !== OWNER_ID ||
    principal.tenant_id !== OWNER_TENANT ||
    !bound
  ) {
    return false;
  }
  const token = cookieValue(request, PRESENCE_COOKIE);
  if (!token || token.length > 2048) return false;
  const [body, signature, extra] = token.split(".");
  if (!body || !signature || extra !== undefined) return false;
  const bodyBytes = base64UrlToBytes(body);
  const signatureBytes = base64UrlToBytes(signature);
  if (!bodyBytes || !signatureBytes) return false;
  const valid = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(env.SESSION_SECRET!),
    signatureBytes,
    new TextEncoder().encode(`${PRESENCE_SIGNING_CONTEXT_V2}${body}`),
  );
  if (!valid) return false;
  try {
    const claims = JSON.parse(new TextDecoder().decode(bodyBytes)) as Partial<PresenceClaimsV2>;
    const now = Date.now();
    return (
      claims.v === 2 &&
      claims.purpose === "approve" &&
      claims.sub === principal.id &&
      claims.tenant === principal.tenant_id &&
      claims.aud === new URL(issuer).origin &&
      claims.commitment === bound &&
      typeof claims.exp === "number" &&
      claims.exp > now &&
      claims.exp <= now + PRESENCE_TTL_SECONDS * 1000 + 60_000 &&
      typeof claims.nonce === "string" &&
      claims.nonce.length >= 16
    );
  } catch {
    return false;
  }
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

export function ownerPresenceRedirect(request: Request, issuer: string): Response {
  const current = new URL(request.url);
  const selection = parseApprovalSelection(current);
  if (selection.kind !== "single" && selection.kind !== "batch") {
    return json({ error: "invalid_request", error_description: "operation_id or ids required" }, { status: 400, noStore: true });
  }
  const login = new URL("/login", issuer);
  login.searchParams.set("fresh", "1");
  login.searchParams.set("return_to", approvalSelectionReturnTo(selection));
  return new Response(null, { status: 302, headers: { location: login.toString() } });
}

function loginPage(
  issuer: string,
  returnTo: string,
  registered: boolean,
  locale: AuthLocale,
): Response {
  const mode = registered ? "authenticate" : "register";
  const intro = registered
    ? authText(locale, {
        en: "Use the passkey registered for this self-hosted instance.",
        ja: "このセルフホスト環境に登録したパスキーを使用します。",
        zh: "使用为此自托管实例注册的通行密钥。",
        ru: "Используйте ключ доступа, зарегистрированный для этого экземпляра.",
      })
    : authText(locale, {
        en: "Enter the one-time owner code, then create the first passkey.",
        ja: "一度限りのオーナーコードを入力し、最初のパスキーを作成します。",
        zh: "输入一次性所有者代码，然后创建第一个通行密钥。",
        ru: "Введите одноразовый код владельца и создайте первый ключ доступа.",
      });
  const ownerCodeLabel = authText(locale, {
    en: "One-time owner code",
    ja: "一度限りのオーナーコード",
    zh: "一次性所有者代码",
    ru: "Одноразовый код владельца",
  });
  const codeInput = registered
    ? ""
    : `<label for="owner_code">${ownerCodeLabel}</label><input id="owner_code" name="owner_code" type="password" autocomplete="off" minlength="20" maxlength="128" required>`;
  const button = registered
    ? authText(locale, {
        en: "Sign in with passkey",
        ja: "パスキーでサインイン",
        zh: "使用通行密钥登录",
        ru: "Войти с ключом доступа",
      })
    : authText(locale, {
        en: "Create owner passkey",
        ja: "オーナーのパスキーを作成",
        zh: "创建所有者通行密钥",
        ru: "Создать ключ доступа владельца",
      });
  const note = authText(locale, {
    en: "Private keys stay inside your authenticator. OwnMesh stores only the public credential.",
    ja: "秘密鍵は認証器の中に残り、OwnMeshには公開資格情報だけが保存されます。",
    zh: "私钥始终保留在认证器内；OwnMesh 只保存公钥凭据。",
    ru: "Закрытые ключи остаются в аутентификаторе; OwnMesh хранит только открытые данные.",
  });
  const helpSummary = authText(locale, {
    en: "Can't use this passkey?",
    ja: "このパスキーを使えない場合",
    zh: "无法使用此通行密钥？",
    ru: "Не удаётся использовать ключ доступа?",
  });
  const help = authText(locale, {
    en: "For a headless server, run ownmesh login --device and open its URL on a phone or computer that has this passkey. If every passkey is lost, run pnpm run owner:init -- --reset-passkey from the control-plane deployment.",
    ja: "ヘッドレス環境では ownmesh login --device を実行し、表示されたURLをこのパスキーが使えるスマートフォンまたはPCで開いてください。すべてのパスキーを紛失した場合は、Control Planeのデプロイ環境で pnpm run owner:init -- --reset-passkey を実行します。",
    zh: "在无界面服务器上运行 ownmesh login --device，并在持有此通行密钥的手机或电脑上打开所示网址。若所有通行密钥均已丢失，请在控制平面部署目录运行 pnpm run owner:init -- --reset-passkey。",
    ru: "На сервере без браузера выполните ownmesh login --device и откройте показанный URL на телефоне или компьютере с этим ключом. Если потеряны все ключи, выполните pnpm run owner:init -- --reset-passkey в развёртывании control plane.",
  });
  return html(
    authPage({
      locale,
      title: authText(locale, {
        en: "OwnMesh sign in",
        ja: "OwnMesh サインイン",
        zh: "OwnMesh 登录",
        ru: "Вход в OwnMesh",
      }),
      eyebrow: registered
        ? authText(locale, { en: "Owner authentication", ja: "オーナー認証", zh: "所有者认证", ru: "Аутентификация владельца" })
        : authText(locale, { en: "Initial owner setup", ja: "初回オーナー設定", zh: "初始所有者设置", ru: "Первичная настройка владельца" }),
      heading: registered
        ? authText(locale, { en: "Unlock your private mesh", ja: "プライベートメッシュを開く", zh: "解锁您的私有网格", ru: "Открыть приватную сеть" })
        : authText(locale, { en: "Create the owner identity", ja: "オーナーIDを作成", zh: "创建所有者身份", ru: "Создать учётную запись владельца" }),
      intro,
      body: `<form id="passkey-form" class="stack" data-mode="${mode}"><input type="hidden" name="return_to" value="${escapeHtml(returnTo)}">${codeInput}<button class="primary wide" type="submit">${button}</button></form><p id="passkey-status" class="status" role="status" aria-live="polite"></p><p class="note">${note}</p><details class="help"><summary>${helpSummary}</summary><p>${help}</p></details><script src="/auth/passkey.js" defer></script>`,
      footer: new URL(issuer).host,
    }),
    {
      status: 200,
      noStore: true,
      headers: {
        "content-security-policy": AUTH_PAGE_CSP,
      },
    },
  );
}

export function ownerPasskeyScript(): Response {
  const script = `(()=>{"use strict";const f=document.getElementById("passkey-form"),s=document.getElementById("passkey-status"),b=f&&f.querySelector("button");if(!f||!s||!b)return;const MSG={bootstrap_denied:"That one-time owner code was not accepted. Copy it again from the terminal that printed it.",owner_already_registered:"An owner passkey is already registered. Sign in with it instead of creating a new one.",registration_in_progress:"Another registration is already in progress. Wait a moment and retry.",owner_auth_unavailable:"Owner sign-in is not configured on this control plane yet.",owner_auth_schema_unavailable:"The control-plane database is not migrated yet. Re-run the guided deploy.",challenge_expired:"That sign-in request expired. Retry from this page.",origin_not_allowed:"This page was loaded from an unexpected origin. Open the sign-in URL directly.",request_too_large:"The request was too large. Retry from this page.",rate_limited:"Too many attempts. Wait a minute and retry."};const explain=e=>{const n=e&&e.name;if(n==="NotAllowedError"||n==="AbortError")return "Passkey prompt dismissed. Press the button to try again.";if(n==="InvalidStateError")return "This device already has a passkey registered for OwnMesh. Sign in with it instead.";if(n==="SecurityError")return "The browser blocked this passkey request. Make sure you opened the sign-in URL over HTTPS.";const k=e&&e.message;return (k&&MSG[k])||"Passkey verification failed. Retry from this page.";};const d=x=>{const p="=".repeat((4-x.length%4)%4),v=atob(x.replace(/-/g,"+").replace(/_/g,"/")+p),a=new Uint8Array(v.length);for(let i=0;i<v.length;i++)a[i]=v.charCodeAt(i);return a.buffer},e=x=>{const a=new Uint8Array(x);let v="";for(const n of a)v+=String.fromCharCode(n);return btoa(v).replace(/\\+/g,"-").replace(/\\//g,"_").replace(/=+$/g,"")},creation=o=>({ ...o,challenge:d(o.challenge),user:{...o.user,id:d(o.user.id)},excludeCredentials:(o.excludeCredentials||[]).map(c=>({...c,id:d(c.id)}))}),request=o=>({...o,challenge:d(o.challenge),allowCredentials:(o.allowCredentials||[]).map(c=>({...c,id:d(c.id)}))}),json=c=>typeof c.toJSON==="function"?c.toJSON():{id:c.id,rawId:e(c.rawId),type:c.type,authenticatorAttachment:c.authenticatorAttachment||undefined,clientExtensionResults:c.getClientExtensionResults(),response:c.response.attestationObject?{clientDataJSON:e(c.response.clientDataJSON),attestationObject:e(c.response.attestationObject),transports:typeof c.response.getTransports==="function"?c.response.getTransports():undefined}:{clientDataJSON:e(c.response.clientDataJSON),authenticatorData:e(c.response.authenticatorData),signature:e(c.response.signature),userHandle:c.response.userHandle?e(c.response.userHandle):undefined}};f.addEventListener("submit",async n=>{n.preventDefault();if(!window.PublicKeyCredential){s.textContent="Passkeys are not supported by this browser.";return}b.disabled=true;s.textContent="Waiting for your passkey…";try{const mode=f.dataset.mode,ret=f.elements.return_to.value,payload={return_to:ret};if(mode==="register")payload.owner_code=f.elements.owner_code.value;const optionsPath=mode==="register"?"/auth/passkey/register/options":"/auth/passkey/options",verifyPath=mode==="register"?"/auth/passkey/register/verify":"/auth/passkey/verify",or=await fetch(optionsPath,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(payload)}),ob=await or.json();if(!or.ok)throw new Error(ob.error||"passkey_options_failed");const pk=mode==="register"?creation(ob.options):request(ob.options),credential=mode==="register"?await navigator.credentials.create({publicKey:pk}):await navigator.credentials.get({publicKey:pk});if(!credential)throw new Error("passkey_cancelled");const vr=await fetch(verifyPath,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(json(credential))}),vb=await vr.json();if(!vr.ok||!vb.redirect)throw new Error(vb.error||"passkey_verification_failed");location.assign(vb.redirect)}catch(err){s.textContent=explain(err);b.disabled=false}})})();`;
  return new Response(script, {
    status: 200,
    headers: {
      "content-type": "text/javascript; charset=utf-8",
      "cache-control": "public, max-age=3600",
      "x-content-type-options": "nosniff",
    },
  });
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
  const returnSelection = parseApprovalTarget(returnTo, issuer);
  const forceFreshApproval =
    url.searchParams.get("fresh") === "1" &&
    (returnSelection?.kind === "single" || returnSelection?.kind === "batch");
  if (request.method === "GET") {
    if (!forceFreshApproval && await ownerPrincipalFromRequest(request, env, issuer)) {
      return new Response(null, { status: 302, headers: { location: returnTo } });
    }
    try {
      return loginPage(
        issuer,
        returnTo,
        (await store.listOwnerPasskeys()).length > 0,
        authLocale(request),
      );
    } catch {
      return json({ error: "owner_auth_schema_unavailable" }, { status: 503, noStore: true });
    }
  }
  return json({ error: "method_not_allowed" }, { status: 405, noStore: true });
}

async function ownerPasskeys(store: ControlPlaneStore) {
  try {
    return await store.listOwnerPasskeys();
  } catch {
    return null;
  }
}

function challengeResponse(data: unknown, challengeId: string): Response {
  return json(data, {
    status: 200,
    noStore: true,
    headers: { "set-cookie": passkeyChallengeCookie(challengeId) },
  });
}

function passkeyError(error: string, status: number): Response {
  return json({ error }, { status, noStore: true });
}

async function appendPresenceCookieForReturnTo(
  headers: Headers,
  env: OwnerAuthEnv,
  issuer: string,
  returnTo: string,
  store: ControlPlaneStore,
): Promise<void> {
  const selection = parseApprovalTarget(returnTo, issuer);
  const owner = { id: OWNER_ID, tenant_id: OWNER_TENANT, display_name: "Owner" };
  if (selection?.kind === "single") {
    const presence = await issueOwnerPresenceForOperation(env, issuer, owner, selection.operationId);
    if (presence) headers.append("set-cookie", presence);
    return;
  }
  if (selection?.kind !== "batch") return;
  const commitment = await approvalCommitmentForIds(store, selection.operationIds);
  if (!commitment) return;
  const presence = await issueOwnerPresenceForCommitment(env, issuer, owner, commitment);
  if (presence) headers.append("set-cookie", presence);
}

export async function handleOwnerPasskeyRegistrationOptions(
  request: Request,
  store: ControlPlaneStore,
  issuer: string,
  env: OwnerAuthEnv,
): Promise<Response> {
  if (!ownerAuthConfigured(env)) return passkeyError("owner_auth_unavailable", 503);
  if (!sameOriginBrowserPost(request, issuer)) return passkeyError("origin_not_allowed", 403);
  let body: Record<string, unknown> | null;
  try {
    body = await passkeyJson(request);
  } catch (error) {
    return passkeyError(error instanceof BodyTooLargeError ? "request_too_large" : "invalid_request", 413);
  }
  if (!body) return passkeyError("invalid_request", 400);
  const ownerCode = boundedText(body.owner_code, 128)?.trim() || "";
  if (!/^own_[A-Za-z0-9_-]{20,96}$/.test(ownerCode)) return passkeyError("bootstrap_denied", 401);
  if (!constantTimeEqual(await sha256Hex(ownerCode), env.OWNER_TOKEN_HASH!)) {
    return passkeyError("bootstrap_denied", 401);
  }
  const existing = await ownerPasskeys(store);
  if (!existing) return passkeyError("owner_auth_schema_unavailable", 503);
  if (existing.length > 0) return passkeyError("owner_already_registered", 409);

  await store.ensureBootstrap();
  if (!(await store.tenantExists(OWNER_TENANT))) return passkeyError("owner_tenant_unavailable", 503);
  await store.ensurePrincipal(OWNER_ID, "Owner", "human", OWNER_TENANT);
  const userIdBytes = randomBytes(32);
  const webauthnUserId = bytesToBase64Url(userIdBytes);
  const options = await generateRegistrationOptions({
    rpName: "OwnMesh",
    rpID: rpId(issuer),
    userName: "owner",
    userDisplayName: "Owner",
    userID: userIdBytes,
    timeout: PASSKEY_CHALLENGE_TTL_MS,
    attestationType: "none",
    authenticatorSelection: { residentKey: "required", userVerification: "required" },
    supportedAlgorithmIDs: [-7, -257],
  });
  const createdAt = nowIso();
  const claimed = await store.putOwnerAuthChallenge({
    id: REGISTRATION_CHALLENGE_ID,
    kind: "register",
    challenge: options.challenge,
    webauthn_user_id: webauthnUserId,
    return_to: safeReturnTo(boundedText(body.return_to, 4096), issuer),
    expires_at: Date.now() + PASSKEY_CHALLENGE_TTL_MS,
    created_at: createdAt,
  });
  if (!claimed) return passkeyError("registration_in_progress", 409);
  return challengeResponse({ options }, REGISTRATION_CHALLENGE_ID);
}

export async function handleOwnerPasskeyRegistrationVerify(
  request: Request,
  store: ControlPlaneStore,
  issuer: string,
  env: OwnerAuthEnv,
): Promise<Response> {
  if (!ownerAuthConfigured(env)) return passkeyError("owner_auth_unavailable", 503);
  if (!sameOriginBrowserPost(request, issuer)) return passkeyError("origin_not_allowed", 403);
  let body: Record<string, unknown> | null;
  try {
    body = await passkeyJson(request);
  } catch (error) {
    return passkeyError(error instanceof BodyTooLargeError ? "request_too_large" : "invalid_request", 413);
  }
  const response = registrationResponse(body);
  const challengeId = passkeyChallengeId(request);
  if (!response || challengeId !== REGISTRATION_CHALLENGE_ID) return passkeyError("verification_failed", 400);
  const challenge = await store.takeOwnerAuthChallenge(challengeId, "register");
  if (!challenge?.webauthn_user_id) return passkeyError("challenge_expired", 400);
  try {
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: origin(issuer),
      expectedRPID: rpId(issuer),
      requireUserVerification: true,
      supportedAlgorithmIDs: [-7, -257],
    });
    if (!verification.verified) return passkeyError("verification_failed", 401);
    const info = verification.registrationInfo;
    const inserted = await store.putInitialOwnerPasskey({
      credential_id: info.credential.id,
      principal_id: OWNER_ID,
      webauthn_user_id: challenge.webauthn_user_id,
      public_key: info.credential.publicKey,
      counter: info.credential.counter,
      transports: info.credential.transports || [],
      device_type: info.credentialDeviceType,
      backed_up: info.credentialBackedUp,
      created_at: nowIso(),
    });
    if (!inserted) return passkeyError("owner_already_registered", 409);
    const session = await issueSession(env.SESSION_SECRET!, issuer);
    const headers = new Headers();
    headers.append("set-cookie", cookie(SESSION_COOKIE, session, SESSION_TTL_SECONDS, "Lax"));
    headers.append("set-cookie", passkeyChallengeCookie("", 0));
    await appendPresenceCookieForReturnTo(headers, env, issuer, challenge.return_to, store);
    return json({ ok: true, redirect: challenge.return_to }, { status: 200, noStore: true, headers });
  } catch {
    return passkeyError("verification_failed", 401);
  }
}

export async function handleOwnerPasskeyOptions(
  request: Request,
  store: ControlPlaneStore,
  issuer: string,
  env: OwnerAuthEnv,
): Promise<Response> {
  if (!ownerAuthConfigured(env)) return passkeyError("owner_auth_unavailable", 503);
  if (!sameOriginBrowserPost(request, issuer)) return passkeyError("origin_not_allowed", 403);
  let body: Record<string, unknown> | null;
  try {
    body = await passkeyJson(request);
  } catch (error) {
    return passkeyError(error instanceof BodyTooLargeError ? "request_too_large" : "invalid_request", 413);
  }
  if (!body) return passkeyError("invalid_request", 400);
  const passkeys = await ownerPasskeys(store);
  if (!passkeys) return passkeyError("owner_auth_schema_unavailable", 503);
  if (passkeys.length === 0) return passkeyError("owner_registration_required", 409);
  const options = await generateAuthenticationOptions({
    rpID: rpId(issuer),
    allowCredentials: passkeys.map((passkey) => ({
      id: passkey.credential_id,
      transports: parseTransports(passkey.transports),
    })),
    timeout: PASSKEY_CHALLENGE_TTL_MS,
    userVerification: "required",
  });
  const challengeId = randomToken("pka_");
  const record: OwnerAuthChallenge = {
    id: challengeId,
    kind: "authenticate",
    challenge: options.challenge,
    return_to: safeReturnTo(boundedText(body.return_to, 4096), issuer),
    expires_at: Date.now() + PASSKEY_CHALLENGE_TTL_MS,
    created_at: nowIso(),
  };
  if (!(await store.putOwnerAuthChallenge(record))) return passkeyError("too_many_attempts", 429);
  return challengeResponse({ options }, challengeId);
}

export async function handleOwnerPasskeyVerify(
  request: Request,
  store: ControlPlaneStore,
  issuer: string,
  env: OwnerAuthEnv,
): Promise<Response> {
  if (!ownerAuthConfigured(env)) return passkeyError("owner_auth_unavailable", 503);
  if (!sameOriginBrowserPost(request, issuer)) return passkeyError("origin_not_allowed", 403);
  let body: Record<string, unknown> | null;
  try {
    body = await passkeyJson(request);
  } catch (error) {
    return passkeyError(error instanceof BodyTooLargeError ? "request_too_large" : "invalid_request", 413);
  }
  const response = authenticationResponse(body);
  const challengeId = passkeyChallengeId(request);
  if (!response || !challengeId) return passkeyError("verification_failed", 400);
  const challenge = await store.takeOwnerAuthChallenge(challengeId, "authenticate");
  if (!challenge) return passkeyError("challenge_expired", 400);
  const passkey = await store.getOwnerPasskey(response.id);
  if (!passkey || passkey.principal_id !== OWNER_ID) return passkeyError("verification_failed", 401);
  try {
    const publicKey = new Uint8Array(new ArrayBuffer(passkey.public_key.byteLength));
    publicKey.set(passkey.public_key);
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge.challenge,
      expectedOrigin: origin(issuer),
      expectedRPID: rpId(issuer),
      credential: {
        id: passkey.credential_id,
        publicKey,
        counter: passkey.counter,
        transports: parseTransports(passkey.transports),
      },
      requireUserVerification: true,
    });
    if (!verification.verified) return passkeyError("verification_failed", 401);
    const info = verification.authenticationInfo;
    if (!(await store.updateOwnerPasskeyUsage(
      passkey.credential_id,
      passkey.counter,
      info.newCounter,
      info.credentialDeviceType,
      info.credentialBackedUp,
    ))) {
      return passkeyError("verification_conflict", 409);
    }
    const session = await issueSession(env.SESSION_SECRET!, issuer);
    const headers = new Headers();
    headers.append("set-cookie", cookie(SESSION_COOKIE, session, SESSION_TTL_SECONDS, "Lax"));
    headers.append("set-cookie", passkeyChallengeCookie("", 0));
    await appendPresenceCookieForReturnTo(headers, env, issuer, challenge.return_to, store);
    return json({ ok: true, redirect: challenge.return_to }, { status: 200, noStore: true, headers });
  } catch {
    return passkeyError("verification_failed", 401);
  }
}

export async function handleOwnerLogout(request: Request, issuer: string): Promise<Response> {
  if (request.method !== "POST" || !sameOriginBrowserPost(request, issuer)) {
    return json({ error: "origin_not_allowed" }, { status: 403, noStore: true });
  }
  return new Response(null, {
    status: 303,
    headers: [
      ["location", "/login"],
      ["set-cookie", cookie(SESSION_COOKIE, "", 0, "Lax")],
      ["set-cookie", cookie(PRESENCE_COOKIE, "", 0, "Strict")],
      ["set-cookie", cookie(APPROVE_LIST_CSRF_COOKIE, "", 0, "Strict")],
      ["cache-control", "no-store, no-cache"],
    ],
  });
}

export function chatGptOAuthClientId(redirectUri: string): string | null {
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
      return null;
    }
    const match = /^\/connector\/oauth\/([A-Za-z0-9_-]{8,64})$/.exec(redirect.pathname);
    return match ? `client_chatgpt_${match[1]!.toLowerCase()}` : null;
  } catch {
    return null;
  }
}

export function chatGptOAuthPair(clientId: string, redirectUri: string): boolean {
  return chatGptOAuthClientId(redirectUri) === clientId;
}

export async function handleChatGptConnector(
  request: Request,
  store: ControlPlaneStore,
  issuer: string,
  principal: OwnerPrincipal,
): Promise<Response> {
  if (request.method === "GET") {
    const csrf = randomToken("csrf_");
    const page = authPage({
      title: "Manual ChatGPT fallback — OwnMesh",
      eyebrow: "Compatibility fallback",
      heading: "Register an older ChatGPT client",
      intro: "Current ChatGPT clients need only the MCP URL. Use this page only when automatic OAuth registration is unavailable.",
      body: `<dl class="meta"><dt>MCP endpoint</dt><dd><code>${escapeHtml(issuer)}/mcp</code></dd><dt>Client type</dt><dd>Public + PKCE S256</dd></dl><form class="stack" method="post" action="/connect/chatgpt"><input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}"><div><label for="callback">Exact ChatGPT callback URL</label><input id="callback" name="callback" type="url" placeholder="https://chatgpt.com/connector/oauth/..." maxlength="256" required autofocus></div><button class="primary wide" type="submit">Create fallback client</button></form>`,
      footer: "Manual fallback only",
    });
    const headers = new Headers(html(page, { noStore: true }).headers);
    headers.append("set-cookie", cookie(CSRF_COOKIE, csrf, 600, "Strict"));
    return new Response(page, { status: 200, headers });
  }
  if (request.method !== "POST") {
    return json({ error: "method_not_allowed" }, { status: 405, noStore: true });
  }
  if (!sameOriginBrowserPost(request, issuer)) {
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
  const clientId = chatGptOAuthClientId(callback);
  if (!clientId) {
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
  const page = authPage({
    title: "ChatGPT client ready — OwnMesh",
    eyebrow: "Compatibility fallback",
    heading: "OAuth client ready",
    intro: "Paste the public client ID into ChatGPT, then complete OwnMesh authorization.",
    body: `<dl class="meta"><dt>Client ID</dt><dd><code>${escapeHtml(clientId)}</code></dd><dt>MCP endpoint</dt><dd><code>${escapeHtml(issuer)}/mcp</code></dd><dt>Authentication</dt><dd>OAuth 2.1 / PKCE S256</dd></dl><p class="note">No client secret is used or generated.</p>`,
    footer: "Manual fallback only",
  });
  return html(page, { status: 201, noStore: true });
}
