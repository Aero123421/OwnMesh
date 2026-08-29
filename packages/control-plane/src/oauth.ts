/**
 * OAuth 2.1 authorization server endpoints for OwnMesh control plane.
 *
 * Spec anchors:
 * - OAuth 2.1 / PKCE S256
 * - RFC 8628 Device Authorization Grant
 * - RFC 8414 Authorization Server Metadata
 * - RFC 9728 OAuth Protected Resource Metadata
 * - redirect_uri exact match (OAuth 2.1)
 */

import type { ControlPlaneStore } from "./store.ts";
import {
  AUTH_PAGE_CSP,
  authLocale,
  authPage,
  authText,
  oauthConsentCsp,
  type AuthLocale,
} from "./auth-ui.ts";
import { chatGptOAuthClientId, chatGptOAuthPair } from "./owner-auth.ts";
import {
  ACCESS_TOKEN_TTL_MS,
  DEFAULT_TENANT,
  encodeDevicePublicKey,
  generateUserCode,
  randomId,
  randomToken,
  type DeviceRecord,
} from "./store.ts";
import {
  applyNoStore,
  bearer,
  BodyTooLargeError,
  DuplicateFormFieldError,
  html,
  json as jsonBase,
  nowIso,
  normalizeUserCode,
  readBody,
  readRequestJsonLimited,
  requireScope,
  pkceS256Challenge,
  validPkceVerifier,
  sha256Hex,
  UnsupportedMediaTypeError,
  verifyEd25519Hex,
  type JsonInit,
} from "./util.ts";

/** All OAuth/device JSON responses default to Cache-Control: no-store, no-cache. */
function json(data: unknown, init: JsonInit = {}): Response {
  return jsonBase(data, { ...init, noStore: true });
}

async function readOAuthBody(req: Request): Promise<Record<string, string> | Response> {
  try {
    return await readBody(req);
  } catch (error) {
    if (error instanceof BodyTooLargeError) {
      return json({ error: "invalid_request" }, { status: 413 });
    }
    if (error instanceof UnsupportedMediaTypeError) {
      return json({ error: "unsupported_media_type" }, { status: 415 });
    }
    if (error instanceof DuplicateFormFieldError || error instanceof SyntaxError) {
      return json({ error: "invalid_request" }, { status: 400 });
    }
    throw error;
  }
}

export type AuthenticatedPrincipal = { id: string; tenant_id: string; display_name?: string };
export type OAuthRequestSecurity = {
  principal?: AuthenticatedPrincipal;
  allowDevBypass?: boolean;
  allowDynamicRegistration?: boolean;
  /** Test seam for bounded CIMD retrieval; production always uses global fetch. */
  fetchClientMetadata?: typeof fetch;
};

// Request identity is the capability: only the Worker entrypoint that receives
// the original Request can establish its receipt timestamp. A caller cannot
// supply an arbitrary clock or timestamp to the authorize handler.
const authorizeRequestReceipts = new WeakMap<Request, number>();

/** Record an OAuth authorize GET's receipt before route-level async work. */
export function captureAuthorizeRequestReceipt(request: Request): void {
  authorizeRequestReceipts.set(request, Date.now());
}

const SUPPORTED_SCOPES = new Set([
  "ownmesh.read", "ownmesh.write", "ownmesh.exec", "ownmesh.session", "ownmesh.device", "offline_access",
]);
const DEFAULT_SCOPE = "ownmesh.read ownmesh.device";
const SCOPE_COPY: Record<string, string> = {
  "ownmesh.read": "Read device status and permitted workspace content.",
  "ownmesh.write": "Create or modify content inside permitted workspaces.",
  "ownmesh.exec": "Run commands allowed by the local device policy.",
  "ownmesh.session": "Open and control permitted interactive sessions.",
  "ownmesh.device": "Discover and address devices enrolled in this instance.",
  offline_access: "Keep ChatGPT connected using rotating refresh tokens.",
};
function scopeDescription(locale: AuthLocale, value: string): string {
  const fallback = authText(locale, {
    en: "Access requested by this OAuth client.",
    ja: "この OAuth クライアントが要求するアクセスです。",
    zh: "此 OAuth 客户端请求的访问权限。",
    ru: "Доступ, запрошенный этим OAuth-клиентом.",
  });
  const en = SCOPE_COPY[value];
  if (!en) return fallback;
  const translated: Record<string, { ja: string; zh: string; ru: string }> = {
    "ownmesh.read": {
      ja: "許可されたワークスペースの内容とデバイス状態を読み取ります。",
      zh: "读取设备状态和已允许工作区的内容。",
      ru: "Чтение состояния устройств и разрешённого содержимого рабочих областей.",
    },
    "ownmesh.write": {
      ja: "許可されたワークスペース内で内容を作成・変更します。",
      zh: "在已允许的工作区内创建或修改内容。",
      ru: "Создание и изменение данных в разрешённых рабочих областях.",
    },
    "ownmesh.exec": {
      ja: "ローカルデバイスポリシーが許可したコマンドを実行します。",
      zh: "运行本地设备策略允许的命令。",
      ru: "Запуск команд, разрешённых локальной политикой устройства.",
    },
    "ownmesh.session": {
      ja: "許可された対話セッションを開いて操作します。",
      zh: "打开并控制允许的交互式会话。",
      ru: "Открытие и управление разрешёнными интерактивными сеансами.",
    },
    "ownmesh.device": {
      ja: "この環境に登録されたデバイスを検出して指定します。",
      zh: "发现并寻址此实例中已注册的设备。",
      ru: "Обнаружение и выбор устройств, зарегистрированных в этом экземпляре.",
    },
    offline_access: {
      ja: "ローテーションする更新トークンで接続を維持します。",
      zh: "使用轮换刷新令牌保持连接。",
      ru: "Поддержание подключения с ротацией токенов обновления.",
    },
  };
  const copy = translated[value];
  return authText(locale, {
    en,
    ja: copy?.ja || fallback,
    zh: copy?.zh || fallback,
    ru: copy?.ru || fallback,
  });
}

function scopeRows(scope: string, locale: AuthLocale = "en-US"): string {
  return scope.split(/\s+/).filter(Boolean).map((value) =>
    `<div class="scope"><span class="scope-mark" aria-hidden="true"></span><span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(scopeDescription(locale, value))}</small></span></div>`
  ).join("");
}
function validScope(scope: string): boolean {
  const values = scope.split(/\s+/).filter(Boolean);
  return values.length > 0 && values.every((s) => SUPPORTED_SCOPES.has(s));
}

export function oauthMetadata(
  issuer: string,
  opts: { allowDynamicRegistration?: boolean } = {},
) {
  const meta: Record<string, unknown> = {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    device_authorization_endpoint: `${issuer}/oauth/device_authorization`,
    scopes_supported: [
      "ownmesh.read",
      "ownmesh.write",
      "ownmesh.exec",
      "ownmesh.session",
      "ownmesh.device",
      "offline_access",
    ],
    response_types_supported: ["code"],
    grant_types_supported: [
      "authorization_code",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:device_code",
    ],
    code_challenge_methods_supported: ["S256"],
    // Public clients + PKCE only. client_secret_post is neither advertised nor accepted.
    token_endpoint_auth_methods_supported: ["none"],
    client_id_metadata_document_supported: true,
    authorization_response_iss_parameter_supported: true,
  };
  // Only advertise DCR when the operator explicitly enables it. Production
  // defaults keep registration_disabled so ChatGPT setup must use a pre-provisioned
  // public client (or flip ALLOW_DYNAMIC_CLIENT_REGISTRATION=true).
  if (opts.allowDynamicRegistration) {
    meta.registration_endpoint = `${issuer}/oauth/register`;
  }
  return meta;
}

export function protectedResourceMetadata(resource: string, authorizationServer = resource) {
  return {
    resource,
    authorization_servers: [authorizationServer],
    scopes_supported: [
      "ownmesh.read",
      "ownmesh.write",
      "ownmesh.exec",
      "ownmesh.session",
      "ownmesh.device",
    ],
    bearer_methods_supported: ["header"],
  };
}

/** Loopback hosts allowed for http:// redirect_uris (RFC 8252 §7.3). */
function isLoopbackRedirectHost(hostname: string): boolean {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

/**
 * DCR redirect_uri policy: https:// anywhere, or http:// only on loopback
 * (127.0.0.1 / ::1 / localhost). Custom schemes and remote http are rejected.
 */
export function isAllowedDcrRedirectUri(uri: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(uri);
  } catch {
    return false;
  }
  if (parsed.username || parsed.password || parsed.hash) return false;
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol === "http:" && isLoopbackRedirectHost(parsed.hostname)) return true;
  return false;
}

const CIMD_MAX_BYTES = 16 * 1024;
const CIMD_TIMEOUT_MS = 3_000;

type ClientMetadataDocument = {
  client_id: string;
  client_name: string;
  redirect_uris: string[];
  token_endpoint_auth_method?: string;
  grant_types?: string[];
  response_types?: string[];
};

/** URL-form client identifiers allowed to trigger a bounded metadata fetch. */
export function isAllowedCimdClientId(clientId: string): boolean {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash || url.pathname === "/") {
    return false;
  }
  if (url.port && url.port !== "443") return false;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    isLoopbackRedirectHost(host)
    || host.endsWith(".localhost")
    || host.endsWith(".local")
    || host === "0.0.0.0"
    || host === "::"
  ) return false;
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (ipv4) {
    const octets = ipv4.slice(1).map(Number);
    if (octets.some((part) => part > 255)) return false;
    const [a, b] = octets;
    if (
      a === 0 || a === 10 || a === 127 || a! >= 224
      || (a === 100 && b! >= 64 && b! <= 127)
      || (a === 169 && b === 254)
      || (a === 172 && b! >= 16 && b! <= 31)
      || (a === 192 && (b === 0 || b === 2 || b === 168))
      || (a === 198 && (b === 18 || b === 19 || b === 51))
      || (a === 203 && b === 0 && octets[2] === 113)
    ) return false;
  }
  if (host.includes(":")) {
    // Literal IPv6 client IDs are unnecessary for current interoperability;
    // refusing all avoids loopback/link-local/ULA parser ambiguity and DNS
    // rebinding through alternate textual forms.
    return false;
  }
  return true;
}

async function readBoundedClientMetadata(response: Response): Promise<unknown> {
  const declared = Number(response.headers.get("content-length") || "0");
  if (Number.isFinite(declared) && declared > CIMD_MAX_BYTES) throw new Error("metadata_too_large");
  if (!response.body) throw new Error("metadata_body_missing");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > CIMD_MAX_BYTES) throw new Error("metadata_too_large");
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
}

async function fetchClientMetadataDocument(
  clientId: string,
  fetcher: typeof fetch,
): Promise<ClientMetadataDocument> {
  if (!isAllowedCimdClientId(clientId)) throw new Error("invalid_client_id_metadata_url");
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CIMD_TIMEOUT_MS);
  let raw: unknown;
  try {
    const response = await fetcher(clientId, {
      method: "GET",
      redirect: "error",
      signal: controller.signal,
      headers: { accept: "application/json" },
    });
    if (!response.ok || !(response.headers.get("content-type") || "").toLowerCase().includes("application/json")) {
      throw new Error("client_metadata_unavailable");
    }
    raw = await readBoundedClientMetadata(response);
  } finally {
    clearTimeout(timeout);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("invalid_client_metadata");
  const document = raw as Partial<ClientMetadataDocument>;
  if (
    document.client_id !== clientId
    || typeof document.client_name !== "string"
    || document.client_name.length < 1
    || document.client_name.length > 256
    || !Array.isArray(document.redirect_uris)
    || document.redirect_uris.length < 1
    || document.redirect_uris.length > 8
    || document.redirect_uris.some((uri) => typeof uri !== "string" || !isAllowedDcrRedirectUri(uri))
    || document.token_endpoint_auth_method !== "none"
    || (document.response_types !== undefined && (!Array.isArray(document.response_types) || document.response_types.some((value) => value !== "code")))
    || (document.grant_types !== undefined && (!Array.isArray(document.grant_types) || document.grant_types.some((value) => value !== "authorization_code" && value !== "refresh_token")))
  ) throw new Error("invalid_client_metadata");
  return document as ClientMetadataDocument;
}

/**
 * RFC 7591 Dynamic Client Registration.
 *
 * Security contract:
 * - Disabled unless allowDynamicRegistration is explicitly true (flag).
 * - Exact ChatGPT public callbacks register statelessly; tenant binding occurs
 *   only after owner authentication at /oauth/authorize.
 * - Every other registration requires a Bearer token with ownmesh.device and
 *   binds to that token's tenant_id (never implicit DEFAULT_TENANT).
 * - redirect_uris must be https:// or loopback http:// only.
 */
export async function handleRegister(
  req: Request,
  store: ControlPlaneStore,
  security: OAuthRequestSecurity = {},
): Promise<Response> {
  if (!security.allowDynamicRegistration) {
    return json({ error: "registration_disabled" }, { status: 403 });
  }

  let body: {
    client_name?: string;
    redirect_uris?: string[];
    token_endpoint_auth_method?: string;
    grant_types?: string[];
    response_types?: string[];
    application_type?: "native" | "web";
  };
  try {
    body = await readRequestJsonLimited(req, 16 * 1024);
  } catch (error) {
    if (error instanceof BodyTooLargeError) {
      return json({ error: "invalid_client_metadata", error_description: "registration request too large" }, { status: 413 });
    }
    return json({ error: "invalid_client_metadata", error_description: "invalid JSON" }, { status: 400 });
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    return json({ error: "invalid_client_metadata", error_description: "JSON object required" }, { status: 400 });
  }
  // Only public clients (auth method "none") are supported. Reject client_secret_*.
  const authMethod = body.token_endpoint_auth_method || "none";
  if (authMethod !== "none") {
    return json(
      {
        error: "invalid_client_metadata",
        error_description:
          "only token_endpoint_auth_method=none (public client + PKCE) is supported",
      },
      { status: 400 },
    );
  }
  const redirectUris = body.redirect_uris || [];
  if (!Array.isArray(redirectUris) || redirectUris.length < 1 || redirectUris.length > 8) {
    return json({ error: "invalid_client_metadata", error_description: "redirect_uris must contain 1 to 8 entries" }, { status: 400 });
  }
  for (const u of redirectUris) {
    if (typeof u !== "string" || !isAllowedDcrRedirectUri(u)) {
      return json({ error: "invalid_redirect_uri", uri: u }, { status: 400 });
    }
  }
  if (body.application_type !== undefined && body.application_type !== "native" && body.application_type !== "web") {
    return json({ error: "invalid_client_metadata", error_description: "invalid application_type" }, { status: 400 });
  }
  if (body.application_type === "native" && redirectUris.some((uri) => new URL(uri).protocol !== "http:")) {
    return json({ error: "invalid_client_metadata", error_description: "native clients require loopback http redirect_uris" }, { status: 400 });
  }
  if (body.application_type === "web" && redirectUris.some((uri) => new URL(uri).protocol !== "https:")) {
    return json({ error: "invalid_client_metadata", error_description: "web clients require https redirect_uris" }, { status: 400 });
  }

  // ChatGPT discovers this endpoint from OAuth metadata before it has an
  // OwnMesh token. Permit only its exact public callback form. Registration is
  // stateless: the deterministic client id is bound to the signed-in owner's
  // tenant on /oauth/authorize, so anonymous requests cannot create D1 rows.
  const chatGptClientId = redirectUris.length === 1
    ? chatGptOAuthClientId(redirectUris[0]!)
    : null;
  if (chatGptClientId) {
    if (
      (body.response_types &&
        (!Array.isArray(body.response_types) || body.response_types.some((value) => value !== "code"))) ||
      (body.grant_types &&
        (!Array.isArray(body.grant_types) ||
          body.grant_types.some((value) => value !== "authorization_code" && value !== "refresh_token")))
    ) {
      return json({ error: "invalid_client_metadata", error_description: "unsupported OAuth flow" }, { status: 400 });
    }
    return json(
      {
        client_id: chatGptClientId,
        client_name: "ChatGPT",
        redirect_uris: redirectUris,
        token_endpoint_auth_method: "none",
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
      },
      { status: 201 },
    );
  }

  // General-purpose DCR remains tenant-authenticated and scope-gated.
  const token = bearer(req);
  if (!token) return json({ error: "unauthorized" }, { status: 401 });
  const rec = await store.getAccess(token);
  if (!rec) return json({ error: "invalid_token" }, { status: 401 });
  if (!requireScope(rec.scope, "ownmesh.device")) {
    return json({ error: "insufficient_scope" }, { status: 403 });
  }
  if (!rec.tenant_id) {
    return json({ error: "invalid_token", error_description: "missing tenant" }, { status: 401 });
  }
  const clientId = randomToken("client_").slice(0, 24);
  const clientName = body.client_name || "ownmesh-client";
  await store.ensureBootstrap();
  await store.putClient({
    client_id: clientId,
    tenant_id: rec.tenant_id,
    client_name: clientName,
    redirect_uris: redirectUris,
    created_at: nowIso(),
  });
  return json(
    {
      client_id: clientId,
      client_name: clientName,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: "none",
      grant_types: [
        "authorization_code",
        "refresh_token",
        "urn:ietf:params:oauth:grant-type:device_code",
      ],
      response_types: ["code"],
      client_id_metadata_document_supported: true,
      policy: {
        dynamic_client_registration: "supported",
        client_id_metadata_document: "preferred",
        redirect_uri_match: "exact",
      },
    },
    { status: 201 },
  );
}

export async function handleAuthorize(
  req: Request,
  store: ControlPlaneStore,
  issuer: string,
  security: OAuthRequestSecurity = {},
): Promise<Response> {
  // The Worker records GET receipt before form parsing/authentication. Direct
  // internal callers have no forged-clock seam and fall back to handler entry.
  const requestReceivedAt = authorizeRequestReceipts.get(req) ?? Date.now();
  authorizeRequestReceipts.delete(req);
  const url = new URL(req.url);
  const locale = authLocale(req);

  // POST consent decision first: consume one-time transaction and issue code
  // solely from the stored snapshot (ignore any resubmitted/altered OAuth params).
  // index.ts merges form fields into url.searchParams before calling us.
  if (req.method === "POST" && url.searchParams.has("decision")) {
    await store.ensureBootstrap();
    let postPrincipal = security.principal;
    if (!postPrincipal && security.allowDevBypass) {
      postPrincipal = { id: "prin_dev", tenant_id: DEFAULT_TENANT, display_name: "prin_dev" };
    }
    if (!postPrincipal) return json({ error: "authentication_required" }, { status: 401 });

    const decision = url.searchParams.get("decision") || "";
    const transactionId = url.searchParams.get("transaction_id") || "";
    const csrfToken = url.searchParams.get("csrf_token") || "";
    if (!transactionId || !csrfToken) {
      return json({ error: "invalid_request", error_description: "missing consent transaction" }, { status: 400 });
    }

    const tx = await store.consumeAuthorizeTransaction(
      transactionId,
      await sha256Hex(csrfToken),
      postPrincipal.id,
    );
    if (!tx || tx.tenant_id !== postPrincipal.tenant_id) {
      return json(
        { error: "invalid_request", error_description: "invalid, expired, or used transaction" },
        { status: 400 },
      );
    }

    // A consent transaction is a snapshot, but URL client metadata can change
    // during the human review. Re-fetch before either redirect so removal or
    // substitution after GET cannot turn a once-valid destination into an
    // unreviewed callback. The transaction is already consumed fail-closed.
    if (isAllowedCimdClientId(tx.client_id)) {
      try {
        const metadata = await fetchClientMetadataDocument(
          tx.client_id,
          security.fetchClientMetadata || fetch,
        );
        if (!metadata.redirect_uris.includes(tx.redirect_uri)) {
          return json(
            { error: "invalid_request", error_description: "redirect_uri no longer matches client metadata" },
            { status: 400 },
          );
        }
      } catch {
        return json(
          { error: "unauthorized_client", error_description: "client metadata revalidation failed" },
          { status: 401 },
        );
      }
    }

    if (decision !== "approve") {
      const dest = new URL(tx.redirect_uri);
      dest.searchParams.set("error", "access_denied");
      dest.searchParams.set("iss", issuer);
      if (tx.state) dest.searchParams.set("state", tx.state);
      return Response.redirect(dest.toString(), 302);
    }

    const code = randomToken("ac_");
    await store.putAuthCode({
      code,
      client_id: tx.client_id,
      principal_id: tx.principal_id,
      redirect_uri: tx.redirect_uri,
      scope: tx.scope,
      code_challenge: tx.code_challenge,
      code_challenge_method: tx.code_challenge_method,
      expires_at: Date.now() + 10 * 60 * 1000,
      used: false,
    });
    const dest = new URL(tx.redirect_uri);
    dest.searchParams.set("code", code);
    dest.searchParams.set("iss", issuer);
    if (tx.state) dest.searchParams.set("state", tx.state);
    return Response.redirect(dest.toString(), 302);
  }

  const redirect = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state") || "";
  const clientId = url.searchParams.get("client_id") || "";
  const scope = url.searchParams.get("scope") || DEFAULT_SCOPE;
  const challenge = url.searchParams.get("code_challenge") || "";
  const method = url.searchParams.get("code_challenge_method") || "S256";
  const responseType = url.searchParams.get("response_type") || "code";

  if (!redirect || !clientId) {
    return json({ error: "invalid_request" }, { status: 400 });
  }
  if (responseType !== "code") {
    return json({ error: "unsupported_response_type" }, { status: 400 });
  }
  if (!validScope(scope)) return json({ error: "invalid_scope" }, { status: 400 });
  if (method !== "S256" || !challenge) {
    return json(
      { error: "invalid_request", error_description: "PKCE S256 required" },
      { status: 400 },
    );
  }

  await store.ensureBootstrap();
  let client = await store.getClient(clientId);
  // For a known client, reject an altered redirect before authentication.
  if (client && !isAllowedCimdClientId(clientId) && !client.redirect_uris.includes(redirect)) {
    return json(
      {
        error: "invalid_request",
        error_description: "redirect_uri does not exactly match registration",
      },
      { status: 400 },
    );
  }

  let authenticated = security.principal;
  if (!authenticated && security.allowDevBypass) {
    const id = url.searchParams.get("login_hint") || "prin_dev";
    authenticated = { id, tenant_id: DEFAULT_TENANT, display_name: id };
  }
  if (!authenticated) return json({ error: "authentication_required" }, { status: 401 });
  // Fail closed for AUTH_PROVIDER (or any) principal whose tenant is not provisioned.
  // Prevents principals INSERT FK violation (500) on SqlStore/D1.
  if (!(await store.tenantExists(authenticated.tenant_id))) {
    return json(
      { error: "unknown_tenant", error_description: "tenant is not provisioned" },
      { status: 403 },
    );
  }
  // CIMD is fetched only after owner authentication and tenant validation, is
  // bounded/no-redirect/no-credential, and must bind its exact URL as client_id.
  // Re-fetch URL clients on authorization so metadata substitution or redirect
  // removal cannot be hidden behind a stale D1 registration.
  if (isAllowedCimdClientId(clientId)) {
    let metadata: ClientMetadataDocument;
    try {
      metadata = await fetchClientMetadataDocument(
        clientId,
        security.fetchClientMetadata || fetch,
      );
    } catch {
      return json(
        { error: "unauthorized_client", error_description: "client metadata validation failed" },
        { status: 401 },
      );
    }
    if (!metadata.redirect_uris.includes(redirect)) {
      return json(
        { error: "invalid_request", error_description: "redirect_uri does not exactly match client metadata" },
        { status: 400 },
      );
    }
    if (client && client.tenant_id !== authenticated.tenant_id) {
      return json({ error: "unauthorized_client" }, { status: 403 });
    }
    client = {
      client_id: clientId,
      tenant_id: authenticated.tenant_id,
      client_name: metadata.client_name,
      redirect_uris: metadata.redirect_uris,
      created_at: client?.created_at || nowIso(),
    };
    await store.putClient(client);
  }

  // ChatGPT provides a per-connector callback slug. A signed-in owner may bind
  // the matching deterministic client id on first use; anonymous auto-registration
  // remains impossible and every later redirect still requires exact match.
  if (!client && chatGptOAuthPair(clientId, redirect)) {
    client = {
      client_id: clientId,
      tenant_id: authenticated.tenant_id,
      client_name: "ChatGPT",
      redirect_uris: [redirect],
      created_at: nowIso(),
    };
    await store.putClient(client);
  }
  if (!client) {
    return json({ error: "unauthorized_client", error_description: "unknown client" }, { status: 401 });
  }

  // OAuth 2.1: redirect_uri MUST exactly match a pre-registered URI.
  if (!client.redirect_uris.includes(redirect)) {
    return json(
      {
        error: "invalid_request",
        error_description: "redirect_uri does not exactly match registration",
      },
      { status: 400 },
    );
  }
  if (authenticated.tenant_id !== client.tenant_id) return json({ error: "unauthorized_client" }, { status: 403 });
  const principal = authenticated.id;
  await store.ensurePrincipal(principal, authenticated.display_name || principal, "human", authenticated.tenant_id);

  // Dev-only auto-approve shortcut (auto=1 + allowDevBypass). Production never sets the flag.
  const devAuto = security.allowDevBypass && url.searchParams.get("auto") === "1";
  if (devAuto) {
    const code = randomToken("ac_");
    await store.putAuthCode({
      code,
      client_id: clientId,
      principal_id: principal,
      redirect_uri: redirect,
      scope,
      code_challenge: challenge,
      code_challenge_method: method,
      expires_at: Date.now() + 10 * 60 * 1000,
      used: false,
    });
    const dest = new URL(redirect);
    dest.searchParams.set("code", code);
    dest.searchParams.set("iss", issuer);
    if (state) dest.searchParams.set("state", state);
    return Response.redirect(dest.toString(), 302);
  }

  // Consent GET: issue a short-lived one-time transaction bound to the full snapshot.
  const transactionId = randomId("atz_");
  const csrf = randomToken("csrf_");
  const txTtlMs = 5 * 60 * 1000;
  // Anchor expiry at request receipt so validation, hashing, and persistence
  // cannot extend the externally promised five-minute consent window.
  const transactionIssuedAt = requestReceivedAt;
  await store.putAuthorizeTransaction({
    id: transactionId,
    csrf_hash: await sha256Hex(csrf),
    principal_id: principal,
    tenant_id: authenticated.tenant_id,
    client_id: clientId,
    redirect_uri: redirect,
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: method,
    expires_at: transactionIssuedAt + txTtlMs,
    consumed: false,
  });

  const page = authPage({
    locale,
    title: authText(locale, {
      en: "Authorize ChatGPT — OwnMesh",
      ja: "ChatGPT を認証 — OwnMesh",
      zh: "授权 ChatGPT — OwnMesh",
      ru: "Авторизация ChatGPT — OwnMesh",
    }),
    eyebrow: authText(locale, {
      en: "OAuth authorization",
      ja: "OAuth 認証",
      zh: "OAuth 授权",
      ru: "Авторизация OAuth",
    }),
    heading: authText(locale, {
      en: `Connect ${client.client_name || clientId}`,
      ja: `${client.client_name || clientId} を接続`,
      zh: `连接 ${client.client_name || clientId}`,
      ru: `Подключить ${client.client_name || clientId}`,
    }),
    intro: authText(locale, {
      en: "Review the capabilities ChatGPT is requesting from this self-hosted OwnMesh instance.",
      ja: "ChatGPT がこのセルフホスト OwnMesh に要求している権限を確認してください。",
      zh: "请检查 ChatGPT 向此自托管 OwnMesh 实例请求的权限。",
      ru: "Проверьте права, которые ChatGPT запрашивает у этого экземпляра OwnMesh.",
    }),
    body: `<dl class="meta"><dt>${authText(locale, { en: "Client", ja: "クライアント", zh: "客户端", ru: "Клиент" })}</dt><dd>${escapeHtml(client.client_name || clientId)}</dd><dt>${authText(locale, { en: "Returns to", ja: "戻り先", zh: "返回到", ru: "Возврат" })}</dt><dd><code>${escapeHtml(new URL(redirect).host)}</code></dd><dt>${authText(locale, { en: "Protocol", ja: "プロトコル", zh: "协议", ru: "Протокол" })}</dt><dd>OAuth 2.1 / PKCE S256</dd></dl><div class="scope-list">${scopeRows(scope, locale)}</div><p class="note">${authText(locale, { en: "Your device policy remains the final authority. ChatGPT cannot bypass local workspace, command, or approval rules.", ja: "最終権限は常にデバイス側のポリシーです。ChatGPT はローカルのワークスペース、コマンド、承認ルールを迂回できません。", zh: "设备策略始终拥有最终权限。ChatGPT 无法绕过本地工作区、命令或审批规则。", ru: "Политика устройства остаётся окончательным источником прав. ChatGPT не может обойти локальные правила рабочих областей, команд или подтверждений." })}</p><form method="post" action="/oauth/authorize"><input type="hidden" name="transaction_id" value="${escapeHtml(transactionId)}"><input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}"><div class="actions"><button class="primary" name="decision" value="approve" type="submit">${authText(locale, { en: "Authorize connection", ja: "接続を許可", zh: "授权连接", ru: "Разрешить подключение" })}</button><button class="danger" name="decision" value="deny" type="submit">${authText(locale, { en: "Deny", ja: "拒否", zh: "拒绝", ru: "Отклонить" })}</button></div></form>`,
    footer: authText(locale, {
      en: "One-time consent / 5 minute expiry",
      ja: "一度限りの同意 / 5分で期限切れ",
      zh: "一次性同意 / 5 分钟后过期",
      ru: "Одноразовое согласие / срок 5 минут",
    }),
  });
  return html(page, {
    status: 200,
    noStore: true,
    headers: { "content-security-policy": oauthConsentCsp(redirect) },
  });
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

export async function handleToken(
  req: Request,
  store: ControlPlaneStore,
): Promise<Response> {
  const parsedBody = await readOAuthBody(req);
  if (parsedBody instanceof Response) return parsedBody;
  const body = parsedBody;
  const grant = body.grant_type;
  await store.ensureBootstrap();

  // Reject confidential-client auth. We only support public clients + PKCE (none).
  // Presence of client_secret (including empty string) is client_secret_post — fail closed.
  // HTTP Basic is client_secret_basic — reject the Authorization scheme entirely.
  const authorization = req.headers.get("authorization");
  if (authorization != null && /^Basic\s+/i.test(authorization.trim())) {
    return json(
      {
        error: "invalid_client",
        error_description: "client_secret_basic is not supported; use public client + PKCE",
      },
      { status: 401 },
    );
  }
  if (body.client_secret != null) {
    return json(
      {
        error: "invalid_client",
        error_description: "client_secret_post is not supported; use public client + PKCE",
      },
      { status: 401 },
    );
  }
  const tokenAuthMethod = body.token_endpoint_auth_method;
  if (
    tokenAuthMethod != null &&
    String(tokenAuthMethod).length > 0 &&
    String(tokenAuthMethod) !== "none"
  ) {
    return json(
      {
        error: "invalid_client",
        error_description: "only token_endpoint_auth_method=none is supported",
      },
      { status: 401 },
    );
  }

  if (grant === "authorization_code") {
    // Keep all code/binding failures indistinguishable and, critically, do not
    // consume the code until the complete public-client binding matches.
    if (
      !body.code || !body.client_id || !body.redirect_uri || !body.code_verifier ||
      !validPkceVerifier(body.code_verifier)
    ) {
      return json({ error: "invalid_grant" }, { status: 400 });
    }
    const redemption = await store.redeemAuthCode({
      code: body.code,
      clientId: body.client_id,
      redirectUri: body.redirect_uri,
      codeChallenge: await pkceS256Challenge(body.code_verifier),
    });
    if (redemption.status !== "redeemed") {
      return json({ error: "invalid_grant" }, { status: 400 });
    }
    const auth = redemption.record;
    const tok = redemption.token;
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: tok.tenant_id,
      principal_id: auth.principal_id,
      kind: "oauth.token_issued",
      summary: "authorization_code exchange",
      created_at: nowIso(),
      meta: { client_id: auth.client_id, grant: "authorization_code" },
    });
    return json({
      access_token: tok.access_token,
      ...(requireScope(tok.scope, "offline_access") || chatGptOAuthPair(auth.client_id, auth.redirect_uri)
        ? { refresh_token: tok.refresh_token }
        : {}),
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_MS / 1000,
      scope: tok.scope,
    });
  }

  if (grant === "refresh_token") {
    const rt = body.refresh_token;
    if (!rt) return json({ error: "invalid_request" }, { status: 400 });
    const result = await store.rotateRefresh(rt);
    if (!result.ok) {
      return json(
        {
          error: "invalid_grant",
          error_description:
            result.error === "reuse"
              ? result.description || "refresh token reuse detected"
              : undefined,
        },
        { status: 400 },
      );
    }
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: result.token.tenant_id,
      principal_id: result.token.principal,
      kind: "oauth.refresh_rotated",
      summary: "refresh token rotated",
      created_at: nowIso(),
      meta: { family: result.token.refresh_family },
    });
    return json({
      access_token: result.token.access_token,
      refresh_token: result.token.refresh_token,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_MS / 1000,
      scope: result.token.scope,
    });
  }

  if (grant === "urn:ietf:params:oauth:grant-type:device_code") {
    const deviceCode = body.device_code;
    if (!deviceCode) return json({ error: "invalid_request" }, { status: 400 });
    const rec = await store.getDeviceCode(deviceCode);
    if (!rec) return json({ error: "invalid_grant" }, { status: 400 });
    if (rec.status === "expired") {
      return json({ error: "expired_token" }, { status: 400 });
    }
    if (rec.status === "denied") {
      return json({ error: "access_denied" }, { status: 400 });
    }
    if (rec.status === "pending") {
      await store.markDeviceCodePolled(deviceCode);
      // slow_down if polled too fast
      if (
        rec.last_polled_at &&
        Date.now() - rec.last_polled_at < rec.interval_sec * 1000
      ) {
        return json({ error: "slow_down", interval: rec.interval_sec + 5 }, {
          status: 400,
        });
      }
      return json({ error: "authorization_pending" }, { status: 400 });
    }
    // Atomic approved -> consumed transition prevents concurrent/replayed exchange.
    const requestedClient = body.client_id || "";
    if (!requestedClient || requestedClient !== rec.client_id) {
      return json({ error: "invalid_grant" }, { status: 400 });
    }
    const consumed = await store.consumeApprovedDeviceCode(deviceCode, requestedClient);
    if (!consumed) return json({ error: "invalid_grant" }, { status: 400 });
    const principal = consumed.principal_id!;
    const tok = await store.issueTokens(consumed.client_id, principal, consumed.scope);
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: tok.tenant_id,
      principal_id: principal,
      kind: "oauth.device_code_token",
      summary: "device_code exchanged",
      created_at: nowIso(),
    });
    return json({
      access_token: tok.access_token,
      ...(requireScope(tok.scope, "offline_access") ? { refresh_token: tok.refresh_token } : {}),
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_MS / 1000,
      scope: tok.scope,
    });
  }

  return json({ error: "unsupported_grant_type" }, { status: 400 });
}

export async function handleRevoke(
  req: Request,
  store: ControlPlaneStore,
): Promise<Response> {
  const parsedBody = await readOAuthBody(req);
  if (parsedBody instanceof Response) return parsedBody;
  const body = parsedBody;
  const token = body.token || "";
  if (token) {
    // RFC 7009: always 200. Audit only when the token matches a real issued record,
    // attributed to that token's tenant/principal (never a blanket DEFAULT_TENANT).
    const meta = await store.lookupRevocableToken(token);
    await store.revokeToken(token);
    if (meta) {
      await store.appendAudit({
        id: randomId("aud_"),
        tenant_id: meta.tenant_id,
        principal_id: meta.principal_id,
        kind: "oauth.revoke",
        summary: "token revoked",
        created_at: nowIso(),
        meta: { token_prefix: token.slice(0, 8), client_id: meta.client_id },
      });
    }
  }
  return new Response(null, { status: 200, headers: applyNoStore() });
}

/** RFC 8628 device authorization endpoint. */
export async function handleDeviceAuthorization(
  req: Request,
  store: ControlPlaneStore,
  issuer: string,
  userCodeGenerator: () => string = generateUserCode,
): Promise<Response> {
  const parsedBody = await readOAuthBody(req);
  if (parsedBody instanceof Response) return parsedBody;
  const body = parsedBody;
  const clientId = body.client_id || "";
  const scope = body.scope || DEFAULT_SCOPE;
  await store.ensureBootstrap();
  if (!clientId || !(await store.getClient(clientId))) {
    return json({ error: "unauthorized_client" }, { status: 401 });
  }
  if (!validScope(scope)) return json({ error: "invalid_scope" }, { status: 400 });

  const deviceCode = randomToken("dcode_");
  const verificationUri = `${issuer}/oauth/device`;
  const expiresIn = 900;
  let userCode = "";
  let created = false;
  for (let attempt = 0; attempt < 8; attempt++) {
    const candidate = normalizeUserCode(userCodeGenerator());
    if (!candidate) continue;
    const result = await store.putDeviceCode({
      device_code: deviceCode,
      user_code: candidate,
      client_id: clientId,
      scope,
      verification_uri: verificationUri,
      interval_sec: 5,
      expires_at: Date.now() + expiresIn * 1000,
      status: "pending",
    });
    if (result === "created") {
      userCode = candidate;
      created = true;
      break;
    }
  }
  if (!created) {
    return json({ error: "temporarily_unavailable" }, { status: 503 });
  }

  return json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: verificationUri,
    verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(userCode)}`,
    expires_in: expiresIn,
    interval: 5,
  });
}

/** Browser verification page + approve POST for device flow. */
export async function handleDeviceVerification(
  req: Request,
  store: ControlPlaneStore,
  security: OAuthRequestSecurity = {},
): Promise<Response> {
  await store.ensureBootstrap();
  const locale = authLocale(req);
  let principal = security.principal;
  if (!principal && security.allowDevBypass) principal = { id: "prin_dev", tenant_id: DEFAULT_TENANT };
  if (!principal) return json({ error: "authentication_required" }, { status: 401 });
  // Fail closed before principals INSERT when AUTH_PROVIDER tenant is unknown.
  if (!(await store.tenantExists(principal.tenant_id))) {
    return json(
      { error: "unknown_tenant", error_description: "tenant is not provisioned" },
      { status: 403 },
    );
  }
  await store.ensurePrincipal(principal.id, principal.display_name || principal.id, "human", principal.tenant_id);

  if (req.method === "GET") {
    const url = new URL(req.url);
    const rawUserCode = url.searchParams.get("user_code") || "";
    if (!rawUserCode.trim()) {
      return html(authPage({
        locale,
        title: authText(locale, { en: "Device sign in — OwnMesh", ja: "デバイスのサインイン — OwnMesh", zh: "设备登录 — OwnMesh", ru: "Вход устройства — OwnMesh" }),
        eyebrow: authText(locale, { en: "Device authorization", ja: "デバイス認証", zh: "设备授权", ru: "Авторизация устройства" }),
        heading: authText(locale, { en: "Enter the code from your terminal", ja: "端末に表示されたコードを入力", zh: "输入终端中显示的代码", ru: "Введите код из терминала" }),
        intro: authText(locale, { en: "Use this page when OwnMesh is running on a server without a local browser.", ja: "ローカルブラウザのないサーバーで OwnMesh を使うときの認証ページです。", zh: "当 OwnMesh 运行在没有本地浏览器的服务器上时，请使用此页面。", ru: "Используйте эту страницу, когда OwnMesh работает на сервере без локального браузера." }),
        body: `<form class="stack" method="get" action="/oauth/device"><div><label for="user_code">${authText(locale, { en: "One-time device code", ja: "一度限りのデバイスコード", zh: "一次性设备代码", ru: "Одноразовый код устройства" })}</label><input id="user_code" name="user_code" autocomplete="one-time-code" required autofocus></div><button class="primary wide" type="submit">${authText(locale, { en: "Continue", ja: "続ける", zh: "继续", ru: "Продолжить" })}</button></form>`,
        footer: authText(locale, { en: "RFC 8628 device flow", ja: "RFC 8628 デバイスフロー", zh: "RFC 8628 设备流程", ru: "Поток устройства RFC 8628" }),
      }), {
        noStore: true,
        headers: { "content-security-policy": AUTH_PAGE_CSP },
      });
    }
    const userCode = normalizeUserCode(rawUserCode);
    if (!userCode) {
      return json(
        { error: "invalid_request", error_description: "malformed device code" },
        { status: 400 },
      );
    }
    const dc = await store.getDeviceCodeByUserCode(userCode);
    const client = dc ? await store.getClient(dc.client_id) : null;
    if (!dc || !client || client.tenant_id !== principal.tenant_id || dc.status !== "pending" || Date.now() > dc.expires_at) {
      return json({ error: "invalid_request", error_description: "unknown or expired code" }, { status: 400 });
    }
    const transactionId = randomId("dvt_");
    const csrf = randomToken("csrf_");
    await store.putDeviceVerificationTransaction({
      id: transactionId, csrf_hash: await sha256Hex(csrf), user_code: userCode,
      principal_id: principal.id, client_id: dc.client_id, scope: dc.scope,
      expires_at: Math.min(dc.expires_at, Date.now() + 5 * 60 * 1000), consumed: false,
    });
    const page = authPage({
      locale,
      title: authText(locale, { en: "Authorize device — OwnMesh", ja: "デバイスを認証 — OwnMesh", zh: "授权设备 — OwnMesh", ru: "Авторизация устройства — OwnMesh" }),
      eyebrow: authText(locale, { en: "Device authorization", ja: "デバイス認証", zh: "设备授权", ru: "Авторизация устройства" }),
      heading: authText(locale, { en: `Authorize ${client.client_name || dc.client_id}`, ja: `${client.client_name || dc.client_id} を認証`, zh: `授权 ${client.client_name || dc.client_id}`, ru: `Разрешить ${client.client_name || dc.client_id}` }),
      intro: authText(locale, { en: "Confirm the terminal or headless server that requested this one-time code.", ja: "この一度限りのコードを要求した端末またはヘッドレスサーバーを確認してください。", zh: "请确认请求此一次性代码的终端或无界面服务器。", ru: "Подтвердите терминал или сервер без интерфейса, запросивший этот одноразовый код." }),
      body: `<dl class="meta"><dt>${authText(locale, { en: "Client", ja: "クライアント", zh: "客户端", ru: "Клиент" })}</dt><dd>${escapeHtml(client.client_name || dc.client_id)}</dd><dt>${authText(locale, { en: "User code", ja: "ユーザーコード", zh: "用户代码", ru: "Код пользователя" })}</dt><dd><code>${escapeHtml(userCode)}</code></dd><dt>${authText(locale, { en: "Expires", ja: "有効期限", zh: "过期时间", ru: "Истекает" })}</dt><dd>${escapeHtml(new Date(dc.expires_at).toISOString())}</dd></dl><div class="scope-list">${scopeRows(dc.scope, locale)}</div><form method="post" action="/oauth/device"><input type="hidden" name="transaction_id" value="${escapeHtml(transactionId)}"><input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}"><div class="actions"><button class="primary" name="decision" value="approve" type="submit">${authText(locale, { en: "Authorize device", ja: "デバイスを許可", zh: "授权设备", ru: "Разрешить устройство" })}</button><button class="danger" name="decision" value="deny" type="submit">${authText(locale, { en: "Deny", ja: "拒否", zh: "拒绝", ru: "Отклонить" })}</button></div></form>`,
      footer: authText(locale, { en: "One-time device authorization", ja: "一度限りのデバイス認証", zh: "一次性设备授权", ru: "Одноразовая авторизация устройства" }),
    });
    return html(page, {
      noStore: true,
      headers: { "content-security-policy": AUTH_PAGE_CSP },
    });
  }
  if (req.method === "POST") {
    const parsedBody = await readOAuthBody(req);
    if (parsedBody instanceof Response) return parsedBody;
    const body = parsedBody;
    if ((body.decision !== "approve" && body.decision !== "deny") || !body.transaction_id || !body.csrf_token) {
      return json({ error: "invalid_request" }, { status: 400 });
    }
    const tx = await store.consumeDeviceVerificationTransaction(
      body.transaction_id, await sha256Hex(body.csrf_token), principal.id, body.decision,
    );
    if (!tx) return json({ error: "invalid_request", error_description: "invalid, expired, or used transaction" }, { status: 400 });
    const approved = body.decision === "approve";
    return html(authPage({
      locale,
      title: approved
        ? authText(locale, { en: "Device authorized — OwnMesh", ja: "デバイスを許可しました — OwnMesh", zh: "设备已授权 — OwnMesh", ru: "Устройство разрешено — OwnMesh" })
        : authText(locale, { en: "Device denied — OwnMesh", ja: "デバイスを拒否しました — OwnMesh", zh: "设备已拒绝 — OwnMesh", ru: "Устройство отклонено — OwnMesh" }),
      eyebrow: authText(locale, { en: "Device authorization", ja: "デバイス認証", zh: "设备授权", ru: "Авторизация устройства" }),
      heading: approved
        ? authText(locale, { en: "Device authorized", ja: "デバイスを許可しました", zh: "设备已授权", ru: "Устройство разрешено" })
        : authText(locale, { en: "Device denied", ja: "デバイスを拒否しました", zh: "设备已拒绝", ru: "Устройство отклонено" }),
      intro: approved
        ? authText(locale, { en: "Return to the terminal. It can now complete the token exchange.", ja: "端末に戻ってください。トークン交換を完了できます。", zh: "请返回终端。现在可以完成令牌交换。", ru: "Вернитесь в терминал. Теперь он может завершить обмен токенов." })
        : authText(locale, { en: "Return to the terminal. The request was denied and no token will be issued.", ja: "端末に戻ってください。この要求は拒否され、トークンは発行されません。", zh: "请返回终端。请求已被拒绝，不会颁发令牌。", ru: "Вернитесь в терминал. Запрос отклонён, токен выдан не будет." }),
      body: `<p class="note">${authText(locale, { en: "This one-time decision has been consumed and cannot be replayed.", ja: "この一度限りの判断は消費済みで、再利用できません。", zh: "此一次性决定已使用，无法重放。", ru: "Это одноразовое решение уже использовано и не может быть повторено." })}</p>`,
      footer: authText(locale, { en: "You can close this tab", ja: "このタブを閉じられます", zh: "可以关闭此标签页", ru: "Эту вкладку можно закрыть" }),
    }), {
      noStore: true,
      headers: { "content-security-policy": AUTH_PAGE_CSP },
    });
  }
  return json({ error: "method_not_allowed" }, { status: 405 });
}

// ---------------------------------------------------------------------------
// Device registry + enrollment (server contract for cli-auth-09)
// ---------------------------------------------------------------------------

const DEVICE_METADATA_BODY_MAX_BYTES = 4 * 1024;
const DEVICE_NAME_MAX_BYTES = 128;
const DEVICE_LABEL_MAX_BYTES = 64;
const DEVICE_LABELS_MAX = 16;
const UNICODE_CONTROL = /\p{Cc}/u;

function normalizeDeviceName(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    UNICODE_CONTROL.test(normalized) ||
    new TextEncoder().encode(normalized).byteLength > DEVICE_NAME_MAX_BYTES
  ) {
    return null;
  }
  return normalized;
}

/** Stable first-occurrence dedupe; labels remain non-authoritative metadata. */
function normalizeDeviceLabels(value: unknown): string[] | null {
  if (!Array.isArray(value) || value.length > DEVICE_LABELS_MAX) return null;
  const labels: string[] = [];
  const seen = new Set<string>();
  for (const raw of value) {
    if (typeof raw !== "string") return null;
    const label = raw.trim();
    if (
      label.length === 0 ||
      UNICODE_CONTROL.test(label) ||
      new TextEncoder().encode(label).byteLength > DEVICE_LABEL_MAX_BYTES
    ) {
      return null;
    }
    if (!seen.has(label)) {
      seen.add(label);
      labels.push(label);
    }
  }
  return labels;
}

/**
 * Enrollment API contract (cli-auth-09 implements CLI side):
 *
 * POST /v1/devices/enroll
 *   Authorization: Bearer <human access token with ownmesh.device>
 *   Body: {
 *     name, hostname, os, arch, agent_version,
 *     protocol_version: "ownmesh.device/1.0",
 *     public_key: "<ed25519 hex>",
 *     labels?: string[]
 *   }
 *   201: {
 *     device_id: "dev_...",
 *     enrollment_token: "enr_...",  // short-lived; may equal access for 1.0.1
 *     expires_in: 300,
 *     challenge: {
 *       id: "ech_...",
 *       nonce: "...",
 *       message: "ownmesh-device-challenge:<nonce>:<device_id>",
 *       expires_at: ISO-8601
 *     },
 *     connect_path: "/agent/connect"
 *   }
 *
 * POST /v1/devices/enroll/proof
 *   Authorization: Bearer <human or enrollment token>
 *   Body: { device_id, challenge_id, signature: "<hex ed25519 sig over challenge.message>" }
 *   200: { ok: true, device: {...}, status: "active" }
 *
 * GET  /v1/devices
 * DELETE /v1/devices?id=dev_...   (revoke)
 * POST /v1/devices/revoke         Body: { id }
 *
 * Agent WebSocket:
 * GET /agent/connect?device_id=dev_...  Upgrade: websocket
 * Handshake (spec §21.2) over WS JSON envelopes (ownmesh.device/1.0).
 */
export async function handleDevices(
  req: Request,
  store: ControlPlaneStore,
  url: URL,
  options?: {
    /** Presence is a best-effort live DeviceRoom observation, not enrollment state. */
    presenceForDevice?: (device: DeviceRecord) => Promise<"online" | "offline" | "unknown">;
  },
): Promise<Response> {
  const token = bearer(req);
  if (!token) return json({ error: "unauthorized" }, { status: 401 });
  const rec = await store.getAccess(token);
  if (!rec) return json({ error: "invalid_token" }, { status: 401 });
  if (!requireScope(rec.scope, "ownmesh.device")) {
    return json({ error: "insufficient_scope" }, { status: 403 });
  }

  const metadataPath = /^\/v1\/devices\/([A-Za-z0-9_-]{1,128})$/.exec(url.pathname);
  if (metadataPath && req.method === "PATCH") {
    let body: unknown;
    try {
      body = await readRequestJsonLimited<unknown>(req, DEVICE_METADATA_BODY_MAX_BYTES);
    } catch (error) {
      if (error instanceof BodyTooLargeError) {
        return json({ error: "request_too_large" }, { status: 413 });
      }
      return json({ error: "invalid_request", field: "body" }, { status: 400 });
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({ error: "invalid_request", field: "body" }, { status: 400 });
    }
    const object = body as Record<string, unknown>;
    const keys = Object.keys(object);
    if (
      keys.length === 0 ||
      keys.some((key) => key !== "name" && key !== "labels")
    ) {
      return json({ error: "invalid_request", field: "body" }, { status: 400 });
    }

    const patch: { name?: string; labels?: string[] } = {};
    if (Object.prototype.hasOwnProperty.call(object, "name")) {
      const name = normalizeDeviceName(object.name);
      if (name === null) {
        return json({ error: "invalid_request", field: "name" }, { status: 400 });
      }
      patch.name = name;
    }
    if (Object.prototype.hasOwnProperty.call(object, "labels")) {
      const labels = normalizeDeviceLabels(object.labels);
      if (labels === null) {
        return json({ error: "invalid_request", field: "labels" }, { status: 400 });
      }
      patch.labels = labels;
    }

    const deviceId = metadataPath[1]!;
    const device = await store.updateDeviceMetadata(deviceId, rec.principal, patch);
    if (!device) return json({ error: "not_found" }, { status: 404 });
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: rec.tenant_id,
      principal_id: rec.principal,
      device_id: deviceId,
      kind: "device.metadata_updated",
      summary: "device display metadata updated",
      created_at: nowIso(),
      meta: {
        fields: Object.keys(patch).sort(),
        ...(patch.labels ? { label_count: patch.labels.length } : {}),
      },
    });
    return json({ ok: true, device });
  }

  if (url.pathname === "/v1/devices/enroll" && req.method === "POST") {
    if (!requireScope(rec.scope, "ownmesh.device")) {
      return json({ error: "insufficient_scope" }, { status: 403 });
    }
    const body = (await req.json()) as {
      name?: string;
      hostname?: string;
      os?: string;
      arch?: string;
      agent_version?: string;
      protocol_version?: string;
      public_key?: string;
      labels?: unknown;
    };
    if (!body.public_key || !/^[0-9a-fA-F]{64}$/.test(body.public_key)) {
      return json({ error: "invalid_request", field: "public_key" }, { status: 400 });
    }
    const deviceId = randomId("dev_");
    const created = nowIso();
    const name = normalizeDeviceName(body.name ?? body.hostname ?? deviceId);
    if (name === null) {
      return json({ error: "invalid_request", field: "name" }, { status: 400 });
    }
    const labels = body.labels === undefined ? [] : normalizeDeviceLabels(body.labels);
    if (labels === null) {
      return json({ error: "invalid_request", field: "labels" }, { status: 400 });
    }
    const device: DeviceRecord = {
      id: deviceId,
      tenant_id: rec.tenant_id,
      principal_id: rec.principal,
      name,
      labels,
      hostname: body.hostname || body.name || "unknown",
      os: body.os || "unknown",
      arch: body.arch || "unknown",
      agent_version: body.agent_version || "0",
      protocol_version: body.protocol_version || "ownmesh.device/1.0",
      public_key: body.public_key,
      revoked: false,
      created_at: created,
      status: "pending",
    };
    // Persist with metadata envelope for SQL store compatibility.
    const toStore: DeviceRecord = {
      ...device,
      public_key: encodeDevicePublicKey(body.public_key, device),
    };
    await store.putDevice(toStore);
    // Every daemon creates a device-local `ws_default`. Register its id under
    // this exact device at enrollment time so pre-ready and legacy Agents do
    // not inherit another device's same-named custody row. The root never
    // leaves the Agent, and the reservation stays pending until a generation
    // is observed.
    await store.putWorkspace({
      workspace_id: "ws_default",
      tenant_id: rec.tenant_id,
      device_id: deviceId,
      owner_principal_id: rec.principal,
      version: 1,
      active: false,
      created_at: created,
      updated_at: created,
    });
    const nonce = randomToken("n_").slice(0, 24);
    const challengeId = randomId("ech_");
    const message = `ownmesh-device-challenge:${nonce}:${deviceId}`;
    const expiresAt = nowIso(Date.now() + 5 * 60 * 1000);
    await store.putEnrollmentChallenge({
      id: challengeId,
      device_id: deviceId,
      nonce,
      message,
      expires_at: expiresAt,
      consumed: false,
    });
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: rec.tenant_id,
      principal_id: rec.principal,
      device_id: deviceId,
      kind: "device.enroll_started",
      summary: `enroll ${device.name}`,
      created_at: created,
    });
    // Short-lived enrollment token: issue scoped token.
    const enr = await store.issueTokens(
      rec.client_id,
      rec.principal,
      "ownmesh.device",
      undefined,
      5 * 60 * 1000,
    );
    return json(
      {
        device_id: deviceId,
        enrollment_token: enr.access_token,
        expires_in: 300,
        challenge: {
          id: challengeId,
          nonce,
          message,
          expires_at: expiresAt,
        },
        connect_path: "/agent/connect",
        device,
      },
      { status: 201 },
    );
  }

  if (url.pathname === "/v1/devices/enroll/proof" && req.method === "POST") {
    const body = (await req.json()) as {
      device_id?: string;
      challenge_id?: string;
      signature?: string;
    };
    if (!body.device_id || !body.challenge_id || !body.signature) {
      return json({ error: "invalid_request" }, { status: 400 });
    }
    const device = await store.getDevice(body.device_id);
    if (!device || device.principal_id !== rec.principal || device.tenant_id !== rec.tenant_id) {
      return json({ error: "not_found" }, { status: 404 });
    }
    if (device.revoked) return json({ error: "device_revoked" }, { status: 403 });
    const ch = await store.getEnrollmentChallenge(body.challenge_id);
    if (!ch || ch.device_id !== body.device_id) {
      return json({ error: "invalid_challenge" }, { status: 400 });
    }
    if (device.status !== "pending") return json({ error: "invalid_device_state" }, { status: 409 });
    if (!(await verifyEd25519Hex(device.public_key, ch.message, body.signature))) {
      return json({ error: "invalid_proof" }, { status: 400 });
    }
    const credential = await store.activateDeviceAndIssueCredential(body.device_id, body.challenge_id);
    if (!credential) return json({ error: "challenge_consumed_or_expired" }, { status: 400 });
    const activeDevice = await store.getDevice(body.device_id);
    if (!activeDevice) return json({ error: "not_found" }, { status: 404 });
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: rec.tenant_id,
      principal_id: rec.principal,
      device_id: body.device_id,
      kind: "device.enroll_proof",
      summary: "enrollment proof accepted",
      created_at: nowIso(),
      meta: { challenge_id: body.challenge_id },
    });
    return json({
      ok: true,
      status: "active",
      device: activeDevice,
      device_credential: credential.token,
      credential_expires_at: nowIso(credential.expires_at),
      connect_path: "/agent/connect",
    });
  }

  if (
    (url.pathname === "/v1/devices/revoke" && req.method === "POST") ||
    (url.pathname === "/v1/devices" && req.method === "DELETE")
  ) {
    let id = url.searchParams.get("id") || "";
    if (req.method === "POST") {
      const body = (await req.json().catch(() => ({}))) as { id?: string };
      id = body.id || id;
    }
    if (!id) return json({ error: "invalid_request" }, { status: 400 });
    const ok = await store.revokeDevice(id, rec.principal);
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: rec.tenant_id,
      principal_id: rec.principal,
      device_id: id,
      kind: "device.revoke",
      summary: ok ? "device revoked" : "device revoke failed",
      created_at: nowIso(),
    });
    return json({ ok });
  }

  if (url.pathname === "/v1/devices" && req.method === "GET") {
    const devices = await store.listDevices(rec.principal);
    const withPresence = options?.presenceForDevice
      ? await Promise.all(devices.map(async (device) => ({
        ...device,
        connection_status: await options.presenceForDevice!(device).catch(() => "unknown" as const),
      })))
      : devices;
    return json({ devices: withPresence });
  }

  // The legacy direct-create endpoint bypassed key proof and is intentionally
  // retired. Callers must use /enroll followed by /enroll/proof.
  if (url.pathname === "/v1/devices" && req.method === "POST") {
    return json({ error: "proof_required", enroll: "/v1/devices/enroll" }, { status: 410 });
  }

  return json({ error: "not_found", path: url.pathname }, { status: 404 });
}

export { requireScope, bearer };
