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
import { AUTH_PAGE_CSP, authPage, oauthConsentCsp } from "./auth-ui.ts";
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
  html,
  json as jsonBase,
  nowIso,
  readBody,
  readRequestJsonLimited,
  requireScope,
  verifyPkceS256,
  sha256Hex,
  verifyEd25519Hex,
  type JsonInit,
} from "./util.ts";

/** All OAuth/device JSON responses default to Cache-Control: no-store, no-cache. */
function json(data: unknown, init: JsonInit = {}): Response {
  return jsonBase(data, { ...init, noStore: true });
}

export type AuthenticatedPrincipal = { id: string; tenant_id: string; display_name?: string };
export type OAuthRequestSecurity = {
  principal?: AuthenticatedPrincipal;
  allowDevBypass?: boolean;
  allowDynamicRegistration?: boolean;
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
function scopeRows(scope: string): string {
  return scope.split(/\s+/).filter(Boolean).map((value) =>
    `<div class="scope"><span class="scope-mark" aria-hidden="true"></span><span><strong>${escapeHtml(value)}</strong><small>${escapeHtml(SCOPE_COPY[value] || "Access requested by this OAuth client.")}</small></span></div>`
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
  };
  // Only advertise DCR when the operator explicitly enables it. Production
  // defaults keep registration_disabled so ChatGPT setup must use a pre-provisioned
  // public client (or flip ALLOW_DYNAMIC_CLIENT_REGISTRATION=true).
  if (opts.allowDynamicRegistration) {
    meta.registration_endpoint = `${issuer}/oauth/register`;
  }
  return meta;
}

export function protectedResourceMetadata(resource: string) {
  return {
    resource,
    authorization_servers: [resource],
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
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol === "http:" && isLoopbackRedirectHost(parsed.hostname)) return true;
  return false;
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
      // CIMD (Client ID Metadata Document) policy: not required; DCR is supported.
      client_id_metadata_document_supported: false,
      policy: {
        dynamic_client_registration: "supported",
        client_id_metadata_document: "optional_future",
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
  void issuer;
  // The Worker records GET receipt before form parsing/authentication. Direct
  // internal callers have no forged-clock seam and fall back to handler entry.
  const requestReceivedAt = authorizeRequestReceipts.get(req) ?? Date.now();
  authorizeRequestReceipts.delete(req);
  const url = new URL(req.url);

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

    if (decision !== "approve") {
      const dest = new URL(tx.redirect_uri);
      dest.searchParams.set("error", "access_denied");
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
  if (client && !client.redirect_uris.includes(redirect)) {
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
    title: "Authorize ChatGPT — OwnMesh",
    eyebrow: "OAuth authorization",
    heading: `Connect ${client.client_name || clientId}`,
    intro: "Review the capabilities ChatGPT is requesting from this self-hosted OwnMesh instance.",
    body: `<dl class="meta"><dt>Client</dt><dd>${escapeHtml(client.client_name || clientId)}</dd><dt>Returns to</dt><dd><code>${escapeHtml(new URL(redirect).host)}</code></dd><dt>Protocol</dt><dd>OAuth 2.1 / PKCE S256</dd></dl><div class="scope-list">${scopeRows(scope)}</div><p class="note">Your device policy remains the final authority. ChatGPT cannot bypass local workspace, command, or approval rules.</p><form method="post" action="/oauth/authorize"><input type="hidden" name="transaction_id" value="${escapeHtml(transactionId)}"><input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}"><div class="actions"><button class="primary" name="decision" value="approve" type="submit">Authorize connection</button><button class="danger" name="decision" value="deny" type="submit">Deny</button></div></form>`,
    footer: "One-time consent / 5 minute expiry",
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
  const body = await readBody(req);
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
    if (!body.code || !body.code_verifier || !body.redirect_uri) {
      return json({ error: "invalid_request" }, { status: 400 });
    }
    const auth = await store.takeAuthCode(body.code);
    if (!auth) return json({ error: "invalid_grant" }, { status: 400 });
    if (auth.redirect_uri !== body.redirect_uri) {
      return json(
        {
          error: "invalid_grant",
          error_description: "redirect_uri mismatch",
        },
        { status: 400 },
      );
    }
    if (body.client_id && body.client_id !== auth.client_id) {
      return json({ error: "invalid_grant" }, { status: 400 });
    }
    const pkceOk = await verifyPkceS256(body.code_verifier, auth.code_challenge);
    if (!pkceOk) {
      return json(
        { error: "invalid_grant", error_description: "pkce verification failed" },
        { status: 400 },
      );
    }
    const tok = await store.issueTokens(
      auth.client_id,
      auth.principal_id,
      auth.scope,
    );
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
  const body = await readBody(req);
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
): Promise<Response> {
  const body = await readBody(req);
  const clientId = body.client_id || "";
  const scope = body.scope || DEFAULT_SCOPE;
  await store.ensureBootstrap();
  if (!clientId || !(await store.getClient(clientId))) {
    return json({ error: "unauthorized_client" }, { status: 401 });
  }
  if (!validScope(scope)) return json({ error: "invalid_scope" }, { status: 400 });

  const deviceCode = randomToken("dcode_");
  const userCode = generateUserCode();
  const verificationUri = `${issuer}/oauth/device`;
  const expiresIn = 900;
  await store.putDeviceCode({
    device_code: deviceCode,
    user_code: userCode,
    client_id: clientId,
    scope,
    verification_uri: verificationUri,
    interval_sec: 5,
    expires_at: Date.now() + expiresIn * 1000,
    status: "pending",
  });

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
    const userCode = (url.searchParams.get("user_code") || "").trim().toUpperCase();
    if (!userCode) {
      return html(authPage({
        title: "Device sign in — OwnMesh",
        eyebrow: "Device authorization",
        heading: "Enter the code from your terminal",
        intro: "Use this page when OwnMesh is running on a server without a local browser.",
        body: `<form class="stack" method="get" action="/oauth/device"><div><label for="user_code">One-time device code</label><input id="user_code" name="user_code" autocomplete="one-time-code" required autofocus></div><button class="primary wide" type="submit">Continue</button></form>`,
        footer: "RFC 8628 device flow",
      }), {
        noStore: true,
        headers: { "content-security-policy": AUTH_PAGE_CSP },
      });
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
      title: "Authorize device — OwnMesh",
      eyebrow: "Device authorization",
      heading: `Authorize ${client.client_name || dc.client_id}`,
      intro: "Confirm the terminal or headless server that requested this one-time code.",
      body: `<dl class="meta"><dt>Client</dt><dd>${escapeHtml(client.client_name || dc.client_id)}</dd><dt>User code</dt><dd><code>${escapeHtml(userCode)}</code></dd><dt>Expires</dt><dd>${escapeHtml(new Date(dc.expires_at).toISOString())}</dd></dl><div class="scope-list">${scopeRows(dc.scope)}</div><form method="post" action="/oauth/device"><input type="hidden" name="transaction_id" value="${escapeHtml(transactionId)}"><input type="hidden" name="csrf_token" value="${escapeHtml(csrf)}"><button class="primary wide" name="decision" value="approve" type="submit">Authorize device</button></form>`,
      footer: "One-time device authorization",
    });
    return html(page, {
      noStore: true,
      headers: { "content-security-policy": AUTH_PAGE_CSP },
    });
  }
  if (req.method === "POST") {
    const body = await readBody(req);
    if (body.decision !== "approve" || !body.transaction_id || !body.csrf_token) {
      return json({ error: "invalid_request" }, { status: 400 });
    }
    const tx = await store.consumeDeviceVerificationTransaction(
      body.transaction_id, await sha256Hex(body.csrf_token), principal.id,
    );
    if (!tx) return json({ error: "invalid_request", error_description: "invalid, expired, or used transaction" }, { status: 400 });
    return html(authPage({
      title: "Device authorized — OwnMesh",
      eyebrow: "Device authorization",
      heading: "Device authorized",
      intro: "Return to the terminal. It can now complete the token exchange.",
      body: `<p class="note">This one-time authorization has been consumed and cannot be replayed.</p>`,
      footer: "You can close this tab",
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
    return json({ devices });
  }

  // The legacy direct-create endpoint bypassed key proof and is intentionally
  // retired. Callers must use /enroll followed by /enroll/proof.
  if (url.pathname === "/v1/devices" && req.method === "POST") {
    return json({ error: "proof_required", enroll: "/v1/devices/enroll" }, { status: 410 });
  }

  return json({ error: "not_found", path: url.pathname }, { status: 404 });
}

export { requireScope, bearer };
