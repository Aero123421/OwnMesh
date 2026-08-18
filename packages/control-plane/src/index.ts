/**
 * OwnMesh control plane — Cloudflare Worker entrypoint.
 *
 * Provides health, OAuth 2.1 (+ device code), device registry/enrollment,
 * Streamable HTTP MCP, and Durable Object DeviceRoom (hibernation WS).
 *
 * Deployed to the user's own Cloudflare account — no vendor SaaS.
 *
 * References:
 * - D1 Binding API: https://developers.cloudflare.com/d1/worker-api/
 * - DO WebSocket hibernation:
 *   https://developers.cloudflare.com/durable-objects/best-practices/websockets/
 * - Deploy to Cloudflare button:
 *   https://developers.cloudflare.com/workers/platform/deploy-buttons/
 */

import {
  createStore,
  MemoryStore,
  MissingD1Error,
  type ControlPlaneStore,
  type DeviceRecord,
  type SchemaReadiness,
} from "./store.ts";
import {
  captureAuthorizeRequestReceipt,
  handleAuthorize,
  handleDeviceAuthorization,
  handleDeviceVerification,
  handleDevices,
  handleRegister,
  handleRevoke,
  handleToken,
  oauthMetadata,
  protectedResourceMetadata,
  type AuthenticatedPrincipal,
} from "./oauth.ts";
import { handleApprove, handleMcp, MCP_SYNC_WAIT_MS, MCP_TOOLS } from "./mcp.ts";
import { DeviceRoom } from "./device-room.ts";
import {
  handleChatGptConnector,
  handleOwnerLogin,
  handleOwnerLogout,
  handleOwnerPasskeyOptions,
  handleOwnerPasskeyRegistrationOptions,
  handleOwnerPasskeyRegistrationVerify,
  handleOwnerPasskeyVerify,
  ownerAuthConfigured,
  ownerLoginRedirect,
  ownerPresenceForOperation,
  ownerPresenceRedirect,
  ownerPasskeyScript,
  ownerPrincipalFromRequest,
  sameOriginBrowserPost,
} from "./owner-auth.ts";
import {
  TransferRoom,
  issueTransferTerminalControl,
  verifyTransferEphemeralProof,
  verifyTransferTicket,
} from "./transfer-room.ts";
import {
  internalContextHeaderName,
  internalDoHeaders,
  json,
  requireScope,
  SERVICE_NAME,
  SERVICE_VERSION,
  sha256Hex,
  signInternalContext,
} from "./util.ts";

export interface Env {
  DB?: D1Database;
  DEVICE_ROOM?: DurableObjectNamespace;
  TRANSFER_ROOM?: DurableObjectNamespace;
  OAUTH_ISSUER?: string;
  SESSION_SECRET?: string;
  OWNER_TOKEN_HASH?: string;
  AUTH_PROVIDER?: Fetcher;
  OWNMESH_DEV_AUTH_BYPASS?: string;
  ALLOW_DYNAMIC_CLIENT_REGISTRATION?: string;
  OWNMESH_ALLOWED_ORIGINS?: string;
  OWNMESH_DEVICE_ROUTE_TIMEOUT_MS?: string;
  MCP_OPS_MAX_PER_TENANT?: string;
  AUTH_RATE_LIMITER?: RateLimitBinding;
  MCP_RATE_LIMITER?: RateLimitBinding;
  AUTH_IP_RATE_LIMITER?: RateLimitBinding;
  MCP_IP_RATE_LIMITER?: RateLimitBinding;
}

type RateLimitBinding = {
  limit(options: { key: string }): Promise<{ success: boolean }>;
};

type RateLimitClass = "auth" | "mcp";

function rateLimitClass(pathname: string, method: string): RateLimitClass | null {
  if (pathname === "/mcp") return "mcp";
  if (method !== "POST") return null;
  if (
    pathname === "/login" ||
    pathname === "/logout" ||
    pathname === "/approve" ||
    pathname === "/oauth/register" ||
    pathname === "/oauth/authorize" ||
    pathname === "/oauth/token" ||
    pathname === "/oauth/revoke" ||
    pathname === "/oauth/device_authorization" ||
    pathname === "/oauth/device" ||
    pathname.startsWith("/auth/passkey/")
  ) {
    return "auth";
  }
  return null;
}

async function enforceRateLimit(
  request: Request,
  env: Env,
  issuer: string,
  pathname: string,
): Promise<Response | null> {
  if (devBypass(env, request)) return null;
  const category = rateLimitClass(pathname, request.method.toUpperCase());
  if (!category) return null;
  const credentialLimiter = category === "mcp" ? env.MCP_RATE_LIMITER : env.AUTH_RATE_LIMITER;
  const addressLimiter =
    category === "mcp" ? env.MCP_IP_RATE_LIMITER : env.AUTH_IP_RATE_LIMITER;

  const issuerHost = new URL(issuer).host;
  try {
    const address = request.headers.get("cf-connecting-ip") || "anonymous";
    const credential = request.headers.get("authorization") || request.headers.get("cookie");
    const checks: Array<{ limiter: RateLimitBinding; key: string }> = [];
    if (credential) {
      // Authenticated traffic gets a tight per-credential budget and a separate,
      // deliberately coarser address ceiling. Random credentials therefore
      // cannot bypass abuse protection, while ordinary unauthenticated traffic
      // cannot consume a valid credential's budget behind shared NAT egress.
      if (addressLimiter) {
        checks.push({
          limiter: addressLimiter,
          key: `${issuerHost}:${category}:addr:${await sha256Hex(address)}`,
        });
      }
      if (credentialLimiter) {
        checks.push({
          limiter: credentialLimiter,
          key: `${issuerHost}:${category}:cred:${await sha256Hex(credential)}`,
        });
      }
    } else if (credentialLimiter) {
      // Bootstrap traffic has no stable credential, so retain the tighter
      // address-keyed budget on the primary limiter.
      checks.push({
        limiter: credentialLimiter,
        key: `${issuerHost}:${category}:addr:${await sha256Hex(address)}`,
      });
    }
    if (checks.length === 0) return null;

    const results = await Promise.all(checks.map(({ limiter, key }) => limiter.limit({ key })));
    if (results.every((result) => result.success)) return null;
  } catch {
    // This is an abuse/cost guard, not an authorization boundary. Preserve
    // availability if Cloudflare's approximate counter is temporarily absent.
    return null;
  }
  return json(
    { error: "rate_limited", retry_after: 60 },
    {
      status: 429,
      noStore: true,
      headers: { "retry-after": "60" },
    },
  );
}

export { DeviceRoom, TransferRoom, MCP_TOOLS };
export type { ControlPlaneStore };

/** Optional injected store for unit tests (avoids global mutable singleton). */
let testStore: ControlPlaneStore | null = null;

/**
 * A readiness scan probes every required table, column, and index. Keep its
 * result briefly per D1 binding/store so operator checks cannot turn it into a
 * public D1 query multiplier. This caches no request data or secrets.
 */
const READINESS_CACHE_TTL_MS = 5_000;
type ReadinessCacheEntry = {
  checkedAt: number;
  value?: SchemaReadiness;
  pending?: Promise<SchemaReadiness>;
};
const readinessCache = new WeakMap<object, ReadinessCacheEntry>();

export function __setTestStore(store: ControlPlaneStore | null): void {
  testStore = store;
}

function storeFor(env: Env): ControlPlaneStore {
  if (testStore) return testStore;
  return createStore(env);
}

function readinessCacheKey(env: Env, store: ControlPlaneStore): object {
  // D1 bindings are isolate-scoped objects. In tests without D1, the injected
  // store is the stable identity. Neither key contains request-scoped state.
  return env.DB || store;
}

async function schemaReadinessFor(env: Env, store: ControlPlaneStore): Promise<SchemaReadiness> {
  const key = readinessCacheKey(env, store);
  const now = Date.now();
  let entry = readinessCache.get(key);
  if (entry?.value && now - entry.checkedAt < READINESS_CACHE_TTL_MS) {
    return entry.value;
  }
  if (entry?.pending) return entry.pending;

  entry ??= { checkedAt: 0 };
  const pending = store.schemaReadiness()
    .then((value) => {
      entry!.value = value;
      entry!.checkedAt = Date.now();
      return value;
    })
    .finally(() => {
      entry!.pending = undefined;
    });
  entry.pending = pending;
  readinessCache.set(key, entry);
  return pending;
}

function healthBase(env: Env) {
  return {
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    features: [
      "oauth",
      "oauth-device-code",
      "mcp",
      "devices",
      "device-room-hibernation",
      "d1",
      "no-central-telemetry",
      "no-r2-turn",
    ],
    durable_objects: Boolean(env.DEVICE_ROOM),
  };
}

function readinessBindings(env: Env) {
  return {
    sessionSecretBound: Boolean(env.SESSION_SECRET),
    browserAuthBound: Boolean(env.AUTH_PROVIDER) || ownerAuthConfigured(env),
  };
}

/** True for loopback hosts only (IPv4/IPv6 localhost names and literals). */
function isLoopbackHost(host: string): boolean {
  const h = host.trim().toLowerCase().replace(/^\[|\]$/g, "");
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

/**
 * Dev auth bypass is active only when ALL of:
 * - OWNMESH_DEV_AUTH_BYPASS === "true"
 * - request URL host is loopback
 * - OAUTH_ISSUER (or request origin) host is loopback
 * Remote host or remote issuer never enables bypass, even with the flag set.
 */
function devBypass(env: Env, request: Request): boolean {
  if (env.OWNMESH_DEV_AUTH_BYPASS !== "true") return false;
  let requestHost: string;
  try {
    requestHost = new URL(request.url).hostname;
  } catch {
    return false;
  }
  if (!isLoopbackHost(requestHost)) return false;
  const issuerRaw = env.OAUTH_ISSUER || new URL(request.url).origin;
  let issuerHost: string;
  try {
    issuerHost = new URL(issuerRaw).hostname;
  } catch {
    return false;
  }
  return isLoopbackHost(issuerHost);
}

async function browserPrincipal(request: Request, env: Env): Promise<AuthenticatedPrincipal | null> {
  return (await browserAuthentication(request, env)).principal;
}

type BrowserAuthentication = {
  principal: AuthenticatedPrincipal | null;
  fresh: boolean;
};

async function browserAuthentication(
  request: Request,
  env: Env,
  freshOperationId?: string,
): Promise<BrowserAuthentication> {
  if (devBypass(env, request)) {
    const url = new URL(request.url);
    const id = request.headers.get("x-ownmesh-dev-principal") || url.searchParams.get("login_hint") || "prin_dev";
    return { principal: { id, tenant_id: "ten_default", display_name: id }, fresh: true };
  }
  if (env.AUTH_PROVIDER) {
    const headers = new Headers({
      authorization: request.headers.get("authorization") || "",
      cookie: request.headers.get("cookie") || "",
      "x-ownmesh-request-url": request.url,
    });
    if (freshOperationId) {
      headers.set("x-ownmesh-auth-purpose", "approve");
      headers.set("x-ownmesh-operation-id", freshOperationId);
      headers.set("x-ownmesh-require-fresh", "true");
    }
    const response = await env.AUTH_PROVIDER.fetch(new Request("https://auth-provider/authenticate", {
      method: "POST",
      headers,
    }));
    if (response.ok) {
      const body = await response.json() as {
        principal_id?: string;
        tenant_id?: string;
        display_name?: string;
        fresh?: boolean;
      };
      if (body.principal_id && body.tenant_id) {
        return {
          principal: { id: body.principal_id, tenant_id: body.tenant_id, display_name: body.display_name },
          fresh: !freshOperationId || body.fresh === true,
        };
      }
    }
  }
  const issuer = env.OAUTH_ISSUER || new URL(request.url).origin;
  const owner = await ownerPrincipalFromRequest(request, env, issuer);
  if (!owner) return { principal: null, fresh: false };
  const fresh = freshOperationId
    ? await ownerPresenceForOperation(request, env, issuer, owner, freshOperationId)
    : true;
  return { principal: owner, fresh };
}

function originAllowed(request: Request, env: Env, issuer: string): boolean {
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const allowed = new Set([new URL(issuer).origin, ...(env.OWNMESH_ALLOWED_ORIGINS || "").split(",").map((v) => v.trim()).filter(Boolean)]);
  return allowed.has(origin);
}

async function routeToDeviceRoom(
  env: Env,
  deviceId: string,
  operation: {
    type: string;
    payload: Record<string, unknown>;
    correlation_id: string;
    expires_at?: string;
    claim_version?: number;
    oauth_client_id?: string | null;
  },
  bind?: { principal_id?: string; tenant_id?: string },
  liveOnly = false,
): Promise<{ status: string; detail?: unknown }> {
  if (!env.DEVICE_ROOM) {
    // Fail closed: never pretends routing succeeded without a DO binding.
    return {
      status: "unavailable",
      detail: {
        error: "device_room_unbound",
        note: "DEVICE_ROOM binding is required to route device operations",
      },
    };
  }
  if (!env.SESSION_SECRET) {
    return {
      status: "unavailable",
      detail: {
        error: "session_secret_unbound",
        note: "SESSION_SECRET is required to authorize internal DeviceRoom calls",
      },
    };
  }
  // Bind principal/tenant from caller or authoritative device record.
  let principalId = bind?.principal_id || "";
  let tenantId = bind?.tenant_id || "";
  if (!principalId || !tenantId) {
    try {
      const device = await storeFor(env).getDevice(deviceId);
      if (device) {
        principalId = principalId || device.principal_id;
        tenantId = tenantId || device.tenant_id;
      }
    } catch {
      /* store may be unavailable in unit stubs; claims still require non-empty bind below */
    }
  }
  if (!principalId || !tenantId) {
    return {
      status: "rejected",
      detail: { error: "device_bind_unavailable" },
    };
  }
  const id = env.DEVICE_ROOM.idFromName(deviceId);
  const stub = env.DEVICE_ROOM.get(id);
  // Single serialization source: body bytes hashed and sent are identical.
  const body = JSON.stringify(operation);
  const bodySha256 = await sha256Hex(body);
  const method = "POST";
  const path = liveOnly ? "/live-operation" : "/operation";
  const headers = await internalDoHeaders(env.SESSION_SECRET, {
    op: liveOnly ? "live_operation" : "operation",
    device_id: deviceId,
    principal_id: principalId,
    tenant_id: tenantId,
    correlation_id: operation.correlation_id,
    method,
    path,
    body_sha256: bodySha256,
  });
  const configuredTimeout = Number(env.OWNMESH_DEVICE_ROUTE_TIMEOUT_MS);
  const timeoutMs = Number.isFinite(configuredTimeout) && configuredTimeout > 0
    ? Math.min(60_000, Math.floor(configuredTimeout))
    : 10_000;
  const timedOut = Symbol("device_room_fetch_timeout");
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
  let res: Response;
  try {
    const outcome = await Promise.race<Response | typeof timedOut>([
      stub.fetch(
        new Request(`https://device-room${path}?device_id=${encodeURIComponent(deviceId)}`, {
          method,
          headers,
          body,
        }),
      ),
      new Promise<typeof timedOut>((resolve) => {
        timeoutHandle = setTimeout(() => resolve(timedOut), timeoutMs);
      }),
    ]);
    if (outcome === timedOut) {
      // Post-send timeout is not proof of rejection: DeviceRoom may already have
      // durably accepted and dispatched the body. Leave the operation non-terminal
      // so a delayed result can still CAS-finalize (E2/E3 exact-once).
      return {
        status: "dispatch_uncertain",
        detail: {
          reason: "dispatch_uncertain",
          error: "device_room_fetch_timeout",
          timeout_ms: timeoutMs,
          note: liveOnly
            ? "live ticket delivery is uncertain; never replay its bearer, advance to a fresh proof generation"
            : "request may already be durable in DeviceRoom; keep pending and await result or redeliver identical body",
        },
      };
    }
    res = outcome;
  } catch {
    // Post-send throw is also uncertain: the DO may have accepted before the
    // Worker observed failure. Do not terminal-fail the MCP operation.
    return {
      status: "dispatch_uncertain",
      detail: {
        reason: "dispatch_uncertain",
        error: "device_room_fetch_failed",
        note: liveOnly
            ? "live ticket delivery is uncertain; never replay its bearer, advance to a fresh proof generation"
            : "post-send failure is not proof of rejection; keep pending for redelivery/dedup",
      },
    };
  } finally {
    if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
  }

  // Inspect DO HTTP status: never treat non-2xx / status-less error bodies as routed.
  let parsed: Record<string, unknown> | null = null;
  try {
    const raw: unknown = await res.json();
    if (raw && typeof raw === "object" && !Array.isArray(raw)) {
      parsed = raw as Record<string, unknown>;
    }
  } catch {
    parsed = null;
  }

  const httpOk = res.status >= 200 && res.status < 300;
  if (httpOk) {
    // 2xx with explicit status: unchanged success path.
    if (parsed && typeof parsed.status === "string") {
      return parsed as { status: string; detail?: unknown };
    }
    // 2xx unparseable or status-less (especially error-shaped) → unavailable.
    return {
      status: "unavailable",
      detail: {
        http_status: res.status,
        error:
          (parsed && typeof parsed.error === "string" && parsed.error) ||
          "unparseable_or_status_less_body",
        upstream: parsed ?? undefined,
      },
    };
  }

  const upstreamError =
    (parsed && typeof parsed.error === "string" && parsed.error) ||
    (parsed && typeof parsed.status === "string" && parsed.status) ||
    "upstream_http_error";
  const detail: Record<string, unknown> = {
    http_status: res.status,
    error: upstreamError,
    upstream: parsed ?? undefined,
  };
  if (parsed && parsed.detail !== undefined) {
    detail.upstream_detail = parsed.detail;
  }

  // Preserve explicit device_offline (DO uses 503) — never upgrade to routed/pending.
  if (parsed && parsed.status === "device_offline") {
    return parsed as { status: string; detail?: unknown };
  }

  // 403 (device_not_active / binding_mismatch) → explicit rejected.
  // 429 / 503 / other non-2xx → unavailable (never routed/pending).
  // Ignore any success-shaped body.status on non-2xx responses.
  if (res.status === 403) {
    return { status: "rejected", detail };
  }
  return { status: "unavailable", detail };
}

/** Presence is a bounded observation of the hibernatable DeviceRoom, not a
 * durable enrollment state. A failed or slow probe is explicitly unknown. */
const DEVICE_PRESENCE_PROBE_TIMEOUT_MS = 1_000;

async function deviceConnectionStatus(
  env: Env,
  device: DeviceRecord,
): Promise<"online" | "offline" | "unknown"> {
  if (!env.DEVICE_ROOM) return "unknown";
  const stub = env.DEVICE_ROOM.get(env.DEVICE_ROOM.idFromName(device.id));
  const timeout = Symbol("presence_probe_timeout");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race<Response | typeof timeout>([
      stub.fetch(new Request(`https://device-room/status?device_id=${encodeURIComponent(device.id)}`)),
      new Promise<typeof timeout>((resolve) => {
        timer = setTimeout(() => resolve(timeout), DEVICE_PRESENCE_PROBE_TIMEOUT_MS);
      }),
    ]);
    if (result === timeout || !result.ok) return "unknown";
    const body: unknown = await result.json().catch(() => null);
    if (!body || typeof body !== "object" || Array.isArray(body)) return "unknown";
    const status = (body as { connection_status?: unknown }).connection_status;
    return status === "online" || status === "offline" ? status : "unknown";
  } catch {
    return "unknown";
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const issuer = env.OAUTH_ISSUER || url.origin;

    if (request.method === "OPTIONS") {
      return json({ error: "cors_not_enabled" }, { status: 405 });
    }

    const rateLimited = await enforceRateLimit(request, env, issuer, url.pathname);
    if (rateLimited) return rateLimited;

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      // Keep the endpoint used by deploy/doctor as liveness only: it must not
      // execute D1 queries or disclose readiness internals to anonymous callers.
      return json({
        ...healthBase(env),
        status: "ok",
        liveness: true,
        storage: env.DB ? "d1" : "unavailable",
      });
    }

    if (request.method === "GET" && url.pathname === "/health/ready") {
      const base = healthBase(env);
      const { sessionSecretBound, browserAuthBound } = readinessBindings(env);
      try {
        const store = storeFor(env);
        const readiness = await schemaReadinessFor(env, store);
        const storage = env.DB ? "d1" : store.kind;
        // Browser OAuth must be usable before the instance is declared ready.
        const ready =
          readiness.schema_ready && Boolean(env.DEVICE_ROOM) && sessionSecretBound && browserAuthBound;
        return json({
          ...base,
          status: ready ? "ok" : "not_ready",
          storage,
          schema_ready: readiness.schema_ready,
          schema_checks: readiness.checks,
          session_secret_bound: sessionSecretBound,
          browser_auth_bound: browserAuthBound,
          durable_objects: Boolean(env.DEVICE_ROOM),
        }, { status: ready ? 200 : 503, noStore: true });
      } catch (error) {
        if (error instanceof MissingD1Error) {
          return json({
            ...base,
            status: "not_ready",
            storage: "unavailable",
            schema_ready: false,
            session_secret_bound: sessionSecretBound,
            browser_auth_bound: browserAuthBound,
            durable_objects: Boolean(env.DEVICE_ROOM),
          }, { status: 503, noStore: true });
        }
        // Do not disclose internal D1/binding failures from a public endpoint.
        return json({
          ...base,
          status: "not_ready",
          storage: env.DB ? "d1" : "unavailable",
          schema_ready: false,
          session_secret_bound: sessionSecretBound,
          browser_auth_bound: browserAuthBound,
          durable_objects: Boolean(env.DEVICE_ROOM),
        }, { status: 503, noStore: true });
      }
    }

    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return json(oauthMetadata(issuer, {
        allowDynamicRegistration: env.ALLOW_DYNAMIC_CLIENT_REGISTRATION === "true",
      }));
    }
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json(protectedResourceMetadata(issuer));
    }

    let store: ControlPlaneStore;
    try {
      store = storeFor(env);
    } catch (error) {
      if (error instanceof MissingD1Error) return json({ error: "storage_unavailable" }, { status: 503 });
      throw error;
    }

    if (url.pathname === "/login") {
      return handleOwnerLogin(request, store, issuer, env);
    }
    if (url.pathname === "/auth/passkey.js" && request.method === "GET") {
      return ownerPasskeyScript();
    }
    if (url.pathname === "/auth/passkey/register/options" && request.method === "POST") {
      return handleOwnerPasskeyRegistrationOptions(request, store, issuer, env);
    }
    if (url.pathname === "/auth/passkey/register/verify" && request.method === "POST") {
      return handleOwnerPasskeyRegistrationVerify(request, store, issuer, env);
    }
    if (url.pathname === "/auth/passkey/options" && request.method === "POST") {
      return handleOwnerPasskeyOptions(request, store, issuer, env);
    }
    if (url.pathname === "/auth/passkey/verify" && request.method === "POST") {
      return handleOwnerPasskeyVerify(request, store, issuer, env);
    }
    if (url.pathname === "/logout") {
      return handleOwnerLogout(request, issuer);
    }
    if (url.pathname === "/connect/chatgpt") {
      const principal = await browserPrincipal(request, env);
      if (!principal) {
        if (request.method === "GET" && ownerAuthConfigured(env)) {
          return ownerLoginRedirect(request, issuer);
        }
        return json({ error: "unauthorized" }, { status: 401, noStore: true });
      }
      return handleChatGptConnector(request, store, issuer, {
        id: principal.id,
        tenant_id: principal.tenant_id,
        display_name: principal.display_name || principal.id,
      });
    }

    if (url.pathname === "/oauth/register" && request.method === "POST") {
      // Exact ChatGPT public callbacks may register statelessly. All other DCR
      // remains tenant-authenticated with ownmesh.device; devBypass never applies.
      return handleRegister(request, store, {
        allowDynamicRegistration: env.ALLOW_DYNAMIC_CLIENT_REGISTRATION === "true",
      });
    }
    if (url.pathname === "/oauth/authorize" && (request.method === "GET" || request.method === "POST")) {
      // Consent expiry begins on GET receipt, before any form parsing or external
      // AUTH_PROVIDER round trip; POST only consumes an existing transaction.
      if (request.method === "GET") captureAuthorizeRequestReceipt(request);
      if (request.method === "POST" && !sameOriginBrowserPost(request, issuer)) {
        return json({ error: "origin_not_allowed" }, { status: 403 });
      }
      let authRequest = request;
      if (request.method === "POST") {
        const form = await request.clone().formData();
        const postUrl = new URL(request.url);
        for (const [key, value] of form.entries()) postUrl.searchParams.set(key, String(value));
        authRequest = new Request(postUrl, { method: "POST", headers: request.headers });
      }
      const principal = await browserPrincipal(authRequest, env);
      const bypass = devBypass(env, request);
      if (!principal && request.method === "GET" && ownerAuthConfigured(env)) {
        return ownerLoginRedirect(request, issuer);
      }
      if (!principal && !env.AUTH_PROVIDER && !ownerAuthConfigured(env) && !bypass) {
        return json({ error: "auth_provider_unavailable" }, { status: 503 });
      }
      return handleAuthorize(authRequest, store, issuer, { principal: principal || undefined, allowDevBypass: bypass });
    }
    if (url.pathname === "/oauth/token" && request.method === "POST") {
      return handleToken(request, store);
    }
    if (url.pathname === "/oauth/revoke" && request.method === "POST") {
      return handleRevoke(request, store);
    }
    if (url.pathname === "/oauth/device_authorization" && request.method === "POST") {
      return handleDeviceAuthorization(request, store, issuer);
    }
    if (url.pathname === "/oauth/device") {
      if (request.method === "POST" && !sameOriginBrowserPost(request, issuer)) {
        return json({ error: "origin_not_allowed" }, { status: 403 });
      }
      const principal = await browserPrincipal(request, env);
      const bypass = devBypass(env, request);
      if (!principal && request.method === "GET" && ownerAuthConfigured(env)) {
        return ownerLoginRedirect(request, issuer);
      }
      if (!principal && !env.AUTH_PROVIDER && !ownerAuthConfigured(env) && !bypass) {
        return json({ error: "auth_provider_unavailable" }, { status: 503 });
      }
      return handleDeviceVerification(request, store, { principal: principal || undefined, allowDevBypass: bypass });
    }

    // Human approval for MCP approval_required ops: independent human auth +
    // CSRF + one-time tx, then deliver decision into DeviceRoom (never a stub).
    // OAuth/MCP/device bearer tokens must NOT approve — that enables creator
    // self-approval of write/exec ops. A browser principal also needs recent,
    // operation-bound user verification below.
    if (url.pathname === "/approve") {
      const bearerToken =
        request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      const access = bearerToken ? await store.getAccess(bearerToken) : null;
      // Fail closed: any resolvable control-plane access token is rejected here.
      // (MCP write/exec creator bearer cannot self-approve via /approve.)
      if (access) {
        return json(
          {
            error: "self_approval_forbidden",
            error_description:
              "bearer tokens cannot approve MCP operations; use an independently authenticated human session",
          },
          { status: 403 },
        );
      }

      const operationId = url.searchParams.get("operation_id") || "";
      // The fresh-auth proof is bound to the URL operation. Do not let a POST
      // move authority into an unverified body-only operation_id.
      if (request.method === "POST" && !operationId) {
        return json(
          { error: "invalid_request", error_description: "operation_id required in approval URL" },
          { status: 400, noStore: true },
        );
      }
      const authentication = await browserAuthentication(request, env, operationId || undefined);
      const principal = authentication.principal;
      if (!principal || !authentication.fresh) {
        if (request.method === "GET" && ownerAuthConfigured(env)) {
          return ownerPresenceRedirect(request, issuer);
        }
        return json(
          {
            error: authentication.principal ? "fresh_authentication_required" : "unauthorized",
            error_description: "approval requires recent user verification for this exact operation",
          },
          { status: 401, noStore: true },
        );
      }

      const postOriginOk =
        request.method !== "POST" || sameOriginBrowserPost(request, issuer);

      return handleApprove(request, store, {
        issuer,
        principal: { id: principal.id, tenant_id: principal.tenant_id },
        authSource: "browser",
        originAllowed: postOriginOk,
        routeToDevice: (deviceId, operation) =>
          routeToDeviceRoom(env, deviceId, operation, {
            principal_id: principal.id,
            tenant_id: principal.tenant_id,
          }),
      });
    }

    if (url.pathname === "/mcp") {
      // Browser MCP clients send Origin — reject anything outside the allowlist.
      // Non-browser clients omit Origin and authenticate via bearer token instead.
      const mcpOrigin = request.headers.get("origin");
      if (mcpOrigin && !originAllowed(request, env, issuer)) {
        return json({ error: "origin_not_allowed" }, { status: 403 });
      }
      // Bind principal/tenant from the bearer at route time (store re-checks device).
      const mcpToken = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      const mcpAccess = mcpToken ? await store.getAccess(mcpToken) : null;
      return handleMcp(
        request,
        store,
        url,
        {
          routeToDevice: (deviceId, operation) =>
            routeToDeviceRoom(env, deviceId, operation, mcpAccess
              ? { principal_id: mcpAccess.principal, tenant_id: mcpAccess.tenant_id }
              : undefined),
          routeLiveToDevice: (deviceId, operation) =>
            routeToDeviceRoom(env, deviceId, operation, mcpAccess
              ? { principal_id: mcpAccess.principal, tenant_id: mcpAccess.tenant_id }
              : undefined, true),
        },
        {
          issuer,
          presenceForDevice: (device) => deviceConnectionStatus(env, device),
          // Short fixed fast path only; command timeout remains device-side.
          waitForDeviceMs: MCP_SYNC_WAIT_MS,
          transferTicketSecret: env.SESSION_SECRET,
          terminalizeTransferRoom: env.TRANSFER_ROOM && env.SESSION_SECRET ? async (control) => {
            const signed = await issueTransferTerminalControl(env.SESSION_SECRET!, { v: 1, ...control });
            const stub = env.TRANSFER_ROOM!.get(env.TRANSFER_ROOM!.idFromName(control.transfer_id));
            const response = await stub.fetch(new Request("https://transfer-room/terminal", {
              method: "POST",
              headers: { "content-type": "application/json", "content-length": String(new TextEncoder().encode(signed.body).byteLength), "x-ownmesh-transfer-control": signed.signature },
              body: signed.body,
            }));
            return response.ok;
          } : undefined,
        },
      );
    }

    // Transfer data plane: a short-lived ticket is the sole transfer authority.
    // Query strings and client-selected role/device values are rejected; the
    // agent credential and ticket must agree with the live D1 device record.
    if (url.pathname === "/transfer/connect") {
      if (request.method !== "GET" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") return json({ error: "expected_websocket" }, { status: 426 });
      if (url.search) return json({ error: "query_authority_forbidden" }, { status: 400 });
      if (!originAllowed(request, env, issuer)) return json({ error: "origin_not_allowed" }, { status: 403 });
      if (!env.TRANSFER_ROOM || !env.SESSION_SECRET) return json({ error: "transfer_room_unavailable" }, { status: 503 });
      const ticket = await verifyTransferTicket(env.SESSION_SECRET, request.headers.get("x-ownmesh-transfer-ticket"));
      const bearerToken = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      const credential = bearerToken ? await store.getDeviceCredential(bearerToken) : null;
      if (!ticket || !credential || ticket.ticket_exp <= Date.now() || ticket.transfer_expires_at <= Date.now() || credential.device_id !== ticket.device_id || credential.tenant_id !== ticket.tenant_id || credential.principal_id !== ticket.principal_id) return json({ error: "invalid_transfer_identity" }, { status: 401 });
      const device = await store.getDevice(ticket.device_id);
      const sourceDevice = await store.getDevice(ticket.source_device_id);
      const destinationDevice = await store.getDevice(ticket.destination_device_id);
      if (!device || !sourceDevice || !destinationDevice || device.revoked || sourceDevice.revoked || destinationDevice.revoked || device.status !== "active" || sourceDevice.status !== "active" || destinationDevice.status !== "active" || device.tenant_id !== ticket.tenant_id || sourceDevice.tenant_id !== ticket.tenant_id || destinationDevice.tenant_id !== ticket.tenant_id) return json({ error: "device_not_active" }, { status: 403 });
      if (ticket.source_device_public_key !== sourceDevice.public_key || ticket.destination_device_public_key !== destinationDevice.public_key || !(await verifyTransferEphemeralProof(ticket, "source", sourceDevice.public_key)) || !(await verifyTransferEphemeralProof(ticket, "destination", destinationDevice.public_key))) return json({ error: "invalid_transfer_key_proof" }, { status: 403 });
      if (!(await store.canOperateDevice(ticket.source_device_id, ticket.principal_id, ticket.tenant_id)) || !(await store.canOperateDevice(ticket.destination_device_id, ticket.principal_id, ticket.tenant_id))) return json({ error: "transfer_member_denied" }, { status: 403 });
      const stub = env.TRANSFER_ROOM.get(env.TRANSFER_ROOM.idFromName(ticket.transfer_id));
      return stub.fetch(new Request("https://transfer-room/ws", { method: "GET", headers: request.headers }));
    }

    // Agent / client WebSocket connect → DeviceRoom DO
    // MUST be registered before the broad /v1/devices/* handler so
    // GET /v1/devices/:id/ws is not swallowed by device REST routes.
    // Spec §21 + §6.4 step 5: /agent/connect
    if (
      url.pathname === "/agent/connect" ||
      (url.pathname.startsWith("/v1/devices/") && url.pathname.endsWith("/ws"))
    ) {
      const deviceId =
        url.searchParams.get("device_id") ||
        url.pathname.split("/").filter((p) => p.startsWith("dev_"))[0] ||
        "";
      if (!deviceId) return json({ error: "device_id required" }, { status: 400 });
      const role = url.searchParams.get("role") || "agent";
      if (role !== "agent" && role !== "client") return json({ error: "invalid_role" }, { status: 403 });
      if (!originAllowed(request, env, issuer)) return json({ error: "origin_not_allowed" }, { status: 403 });
      const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      const device = await store.getDevice(deviceId);
      if (!device || device.revoked || device.status !== "active") return json({ error: "device_not_active" }, { status: 403 });
      if (role === "agent") {
        const credential = token ? await store.getDeviceCredential(token) : null;
        if (!credential || credential.device_id !== deviceId || credential.tenant_id !== device.tenant_id || credential.principal_id !== device.principal_id) {
          return json({ error: "invalid_device_credential" }, { status: 401 });
        }
      } else {
        const access = token ? await store.getAccess(token) : null;
        if (!access || access.principal !== device.principal_id || access.tenant_id !== device.tenant_id) {
          return json({ error: "unauthorized" }, { status: 401 });
        }
      }
      if (!env.DEVICE_ROOM) {
        return json(
          { error: "device_room_unbound", device_id: deviceId },
          { status: 503 },
        );
      }
      if (!env.SESSION_SECRET) {
        return json(
          { error: "session_secret_unbound", device_id: deviceId },
          { status: 503 },
        );
      }
      if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
        return json(
          {
            error: "expected_websocket",
            connect: `/agent/connect?device_id=${deviceId}&role=agent`,
          },
          { status: 426 },
        );
      }
      const id = env.DEVICE_ROOM.idFromName(deviceId);
      const stub = env.DEVICE_ROOM.get(id);
      const doUrl = new URL(request.url);
      doUrl.pathname = "/ws";
      doUrl.searchParams.set("device_id", deviceId);
      doUrl.searchParams.set("role", role);
      // Bind HTTP method + DO path into the signed context (WS upgrade is GET /ws).
      const wsMethod = (request.method || "GET").toUpperCase();
      const wsBindPath = "/ws";
      const doHeaders = await internalDoHeaders(
        env.SESSION_SECRET,
        {
          op: "ws",
          device_id: deviceId,
          principal_id: device.principal_id,
          tenant_id: device.tenant_id,
          role,
          method: wsMethod,
          path: wsBindPath,
        },
        request.headers,
      );
      doHeaders.set("x-ownmesh-allowed-origin", new URL(issuer).origin);
      // Strip any client-supplied legacy constant — never forward as authority.
      doHeaders.delete("x-ownmesh-edge-authorized");
      return stub.fetch(new Request(doUrl.toString(), { method: request.method, headers: doHeaders }));
    }

    if (url.pathname.startsWith("/v1/devices")) {
      return handleDevices(request, store, url, {
        presenceForDevice: (device) => deviceConnectionStatus(env, device),
      });
    }

    if (url.pathname === "/v1/migrations/status" && request.method === "GET") {
      // Do not synthesize applied migrations — only report rows actually present.
      const applied = await store.appliedMigrations();
      const readiness = await schemaReadinessFor(env, store);
      return json({
        applied,
        d1_bound: Boolean(env.DB),
        store_kind: store.kind,
        schema_ready: readiness.schema_ready,
        schema_checks: readiness.checks,
      });
    }

    if (url.pathname === "/v1/audit" && request.method === "GET") {
      const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      const access = token ? await store.getAccess(token) : null;
      if (!access) return json({ error: "unauthorized" }, { status: 401 });
      if (!requireScope(access.scope, "ownmesh.read")) return json({ error: "insufficient_scope" }, { status: 403 });
      const events = await store.listAudit(access.tenant_id, 50);
      return json({ events });
    }

    return json({ error: "not_found", path: url.pathname }, { status: 404 });
  },
};

// ---------------------------------------------------------------------------
// Test surface (extends prior __test used by oauth.test.ts)
// ---------------------------------------------------------------------------

import {
  handleToken as oauthHandleToken,
  handleRevoke as oauthHandleRevoke,
} from "./oauth.ts";

const legacyMem = new MemoryStore();

export const __test = {
  MemoryStore,
  createStore,
  MCP_TOOLS,
  requireScope,
  routeToDeviceRoom,
  deviceConnectionStatus,
  signInternalContext,
  internalContextHeaderName,
  get store() {
    return testStore || legacyMem;
  },
  async issueTokens(clientId: string, principal: string, scope: string) {
    const s = testStore || legacyMem;
    await s.ensureBootstrap();
    return s.issueTokens(clientId, principal, scope);
  },
  async getAccess(token: string) {
    const s = testStore || legacyMem;
    return s.getAccess(token);
  },
  async handleOAuthToken(req: Request) {
    const s = testStore || legacyMem;
    return oauthHandleToken(req, s);
  },
  async handleOAuthRevoke(req: Request) {
    const s = testStore || legacyMem;
    return oauthHandleRevoke(req, s);
  },
  reset() {
    testStore = new MemoryStore();
  },
  __setTestStore,
};

export {
  MemoryStore,
  createStore,
  DeviceRoomRouter,
  DeviceRoomHarness,
} from "./reexports.ts";
