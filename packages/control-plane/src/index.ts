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

import { createStore, MemoryStore, MissingD1Error, type ControlPlaneStore } from "./store.ts";
import {
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
import { handleMcp, MCP_TOOLS } from "./mcp.ts";
import { DeviceRoom } from "./device-room.ts";
import { json, SERVICE_NAME, SERVICE_VERSION } from "./util.ts";

export interface Env {
  DB?: D1Database;
  DEVICE_ROOM?: DurableObjectNamespace;
  OAUTH_ISSUER?: string;
  SESSION_SECRET?: string;
  AUTH_PROVIDER?: Fetcher;
  OWNMESH_DEV_AUTH_BYPASS?: string;
  ALLOW_DYNAMIC_CLIENT_REGISTRATION?: string;
  OWNMESH_ALLOWED_ORIGINS?: string;
}

export { DeviceRoom, MCP_TOOLS };
export type { ControlPlaneStore };

/** Optional injected store for unit tests (avoids global mutable singleton). */
let testStore: ControlPlaneStore | null = null;

export function __setTestStore(store: ControlPlaneStore | null): void {
  testStore = store;
}

function storeFor(env: Env): ControlPlaneStore {
  if (testStore) return testStore;
  return createStore(env);
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
  if (devBypass(env, request)) {
    const url = new URL(request.url);
    const id = request.headers.get("x-ownmesh-dev-principal") || url.searchParams.get("login_hint") || "prin_dev";
    return { id, tenant_id: "ten_default", display_name: id };
  }
  if (!env.AUTH_PROVIDER) return null;
  const response = await env.AUTH_PROVIDER.fetch(new Request("https://auth-provider/authenticate", {
    method: "POST",
    headers: {
      authorization: request.headers.get("authorization") || "",
      cookie: request.headers.get("cookie") || "",
      "x-ownmesh-request-url": request.url,
    },
  }));
  if (!response.ok) return null;
  const body = await response.json() as { principal_id?: string; tenant_id?: string; display_name?: string };
  if (!body.principal_id || !body.tenant_id) return null;
  return { id: body.principal_id, tenant_id: body.tenant_id, display_name: body.display_name };
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
  },
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
  const id = env.DEVICE_ROOM.idFromName(deviceId);
  const stub = env.DEVICE_ROOM.get(id);
  const res = await stub.fetch(
    new Request(`https://device-room/operation?device_id=${encodeURIComponent(deviceId)}`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-ownmesh-edge-authorized": "1" },
      body: JSON.stringify(operation),
    }),
  );
  return (await res.json()) as { status: string; detail?: unknown };
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const issuer = env.OAUTH_ISSUER || url.origin;

    if (request.method === "OPTIONS") {
      return json({ error: "cors_not_enabled" }, { status: 405 });
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      const base = {
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
      try {
        const store = storeFor(env);
        const readiness = await store.schemaReadiness();
        const storage = env.DB ? "d1" : store.kind;
        // Ready only when schema is migrated AND DeviceRoom DO is bound.
        const ready = readiness.schema_ready && Boolean(env.DEVICE_ROOM);
        return json({
          ...base,
          status: ready ? "ok" : "not_ready",
          storage,
          schema_ready: readiness.schema_ready,
          schema_checks: readiness.checks,
        }, { status: ready ? 200 : 503 });
      } catch (error) {
        if (error instanceof MissingD1Error) {
          return json({
            ...base,
            status: "not_ready",
            storage: "unavailable",
            schema_ready: false,
          }, { status: 503 });
        }
        throw error;
      }
    }

    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return json(oauthMetadata(issuer));
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

    if (url.pathname === "/oauth/register" && request.method === "POST") {
      // DCR requires explicit flag + authenticated Bearer (ownmesh.device); never enable via devBypass.
      return handleRegister(request, store, {
        allowDynamicRegistration: env.ALLOW_DYNAMIC_CLIENT_REGISTRATION === "true",
      });
    }
    if (url.pathname === "/oauth/authorize" && (request.method === "GET" || request.method === "POST")) {
      if (request.method === "POST" && request.headers.get("origin") !== new URL(issuer).origin) {
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
      if (!principal && !env.AUTH_PROVIDER && !bypass) {
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
      if (request.method === "POST" && request.headers.get("origin") !== new URL(issuer).origin) {
        return json({ error: "origin_not_allowed" }, { status: 403 });
      }
      const principal = await browserPrincipal(request, env);
      const bypass = devBypass(env, request);
      if (!principal && !env.AUTH_PROVIDER && !bypass) {
        return json({ error: "auth_provider_unavailable" }, { status: 503 });
      }
      return handleDeviceVerification(request, store, { principal: principal || undefined, allowDevBypass: bypass });
    }

    // Approval persistence is not implemented yet. Authenticate first, then fail
    // closed rather than recording a meaningless success response.
    if (url.pathname === "/approve") {
      const token = request.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || "";
      const access = token ? await store.getAccess(token) : null;
      if (!access) return json({ error: "unauthorized" }, { status: 401 });
      return json({ error: "approval_not_implemented" }, { status: 501 });
    }

    if (url.pathname === "/mcp") {
      return handleMcp(
        request,
        store,
        url,
        {
          routeToDevice: (deviceId, operation) =>
            routeToDeviceRoom(env, deviceId, operation),
        },
        { issuer },
      );
    }

    if (url.pathname.startsWith("/v1/devices")) {
      return handleDevices(request, store, url);
    }

    // Agent / client WebSocket connect → DeviceRoom DO
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
      const doHeaders = new Headers(request.headers);
      doHeaders.set("x-ownmesh-edge-authorized", "1");
      doHeaders.set("x-ownmesh-allowed-origin", new URL(issuer).origin);
      return stub.fetch(new Request(doUrl.toString(), { method: request.method, headers: doHeaders }));
    }

    if (url.pathname === "/v1/migrations/status" && request.method === "GET") {
      // Do not synthesize applied migrations — only report rows actually present.
      const applied = await store.appliedMigrations();
      const readiness = await store.schemaReadiness();
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
import { requireScope } from "./util.ts";

const legacyMem = new MemoryStore();

export const __test = {
  MemoryStore,
  createStore,
  MCP_TOOLS,
  requireScope,
  routeToDeviceRoom,
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
