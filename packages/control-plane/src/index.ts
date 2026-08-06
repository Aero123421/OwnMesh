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

import { createStore, MemoryStore, type ControlPlaneStore } from "./store.ts";
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
} from "./oauth.ts";
import { handleMcp, MCP_TOOLS } from "./mcp.ts";
import { DeviceRoom } from "./device-room.ts";
import { json, SERVICE_NAME, SERVICE_VERSION } from "./util.ts";

export interface Env {
  DB?: D1Database;
  DEVICE_ROOM?: DurableObjectNamespace;
  OAUTH_ISSUER?: string;
  SESSION_SECRET?: string;
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
    return {
      status: "routed_to_device",
      detail: { note: "DEVICE_ROOM unbound; logical route only", ...operation },
    };
  }
  const id = env.DEVICE_ROOM.idFromName(deviceId);
  const stub = env.DEVICE_ROOM.get(id);
  const res = await stub.fetch(
    new Request(`https://device-room/operation?device_id=${encodeURIComponent(deviceId)}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(operation),
    }),
  );
  return (await res.json()) as { status: string; detail?: unknown };
}

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const issuer = env.OAUTH_ISSUER || url.origin;
    const store = storeFor(env);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-headers":
            "authorization, content-type, mcp-session-id",
          "access-control-allow-methods": "GET, POST, OPTIONS, DELETE",
        },
      });
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      return json({
        service: SERVICE_NAME,
        status: "ok",
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
        storage: env.DB ? "d1" : testStore ? testStore.kind : "memory",
        durable_objects: Boolean(env.DEVICE_ROOM),
      });
    }

    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return json(oauthMetadata(issuer));
    }
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json(protectedResourceMetadata(issuer));
    }

    if (url.pathname === "/oauth/register" && request.method === "POST") {
      return handleRegister(request, store);
    }
    if (url.pathname === "/oauth/authorize" && request.method === "GET") {
      return handleAuthorize(request, store, issuer);
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
      return handleDeviceVerification(request, store);
    }

    // One-time browser approval page (checklist §7)
    if (url.pathname === "/approve" && request.method === "GET") {
      const op = url.searchParams.get("operation_id") || "";
      const html = `<!doctype html><html><head><meta charset="utf-8"><title>OwnMesh Approval</title>
<style>body{font-family:system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem}
button{margin-right:.5rem;padding:.5rem 1rem;font-size:1rem;cursor:pointer}</style></head>
<body><h1>Approve operation</h1>
<p>Operation: <code>${op.replace(/[<>&]/g, "")}</code></p>
<p>Local device policy remains the final authority. This page records human consent metadata only.</p>
<form method="post" action="/approve"><input type="hidden" name="operation_id" value="${op.replace(/"/g, "")}"/>
<button name="decision" value="approve">Approve once</button>
<button name="decision" value="deny">Deny</button>
</form></body></html>`;
      return new Response(html, {
        headers: { "content-type": "text/html; charset=utf-8" },
      });
    }
    if (url.pathname === "/approve" && request.method === "POST") {
      const body = await request.formData();
      return json({
        ok: true,
        operation_id: String(body.get("operation_id") || ""),
        decision: String(body.get("decision") || ""),
      });
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
      if (!deviceId) {
        return json({ error: "device_id required" }, { status: 400 });
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
      const role = url.searchParams.get("role") || "agent";
      const doUrl = new URL(request.url);
      doUrl.pathname = "/ws";
      doUrl.searchParams.set("device_id", deviceId);
      doUrl.searchParams.set("role", role);
      return stub.fetch(
        new Request(doUrl.toString(), {
          method: request.method,
          headers: request.headers,
        }),
      );
    }

    if (url.pathname === "/v1/migrations/status" && request.method === "GET") {
      await store.ensureBootstrap();
      const applied = await store.appliedMigrations();
      return json({
        applied: applied.length
          ? applied
          : ["0001_init.sql", "0002_oauth_device_enrollment.sql"],
        d1_bound: Boolean(env.DB),
        store_kind: store.kind,
      });
    }

    if (url.pathname === "/v1/audit" && request.method === "GET") {
      await store.ensureBootstrap();
      const events = await store.listAudit("ten_default", 50);
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
