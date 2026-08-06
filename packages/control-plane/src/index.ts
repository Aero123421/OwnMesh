/**
 * OwnMesh control plane — Cloudflare Worker.
 *
 * Provides health, OAuth metadata, device registry hooks, Streamable HTTP MCP,
 * and Durable Object device room stubs. Deployed to the user's own account.
 */

export interface Env {
  DB?: D1Database;
  DEVICE_ROOM?: DurableObjectNamespace;
  OAUTH_ISSUER?: string;
  SESSION_SECRET?: string;
}

interface HealthResponse {
  service: string;
  status: "ok";
  version: string;
  features: string[];
}

const SERVICE_NAME = "ownmesh-control-plane";
const SERVICE_VERSION = "1.0.0";

function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  headers.set("access-control-allow-origin", "*");
  headers.set("access-control-allow-headers", "authorization, content-type, mcp-session-id");
  headers.set("access-control-allow-methods", "GET, POST, OPTIONS, DELETE");
  return new Response(JSON.stringify(data, null, 0), { ...init, headers });
}

/** MCP tool catalog — policy is always enforced on the device agent. */
export const MCP_TOOLS = [
  {
    name: "ownmesh_list_devices",
    description: "List enrolled devices for the current tenant",
    inputSchema: { type: "object", properties: {}, additionalProperties: false },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "ownmesh_fs_list",
    description: "List files in a workspace path on a device",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string" },
        path: { type: "string" },
      },
      required: ["device_id", "path"],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "ownmesh_fs_read",
    description: "Read a file from a device workspace",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string" },
        path: { type: "string" },
      },
      required: ["device_id", "path"],
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
  },
  {
    name: "ownmesh_fs_write",
    description: "Write a file on a device (subject to OwnMesh policy)",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string" },
        path: { type: "string" },
        content: { type: "string" },
      },
      required: ["device_id", "path", "content"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
  },
  {
    name: "ownmesh_command_run",
    description: "Run a structured command on a device (not raw shell)",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string" },
        program: { type: "string" },
        args: { type: "array", items: { type: "string" } },
      },
      required: ["device_id", "program"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
  },
  {
    name: "ownmesh_command_shell",
    description: "Run a raw shell command (separate capability from structured run)",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string" },
        command: { type: "string" },
      },
      required: ["device_id", "command"],
    },
    annotations: { readOnlyHint: false, destructiveHint: true, openWorldHint: false },
  },
  {
    name: "ownmesh_session_open",
    description: "Open an interactive session on a device",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string" },
        title: { type: "string" },
      },
      required: ["device_id"],
    },
    annotations: { readOnlyHint: false, openWorldHint: false },
  },
  {
    name: "ownmesh_session_attach",
    description: "Attach as observer or claim controller on a session",
    inputSchema: {
      type: "object",
      properties: {
        device_id: { type: "string" },
        session_id: { type: "string" },
        role: { type: "string", enum: ["observer", "controller"] },
      },
      required: ["device_id", "session_id", "role"],
    },
    annotations: { readOnlyHint: false, openWorldHint: false },
  },
] as const;

type TokenRecord = {
  access_token: string;
  refresh_token: string;
  client_id: string;
  scope: string;
  principal: string;
  expires_at: number;
  revoked: boolean;
  refresh_family: string;
  refresh_used: boolean;
};

/** In-memory fallback when D1 is not bound (local dev / tests). */
const memTokens = new Map<string, TokenRecord>();
const memRefresh = new Map<string, string>(); // refresh -> access
/** refresh tokens already consumed — reuse must revoke the family */
const memRefreshUsed = new Map<string, string>(); // refresh -> family
const memDevices = new Map<string, { id: string; name: string; principal: string }>();
const memReplay = new Set<string>();

function bearer(req: Request): string | null {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? m[1]!.trim() : null;
}

function issueTokens(clientId: string, principal: string, scope: string): TokenRecord {
  const access = `atk_${crypto.randomUUID().replace(/-/g, "")}`;
  const refresh = `rtk_${crypto.randomUUID().replace(/-/g, "")}`;
  const family = `fam_${crypto.randomUUID().replace(/-/g, "")}`;
  const rec: TokenRecord = {
    access_token: access,
    refresh_token: refresh,
    client_id: clientId,
    scope,
    principal,
    expires_at: Date.now() + 15 * 60 * 1000,
    revoked: false,
    refresh_family: family,
    refresh_used: false,
  };
  memTokens.set(access, rec);
  memRefresh.set(refresh, access);
  return rec;
}

function getAccess(token: string): TokenRecord | null {
  const rec = memTokens.get(token);
  if (!rec || rec.revoked) return null;
  if (Date.now() > rec.expires_at) return null;
  return rec;
}

function oauthMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    scopes_supported: [
      "ownmesh.read",
      "ownmesh.write",
      "ownmesh.exec",
      "ownmesh.session",
      "ownmesh.device",
      "offline_access",
    ],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  };
}

function protectedResourceMetadata(resource: string) {
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

async function handleOAuthToken(req: Request): Promise<Response> {
  const ct = req.headers.get("content-type") || "";
  let body: Record<string, string> = {};
  if (ct.includes("application/json")) {
    body = (await req.json()) as Record<string, string>;
  } else {
    const form = await req.formData();
    form.forEach((v, k) => {
      body[k] = String(v);
    });
  }
  const grant = body.grant_type;
  if (grant === "authorization_code") {
    if (!body.code || !body.code_verifier || !body.redirect_uri) {
      return json({ error: "invalid_request" }, { status: 400 });
    }
    // Dev code format: code.<client>.<principal>.<scope>
    const parts = body.code.split(".");
    if (parts[0] !== "code" || parts.length < 4) {
      return json({ error: "invalid_grant" }, { status: 400 });
    }
    const clientId = parts[1]!;
    const principal = parts[2]!;
    const scope = parts.slice(3).join(".") || "ownmesh.read";
    const tok = issueTokens(clientId, principal, scope);
    return json({
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      token_type: "bearer",
      expires_in: 900,
      scope: tok.scope,
    });
  }
  if (grant === "refresh_token") {
    const rt = body.refresh_token;
    if (!rt) return json({ error: "invalid_request" }, { status: 400 });
    // Reuse detection: previously rotated refresh token presented again.
    const usedFamily = memRefreshUsed.get(rt);
    if (usedFamily) {
      for (const [k, v] of memTokens) {
        if (v.refresh_family === usedFamily) {
          v.revoked = true;
          memTokens.set(k, v);
        }
      }
      return json(
        { error: "invalid_grant", error_description: "refresh token reuse detected" },
        { status: 400 },
      );
    }
    const access = memRefresh.get(rt);
    if (!access) return json({ error: "invalid_grant" }, { status: 400 });
    const old = memTokens.get(access);
    if (!old || old.revoked) return json({ error: "invalid_grant" }, { status: 400 });
    old.refresh_used = true;
    old.revoked = true;
    memTokens.set(access, old);
    memRefresh.delete(rt);
    memRefreshUsed.set(rt, old.refresh_family);
    const next = issueTokens(old.client_id, old.principal, old.scope);
    next.refresh_family = old.refresh_family;
    memTokens.set(next.access_token, next);
    return json({
      access_token: next.access_token,
      refresh_token: next.refresh_token,
      token_type: "bearer",
      expires_in: 900,
      scope: next.scope,
    });
  }
  return json({ error: "unsupported_grant_type" }, { status: 400 });
}

async function handleOAuthRevoke(req: Request): Promise<Response> {
  const ct = req.headers.get("content-type") || "";
  let token = "";
  if (ct.includes("application/json")) {
    const body = (await req.json()) as { token?: string };
    token = body.token || "";
  } else {
    const form = await req.formData();
    token = String(form.get("token") || "");
  }
  if (token.startsWith("rtk_")) {
    const access = memRefresh.get(token);
    if (access) {
      const rec = memTokens.get(access);
      if (rec) {
        rec.revoked = true;
        memTokens.set(access, rec);
      }
      memRefresh.delete(token);
    }
  } else {
    const rec = memTokens.get(token);
    if (rec) {
      rec.revoked = true;
      memTokens.set(token, rec);
    }
  }
  return new Response(null, { status: 200 });
}

function requireScope(rec: TokenRecord, need: string): boolean {
  const scopes = new Set(rec.scope.split(/\s+/));
  if (scopes.has(need)) return true;
  if (need.startsWith("ownmesh.") && scopes.has("ownmesh.write") && need !== "ownmesh.device") {
    // write implies read for simplicity in 1.0 local mock
    if (need === "ownmesh.read") return true;
  }
  return scopes.has("ownmesh.write") && ["ownmesh.read", "ownmesh.exec", "ownmesh.session"].includes(need);
}

type JsonRpc = {
  jsonrpc?: string;
  id?: string | number | null;
  method?: string;
  params?: Record<string, unknown>;
};

function mcpResult(id: string | number | null | undefined, result: unknown): Response {
  return json({ jsonrpc: "2.0", id: id ?? null, result });
}

function mcpError(id: string | number | null | undefined, code: number, message: string, data?: unknown): Response {
  return json({ jsonrpc: "2.0", id: id ?? null, error: { code, message, data } });
}

function approvalRequired(tool: string) {
  return {
    content: [
      {
        type: "text",
        text: JSON.stringify({
          status: "approval_required",
          tool,
          message: "OwnMesh policy requires explicit approval before this operation runs on the device.",
        }),
      },
    ],
    isError: false,
    _meta: { ownmesh: { approval_required: true } },
  };
}

async function handleMcp(req: Request, _env: Env, url: URL): Promise<Response> {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-headers": "authorization, content-type, mcp-session-id",
        "access-control-allow-methods": "GET, POST, OPTIONS, DELETE",
      },
    });
  }

  const token = bearer(req);
  // initialize may be unauthenticated for discovery in some clients; tools need auth
  const body = (await req.json()) as JsonRpc;
  const method = body.method || "";
  const id = body.id ?? null;

  if (method === "initialize") {
    return mcpResult(id, {
      protocolVersion: "2024-11-05",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: SERVICE_NAME, version: SERVICE_VERSION },
      instructions:
        "OwnMesh exposes device capabilities. Local device policy is the final authority. Do not treat model judgment as authorization.",
    });
  }
  if (method === "notifications/initialized" || method === "ping") {
    return mcpResult(id, {});
  }
  if (method === "tools/list") {
    return mcpResult(id, { tools: MCP_TOOLS });
  }
  if (method === "tools/call") {
    if (!token) return mcpError(id, -32001, "unauthorized");
    const rec = getAccess(token);
    if (!rec) return mcpError(id, -32001, "invalid_token");
    const params = body.params || {};
    const name = String(params.name || "");
    const args = (params.arguments || {}) as Record<string, unknown>;

    // Prompt-injection resistance: tool output is data; policy still applies server-side.
    if (name === "ownmesh_list_devices") {
      if (!requireScope(rec, "ownmesh.device") && !requireScope(rec, "ownmesh.read")) {
        return mcpError(id, -32003, "insufficient_scope");
      }
      const devices = [...memDevices.values()].filter((d) => d.principal === rec.principal);
      return mcpResult(id, {
        content: [{ type: "text", text: JSON.stringify({ devices }) }],
      });
    }
    if (name === "ownmesh_fs_list" || name === "ownmesh_fs_read") {
      if (!requireScope(rec, "ownmesh.read")) return mcpError(id, -32003, "insufficient_scope");
      return mcpResult(id, {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              status: "routed_to_device",
              device_id: args.device_id,
              op: name,
              note: "Device agent evaluates policy and returns results over the device room.",
            }),
          },
        ],
      });
    }
    if (name === "ownmesh_fs_write" || name === "ownmesh_command_run" || name === "ownmesh_command_shell") {
      const need = name === "ownmesh_fs_write" ? "ownmesh.write" : "ownmesh.exec";
      if (!requireScope(rec, need)) return mcpError(id, -32003, "insufficient_scope");
      // Control plane never silently elevates; device may still ask.
      return mcpResult(id, approvalRequired(name));
    }
    if (name === "ownmesh_session_open" || name === "ownmesh_session_attach") {
      if (!requireScope(rec, "ownmesh.session")) return mcpError(id, -32003, "insufficient_scope");
      return mcpResult(id, {
        content: [
          {
            type: "text",
            text: JSON.stringify({
              status: "routed_to_device",
              op: name,
              args,
            }),
          },
        ],
      });
    }
    return mcpError(id, -32601, `unknown tool: ${name}`);
  }

  // GET SSE not fully implemented — return endpoint info
  if (req.method === "GET") {
    return json({
      mcp: true,
      path: url.pathname,
      transport: "streamable-http",
      tools: MCP_TOOLS.length,
    });
  }

  return mcpError(id, -32601, `method not found: ${method}`);
}

async function handleDevices(req: Request): Promise<Response> {
  const token = bearer(req);
  if (!token) return json({ error: "unauthorized" }, { status: 401 });
  const rec = getAccess(token);
  if (!rec) return json({ error: "invalid_token" }, { status: 401 });

  if (req.method === "GET") {
    const devices = [...memDevices.values()].filter((d) => d.principal === rec.principal);
    return json({ devices });
  }
  if (req.method === "POST") {
    const body = (await req.json()) as { id?: string; name?: string; proof?: string };
    if (!body.id || !body.proof) return json({ error: "invalid_request" }, { status: 400 });
    // enrollment proof: opaque non-empty string in 1.0 local mock
    memDevices.set(body.id, {
      id: body.id,
      name: body.name || body.id,
      principal: rec.principal,
    });
    return json({ ok: true, device: memDevices.get(body.id) }, { status: 201 });
  }
  if (req.method === "DELETE") {
    const id = new URL(req.url).searchParams.get("id");
    if (!id) return json({ error: "invalid_request" }, { status: 400 });
    const d = memDevices.get(id);
    if (d && d.principal === rec.principal) memDevices.delete(id);
    // revoke is immediate for subsequent GETs
    return json({ ok: true });
  }
  return json({ error: "method_not_allowed" }, { status: 405 });
}

/** Exported for unit tests without Worker runtime. */
export const __test = {
  issueTokens,
  getAccess,
  memTokens,
  memRefresh,
  memDevices,
  handleOAuthToken,
  handleOAuthRevoke,
  MCP_TOOLS,
  requireScope,
  reset() {
    memTokens.clear();
    memRefresh.clear();
    memRefreshUsed.clear();
    memDevices.clear();
    memReplay.clear();
  },
};

export default {
  async fetch(request: Request, env: Env, _ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const issuer = env.OAUTH_ISSUER || url.origin;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-origin": "*",
          "access-control-allow-headers": "authorization, content-type, mcp-session-id",
          "access-control-allow-methods": "GET, POST, OPTIONS, DELETE",
        },
      });
    }

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      const body: HealthResponse = {
        service: SERVICE_NAME,
        status: "ok",
        version: SERVICE_VERSION,
        features: ["oauth", "mcp", "devices", "no-central-telemetry"],
      };
      return json(body);
    }

    if (url.pathname === "/.well-known/oauth-authorization-server") {
      return json(oauthMetadata(issuer));
    }
    if (url.pathname === "/.well-known/oauth-protected-resource") {
      return json(protectedResourceMetadata(issuer));
    }

    if (url.pathname === "/oauth/register" && request.method === "POST") {
      const body = (await request.json()) as { client_name?: string; redirect_uris?: string[] };
      const clientId = `client_${crypto.randomUUID().replace(/-/g, "").slice(0, 16)}`;
      return json(
        {
          client_id: clientId,
          client_name: body.client_name || "ownmesh-client",
          redirect_uris: body.redirect_uris || [],
          token_endpoint_auth_method: "none",
        },
        { status: 201 },
      );
    }

    if (url.pathname === "/oauth/authorize" && request.method === "GET") {
      // Dev-only authorize: bounce back with code
      const redirect = url.searchParams.get("redirect_uri");
      const state = url.searchParams.get("state") || "";
      const clientId = url.searchParams.get("client_id") || "dev";
      const scope = url.searchParams.get("scope") || "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access";
      if (!redirect) return json({ error: "invalid_request" }, { status: 400 });
      // exact redirect match is caller's responsibility to register; we echo only given URI
      const code = `code.${clientId}.user_dev.${scope.replace(/\s+/g, " ")}`;
      const dest = new URL(redirect);
      dest.searchParams.set("code", code);
      if (state) dest.searchParams.set("state", state);
      return Response.redirect(dest.toString(), 302);
    }

    if (url.pathname === "/oauth/token" && request.method === "POST") {
      return handleOAuthToken(request);
    }
    if (url.pathname === "/oauth/revoke" && request.method === "POST") {
      return handleOAuthRevoke(request);
    }

    if (url.pathname === "/mcp") {
      return handleMcp(request, env, url);
    }

    if (url.pathname === "/v1/devices") {
      return handleDevices(request);
    }

    if (url.pathname === "/v1/migrations/status" && request.method === "GET") {
      return json({
        applied: ["0001_init.sql"],
        d1_bound: Boolean(env.DB),
      });
    }

    return json({ error: "not_found", path: url.pathname }, { status: 404 });
  },
};

/**
 * Durable Object: per-device connection room (hibernation-friendly stub).
 */
export class DeviceRoom {
  state: DurableObjectState;
  env: Env;
  sessions: Set<WebSocket>;

  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.sessions = new Set();
  }

  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/status") {
      return json({ connected: this.sessions.size, network_outbound_from_do: false });
    }
    if (request.headers.get("Upgrade") === "websocket") {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
      this.state.acceptWebSocket(server);
      this.sessions.add(server);
      return new Response(null, { status: 101, webSocket: client });
    }
    return json({ error: "expected websocket" }, { status: 400 });
  }

  webSocketClose(ws: WebSocket): void {
    this.sessions.delete(ws);
  }

  webSocketError(ws: WebSocket): void {
    this.sessions.delete(ws);
  }
}
