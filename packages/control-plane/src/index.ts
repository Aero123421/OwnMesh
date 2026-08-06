/**
 * OwnMesh control plane entrypoint (Cloudflare Worker skeleton).
 *
 * Later chapters add OAuth, MCP `/mcp`, D1, Durable Objects, and device rooms.
 */

export interface Env {
  // Bindings (D1, DO namespaces, secrets) are introduced in later chapters.
}

interface HealthResponse {
  service: string;
  status: "ok";
  version: string;
}

const SERVICE_NAME = "ownmesh-control-plane";
const SERVICE_VERSION = "0.1.0";

function json(data: unknown, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(data), { ...init, headers });
}

export default {
  async fetch(
    request: Request,
    _env: Env,
    _ctx: ExecutionContext,
  ): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "GET" && (url.pathname === "/" || url.pathname === "/health")) {
      const body: HealthResponse = {
        service: SERVICE_NAME,
        status: "ok",
        version: SERVICE_VERSION,
      };
      return json(body);
    }

    return json(
      {
        error: {
          code: "OWNMESH_E_NOT_FOUND",
          message: "Not Found",
          retryable: false,
        },
      },
      { status: 404 },
    );
  },
};
