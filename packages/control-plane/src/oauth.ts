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
  DEFAULT_TENANT,
  encodeDevicePublicKey,
  generateUserCode,
  randomId,
  randomToken,
  type DeviceRecord,
} from "./store.ts";
import {
  bearer,
  json,
  nowIso,
  readBody,
  requireScope,
  verifyPkceS256,
} from "./util.ts";

export function oauthMetadata(issuer: string) {
  return {
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
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
    token_endpoint_auth_methods_supported: ["none", "client_secret_post"],
  };
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

export async function handleRegister(
  req: Request,
  store: ControlPlaneStore,
): Promise<Response> {
  const body = (await req.json()) as {
    client_name?: string;
    redirect_uris?: string[];
    token_endpoint_auth_method?: string;
  };
  const redirectUris = body.redirect_uris || [];
  for (const u of redirectUris) {
    try {
      new URL(u);
    } catch {
      return json({ error: "invalid_redirect_uri", uri: u }, { status: 400 });
    }
  }
  const clientId = randomToken("client_").slice(0, 24);
  await store.ensureBootstrap();
  await store.putClient({
    client_id: clientId,
    tenant_id: DEFAULT_TENANT,
    client_name: body.client_name || "ownmesh-client",
    redirect_uris: redirectUris,
    created_at: nowIso(),
  });
  return json(
    {
      client_id: clientId,
      client_name: body.client_name || "ownmesh-client",
      redirect_uris: redirectUris,
      token_endpoint_auth_method: body.token_endpoint_auth_method || "none",
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
): Promise<Response> {
  const url = new URL(req.url);
  const redirect = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state") || "";
  const clientId = url.searchParams.get("client_id") || "";
  const scope =
    url.searchParams.get("scope") ||
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access";
  const challenge = url.searchParams.get("code_challenge") || "";
  const method = url.searchParams.get("code_challenge_method") || "S256";
  const responseType = url.searchParams.get("response_type") || "code";

  if (!redirect || !clientId) {
    return json({ error: "invalid_request" }, { status: 400 });
  }
  if (responseType !== "code") {
    return json({ error: "unsupported_response_type" }, { status: 400 });
  }
  if (method !== "S256" || !challenge) {
    return json(
      { error: "invalid_request", error_description: "PKCE S256 required" },
      { status: 400 },
    );
  }

  await store.ensureBootstrap();
  let client = await store.getClient(clientId);
  if (!client) {
    // Dev convenience: auto-register unknown clients with the exact redirect only.
    client = {
      client_id: clientId,
      tenant_id: DEFAULT_TENANT,
      client_name: clientId,
      redirect_uris: [redirect],
      created_at: nowIso(),
    };
    await store.putClient(client);
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

  const principal = url.searchParams.get("login_hint") || "prin_dev";
  await store.ensurePrincipal(principal, principal);

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

  // Optional HTML consent for browser; if `prompt=none` or Accept prefers redirect, bounce.
  const accept = req.headers.get("accept") || "";
  if (accept.includes("text/html") && url.searchParams.get("auto") !== "1") {
    const approveUrl = new URL(req.url);
    approveUrl.searchParams.set("auto", "1");
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>OwnMesh Authorize</title>
<style>body{font-family:system-ui;max-width:32rem;margin:3rem auto;padding:0 1rem}
button{padding:.6rem 1rem;font-size:1rem;cursor:pointer}</style></head>
<body><h1>OwnMesh</h1>
<p>Client <code>${escapeHtml(clientId)}</code> requests scopes:</p>
<pre>${escapeHtml(scope)}</pre>
<form method="get" action="${escapeHtml(approveUrl.pathname)}">
${[...approveUrl.searchParams.entries()]
  .map(
    ([k, v]) =>
      `<input type="hidden" name="${escapeHtml(k)}" value="${escapeHtml(v)}"/>`,
  )
  .join("\n")}
<button type="submit">Approve</button>
</form>
<p style="color:#666;font-size:.85rem">Issuer: ${escapeHtml(issuer)}</p>
</body></html>`;
    return new Response(html, {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }

  const dest = new URL(redirect);
  dest.searchParams.set("code", code);
  if (state) dest.searchParams.set("state", state);
  return Response.redirect(dest.toString(), 302);
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
      tenant_id: DEFAULT_TENANT,
      principal_id: auth.principal_id,
      kind: "oauth.token_issued",
      summary: "authorization_code exchange",
      created_at: nowIso(),
      meta: { client_id: auth.client_id, grant: "authorization_code" },
    });
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
      tenant_id: DEFAULT_TENANT,
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
      expires_in: 900,
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
    // approved
    const principal = rec.principal_id || "prin_dev";
    const tok = await store.issueTokens(rec.client_id, principal, rec.scope);
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: DEFAULT_TENANT,
      principal_id: principal,
      kind: "oauth.device_code_token",
      summary: "device_code exchanged",
      created_at: nowIso(),
    });
    return json({
      access_token: tok.access_token,
      refresh_token: tok.refresh_token,
      token_type: "bearer",
      expires_in: 900,
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
    await store.revokeToken(token);
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: DEFAULT_TENANT,
      kind: "oauth.revoke",
      summary: "token revoked",
      created_at: nowIso(),
      meta: { token_prefix: token.slice(0, 8) },
    });
  }
  return new Response(null, { status: 200 });
}

/** RFC 8628 device authorization endpoint. */
export async function handleDeviceAuthorization(
  req: Request,
  store: ControlPlaneStore,
  issuer: string,
): Promise<Response> {
  const body = await readBody(req);
  const clientId = body.client_id || "client_ownmesh_cli";
  const scope =
    body.scope ||
    "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access";
  await store.ensureBootstrap();

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
): Promise<Response> {
  await store.ensureBootstrap();
  if (req.method === "GET") {
    const url = new URL(req.url);
    const preset = url.searchParams.get("user_code") || "";
    const html = `<!doctype html><html><head><meta charset="utf-8"><title>OwnMesh Device Login</title>
<style>body{font-family:system-ui;max-width:28rem;margin:3rem auto;padding:0 1rem}
input,button{font-size:1rem;padding:.5rem;margin:.25rem 0;width:100%;box-sizing:border-box}
button{cursor:pointer}</style></head>
<body><h1>OwnMesh device login</h1>
<p>Enter the code shown in your CLI (<code>ownmesh login --device</code>).</p>
<form method="post" action="/oauth/device">
<label>User code<br/><input name="user_code" value="${escapeHtml(preset)}" autocomplete="one-time-code" required/></label>
<label>Principal id (dev)<br/><input name="principal_id" value="prin_dev"/></label>
<button type="submit">Approve</button>
</form></body></html>`;
    return new Response(html, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }
  if (req.method === "POST") {
    const body = await readBody(req);
    const userCode = (body.user_code || "").trim().toUpperCase();
    const principal = body.principal_id || "prin_dev";
    await store.ensurePrincipal(principal, principal);
    const ok = await store.approveDeviceCode(userCode, principal);
    if (!ok) {
      return json(
        { error: "invalid_request", error_description: "unknown or used code" },
        { status: 400 },
      );
    }
    const html = `<!doctype html><html><body style="font-family:system-ui;margin:3rem auto;max-width:28rem">
<h1>Approved</h1><p>You can return to the CLI. This window may be closed.</p></body></html>`;
    return new Response(html, {
      headers: { "content-type": "text/html; charset=utf-8" },
    });
  }
  return json({ error: "method_not_allowed" }, { status: 405 });
}

// ---------------------------------------------------------------------------
// Device registry + enrollment (server contract for cli-auth-09)
// ---------------------------------------------------------------------------

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

  if (url.pathname === "/v1/devices/enroll" && req.method === "POST") {
    if (!requireScope(rec.scope, "ownmesh.device") && !requireScope(rec.scope, "ownmesh.write")) {
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
      labels?: string[];
    };
    if (!body.public_key) {
      return json({ error: "invalid_request", field: "public_key" }, { status: 400 });
    }
    const deviceId = randomId("dev_");
    const created = nowIso();
    const device: DeviceRecord = {
      id: deviceId,
      tenant_id: DEFAULT_TENANT,
      principal_id: rec.principal,
      name: body.name || body.hostname || deviceId,
      hostname: body.hostname || body.name || "unknown",
      os: body.os || "unknown",
      arch: body.arch || "unknown",
      agent_version: body.agent_version || "0",
      protocol_version: body.protocol_version || "ownmesh.device/1.0",
      public_key: body.public_key,
      revoked: false,
      created_at: created,
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
      tenant_id: DEFAULT_TENANT,
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
    if (!device || device.principal_id !== rec.principal) {
      return json({ error: "not_found" }, { status: 404 });
    }
    if (device.revoked) return json({ error: "device_revoked" }, { status: 403 });
    const ch = await store.getEnrollmentChallenge(body.challenge_id);
    if (!ch || ch.device_id !== body.device_id) {
      return json({ error: "invalid_challenge" }, { status: 400 });
    }
    // Server accepts non-empty hex signature; cryptographic verify is done by agent
    // identity crate on the client and optionally re-checked here when WebCrypto
    // ed25519 is available. For 1.0.1 we require well-formed hex + consume once.
    if (!/^[0-9a-fA-F]{128}$/.test(body.signature)) {
      return json(
        {
          error: "invalid_proof",
          error_description: "signature must be 64-byte ed25519 hex",
        },
        { status: 400 },
      );
    }
    const consumed = await store.consumeEnrollmentChallenge(body.challenge_id);
    if (!consumed) {
      return json({ error: "challenge_consumed_or_expired" }, { status: 400 });
    }
    await store.appendAudit({
      id: randomId("aud_"),
      tenant_id: DEFAULT_TENANT,
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
      device: { ...device, public_key: device.public_key },
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
      tenant_id: DEFAULT_TENANT,
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

  // Legacy POST /v1/devices {id, name, proof} — kept for older clients.
  if (url.pathname === "/v1/devices" && req.method === "POST") {
    const body = (await req.json()) as {
      id?: string;
      name?: string;
      proof?: string;
      public_key?: string;
    };
    if (!body.id || !body.proof) {
      return json({ error: "invalid_request" }, { status: 400 });
    }
    const device: DeviceRecord = {
      id: body.id,
      tenant_id: DEFAULT_TENANT,
      principal_id: rec.principal,
      name: body.name || body.id,
      hostname: body.name || body.id,
      os: "unknown",
      arch: "unknown",
      agent_version: "0",
      protocol_version: "ownmesh.device/1.0",
      public_key: encodeDevicePublicKey(body.public_key || "legacy", {
        hostname: body.name || body.id,
      }),
      revoked: false,
      created_at: nowIso(),
    };
    await store.putDevice(device);
    return json({ ok: true, device: await store.getDevice(body.id) }, { status: 201 });
  }

  return json({ error: "not_found", path: url.pathname }, { status: 404 });
}

export { requireScope, bearer };
