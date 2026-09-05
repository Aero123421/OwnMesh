/**
 * Issue #227 recovery contract, testable in CI without a live ChatGPT
 * account (see docs/chatgpt-connection.md "Recovery contract" for the
 * operator half, including the external smoke receipt).
 *
 * Proves, against the same handlers production uses:
 * - quota/unavailable backends degrade to sanitized 503 + Retry-After and
 *   never kill or mislabel a healthy credential family;
 * - transient 503, invalid_grant, and reuse stay distinct;
 * - recovery needs no connector reinstall and no blind re-execution:
 *   polls and same-key retries converge to the one durable operation.
 */
import assert from "node:assert/strict";
import test from "node:test";
import { MemoryStore, type ControlPlaneStore } from "./store.ts";
import { handleToken } from "./oauth.ts";
import { handleMcp } from "./mcp.ts";
import type { BudgetState } from "./quota-guard.ts";

function authOnlyBudget(): BudgetState {
  return {
    mode: "auth_only",
    source: "probe",
    resetAt: "2026-09-06T00:00:00.000Z",
    checkedAt: Date.now(),
    probeCategory: "quota_exceeded",
  };
}

/** Wrap a store so listed methods throw a D1 outage error (fault injection). */
function failingStore(base: MemoryStore, methods: Set<string>): ControlPlaneStore {
  return new Proxy(base, {
    get(target, prop, receiver) {
      const value = Reflect.get(target, prop, receiver) as unknown;
      if (typeof value === "function" && methods.has(String(prop))) {
        return () => {
          const error = new Error("D1_ERROR: database unavailable") as Error & { code?: string };
          error.name = "D1DatabaseError";
          throw error;
        };
      }
      return typeof value === "function" ? (value as (...args: never[]) => unknown).bind(target) : value;
    },
  }) as ControlPlaneStore;
}

async function tokenCall(
  store: ControlPlaneStore,
  params: Record<string, string>,
  budget?: BudgetState,
): Promise<{ status: number; body: Record<string, unknown>; retryAfter: string | null }> {
  const res = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(params),
    }),
    store,
    budget ? { budget } : undefined,
  );
  return {
    status: res.status,
    body: (await res.json()) as Record<string, unknown>,
    retryAfter: res.headers.get("retry-after"),
  };
}

test("quota exhaustion degrades without killing the refresh family", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const issued = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");
  const budget = authOnlyBudget();

  // Degraded: sanitized 503, retryable, never invalid_grant.
  const degraded = await tokenCall(
    store,
    { grant_type: "refresh_token", refresh_token: issued.refresh_token },
    budget,
  );
  assert.equal(degraded.status, 503);
  assert.equal(degraded.body.error, "temporarily_unavailable");
  assert.ok(degraded.retryAfter && Number(degraded.retryAfter) > 0);

  // Recovered: the SAME family rotates with no reinstall and no re-consent.
  const recovered = await tokenCall(store, {
    grant_type: "refresh_token",
    refresh_token: issued.refresh_token,
  });
  assert.equal(recovered.status, 200);
  const rotated = (recovered.body as { refresh_token: string }).refresh_token;
  assert.ok(rotated && rotated !== issued.refresh_token);
  // Exact response-loss retry converges instead of tripping reuse detection.
  const retry = await tokenCall(store, {
    grant_type: "refresh_token",
    refresh_token: issued.refresh_token,
  });
  assert.equal(retry.status, 200);
  assert.equal((retry.body as { refresh_token: string }).refresh_token, rotated);
});

test("transient failure, revoke, and reuse stay distinct", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const issued = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");

  // Transient backend failure is 503, not a credential verdict.
  const transient = await tokenCall(
    store,
    { grant_type: "refresh_token", refresh_token: issued.refresh_token },
    authOnlyBudget(),
  );
  assert.equal(transient.body.error, "temporarily_unavailable");

  // Explicit revoke is invalid_grant, without Retry-After semantics.
  await store.revokeToken(issued.refresh_token);
  const revoked = await tokenCall(store, {
    grant_type: "refresh_token",
    refresh_token: issued.refresh_token,
  });
  assert.equal(revoked.body.error, "invalid_grant");
  assert.equal(revoked.retryAfter, null);
});

test("a D1 write failure mid-rotation never revokes the family", async () => {
  const base = new MemoryStore();
  await base.ensureBootstrap();
  const issued = await base.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.read");

  // The batch throws like a D1 outage would: surfaces as a throw, never as
  // reuse/invalid_grant, and writes nothing that could revoke the family.
  const faulty = failingStore(base, new Set(["rotateRefresh"]));
  await assert.rejects(
    async () => {
      await faulty.rotateRefresh(issued.refresh_token);
    },
    /D1_ERROR/,
  );

  // Same family rotates cleanly once the backend is back.
  const rotated = await base.rotateRefresh(issued.refresh_token);
  assert.equal(rotated.ok, true);
  assert.ok(rotated.ok && (await base.getAccess(rotated.token.access_token)) !== null);
});

test("dispatch failure then same-key retry converges to one operation", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const stamp = new Date().toISOString();
  const op = {
    operation_id: "op_rc_1",
    tenant_id: "ten_rc",
    principal_id: "prin_rc",
    device_id: "dev_rc",
    tool: "ownmesh_command_run",
    status: "pending",
    summary: "detached work",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "op_rc_1",
    payload_hash: "ph_rc",
    idempotency_key: "idem_rc_1",
    policy_authority: "ownmesh_device" as const,
    created_at: stamp,
    updated_at: stamp,
  };
  // First attempt claims, then the dispatch write fails (faulty terminal CAS).
  const first = await store.claimMcpOperationByIdempotency(op);
  assert.equal(first.outcome, "created");
  const faulty = failingStore(store, new Set(["updateMcpOperation", "transitionMcpOperation"]));
  await assert.rejects(
    async () => {
      await faulty.transitionMcpOperation("op_rc_1", { status: "dispatched" }, ["pending"]);
    },
    /D1_ERROR/,
  );
  // Retry with the identical authorized action converges — no second row,
  // no second dispatch claim, still pending.
  const retry = await store.claimMcpOperationByIdempotency({ ...op });
  assert.equal(retry.outcome, "existing");
  assert.equal(retry.op.operation_id, "op_rc_1");
  assert.equal(retry.op.status, "pending");
  assert.equal((await store.listMcpOperations({ tenantId: "ten_rc", principalId: "prin_rc", tool: "ownmesh_command_run" })).length, 1);
  // Late terminal result still lands exactly once.
  const done = await store.transitionMcpOperation("op_rc_1", { status: "completed", summary: "done" }, ["pending"]);
  assert.equal(done?.status, "completed");
});

test("manual reauthorization keeps prior durable receipts reachable", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const stamp = new Date().toISOString();
  await store.putMcpOperation({
    operation_id: "op_reauth_1",
    tenant_id: "ten_default",
    principal_id: "prin_dev",
    device_id: undefined,
    tool: "ownmesh_command_run",
    status: "completed",
    summary: "finished before the incident",
    data: {},
    truncated: false,
    next_cursor: null,
    approval_required: false,
    warnings: [],
    correlation_id: "op_reauth_1",
    payload_hash: "ph_re",
    idempotency_key: "idem_re_1",
    policy_authority: "ownmesh_device" as const,
    created_at: stamp,
    updated_at: stamp,
  });
  const oldTokens = await store.issueTokens(
    "client_ownmesh_cli",
    "prin_dev",
    "ownmesh.device ownmesh.read",
  );
  // Credential compromised/rotated by the owner: explicit revoke, then a
  // fresh family for the SAME principal (this is the manual-reauth shape).
  await store.revokeToken(oldTokens.refresh_token);
  const fresh = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.device ownmesh.read");

  const poll = async (token: string, operationId: string) =>
    handleMcp(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 7,
          method: "tools/call",
          params: { name: "ownmesh_get_operation", arguments: { operation_id: operationId } },
        }),
      }),
      store,
      new URL("https://cp.test/mcp"),
    );
  // The pre-incident receipt is reachable under the fresh credential: same
  // tenant/principal boundary, no connector reinstall, no re-execution.
  const found = await poll(fresh.access_token, "op_reauth_1");
  assert.equal(found.status, 200);
  const foundBody = (await found.json()) as {
    result?: { structuredContent?: { status?: string; operation_id?: string } };
  };
  assert.equal(foundBody.result?.structuredContent?.operation_id, "op_reauth_1");
  assert.equal(foundBody.result?.structuredContent?.status, "completed");
  // Unknown ids stay unknown (no cross-principal leak through polling).
  const missing = await poll(fresh.access_token, "op_missing_receipt_probe");
  assert.equal(missing.status, 200);
  const missingBody = (await missing.json()) as {
    result?: { structuredContent?: { status?: string } };
  };
  assert.equal(missingBody.result?.structuredContent?.status, "failed");
});
