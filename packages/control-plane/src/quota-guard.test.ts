/**
 * Issue #224 plan F (P4): budget admission, degraded modes, and the write
 * probe that keeps /health/ready honest during quota exhaustion.
 */
import assert from "node:assert/strict";
import test from "node:test";
import worker, { __setTestStore } from "./index.ts";
import { MemoryStore } from "./store.ts";
import {
  checkBudget,
  resolveBudgetOverride,
  secondsUntilUtcReset,
  utcResetIso,
  type BudgetState,
} from "./quota-guard.ts";
import { handleToken } from "./oauth.ts";
import { handleMcp } from "./mcp.ts";

const ctx = {} as ExecutionContext;

function fakeDeviceRoom(): DurableObjectNamespace {
  return {
    idFromName: () => ({}) as DurableObjectId,
    get: () =>
      ({
        fetch: async () => new Response(null, { status: 204 }),
      }) as unknown as DurableObjectStub,
  } as unknown as DurableObjectNamespace;
}

function readyEnv(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    DEVICE_ROOM: fakeDeviceRoom(),
    SESSION_SECRET: "test-session-secret-quota-guard-00",
    OWNER_TOKEN_HASH: "0".repeat(64),
    ...extra,
  };
}

test("resolveBudgetOverride accepts only known modes", () => {
  assert.equal(resolveBudgetOverride({}), null);
  assert.equal(resolveBudgetOverride({ OWNMESH_DEGRADED_MODE: "read_only" }), "read_only");
  assert.equal(resolveBudgetOverride({ OWNMESH_DEGRADED_MODE: "auth_only" }), "auth_only");
  assert.equal(resolveBudgetOverride({ OWNMESH_DEGRADED_MODE: "normal" }), null);
  assert.equal(resolveBudgetOverride({ OWNMESH_DEGRADED_MODE: "bogus" }), null);
});

test("UTC reset helpers point at the next midnight", () => {
  const atNoon = Date.UTC(2026, 8, 5, 12, 0, 0);
  assert.equal(secondsUntilUtcReset(atNoon), 12 * 3600);
  assert.equal(utcResetIso(atNoon), "2026-09-06T00:00:00.000Z");
  const secs = secondsUntilUtcReset();
  assert.ok(secs >= 0 && secs <= 86400);
});

test("checkBudget honors override, probe, and failure", async () => {
  const store = new MemoryStore();
  const overridden = await checkBudget(store, { OWNMESH_DEGRADED_MODE: "read_only" });
  assert.equal(overridden.mode, "read_only");
  assert.equal(overridden.source, "env");

  const normal = await checkBudget(new MemoryStore(), {});
  assert.equal(normal.mode, "normal");
  assert.equal(normal.source, "probe");

  const quotaStore = new MemoryStore();
  quotaStore.probeWriteReadiness = async () => ({ ok: false, category: "quota_exceeded" });
  const exhausted = await checkBudget(quotaStore, {});
  assert.equal(exhausted.mode, "auth_only");
  assert.equal(exhausted.probeCategory, "quota_exceeded");
  assert.match(exhausted.resetAt, /T00:00:00\.000Z/);

  const brokenStore = new MemoryStore();
  brokenStore.probeWriteReadiness = async () => {
    throw new Error("d1_down");
  };
  const broken = await checkBudget(brokenStore, {});
  assert.equal(broken.mode, "auth_only");
  assert.equal(broken.probeCategory, "unknown");
});

async function mcpCall(
  store: MemoryStore,
  token: string,
  name: string,
  args: Record<string, unknown>,
  budgetState?: BudgetState,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const res = await handleMcp(
    new Request("https://cp.test/mcp", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
    }),
    store,
    new URL("https://cp.test/mcp"),
    undefined,
    budgetState ? { budgetState } : {},
  );
  return { status: res.status, body: (await res.json()) as Record<string, unknown> };
}

test("degraded modes gate MCP calls by risk class", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const issued = await store.issueTokens("client_ownmesh_cli", "prin_dev", "ownmesh.device ownmesh.read ownmesh.write ownmesh.exec");
  const future = utcResetIso(Date.now() + 1000);

  const readOnly: BudgetState = { mode: "read_only", source: "env", resetAt: future, checkedAt: Date.now() };
  const authOnly: BudgetState = { mode: "auth_only", source: "probe", resetAt: future, checkedAt: Date.now(), probeCategory: "quota_exceeded" };

  // Reads stay available in read_only.
  const readOk = await mcpCall(store, issued.access_token, "ownmesh_list_devices", {}, readOnly);
  assert.equal(readOk.status, 200);

  // Side effects are rejected with a structured non-retryable error.
  const writeBlocked = await mcpCall(store, issued.access_token, "ownmesh_fs_write", { device_id: "dev_x" }, readOnly);
  const writeErr = (writeBlocked.body.error as { code: number; data: { code: string; retryable: boolean; reset_at: string; mode: string } }).data;
  assert.equal(writeErr.code, "OWNMESH_QUOTA_SIDE_EFFECT_DISABLED");
  assert.equal(writeErr.retryable, false);
  assert.equal(writeErr.reset_at, future);
  assert.equal(writeErr.mode, "read_only");

  // auth_only without room coverage rejects even reads, without D1 writes.
  const readBlocked = await mcpCall(store, issued.access_token, "ownmesh_list_devices", {}, authOnly);
  assert.equal(((readBlocked.body.error as { data: { code: string } }).data).code, "OWNMESH_QUOTA_READ_ONLY_DISABLED");

  // Normal mode is unaffected.
  const normal = await mcpCall(store, issued.access_token, "ownmesh_list_devices", {});
  assert.equal(normal.status, 200);
});

test("OAuth token endpoint fails fast with Retry-After in auth_only", async () => {
  const store = new MemoryStore();
  const future = utcResetIso(Date.now() + 1000);
  const res = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "rtk_x" }),
    }),
    store,
    { budget: { mode: "auth_only", source: "probe", resetAt: future, checkedAt: Date.now() } },
  );
  assert.equal(res.status, 503);
  assert.equal(res.headers.get("retry-after"), String(secondsUntilUtcReset()));
  const body = (await res.json()) as { error: string };
  assert.equal(body.error, "temporarily_unavailable");

  // Normal mode passes the gate (then fails on the bogus grant, proving the
  // gate — not the grant — decided the 503 above).
  const normal = await handleToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "refresh_token", refresh_token: "rtk_x" }),
    }),
    store,
  );
  assert.notEqual(normal.status, 503);
});

test("/health/ready reports budget state and fails on auth_only", async () => {
  const store = new MemoryStore();
  __setTestStore(store);
  try {
    const ok = await worker.fetch(new Request("https://cp.test/health/ready"), readyEnv(), ctx);
    assert.equal(ok.status, 200);
    const okBody = (await ok.json()) as {
      auth_write_ready: boolean;
      budget_mode: string;
      budget_reset_at: string;
    };
    assert.equal(okBody.auth_write_ready, true);
    assert.equal(okBody.budget_mode, "normal");
    assert.match(okBody.budget_reset_at, /T00:00:00\.000Z/);

    const degraded = await worker.fetch(
      new Request("https://cp.test/health/ready"),
      readyEnv({ OWNMESH_DEGRADED_MODE: "auth_only" }),
      ctx,
    );
    assert.equal(degraded.status, 503);
    const degradedBody = (await degraded.json()) as {
      status: string;
      auth_write_ready: boolean;
      budget_mode: string;
    };
    assert.equal(degradedBody.status, "not_ready");
    assert.equal(degradedBody.auth_write_ready, false);
    assert.equal(degradedBody.budget_mode, "auth_only");
  } finally {
    __setTestStore(null);
  }
});

test("/health/ready surfaces a failing write probe with its category", async () => {
  const store = new MemoryStore();
  store.probeWriteReadiness = async () => ({ ok: false, category: "quota_exceeded" });
  __setTestStore(store);
  try {
    const res = await worker.fetch(new Request("https://cp.test/health/ready"), readyEnv(), ctx);
    assert.equal(res.status, 503);
    const body = (await res.json()) as {
      status: string;
      auth_write_ready: boolean;
      budget_mode: string;
      budget_probe_category: string;
    };
    assert.equal(body.status, "not_ready");
    assert.equal(body.auth_write_ready, false);
    assert.equal(body.budget_mode, "auth_only");
    assert.equal(body.budget_probe_category, "quota_exceeded");
  } finally {
    __setTestStore(null);
  }
});

test("scheduled() drains retention through the injected store", async () => {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  __setTestStore(store);
  try {
    // No DB binding -> no-op, never throws.
    await worker.scheduled(
      {} as ScheduledEvent,
      {} as unknown as Parameters<typeof worker.scheduled>[1],
    );
    // DB present -> sweep runs against the injected store.
    await worker.scheduled(
      {} as ScheduledEvent,
      { ...readyEnv(), DB: {} } as unknown as Parameters<typeof worker.scheduled>[1],
    );
  } finally {
    __setTestStore(null);
  }
});
