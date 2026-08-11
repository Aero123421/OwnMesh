import assert from "node:assert/strict";
import test from "node:test";
import worker, { type Env } from "./index.ts";

function denyingLimiter(captured: string[]): NonNullable<Env["MCP_RATE_LIMITER"]> {
  return {
    async limit({ key }) {
      captured.push(key);
      return { success: false };
    },
  };
}

test("MCP limiter rejects before storage and never exposes the bearer", async () => {
  const captured: string[] = [];
  const response = await worker.fetch(
    new Request("https://cp.test/mcp", {
      method: "POST",
      headers: {
        authorization: "Bearer at_distinctive_secret",
        "cf-connecting-ip": "192.0.2.20",
      },
      body: "{}",
    }),
    { MCP_RATE_LIMITER: denyingLimiter(captured) },
    {} as ExecutionContext,
  );
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("retry-after"), "60");
  // Address and credential are counted as separate buckets, so a caller
  // cannot escape the limit by varying either one alone.
  assert.equal(captured.length, 2);
  for (const key of captured) {
    assert.equal(key.includes("at_distinctive_secret"), false);
    assert.equal(key.includes("192.0.2.20"), false);
  }
  assert.ok(captured.some((key) => key.includes(":addr:")));
  assert.ok(captured.some((key) => key.includes(":cred:")));
});

/**
 * The guard must bind to something the caller cannot choose.
 *
 * Keying on `Authorization` first let an unauthenticated attacker randomise
 * that header per request, land in a fresh bucket every time, and never reach
 * the threshold — defeating the counter entirely. The connection address is
 * assigned by Cloudflare, so the address bucket has to stay constant across
 * varying credentials.
 */
test("varying the Authorization header cannot escape the address bucket", async () => {
  const addressKeys = new Set<string>();
  for (const credential of ["Bearer aaa", "Bearer bbb", "Bearer ccc"]) {
    const captured: string[] = [];
    await worker.fetch(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: { authorization: credential, "cf-connecting-ip": "198.51.100.7" },
        body: "{}",
      }),
      { MCP_RATE_LIMITER: denyingLimiter(captured) },
      {} as ExecutionContext,
    );
    const addressKey = captured.find((key) => key.includes(":addr:"));
    assert.ok(addressKey, "an address-keyed bucket must always be counted");
    addressKeys.add(addressKey!);
  }
  assert.equal(
    addressKeys.size,
    1,
    "the address bucket must not change when the caller varies its credential",
  );
});

test("unauthenticated bootstrap traffic is counted by address alone", async () => {
  const captured: string[] = [];
  const response = await worker.fetch(
    new Request("https://cp.test/auth/passkey/register/options", {
      method: "POST",
      headers: { "cf-connecting-ip": "203.0.113.5" },
      body: "{}",
    }),
    { AUTH_RATE_LIMITER: denyingLimiter(captured) },
    {} as ExecutionContext,
  );
  assert.equal(response.status, 429);
  assert.equal(captured.length, 1);
  assert.ok(captured[0]!.includes(":addr:"));
  assert.equal(captured[0]!.includes("203.0.113.5"), false);
});

test("OAuth mutation limiter returns a no-store 429", async () => {
  const captured: string[] = [];
  const response = await worker.fetch(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "cf-connecting-ip": "192.0.2.10" },
      body: "grant_type=refresh_token",
    }),
    { AUTH_RATE_LIMITER: denyingLimiter(captured) },
    {} as ExecutionContext,
  );
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("cache-control"), "no-store, no-cache");
  assert.equal(captured.length, 1);
  assert.equal(captured[0]!.includes("192.0.2.10"), false);
});
