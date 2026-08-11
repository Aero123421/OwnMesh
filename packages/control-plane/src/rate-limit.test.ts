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
      headers: { authorization: "Bearer at_distinctive_secret" },
      body: "{}",
    }),
    { MCP_RATE_LIMITER: denyingLimiter(captured) },
    {} as ExecutionContext,
  );
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("retry-after"), "60");
  assert.equal(captured.length, 1);
  assert.equal(captured[0]!.includes("at_distinctive_secret"), false);
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
