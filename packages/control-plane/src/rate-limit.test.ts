import assert from "node:assert/strict";
import test from "node:test";
import worker, { type Env } from "./index.ts";

function limiter(
  captured: string[],
  success: boolean,
): NonNullable<Env["MCP_RATE_LIMITER"]> {
  return {
    async limit({ key }) {
      captured.push(key);
      return { success };
    },
  };
}

test("MCP limiter rejects before storage and never exposes the bearer", async () => {
  const credentialKeys: string[] = [];
  const addressKeys: string[] = [];
  const response = await worker.fetch(
    new Request("https://cp.test/mcp", {
      method: "POST",
      headers: {
        authorization: "Bearer at_distinctive_secret",
        "cf-connecting-ip": "192.0.2.20",
      },
      body: "{}",
    }),
    {
      MCP_RATE_LIMITER: limiter(credentialKeys, false),
      MCP_IP_RATE_LIMITER: limiter(addressKeys, true),
    },
    {} as ExecutionContext,
  );
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("retry-after"), "60");
  assert.equal(credentialKeys.length, 1);
  assert.equal(addressKeys.length, 1);
  for (const key of [...credentialKeys, ...addressKeys]) {
    assert.equal(key.includes("at_distinctive_secret"), false);
    assert.equal(key.includes("192.0.2.20"), false);
  }
  assert.ok(addressKeys[0]!.includes(":addr:"));
  assert.ok(credentialKeys[0]!.includes(":cred:"));
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
test("varying Authorization cannot escape the coarse address bucket", async () => {
  const addressKeys = new Set<string>();
  for (const credential of ["Bearer aaa", "Bearer bbb", "Bearer ccc"]) {
    const capturedAddress: string[] = [];
    const capturedCredential: string[] = [];
    await worker.fetch(
      new Request("https://cp.test/mcp", {
        method: "POST",
        headers: { authorization: credential, "cf-connecting-ip": "198.51.100.7" },
        body: "{}",
      }),
      {
        MCP_RATE_LIMITER: limiter(capturedCredential, true),
        MCP_IP_RATE_LIMITER: limiter(capturedAddress, false),
      },
      {} as ExecutionContext,
    );
    const addressKey = capturedAddress.find((key) => key.includes(":addr:"));
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
    { AUTH_RATE_LIMITER: limiter(captured, false) },
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
    { AUTH_RATE_LIMITER: limiter(captured, false) },
    {} as ExecutionContext,
  );
  assert.equal(response.status, 429);
  assert.equal(response.headers.get("cache-control"), "no-store, no-cache");
  assert.equal(captured.length, 1);
  assert.equal(captured[0]!.includes("192.0.2.10"), false);
});
