import assert from "node:assert/strict";
import test from "node:test";
import { __test, MCP_TOOLS } from "./index.ts";

test("refresh token reuse is detected and family revoked", async () => {
  __test.reset();
  const first = __test.issueTokens("client", "user1", "ownmesh.read offline_access");
  const body1 = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: first.refresh_token,
  });
  const res1 = await __test.handleOAuthToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body1,
    }),
  );
  assert.equal(res1.status, 200);
  const rotated = (await res1.json()) as { refresh_token: string; access_token: string };

  // reuse old refresh
  const resReuse = await __test.handleOAuthToken(
    new Request("https://cp.test/oauth/token", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "refresh_token",
        refresh_token: first.refresh_token,
      }),
    }),
  );
  assert.equal(resReuse.status, 400);
  const err = (await resReuse.json()) as { error_description?: string };
  assert.match(err.error_description || "", /reuse/i);

  // new refresh should also be dead after family revoke on reuse path —
  // depending on timing, family revoke marks tokens; ensure old access dead
  assert.equal(__test.getAccess(first.access_token), null);
  // rotated access was revoked as part of family
  assert.equal(__test.getAccess(rotated.access_token), null);
});

test("revoke invalidates access token immediately", async () => {
  __test.reset();
  const tok = __test.issueTokens("c", "u", "ownmesh.read");
  assert.ok(__test.getAccess(tok.access_token));
  await __test.handleOAuthRevoke(
    new Request("https://cp.test/oauth/revoke", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: tok.access_token }),
    }),
  );
  assert.equal(__test.getAccess(tok.access_token), null);
});

test("MCP catalog separates raw shell from structured command", () => {
  const names = MCP_TOOLS.map((t) => t.name);
  assert.ok(names.includes("ownmesh_command_run"));
  assert.ok(names.includes("ownmesh_command_shell"));
  assert.notEqual(
    MCP_TOOLS.find((t) => t.name === "ownmesh_command_run"),
    MCP_TOOLS.find((t) => t.name === "ownmesh_command_shell"),
  );
});

test("write scope required for exec tools helper", () => {
  __test.reset();
  const readOnly = __test.issueTokens("c", "u", "ownmesh.read");
  assert.equal(__test.requireScope(readOnly, "ownmesh.exec"), false);
  const full = __test.issueTokens("c", "u", "ownmesh.write ownmesh.exec");
  assert.equal(__test.requireScope(full, "ownmesh.exec"), true);
});
