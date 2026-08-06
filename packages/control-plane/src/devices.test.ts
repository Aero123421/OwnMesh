/** Device enroll / proof / revoke server contract (cli-auth-09 consumes this). */
import assert from "node:assert/strict";
import test from "node:test";
import { handleDevices } from "./oauth.ts";
import { MemoryStore } from "./store.ts";

async function authedStore() {
  const store = new MemoryStore();
  await store.ensureBootstrap();
  const tok = await store.issueTokens(
    "client_ownmesh_cli",
    "prin_dev",
    "ownmesh.device ownmesh.read offline_access",
  );
  return { store, token: tok.access_token };
}

test("enroll returns challenge shape then proof + revoke persist", async () => {
  const { store, token } = await authedStore();
  const enrollRes = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        name: "desk",
        hostname: "desk.local",
        os: "windows",
        arch: "x64",
        agent_version: "1.0.1",
        protocol_version: "ownmesh.device/1.0",
        public_key: "ab".repeat(32),
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll"),
  );
  assert.equal(enrollRes.status, 201);
  const body = (await enrollRes.json()) as {
    device_id: string;
    enrollment_token: string;
    challenge: { id: string; nonce: string; message: string; expires_at: string };
    connect_path: string;
  };
  assert.match(body.device_id, /^dev_/);
  assert.ok(body.enrollment_token);
  assert.match(body.challenge.id, /^ech_/);
  assert.equal(
    body.challenge.message,
    `ownmesh-device-challenge:${body.challenge.nonce}:${body.device_id}`,
  );
  assert.equal(body.connect_path, "/agent/connect");

  const proofRes = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll/proof", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        device_id: body.device_id,
        challenge_id: body.challenge.id,
        signature: "cd".repeat(64),
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll/proof"),
  );
  assert.equal(proofRes.status, 200);
  const proof = (await proofRes.json()) as { ok: boolean; status: string };
  assert.equal(proof.ok, true);
  assert.equal(proof.status, "active");

  // challenge cannot be reused
  const reuse = await handleDevices(
    new Request("https://cp.test/v1/devices/enroll/proof", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        device_id: body.device_id,
        challenge_id: body.challenge.id,
        signature: "cd".repeat(64),
      }),
    }),
    store,
    new URL("https://cp.test/v1/devices/enroll/proof"),
  );
  assert.equal(reuse.status, 400);

  const list = await handleDevices(
    new Request("https://cp.test/v1/devices", {
      headers: { authorization: `Bearer ${token}` },
    }),
    store,
    new URL("https://cp.test/v1/devices"),
  );
  const listed = (await list.json()) as { devices: { id: string }[] };
  assert.equal(listed.devices.length, 1);

  const rev = await handleDevices(
    new Request("https://cp.test/v1/devices/revoke", {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ id: body.device_id }),
    }),
    store,
    new URL("https://cp.test/v1/devices/revoke"),
  );
  assert.equal(((await rev.json()) as { ok: boolean }).ok, true);
  assert.equal((await store.listDevices("prin_dev")).length, 0);
});
