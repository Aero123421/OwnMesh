import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { describe, it } from "node:test";
import {
  parseEnvelope,
  serializeEnvelope,
  PROTOCOL_DEVICE_V1,
} from "./envelope.ts";
import {
  OPERATION_CONTRACT_V1,
  parseOperationEnvelope,
  serializeOperationEnvelope,
} from "./operation.ts";
import {
  parseApprovalId,
  parseCursor,
  parseDeviceId,
  parseGrantId,
  parseMembershipId,
  parseOperationId,
  parsePolicyId,
  parsePrincipalId,
  parseRuleId,
  parseSessionId,
  parseTenantId,
  parseWorkspaceId,
  parseAuditEventId,
  parseMessageId,
} from "./ids.ts";
import { FIXTURES_DIR } from "./paths.ts";
import type {
  Approval,
  AuditEvent,
  CapabilityGrant,
  Device,
  ErrorEnvelope,
  Membership,
  Operation,
  PageRequest,
  PolicyRule,
  Principal,
  ProtocolEnvelope,
  Session,
  Tenant,
  Workspace,
} from "./types.ts";

function readJson(name: string): unknown {
  const p = path.join(FIXTURES_DIR, name);
  return JSON.parse(fs.readFileSync(p, "utf8")) as unknown;
}

function writeAndReload(name: string, value: unknown): unknown {
  const encoded = `${JSON.stringify(value, null, 2)}\n`;
  const tmp = path.join(FIXTURES_DIR, `${name}.roundtrip-tmp`);
  fs.writeFileSync(tmp, encoded, "utf8");
  try {
    return JSON.parse(fs.readFileSync(tmp, "utf8")) as unknown;
  } finally {
    fs.rmSync(tmp, { force: true });
  }
}

function assertDeepEqualRoundTrip(name: string, value: unknown): void {
  const original = readJson(name);
  assert.deepEqual(value, original, `parsed fixture mismatch: ${name}`);
  const reloaded = writeAndReload(name, value);
  assert.deepEqual(reloaded, original, `write round-trip mismatch: ${name}`);
}

describe("shared fixture round-trip", () => {
  it("tenant", () => {
    const t = readJson("tenant.json") as Tenant;
    parseTenantId(t.id);
    if (t.default_policy_id) parsePolicyId(t.default_policy_id);
    assertDeepEqualRoundTrip("tenant.json", t);
  });

  it("principal", () => {
    const p = readJson("principal.json") as Principal;
    parsePrincipalId(p.id);
    parseTenantId(p.tenant_id);
    assertDeepEqualRoundTrip("principal.json", p);
  });

  it("membership", () => {
    const m = readJson("membership.json") as Membership;
    parseMembershipId(m.id);
    assertDeepEqualRoundTrip("membership.json", m);
  });

  it("device", () => {
    const d = readJson("device.json") as Device;
    parseDeviceId(d.id);
    assertDeepEqualRoundTrip("device.json", d);
  });

  it("workspace", () => {
    const w = readJson("workspace.json") as Workspace;
    parseWorkspaceId(w.id);
    assertDeepEqualRoundTrip("workspace.json", w);
  });

  it("capability_grant", () => {
    const g = readJson("capability_grant.json") as CapabilityGrant;
    parseGrantId(g.id);
    assertDeepEqualRoundTrip("capability_grant.json", g);
  });

  it("policy_rule", () => {
    const r = readJson("policy_rule.json") as PolicyRule;
    parseRuleId(r.id);
    assertDeepEqualRoundTrip("policy_rule.json", r);
  });

  it("approval", () => {
    const a = readJson("approval.json") as Approval;
    parseApprovalId(a.id);
    assertDeepEqualRoundTrip("approval.json", a);
  });

  it("operation", () => {
    const o = readJson("operation.json") as Operation;
    parseOperationId(o.id);
    assertDeepEqualRoundTrip("operation.json", o);
  });

  it("session", () => {
    const s = readJson("session.json") as Session;
    parseSessionId(s.session_id);
    assertDeepEqualRoundTrip("session.json", s);
  });

  it("audit_event", () => {
    const a = readJson("audit_event.json") as AuditEvent;
    parseAuditEventId(a.id);
    assertDeepEqualRoundTrip("audit_event.json", a);
  });

  it("error_envelope", () => {
    const e = readJson("error_envelope.json") as ErrorEnvelope;
    assert.equal(e.error.code, "OWNMESH_E_DEVICE_OFFLINE");
    assertDeepEqualRoundTrip("error_envelope.json", e);
  });

  it("page_request", () => {
    const p = readJson("page_request.json") as PageRequest;
    if (p.cursor) parseCursor(p.cursor);
    assertDeepEqualRoundTrip("page_request.json", p);
  });

  it("protocol_envelope", () => {
    const raw = fs.readFileSync(path.join(FIXTURES_DIR, "protocol_envelope.json"), "utf8");
    const env = parseEnvelope(raw);
    assert.equal(env.protocol, PROTOCOL_DEVICE_V1);
    parseMessageId(env.message_id);
    parseDeviceId(env.device_id);
    const pretty = serializeEnvelope(env);
    const again = parseEnvelope(pretty);
    assert.deepEqual(again, env);
    const original = JSON.parse(raw) as ProtocolEnvelope;
    assert.deepEqual(env, original);
  });

  for (const name of [
    "operation_request_envelope.json",
    "operation_progress_envelope.json",
    "operation_event_envelope.json",
    "operation_result_envelope.json",
  ]) {
    it(name.replace(".json", ""), () => {
      const raw = fs.readFileSync(path.join(FIXTURES_DIR, name), "utf8");
      const env = parseOperationEnvelope(raw);
      assert.equal(env.payload.operation_contract, OPERATION_CONTRACT_V1);
      assert.equal(env.correlation_id, env.payload.operation_id);
      const pretty = serializeOperationEnvelope(env);
      assert.deepEqual(parseOperationEnvelope(pretty), env);
      assert.deepEqual(env, JSON.parse(raw));
    });
  }

  it("operation contract rejects unknown fields and binding drift", () => {
    const raw = readJson("operation_request_envelope.json") as Record<string, unknown>;
    const unknown = structuredClone(raw);
    (unknown.payload as Record<string, unknown>).force_allow = true;
    assert.throws(() => parseOperationEnvelope(unknown), /unknown field 'force_allow'/);

    const mismatch = structuredClone(raw);
    mismatch.correlation_id = "op_different";
    assert.throws(() => parseOperationEnvelope(mismatch), /correlation_id must equal/);

    const noExpiry = structuredClone(raw);
    delete noExpiry.expires_at;
    assert.throws(() => parseOperationEnvelope(noExpiry), /requires expires_at/);

    const nullExpiry = structuredClone(raw);
    nullExpiry.expires_at = null;
    assert.throws(() => parseOperationEnvelope(nullExpiry), /expires_at/);

    for (const invalidTimestamp of ["2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z"]) {
      const invalid = structuredClone(raw);
      invalid.sent_at = invalidTimestamp;
      assert.throws(() => parseOperationEnvelope(invalid), /RFC3339 timestamp/);
    }

    const oversizedCapability = structuredClone(raw);
    (oversizedCapability.payload as Record<string, unknown>).capability = "x".repeat(129);
    assert.throws(() => parseOperationEnvelope(oversizedCapability), /exceeds 128/);

    const unsafeSeq = structuredClone(raw);
    unsafeSeq.seq = Number.MAX_SAFE_INTEGER + 1;
    assert.throws(() => parseOperationEnvelope(unsafeSeq), /safe integer/);

    const completed = readJson("operation_result_envelope.json") as Record<string, unknown>;
    (completed.payload as Record<string, unknown>).error = {
      code: "OWNMESH_E_INTERNAL",
      message: "must not accompany success",
      retryable: false,
    };
    assert.throws(() => parseOperationEnvelope(completed), /forbids error/);

    const nullWorkspace = structuredClone(raw);
    (nullWorkspace.payload as Record<string, unknown>).workspace_id = null;
    assert.throws(() => parseOperationEnvelope(nullWorkspace), /workspace_id/);

    const progress = readJson("operation_progress_envelope.json") as Record<string, unknown>;
    for (const field of ["summary", "details"]) {
      const invalid = structuredClone(progress);
      (invalid.payload as Record<string, unknown>)[field] = null;
      assert.throws(() => parseOperationEnvelope(invalid), new RegExp(field));
    }

    const nullResult = readJson("operation_result_envelope.json") as Record<string, unknown>;
    (nullResult.payload as Record<string, unknown>).result = null;
    assert.throws(() => parseOperationEnvelope(nullResult), /result/);
  });
});
