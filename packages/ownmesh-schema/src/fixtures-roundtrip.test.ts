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
});
