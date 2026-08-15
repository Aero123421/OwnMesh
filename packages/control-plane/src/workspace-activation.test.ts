import assert from "node:assert/strict";
import test from "node:test";
import {
  applyObservedGeneration,
  classifyWorkspaceAvailability,
  parseWorkspaceGeneration,
  workspaceActivationView,
} from "./workspace-activation.ts";
import type { WorkspaceRecord } from "./store.ts";

const now = "2026-08-15T00:00:00.000Z";

function record(patch: Partial<WorkspaceRecord> = {}): WorkspaceRecord {
  return {
    workspace_id: "ws_dev",
    tenant_id: "ten_default",
    device_id: "dev_linux",
    owner_principal_id: "prin_dev",
    version: 1,
    active: false,
    created_at: now,
    updated_at: now,
    ...patch,
  };
}

test("a reserved workspace is pending until a generation is observed", () => {
  const reserved = record();
  assert.equal(workspaceActivationView(reserved).activation_state, "pending_activation");
  const gate = classifyWorkspaceAvailability(reserved, "dev_linux", "ten_default");
  assert.equal(gate.ok, false);
  if (!gate.ok) {
    assert.equal(gate.cause, "pending_activation");
    assert.equal(gate.next_action, "retry_activation");
  }
});

test("observing a generation activates the reserved workspace", () => {
  const activated = applyObservedGeneration(record(), {
    workspaceId: "ws_dev",
    deviceId: "dev_linux",
    tenantId: "ten_default",
    ownerPrincipalId: "prin_dev",
    generation: "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    observedAt: now,
  });
  assert.equal(activated.active, true);
  assert.equal(activated.local_generation, "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(activated.version, 2);
  assert.equal(workspaceActivationView(activated).activation_state, "active");
  assert.equal(classifyWorkspaceAvailability(activated, "dev_linux", "ten_default").ok, true);
});

test("parseWorkspaceGeneration rejects non-opaque values", () => {
  assert.equal(parseWorkspaceGeneration("wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(parseWorkspaceGeneration("/home/tonakai/Dev"), undefined);
  assert.equal(parseWorkspaceGeneration("not-a-generation"), undefined);
});
