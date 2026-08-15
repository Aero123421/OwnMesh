import assert from "node:assert/strict";
import test from "node:test";
import {
  applyObservedGeneration,
  classifyWorkspaceAvailability,
  parseWorkspaceGeneration,
  parseWorkspaceId,
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

test("the same generation does not revive a deactivated workspace", () => {
  const generation = "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const deactivated = record({ active: false, local_generation: generation, version: 3 });
  const observed = applyObservedGeneration(deactivated, {
    workspaceId: "ws_dev",
    deviceId: "dev_linux",
    tenantId: "ten_default",
    ownerPrincipalId: "prin_dev",
    generation,
    observedAt: now,
  });
  assert.equal(observed.active, false);
  assert.equal(observed.version, 3);
  assert.equal(workspaceActivationView(observed).activation_state, "unavailable");
  const gate = classifyWorkspaceAvailability(observed, "dev_linux", "ten_default");
  assert.equal(gate.ok, false);
  if (!gate.ok) assert.equal(gate.cause, "inactive");
});

test("a new generation reactivates a deactivated workspace after re-add", () => {
  const revived = applyObservedGeneration(
    record({
      active: false,
      local_generation: "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      version: 3,
    }),
    {
      workspaceId: "ws_dev",
      deviceId: "dev_linux",
      tenantId: "ten_default",
      ownerPrincipalId: "prin_dev",
      generation: "wsg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      observedAt: now,
    },
  );
  assert.equal(revived.active, true);
  assert.equal(revived.local_generation, "wsg_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
  assert.equal(revived.version, 4);
  assert.equal(classifyWorkspaceAvailability(revived, "dev_linux", "ten_default").ok, true);
});

test("parseWorkspaceGeneration rejects non-opaque values", () => {
  assert.equal(parseWorkspaceGeneration("wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), "wsg_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
  assert.equal(parseWorkspaceGeneration("/home/tonakai/Dev"), undefined);
  assert.equal(parseWorkspaceGeneration("not-a-generation"), undefined);
});

test("parseWorkspaceId rejects empty, oversized, and path-like values", () => {
  assert.equal(parseWorkspaceId("ws_dev"), "ws_dev");
  assert.equal(parseWorkspaceId("owner-root"), "owner-root");
  assert.equal(parseWorkspaceId(""), undefined);
  assert.equal(parseWorkspaceId("/home/tonakai/Dev"), undefined);
  assert.equal(parseWorkspaceId("ws other"), undefined);
});
