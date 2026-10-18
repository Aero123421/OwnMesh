/**
 * OperationStore facade for Issue #224 plan F (P2).
 *
 * Device-routed MCP operation authority behind one interface with two
 * backends:
 * - D1OperationStore: today's D1 authority (default; behavior-identical).
 * - OperationRoomStore: tenant-sharded Durable Object authority
 *   (`OperationRoom`), enabled per tenant via the operation_store_cutover
 *   cursor with D1 fallback for pre-cutover rows (HybridOperationStore).
 *
 * Tenant sharding (not device sharding): id-only lookups (get_operation
 * polls, cross-isolate transitions) always carry the tenant but rarely the
 * device, so tenant rooms keep every lookup routable without a
 * per-operation directory write. Per-device side-effect serialization still
 * holds because each daemon executes a single dispatch lane.
 */

import { internalDoHeaders, sha256Hex } from "./util.ts";
import { parseMcpOpsMaxPerTenant } from "./store.ts";
import type {
  ControlPlaneStore,
  McpOperationRecord,
  McpOperationTransition,
} from "./store.ts";

/**
 * Issue #243: authority resolution fails closed. A cursor read failure, a
 * missing binding, or an authority flip between store resolution and a claim
 * is retryable unavailability, never a silent switch to the other authority.
 * The message classifies as a transient storage error so OAuth/MCP already
 * map it to the shared 503 + Retry-After contract.
 */
export class OperationAuthorityUnavailableError extends Error {
  readonly retryable = true;
  readonly reason: string;

  constructor(reason: string) {
    super(`operation_authority_temporarily_unavailable:${reason}`);
    this.name = "OperationAuthorityUnavailableError";
    this.reason = reason;
  }
}

/**
 * Issue #243: two authorities own the same idempotency key or correlation.
 * Fail closed (`stop`, per the issue) instead of picking a winner whose side
 * effects may already be in flight; the runbook covers reconciliation.
 */
export class OperationAuthorityConflictError extends Error {
  readonly retryable = false;

  constructor(scope: string) {
    super(`operation_authority_conflict:${scope}`);
    this.name = "OperationAuthorityConflictError";
  }
}

function assertSingleOwner(
  primary: McpOperationRecord | null,
  fallback: McpOperationRecord | null,
  scope: string,
): void {
  if (primary && fallback && primary.operation_id !== fallback.operation_id) {
    throw new OperationAuthorityConflictError(scope);
  }
}

export interface OperationStore {
  readonly backend: "d1" | "operation-room";
  claim(op: McpOperationRecord): Promise<
    | { outcome: "created"; op: McpOperationRecord }
    | { outcome: "existing"; op: McpOperationRecord }
  >;
  get(operationId: string): Promise<McpOperationRecord | null>;
  getByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }): Promise<McpOperationRecord | null>;
  getByCorrelation(correlationId: string): Promise<McpOperationRecord | null>;
  put(op: McpOperationRecord): Promise<void>;
  transition(
    operationId: string,
    transition: McpOperationTransition,
    fromStatuses?: string[],
  ): Promise<McpOperationRecord | null>;
  update(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ): Promise<McpOperationRecord | null>;
}

/** Behavior-identical D1/memory adapter (default authority). */
export class D1OperationStore implements OperationStore {
  readonly backend = "d1" as const;
  private readonly store: ControlPlaneStore;

  constructor(store: ControlPlaneStore) {
    this.store = store;
  }

  claim(op: McpOperationRecord) {
    return this.store.claimMcpOperationByIdempotency(op);
  }

  get(operationId: string) {
    return this.store.getMcpOperation(operationId);
  }

  getByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }) {
    return this.store.getMcpOperationByIdempotency(opts);
  }

  getByCorrelation(correlationId: string) {
    return this.store.getMcpOperationByCorrelation(correlationId);
  }

  put(op: McpOperationRecord) {
    return this.store.putMcpOperation(op);
  }

  transition(operationId: string, transition: McpOperationTransition, fromStatuses?: string[]) {
    return this.store.transitionMcpOperation(operationId, transition, fromStatuses);
  }

  update(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ) {
    return this.store.updateMcpOperation(operationId, patch, fromStatuses, expectedData);
  }
}

export type OperationRoomEnv = {
  OPERATION_ROOM?: {
    idFromName(name: string): unknown;
    get(id: unknown): {
      fetch(request: Request): Promise<Response>;
    };
  };
  SESSION_SECRET?: string;
  MCP_OPS_MAX_PER_TENANT?: string;
};

const OP_STORE_TIMEOUT_MS = 10_000;
const OP_STORE_MAX_BODY_BYTES = 1_000_000;

function operationRoomName(tenantId: string): string {
  return `ops:v1:${tenantId}`;
}

/**
 * Authenticated Worker/DO -> OperationRoom fetch. Mirrors routeToDeviceRoom's
 * internal-context binding (op/method/path/body/tenant), same fail-closed
 * posture: transport errors and non-OK statuses surface as thrown errors so
 * callers fail closed instead of inventing operation state.
 */
export async function fetchOperationRoom(
  env: OperationRoomEnv,
  tenantId: string,
  principalId: string,
  action: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (!env.OPERATION_ROOM) throw new Error("operation_room_unbound");
  if (!env.SESSION_SECRET) throw new Error("session_secret_unbound");
  if (!tenantId) throw new Error("operation_room_tenant_required");
  const stub = env.OPERATION_ROOM.get(env.OPERATION_ROOM.idFromName(operationRoomName(tenantId)));
  const raw = JSON.stringify({ action, ...body });
  if (new TextEncoder().encode(raw).byteLength > OP_STORE_MAX_BODY_BYTES) {
    throw new Error("operation_room_payload_too_large");
  }
  const path = "/op-store";
  const headers = await internalDoHeaders(env.SESSION_SECRET, {
    op: "op_store",
    device_id: "",
    principal_id: principalId,
    tenant_id: tenantId,
    correlation_id: typeof body.correlation_id === "string" ? body.correlation_id : "",
    method: "POST",
    path,
    body_sha256: await sha256Hex(raw),
  });
  const res = await stub.fetch(
    new Request(`https://operation-room${path}?tenant_id=${encodeURIComponent(tenantId)}`, {
      method: "POST",
      headers,
      body: raw,
    }),
  );
  const text = await res.text();
  if (!res.ok) {
    throw new Error(`operation_room_${res.status}:${text.slice(0, 200)}`);
  }
  const parsed = JSON.parse(text) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("operation_room_malformed_response");
  }
  return parsed as Record<string, unknown>;
}

/** OperationStore backed by the tenant OperationRoom (with a fetch timeout). */
export class OperationRoomStore implements OperationStore {
  readonly backend = "operation-room" as const;
  private readonly env: OperationRoomEnv;
  private readonly tenantId: string;
  private readonly principalId: string;

  constructor(env: OperationRoomEnv, tenantId: string, principalId: string) {
    this.env = env;
    this.tenantId = tenantId;
    this.principalId = principalId;
  }

  private call(action: string, body: Record<string, unknown>) {
    const started = Date.now();
    return Promise.race([
      fetchOperationRoom(this.env, this.tenantId, this.principalId, action, body),
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(
            new Error(
              `operation_room_timeout:action=${action}:elapsed_ms=${Date.now() - started}`,
            ),
          );
        }, OP_STORE_TIMEOUT_MS);
      }),
    ]);
  }

  private static op(value: unknown): McpOperationRecord {
    return value as McpOperationRecord;
  }

  async claim(op: McpOperationRecord) {
    const res = await this.call("claim", { op });
    return {
      outcome: res.outcome as "created" | "existing",
      op: OperationRoomStore.op(res.op),
    };
  }

  async get(operationId: string) {
    const res = await this.call("get", { operation_id: operationId });
    return res.op ? OperationRoomStore.op(res.op) : null;
  }

  async getByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }) {
    const res = await this.call("get_by_idempotency", {
      principal_id: opts.principalId,
      device_id: opts.deviceId,
      idempotency_key: opts.idempotencyKey,
    });
    return res.op ? OperationRoomStore.op(res.op) : null;
  }

  async getByCorrelation(correlationId: string) {
    const res = await this.call("get_by_correlation", { correlation_id: correlationId });
    return res.op ? OperationRoomStore.op(res.op) : null;
  }

  /**
   * Issue #243: bounded occupancy probe. Rollback (`cutover_at = 'd1'`) may
   * only become D1-authoritative once the room is drained, so resolution
   * needs a cheap "does this tenant still own rows?" answer.
   */
  async hasRows(): Promise<boolean> {
    const res = await this.call("has_rows", {});
    return res.has_rows === true;
  }

  async put(op: McpOperationRecord): Promise<void> {
    await this.call("put", { op });
  }

  async transition(operationId: string, transition: McpOperationTransition, fromStatuses?: string[]) {
    const res = await this.call("transition", {
      operation_id: operationId,
      transition,
      from_statuses: fromStatuses ?? null,
    });
    return res.op ? OperationRoomStore.op(res.op) : null;
  }

  async update(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ) {
    const res = await this.call("update", {
      operation_id: operationId,
      patch,
      from_statuses: fromStatuses ?? null,
      expected_data: expectedData ?? null,
    });
    return res.op ? OperationRoomStore.op(res.op) : null;
  }
}

/**
 * Primary (room) with D1 fallback for pre-cutover rows: reads fall back on a
 * miss, claim consults D1 for an idempotency owner before creating, and a
 * transition miss retries once against D1 (in-flight ops at cutover time).
 * Writes never fan out to both authorities.
 *
 * Issue #243: ownership is verified against both authorities after a create
 * and whenever an ownership key is looked up, so a concurrent claim on the
 * other side of a cutover fails closed instead of leaving two owners.
 */
export class HybridOperationStore implements OperationStore {
  readonly backend = "operation-room" as const;
  private readonly primary: OperationStore;
  private readonly fallback: OperationStore;

  constructor(primary: OperationStore, fallback: OperationStore) {
    this.primary = primary;
    this.fallback = fallback;
  }

  async claim(op: McpOperationRecord) {
    if (op.idempotency_key) {
      const owner = await this.fallback.getByIdempotency({
        principalId: op.principal_id,
        tenantId: op.tenant_id,
        deviceId: op.device_id || "",
        idempotencyKey: op.idempotency_key,
      });
      if (owner) return { outcome: "existing" as const, op: owner };
    } else {
      const byId = await this.fallback.get(op.operation_id);
      if (byId) return { outcome: "existing" as const, op: byId };
    }
    const created = await this.primary.claim(op);
    if (created.outcome !== "created") return created;
    // Post-create fence: if the D1 side claimed the same key concurrently
    // (cutover propagation), stop before dispatch rather than dual-owning it.
    const [byId, byIdempotency] = await Promise.all([
      this.fallback.get(op.operation_id),
      op.idempotency_key
        ? this.fallback.getByIdempotency({
            principalId: op.principal_id,
            tenantId: op.tenant_id,
            deviceId: op.device_id || "",
            idempotencyKey: op.idempotency_key,
          })
        : Promise.resolve(null),
    ]);
    const foreign = byId ?? byIdempotency;
    if (foreign && foreign.operation_id !== created.op.operation_id) {
      throw new OperationAuthorityConflictError(
        `claim:${op.idempotency_key || op.operation_id}`,
      );
    }
    return created;
  }

  async get(operationId: string) {
    // Post-cutover rows live only in the room; pre-cutover rows only in D1.
    const primary = await this.primary.get(operationId);
    if (primary) return primary;
    return this.fallback.get(operationId);
  }

  async getByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }) {
    const primary = await this.primary.getByIdempotency(opts);
    const fallback = await this.fallback.getByIdempotency(opts);
    assertSingleOwner(primary, fallback, "idempotency");
    return primary ?? fallback;
  }

  async getByCorrelation(correlationId: string) {
    // Post-cutover rows live only in the room; pre-cutover rows only in D1.
    const primary = await this.primary.getByCorrelation(correlationId);
    const fallback = await this.fallback.getByCorrelation(correlationId);
    assertSingleOwner(primary, fallback, "correlation");
    return primary ?? fallback;
  }

  async put(op: McpOperationRecord) {
    // Create-only across both authorities: a D1-owned id keeps the hybrid
    // from shadowing it with a room duplicate.
    const existing = await this.fallback.get(op.operation_id);
    if (existing) throw new Error(`mcp_operation_exists:${op.operation_id}`);
    return this.primary.put(op);
  }

  async transition(operationId: string, transition: McpOperationTransition, fromStatuses?: string[]) {
    const primary = await this.primary.transition(operationId, transition, fromStatuses);
    if (primary) return primary;
    return this.fallback.transition(operationId, transition, fromStatuses);
  }

  async update(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ) {
    // Like transition: in-flight pre-cutover rows still terminalize on D1.
    const primary = await this.primary.update(operationId, patch, fromStatuses, expectedData);
    if (primary) return primary;
    return this.fallback.update(operationId, patch, fromStatuses, expectedData);
  }
}

/**
 * Issue #243: rollback (`cutover_at = 'd1'`) while the room still owns rows.
 * New ownership is refused until the operator drains/reconciles the room, but
 * reads and terminal transitions fall through both authorities so DO-only
 * operations stay visible and in-flight work converges. `auditCovered` is
 * false in this state, so the D1 audit row is always written.
 */
export class RollbackPendingOperationStore implements OperationStore {
  readonly backend = "d1" as const;
  private readonly d1: OperationStore;
  private readonly room: OperationStore;

  constructor(d1: OperationStore, room: OperationStore) {
    this.d1 = d1;
    this.room = room;
  }

  claim(_op: McpOperationRecord): Promise<never> {
    return Promise.reject(new OperationAuthorityUnavailableError("rollback_pending"));
  }

  put(_op: McpOperationRecord): Promise<void> {
    return Promise.reject(new OperationAuthorityUnavailableError("rollback_pending"));
  }

  async get(operationId: string) {
    const d1 = await this.d1.get(operationId);
    if (d1) return d1;
    return this.room.get(operationId);
  }

  async getByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }) {
    const d1 = await this.d1.getByIdempotency(opts);
    const room = await this.room.getByIdempotency(opts);
    assertSingleOwner(d1, room, "rollback:idempotency");
    return d1 ?? room;
  }

  async getByCorrelation(correlationId: string) {
    const d1 = await this.d1.getByCorrelation(correlationId);
    const room = await this.room.getByCorrelation(correlationId);
    assertSingleOwner(d1, room, "rollback:correlation");
    return d1 ?? room;
  }

  async transition(operationId: string, transition: McpOperationTransition, fromStatuses?: string[]) {
    const d1 = await this.d1.transition(operationId, transition, fromStatuses);
    if (d1) return d1;
    return this.room.transition(operationId, transition, fromStatuses);
  }

  async update(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ) {
    const d1 = await this.d1.update(operationId, patch, fromStatuses, expectedData);
    if (d1) return d1;
    return this.room.update(operationId, patch, fromStatuses, expectedData);
  }
}

/**
 * Issue #243: fresh authority fence around ownership writes. A store resolved
 * from a cached read must re-check the live cursor (and room occupancy) before
 * creating anything, so a cutover or rollback that lands in between surfaces
 * as a retryable error instead of a split authority. `afterClaim` runs after a
 * successful create and lets the D1 authority detect a concurrent room owner.
 */
export class ClaimFencedOperationStore implements OperationStore {
  private readonly inner: OperationStore;
  private readonly fence: () => Promise<void>;
  private readonly afterClaim: ((op: McpOperationRecord) => Promise<void>) | null;

  constructor(
    inner: OperationStore,
    fence: () => Promise<void>,
    afterClaim?: (op: McpOperationRecord) => Promise<void>,
  ) {
    this.inner = inner;
    this.fence = fence;
    this.afterClaim = afterClaim ?? null;
  }

  get backend() {
    return this.inner.backend;
  }

  async claim(op: McpOperationRecord) {
    await this.fence();
    const result = await this.inner.claim(op);
    // Run on both outcomes: a retry that returns an existing D1 owner can
    // still be racing a concurrent room owner (Issue #243).
    if (this.afterClaim) await this.afterClaim(result.op);
    return result;
  }

  async put(op: McpOperationRecord): Promise<void> {
    await this.fence();
    await this.inner.put(op);
  }

  get(operationId: string) {
    return this.inner.get(operationId);
  }

  getByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }) {
    return this.inner.getByIdempotency(opts);
  }

  getByCorrelation(correlationId: string) {
    return this.inner.getByCorrelation(correlationId);
  }

  transition(operationId: string, transition: McpOperationTransition, fromStatuses?: string[]) {
    return this.inner.transition(operationId, transition, fromStatuses);
  }

  update(
    operationId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ) {
    return this.inner.update(operationId, patch, fromStatuses, expectedData);
  }
}

export type OperationStoreMode = "d1" | "device_do";

/** Env flag only; unknown values fail safe to D1 authority. */
export function resolveOperationStoreMode(env: { OWNMESH_OPERATION_STORE?: string }): OperationStoreMode {
  return env.OWNMESH_OPERATION_STORE === "device_do" ? "device_do" : "d1";
}

export type ResolvedOperationStores = {
  mode: OperationStoreMode;
  /**
   * Authority for one tenant. device_do + cutover cursor -> Hybrid room
   * store; otherwise the D1 adapter. The room store doubles as the audit
   * trail for device-routed calls (auditCovered), so per-call D1 audit rows
   * are skipped only then.
   *
   * Issue #243: unknown authority (cursor read failure, missing bindings),
   * rollback-pending tenants, and authority flips between resolution and a
   * claim throw `OperationAuthorityUnavailableError` instead of silently
   * switching stores.
   */
  forTenant(tenantId: string, principalId: string): Promise<{ ops: OperationStore; auditCovered: boolean }>;
};

/** Bounded retry for the one row that decides authority. */
const CUTOVER_READ_ATTEMPTS = 2;

async function readCutoverBounded(
  base: ControlPlaneStore,
  tenantId: string,
): Promise<string | null> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < CUTOVER_READ_ATTEMPTS; attempt += 1) {
    try {
      return await base.getOperationStoreCutover(tenantId);
    } catch (error) {
      lastError = error;
    }
  }
  throw new OperationAuthorityUnavailableError(
    `cutover_unreadable:${lastError instanceof Error ? lastError.name : "error"}`,
  );
}

function isRoomAuthority(cutover: string | null): boolean {
  return typeof cutover === "string" && cutover.length > 0 && cutover !== "d1";
}

export function createOperationStoreResolver(
  env: OperationRoomEnv & { OWNMESH_OPERATION_STORE?: string },
  base: ControlPlaneStore,
): ResolvedOperationStores {
  const mode = resolveOperationStoreMode(env);
  const d1 = new D1OperationStore(base);

  const roomStore = (tenantId: string, principalId: string) =>
    new OperationRoomStore(env, tenantId, principalId);

  const roomHasRows = async (tenantId: string, principalId: string): Promise<boolean> => {
    try {
      return await roomStore(tenantId, principalId).hasRows();
    } catch {
      // Occupancy is unknown: never assume the room is empty (that would hand
      // ownership to D1 while DO-only rows exist).
      throw new OperationAuthorityUnavailableError("room_probe_failed");
    }
  };

  // Post-create fence for the D1 authority: if the room claimed the same
  // operation/idempotency concurrently (cutover propagation), stop before
  // dispatch rather than silently dual-owning the key.
  const assertRoomOwnsNothing = async (
    room: OperationStore,
    op: McpOperationRecord,
  ): Promise<void> => {
    let byId: McpOperationRecord | null = null;
    let byIdempotency: McpOperationRecord | null = null;
    try {
      [byId, byIdempotency] = await Promise.all([
        room.get(op.operation_id),
        op.idempotency_key
          ? room.getByIdempotency({
              principalId: op.principal_id,
              tenantId: op.tenant_id,
              deviceId: op.device_id || "",
              idempotencyKey: op.idempotency_key,
            })
          : Promise.resolve(null),
      ]);
    } catch {
      throw new OperationAuthorityUnavailableError("room_unreadable");
    }
    const owner = byId ?? byIdempotency;
    if (owner && owner.operation_id !== op.operation_id) {
      throw new OperationAuthorityConflictError(
        `claim:${op.idempotency_key || op.operation_id}`,
      );
    }
  };

  const fenceClaim = async (
    expected: "d1" | "room",
    tenantId: string,
    principalId: string,
  ): Promise<void> => {
    const cutover = await readCutoverBounded(base, tenantId);
    if (isRoomAuthority(cutover)) {
      if (expected !== "room") {
        throw new OperationAuthorityUnavailableError("authority_changed");
      }
      return;
    }
    if (expected === "room") {
      throw new OperationAuthorityUnavailableError("authority_changed");
    }
    if (await roomHasRows(tenantId, principalId)) {
      throw new OperationAuthorityUnavailableError("rollback_pending");
    }
  };

  return {
    mode,
    async forTenant(tenantId: string, principalId: string) {
      if (mode !== "device_do") {
        return { ops: d1, auditCovered: false };
      }
      if (!env.OPERATION_ROOM || !env.SESSION_SECRET) {
        // device_do was requested but the room cannot be consulted, so the
        // tenant's authority is unknowable. Never degrade to D1.
        throw new OperationAuthorityUnavailableError("binding_missing");
      }
      const cutover = await readCutoverBounded(base, tenantId);
      const room = roomStore(tenantId, principalId);
      if (isRoomAuthority(cutover)) {
        const hybrid = new HybridOperationStore(room, d1);
        return {
          ops: new ClaimFencedOperationStore(
            hybrid,
            () => fenceClaim("room", tenantId, principalId),
          ),
          auditCovered: true,
        };
      }
      if (await roomHasRows(tenantId, principalId)) {
        return {
          ops: new RollbackPendingOperationStore(d1, room),
          auditCovered: false,
        };
      }
      return {
        ops: new ClaimFencedOperationStore(
          d1,
          () => fenceClaim("d1", tenantId, principalId),
          (op) => assertRoomOwnsNothing(room, op),
        ),
        auditCovered: false,
      };
    },
  };
}

/** Ops-room quota mirrors the D1 per-tenant cap source of truth. */
export function operationRoomOpsLimit(env: { MCP_OPS_MAX_PER_TENANT?: string }): number {
  return parseMcpOpsMaxPerTenant(env.MCP_OPS_MAX_PER_TENANT);
}
