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
    return this.primary.claim(op);
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
    if (primary) return primary;
    return this.fallback.getByIdempotency(opts);
  }

  async getByCorrelation(correlationId: string) {
    // Post-cutover rows live only in the room; pre-cutover rows only in D1.
    const primary = await this.primary.getByCorrelation(correlationId);
    if (primary) return primary;
    return this.fallback.getByCorrelation(correlationId);
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
   */
  forTenant(tenantId: string, principalId: string): Promise<{ ops: OperationStore; auditCovered: boolean }>;
};

const CUTOVER_CACHE_TTL_MS = 60_000;

export function createOperationStoreResolver(
  env: OperationRoomEnv & { OWNMESH_OPERATION_STORE?: string },
  base: ControlPlaneStore,
): ResolvedOperationStores {
  const mode = resolveOperationStoreMode(env);
  const d1 = new D1OperationStore(base);
  const cutoverCache = new Map<string, { at: number; value: string | null }>();
  return {
    mode,
    async forTenant(tenantId: string, principalId: string) {
      if (mode !== "device_do" || !env.OPERATION_ROOM || !env.SESSION_SECRET) {
        return { ops: d1, auditCovered: false };
      }
      const now = Date.now();
      const cached = cutoverCache.get(tenantId);
      let cutover: string | null | undefined = cached && now - cached.at < CUTOVER_CACHE_TTL_MS
        ? cached.value
        : undefined;
      if (cutover === undefined) {
        try {
          cutover = await base.getOperationStoreCutover(tenantId);
        } catch {
          return { ops: d1, auditCovered: false };
        }
        cutoverCache.set(tenantId, { at: now, value: cutover });
      }
      // Explicit per-tenant escape hatch back to D1.
      if (!cutover || cutover === "d1") return { ops: d1, auditCovered: false };
      const room = new OperationRoomStore(env, tenantId, principalId);
      return { ops: new HybridOperationStore(room, d1), auditCovered: true };
    },
  };
}

/** Ops-room quota mirrors the D1 per-tenant cap source of truth. */
export function operationRoomOpsLimit(env: { MCP_OPS_MAX_PER_TENANT?: string }): number {
  return parseMcpOpsMaxPerTenant(env.MCP_OPS_MAX_PER_TENANT);
}
