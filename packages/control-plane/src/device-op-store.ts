/**
 * Tenant-sharded durable operation log for Issue #224 plan F (P2).
 *
 * Authority for MCP operation rows when `OWNMESH_OPERATION_STORE=device_do`
 * with a per-tenant cutover cursor. Lives in a dedicated `OperationRoom`
 * Durable Object (one per tenant), NOT in the device room: id-only lookups
 * (get_operation polls, cross-isolate transitions) always carry the tenant
 * but rarely the device, so tenant sharding keeps every lookup routable
 * without a per-operation directory write. Per-device side-effect
 * serialization still holds because the daemon executes one lane per device.
 *
 * Storage layout (all values bounded JSON via boundMcpOperationRecord):
 * - `dxop:v1:<tenant>:<operation_id>` -> McpOperationRecord
 * - `dxidem:v1:<tenant>\0<principal>\0<device>\0<key>` -> operation_id
 * - `dxcorr:v1:<tenant>:<correlation_id>` -> operation_id
 * - `dxcnt:v1:<tenant>` -> number (admission occupancy)
 *
 * Crash consistency: DO events run serially, so sequential puts within one
 * handler cannot interleave. A crash between index puts heals via TTL prune
 * (orphan rows are listable; dangling indexes resolve to nothing and are
 * overwritten on key reuse).
 */

import {
  boundMcpOperationRecord,
  hasMcpIdempotencyReceipt,
  isTerminalMcpStatus,
  mcpOpAgeMs,
  nowIso,
  MCP_OPS_MAINTENANCE_BATCH,
  MCP_OPS_RESULT_TTL_MS,
  MCP_OPS_TOMBSTONE_TTL_MS,
  type McpOperationRecord,
  type McpOperationTransition,
} from "./store.ts";

/** Minimal key-value surface (subset of Durable Object storage + memory). */
export interface DeviceOpStorage {
  get<T = unknown>(key: string): Promise<T | undefined>;
  put(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<boolean | void>;
  list?(prefix: string, limit?: number): Promise<string[]>;
}

const OP_PREFIX = "dxop:v1:";
const IDEM_PREFIX = "dxidem:v1:";
/** NUL separator: ids never contain it, so index keys cannot collide. */
const SEP = "\u0000";

const CORR_PREFIX = "dxcorr:v1:";
const COUNT_PREFIX = "dxcnt:v1:";

const TERMINAL_STATUSES = new Set([
  "completed",
  "failed",
  "denied",
  "cancelled",
  "device_offline",
]);

function opKey(tenantId: string, operationId: string): string {
  return `${OP_PREFIX}${tenantId}:${operationId}`;
}

function idemKey(tenantId: string, principalId: string, deviceId: string, key: string): string {
  return `${IDEM_PREFIX}${tenantId}${SEP}${principalId}${SEP}${deviceId}${SEP}${key}`;
}

function corrKey(tenantId: string, correlationId: string): string {
  return `${CORR_PREFIX}${tenantId}:${correlationId}`;
}

function countKey(tenantId: string): string {
  return `${COUNT_PREFIX}${tenantId}`;
}

function cloneRecord(op: McpOperationRecord): McpOperationRecord {
  return {
    ...op,
    data: { ...(op.data || {}) },
    warnings: [...(op.warnings || [])],
    action: op.action ? { ...op.action } : op.action,
  };
}

export type DeviceOpClaimResult =
  | { outcome: "created"; op: McpOperationRecord }
  | { outcome: "existing"; op: McpOperationRecord };

export class DeviceOperationLog {
  private readonly storage: DeviceOpStorage;
  private readonly opsLimit: number;

  constructor(storage: DeviceOpStorage, opsLimit: number) {
    this.storage = storage;
    this.opsLimit = Math.max(1, Math.floor(opsLimit));
  }

  private async count(tenantId: string): Promise<number> {
    const raw = await this.storage.get<unknown>(countKey(tenantId));
    return typeof raw === "number" && Number.isFinite(raw) && raw >= 0 ? Math.floor(raw) : 0;
  }

  async get(operationId: string, tenantId: string): Promise<McpOperationRecord | null> {
    const row = await this.storage.get<McpOperationRecord>(opKey(tenantId, operationId));
    return row ? cloneRecord(row) : null;
  }

  /** Create-only insert. Throws mcp_operation_exists / idempotency / quota like D1. */
  async put(op: McpOperationRecord): Promise<void> {
    const bounded = boundMcpOperationRecord(op);
    if (await this.storage.get(opKey(bounded.tenant_id, bounded.operation_id))) {
      throw new Error(`mcp_operation_exists:${bounded.operation_id}`);
    }
    if (bounded.idempotency_key) {
      const ownerId = await this.storage.get<string>(
        idemKey(bounded.tenant_id, bounded.principal_id, bounded.device_id || "", bounded.idempotency_key),
      );
      if (ownerId) throw new Error(`mcp_operation_idempotency_exists:${bounded.idempotency_key}`);
    }
    const occupancy = await this.count(bounded.tenant_id);
    if (occupancy >= this.opsLimit) {
      throw new Error(`mcp_operation_quota_exceeded:tenant=${bounded.tenant_id}:max=${this.opsLimit}`);
    }
    await this.storage.put(opKey(bounded.tenant_id, bounded.operation_id), bounded);
    if (bounded.idempotency_key) {
      await this.storage.put(
        idemKey(bounded.tenant_id, bounded.principal_id, bounded.device_id || "", bounded.idempotency_key),
        bounded.operation_id,
      );
    }
    if (bounded.correlation_id) {
      await this.storage.put(corrKey(bounded.tenant_id, bounded.correlation_id), bounded.operation_id);
    }
    await this.storage.put(countKey(bounded.tenant_id), occupancy + 1);
  }

  async getByIdempotency(opts: {
    principalId: string;
    tenantId: string;
    deviceId: string;
    idempotencyKey: string;
  }): Promise<McpOperationRecord | null> {
    if (!opts.idempotencyKey) return null;
    const operationId = await this.storage.get<string>(
      idemKey(opts.tenantId, opts.principalId, opts.deviceId || "", opts.idempotencyKey),
    );
    if (!operationId) return null;
    const op = await this.get(operationId, opts.tenantId);
    if (!op) return null;
    // Point-exact the 30-day boundary like D1: a closed-window tombstone no
    // longer owns its key.
    if (op.status === "tombstone" && mcpOpAgeMs(op) > MCP_OPS_TOMBSTONE_TTL_MS) {
      await this.deleteRow(op);
      return null;
    }
    return op;
  }

  async getByCorrelation(correlationId: string, tenantId: string): Promise<McpOperationRecord | null> {
    if (!correlationId) return null;
    const operationId = await this.storage.get<string>(corrKey(tenantId, correlationId));
    if (!operationId) return null;
    return this.get(operationId, tenantId);
  }

  async claim(op: McpOperationRecord): Promise<DeviceOpClaimResult> {
    const bounded = boundMcpOperationRecord(op);
    if (bounded.idempotency_key) {
      const existing = await this.getByIdempotency({
        principalId: bounded.principal_id,
        tenantId: bounded.tenant_id,
        deviceId: bounded.device_id || "",
        idempotencyKey: bounded.idempotency_key,
      });
      if (existing) return { outcome: "existing", op: existing };
    }
    try {
      await this.put(bounded);
    } catch (error) {
      // Lost race or quota: prefer the idempotency owner, then the same id.
      if (bounded.idempotency_key) {
        const existing = await this.getByIdempotency({
          principalId: bounded.principal_id,
          tenantId: bounded.tenant_id,
          deviceId: bounded.device_id || "",
          idempotencyKey: bounded.idempotency_key,
        });
        if (existing) return { outcome: "existing", op: existing };
      }
      const byId = await this.get(bounded.operation_id, bounded.tenant_id);
      if (byId) return { outcome: "existing", op: byId };
      throw error;
    }
    const created = await this.get(bounded.operation_id, bounded.tenant_id);
    if (!created) throw new Error(`mcp_operation_claim_missing:${bounded.operation_id}`);
    return { outcome: "created", op: created };
  }

  async transition(
    operationId: string,
    tenantId: string,
    transition: McpOperationTransition,
    fromStatuses?: string[],
  ): Promise<McpOperationRecord | null> {
    const cur = await this.get(operationId, tenantId);
    if (!cur) return null;
    if (fromStatuses && fromStatuses.length > 0 && !fromStatuses.includes(cur.status)) return null;
    const next = boundMcpOperationRecord({
      ...cur,
      status: transition.status,
      summary: transition.summary ?? cur.summary,
      data: transition.data ?? cur.data,
      truncated: transition.truncated ?? cur.truncated,
      next_cursor: transition.next_cursor !== undefined ? transition.next_cursor : cur.next_cursor,
      approval_required: transition.approval_required ?? cur.approval_required,
      approval_url: transition.approval_url ?? cur.approval_url ?? undefined,
      approval_id: transition.approval_id ?? cur.approval_id ?? undefined,
      session_id: transition.session_id !== undefined ? transition.session_id : cur.session_id,
      warnings: transition.warnings ?? cur.warnings,
      updated_at: transition.updated_at || nowIso(),
    });
    await this.storage.put(opKey(tenantId, operationId), next);
    return cloneRecord(next);
  }

  /** Full-row CAS for compatibility paths (transfers, approval delivery). */
  async update(
    operationId: string,
    tenantId: string,
    patch: Partial<McpOperationRecord>,
    fromStatuses?: string[],
    expectedData?: Record<string, unknown>,
  ): Promise<McpOperationRecord | null> {
    const cur = await this.get(operationId, tenantId);
    if (!cur) return null;
    if (fromStatuses && fromStatuses.length > 0 && !fromStatuses.includes(cur.status)) return null;
    if (expectedData !== undefined && JSON.stringify(cur.data || {}) !== JSON.stringify(expectedData)) {
      return null;
    }
    const next = boundMcpOperationRecord({
      ...cur,
      ...patch,
      operation_id: cur.operation_id,
      principal_id: patch.principal_id ?? cur.principal_id,
      tenant_id: patch.tenant_id ?? cur.tenant_id,
      data: patch.data ?? cur.data,
      warnings: patch.warnings ?? cur.warnings,
      action: patch.action !== undefined ? patch.action : cur.action,
      updated_at: patch.updated_at || nowIso(),
    });
    await this.storage.put(opKey(tenantId, operationId), next);
    if (next.idempotency_key && next.idempotency_key !== cur.idempotency_key) {
      await this.storage.put(
        idemKey(next.tenant_id, next.principal_id, next.device_id || "", next.idempotency_key),
        operationId,
      );
    }
    return cloneRecord(next);
  }

  private async deleteRow(op: McpOperationRecord): Promise<void> {
    await this.storage.delete(opKey(op.tenant_id, op.operation_id));
    if (op.idempotency_key) {
      await this.storage.delete(
        idemKey(op.tenant_id, op.principal_id, op.device_id || "", op.idempotency_key),
      );
    }
    const occupancy = await this.count(op.tenant_id);
    await this.storage.put(countKey(op.tenant_id), Math.max(0, occupancy - 1));
  }

  /**
   * Bounded TTL prune for the room alarm. Mirrors D1 retention semantics:
   * expired tombstones and keyless terminals are deleted, expired keyed
   * terminals compact to small idempotency receipts.
   */
  async prune(
    tenantId: string,
    now = Date.now(),
    limit = MCP_OPS_MAINTENANCE_BATCH,
  ): Promise<{ deleted: number; compacted: number }> {
    const stats = { deleted: 0, compacted: 0 };
    if (!this.storage.list) return stats;
    const keys = await this.storage.list(`${OP_PREFIX}${tenantId}:`, Math.max(1, Math.min(512, limit * 2)));
    let examined = 0;
    for (const key of keys) {
      if (examined >= limit) break;
      examined += 1;
      const op = await this.storage.get<McpOperationRecord>(key);
      if (!op || op.tenant_id !== tenantId) continue;
      const age = mcpOpAgeMs(op, now);
      const keyed = hasMcpIdempotencyReceipt(op);
      if (op.status === "tombstone" && (!keyed || age > MCP_OPS_TOMBSTONE_TTL_MS)) {
        await this.deleteRow(op);
        stats.deleted += 1;
        continue;
      }
      if (TERMINAL_STATUSES.has(op.status) && isTerminalMcpStatus(op.status) && age > MCP_OPS_RESULT_TTL_MS) {
        if (!keyed) {
          await this.deleteRow(op);
          stats.deleted += 1;
          continue;
        }
        await this.storage.put(
          opKey(tenantId, op.operation_id),
          boundMcpOperationRecord({
            ...op,
            status: "tombstone",
            summary: "tombstone: result TTL expired; idempotency retained",
            data: { tombstone: true },
            truncated: true,
            warnings: ["durable_result_tombstoned"],
            updated_at: new Date(now).toISOString(),
          }),
        );
        stats.compacted += 1;
      }
    }
    return stats;
  }
}

/** In-memory DeviceOpStorage for unit tests (no DO needed). */
export class InMemoryDeviceOpStorage implements DeviceOpStorage {
  readonly rows = new Map<string, unknown>();

  async get<T = unknown>(key: string): Promise<T | undefined> {
    return this.rows.get(key) as T | undefined;
  }

  async put(key: string, value: unknown): Promise<void> {
    this.rows.set(key, value);
  }

  async delete(key: string): Promise<boolean> {
    return this.rows.delete(key);
  }

  async list(prefix: string, limit = 128): Promise<string[]> {
    const out: string[] = [];
    for (const key of this.rows.keys()) {
      if (key.startsWith(prefix)) {
        out.push(key);
        if (out.length >= limit) break;
      }
    }
    return out.sort();
  }
}
