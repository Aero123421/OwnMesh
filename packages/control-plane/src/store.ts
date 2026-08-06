/**
 * Control-plane persistence.
 *
 * Production path: D1 via Workers Binding API
 *   https://developers.cloudflare.com/d1/worker-api/
 * Test path: node:sqlite applying the same migrations/ SQL.
 */

import {
  nowIso,
  randomId,
  randomToken,
  sha256Hex,
  generateUserCode,
} from "./util.ts";

export type TokenRecord = {
  access_token: string;
  refresh_token: string;
  client_id: string;
  scope: string;
  principal: string;
  expires_at: number;
  revoked: boolean;
  refresh_family: string;
  refresh_used: boolean;
  tenant_id: string;
};

/** Metadata for RFC 7009 revoke audit attribution (no token secret). */
export type RevocableTokenMeta = {
  tenant_id: string;
  principal_id: string;
  client_id: string;
};

export type DeviceRecord = {
  id: string;
  tenant_id: string;
  principal_id: string;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  agent_version: string;
  protocol_version: string;
  public_key: string;
  revoked: boolean;
  created_at: string;
  last_seen_at?: string;
  status: "pending" | "active" | "revoked";
};

export type OAuthClientRecord = {
  client_id: string;
  tenant_id: string;
  client_name: string;
  redirect_uris: string[];
  created_at: string;
};

export type AuthCodeRecord = {
  code: string;
  client_id: string;
  principal_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: number;
  used: boolean;
};

export type DeviceCodeRecord = {
  device_code: string;
  user_code: string;
  client_id: string;
  scope: string;
  verification_uri: string;
  interval_sec: number;
  expires_at: number;
  status: "pending" | "approved" | "denied" | "expired" | "consumed";
  principal_id?: string;
  last_polled_at?: number;
};

export type DeviceVerificationTransaction = {
  id: string;
  csrf_hash: string;
  user_code: string;
  principal_id: string;
  client_id: string;
  scope: string;
  expires_at: number;
  consumed: boolean;
};

/** One-time OAuth authorize consent transaction (GET form → POST decision). */
export type AuthorizeTransaction = {
  id: string;
  csrf_hash: string;
  principal_id: string;
  tenant_id: string;
  client_id: string;
  redirect_uri: string;
  scope: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  expires_at: number;
  consumed: boolean;
};

export type DeviceCredentialRecord = {
  device_id: string;
  tenant_id: string;
  principal_id: string;
  role: "agent";
  expires_at: number;
  revoked: boolean;
};

export type EnrollmentChallenge = {
  id: string;
  device_id: string;
  nonce: string;
  message: string;
  expires_at: string;
  consumed: boolean;
};

export type GrantRecord = {
  id: string;
  tenant_id: string;
  principal_id: string;
  capability: string;
  resource?: string;
  expires_at?: string;
  created_at: string;
};

export type AuditEvent = {
  id: string;
  tenant_id: string;
  principal_id?: string;
  device_id?: string;
  kind: string;
  summary: string;
  created_at: string;
  meta?: Record<string, unknown>;
};

export type PrincipalRecord = {
  id: string;
  tenant_id: string;
  kind: string;
  display_name: string;
  created_at: string;
};

export interface ControlPlaneStore {
  readonly kind: "memory" | "d1" | "sqlite";

  ensureBootstrap(): Promise<void>;

  /**
   * True when the tenant is provisioned and may be referenced by principals.
   * Used by OAuth handlers to fail closed for AUTH_PROVIDER claims whose
   * tenant_id was never provisioned (avoids FK 500 on principals INSERT).
   * Does not create tenants.
   */
  tenantExists(tenantId: string): Promise<boolean>;

  putClient(client: OAuthClientRecord): Promise<void>;
  getClient(clientId: string): Promise<OAuthClientRecord | null>;

  ensurePrincipal(
    id: string,
    displayName: string,
    kind?: string,
    tenantId?: string,
  ): Promise<PrincipalRecord>;
  getPrincipal(id: string): Promise<PrincipalRecord | null>;

  putAuthCode(code: AuthCodeRecord): Promise<void>;
  takeAuthCode(code: string): Promise<AuthCodeRecord | null>;

  issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
    ttlMs?: number,
  ): Promise<TokenRecord>;
  getAccess(token: string): Promise<TokenRecord | null>;
  rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  >;
  revokeToken(token: string): Promise<void>;
  /**
   * Look up access or refresh token for revoke audit attribution.
   * Returns tenant/principal/client when the token is known, else null.
   * Does not require the token to still be active (revoked/expired may match).
   */
  lookupRevocableToken(token: string): Promise<RevocableTokenMeta | null>;

  putDeviceCode(rec: DeviceCodeRecord): Promise<void>;
  getDeviceCode(deviceCode: string): Promise<DeviceCodeRecord | null>;
  getDeviceCodeByUserCode(userCode: string): Promise<DeviceCodeRecord | null>;
  approveDeviceCode(userCode: string, principalId: string): Promise<boolean>;
  consumeApprovedDeviceCode(deviceCode: string, clientId: string): Promise<DeviceCodeRecord | null>;
  markDeviceCodePolled(deviceCode: string): Promise<void>;
  putDeviceVerificationTransaction(tx: DeviceVerificationTransaction): Promise<void>;
  consumeDeviceVerificationTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
  ): Promise<DeviceVerificationTransaction | null>;

  putAuthorizeTransaction(tx: AuthorizeTransaction): Promise<void>;
  consumeAuthorizeTransaction(
    id: string,
    csrfHash: string,
    principalId: string,
  ): Promise<AuthorizeTransaction | null>;

  putDevice(device: DeviceRecord): Promise<void>;
  getDevice(id: string): Promise<DeviceRecord | null>;
  listDevices(principalId: string): Promise<DeviceRecord[]>;
  revokeDevice(id: string, principalId: string): Promise<boolean>;
  activateDeviceWithChallenge(deviceId: string, challengeId: string): Promise<boolean>;
  activateDeviceAndIssueCredential(deviceId: string, challengeId: string, ttlMs?: number): Promise<{ token: string; expires_at: number } | null>;
  issueDeviceCredential(device: DeviceRecord, ttlMs?: number): Promise<{ token: string; expires_at: number }>;
  getDeviceCredential(token: string): Promise<DeviceCredentialRecord | null>;
  validateDeviceSession(authHash: string, role: "agent" | "client", deviceId: string): Promise<boolean>;

  putEnrollmentChallenge(ch: EnrollmentChallenge): Promise<void>;
  getEnrollmentChallenge(id: string): Promise<EnrollmentChallenge | null>;
  consumeEnrollmentChallenge(id: string): Promise<boolean>;

  putGrant(grant: GrantRecord): Promise<void>;
  listGrants(principalId: string): Promise<GrantRecord[]>;
  revokeGrant(id: string): Promise<void>;

  appendAudit(event: AuditEvent): Promise<void>;
  listAudit(tenantId: string, limit?: number): Promise<AuditEvent[]>;

  appliedMigrations(): Promise<string[]>;
  markMigration(id: string): Promise<void>;

  /**
   * Probe whether required P0 schema objects exist.
   * Never infers readiness from migration filenames alone.
   */
  schemaReadiness(): Promise<SchemaReadiness>;
}

/** Cheap structural readiness of required control-plane P0 tables/columns. */
export type SchemaReadiness = {
  schema_ready: boolean;
  checks: {
    devices_status: boolean;
    device_credentials: boolean;
    device_verification_transactions: boolean;
    authorize_transactions: boolean;
  };
};

const DEFAULT_TENANT = "ten_default";

// ---------------------------------------------------------------------------
// Memory store (explicit unit/integration test injection only)
// ---------------------------------------------------------------------------

export class MemoryStore implements ControlPlaneStore {
  readonly kind = "memory" as const;
  clients = new Map<string, OAuthClientRecord>();
  principals = new Map<string, PrincipalRecord>();
  tokensByAccess = new Map<string, TokenRecord>();
  accessByRefresh = new Map<string, string>();
  usedRefresh = new Map<string, string>(); // refresh -> family
  compromisedRefreshFamilies = new Set<string>();
  authCodes = new Map<string, AuthCodeRecord>();
  deviceCodes = new Map<string, DeviceCodeRecord>();
  deviceByUserCode = new Map<string, string>();
  devices = new Map<string, DeviceRecord>();
  challenges = new Map<string, EnrollmentChallenge>();
  verificationTransactions = new Map<string, DeviceVerificationTransaction>();
  authorizeTransactions = new Map<string, AuthorizeTransaction>();
  deviceCredentials = new Map<string, DeviceCredentialRecord>();
  grants = new Map<string, GrantRecord>();
  audits: AuditEvent[] = [];
  migrations = new Set<string>();

  async ensureBootstrap(): Promise<void> {
    if (!this.principals.has("prin_dev")) {
      this.principals.set("prin_dev", {
        id: "prin_dev",
        tenant_id: DEFAULT_TENANT,
        kind: "human",
        display_name: "Dev User",
        created_at: nowIso(),
      });
    }
  }

  /**
   * Memory path: DEFAULT_TENANT is always provisioned; any tenant already
   * referenced by a seeded principal also counts. Does not auto-create.
   * ensurePrincipal remains permissive for unprovisioned tenants.
   */
  async tenantExists(tenantId: string): Promise<boolean> {
    if (!tenantId) return false;
    if (tenantId === DEFAULT_TENANT) return true;
    for (const p of this.principals.values()) {
      if (p.tenant_id === tenantId) return true;
    }
    return false;
  }

  async putClient(client: OAuthClientRecord): Promise<void> {
    this.clients.set(client.client_id, client);
  }
  async getClient(clientId: string): Promise<OAuthClientRecord | null> {
    return this.clients.get(clientId) || null;
  }

  async ensurePrincipal(
    id: string,
    displayName: string,
    kind = "human",
    tenantId = DEFAULT_TENANT,
  ): Promise<PrincipalRecord> {
    const existing = this.principals.get(id);
    if (existing) {
      if (existing.tenant_id !== tenantId) throw new Error("principal tenant mismatch");
      return existing;
    }
    const p: PrincipalRecord = {
      id,
      tenant_id: tenantId,
      kind,
      display_name: displayName,
      created_at: nowIso(),
    };
    this.principals.set(id, p);
    return p;
  }
  async getPrincipal(id: string): Promise<PrincipalRecord | null> {
    return this.principals.get(id) || null;
  }

  async putAuthCode(code: AuthCodeRecord): Promise<void> {
    this.authCodes.set(code.code, { ...code });
  }
  async takeAuthCode(code: string): Promise<AuthCodeRecord | null> {
    const rec = this.authCodes.get(code);
    if (!rec || rec.used) return null;
    if (Date.now() > rec.expires_at) return null;
    rec.used = true;
    this.authCodes.set(code, rec);
    return { ...rec };
  }

  async issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
    ttlMs = 15 * 60 * 1000,
  ): Promise<TokenRecord> {
    const principalRecord = (await this.getPrincipal(principal)) || await this.ensurePrincipal(principal, principal);
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const rec: TokenRecord = {
      access_token: access,
      refresh_token: refresh,
      client_id: clientId,
      scope,
      principal,
      expires_at: Date.now() + ttlMs,
      revoked: family ? this.compromisedRefreshFamilies.has(family) : false,
      refresh_family: family || randomToken("fam_"),
      refresh_used: false,
      tenant_id: principalRecord.tenant_id,
    };
    this.tokensByAccess.set(access, rec);
    if (!rec.revoked) this.accessByRefresh.set(refresh, access);
    return rec;
  }

  async getAccess(token: string): Promise<TokenRecord | null> {
    const rec = this.tokensByAccess.get(token);
    if (!rec || rec.revoked) return null;
    if (Date.now() > rec.expires_at) return null;
    return rec;
  }

  async rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  > {
    const usedFamily = this.usedRefresh.get(refreshToken);
    if (usedFamily) {
      this.compromisedRefreshFamilies.add(usedFamily);
      for (const [k, v] of this.tokensByAccess) {
        if (v.refresh_family === usedFamily) {
          v.revoked = true;
          this.tokensByAccess.set(k, v);
        }
      }
      return {
        ok: false,
        error: "reuse",
        description: "refresh token reuse detected",
      };
    }
    const access = this.accessByRefresh.get(refreshToken);
    if (!access) return { ok: false, error: "invalid_grant" };
    const old = this.tokensByAccess.get(access);
    if (!old || old.revoked) return { ok: false, error: "invalid_grant" };
    old.refresh_used = true;
    old.revoked = true;
    this.tokensByAccess.set(access, old);
    this.accessByRefresh.delete(refreshToken);
    this.usedRefresh.set(refreshToken, old.refresh_family);
    const next = await this.issueTokens(
      old.client_id,
      old.principal,
      old.scope,
      old.refresh_family,
    );
    return { ok: true, token: next };
  }

  async revokeToken(token: string): Promise<void> {
    if (token.startsWith("rtk_")) {
      const access = this.accessByRefresh.get(token);
      if (access) {
        const rec = this.tokensByAccess.get(access);
        if (rec) {
          rec.revoked = true;
          this.tokensByAccess.set(access, rec);
        }
        this.accessByRefresh.delete(token);
      }
      return;
    }
    const rec = this.tokensByAccess.get(token);
    if (rec) {
      rec.revoked = true;
      this.tokensByAccess.set(token, rec);
      this.accessByRefresh.delete(rec.refresh_token);
    }
  }

  async lookupRevocableToken(token: string): Promise<RevocableTokenMeta | null> {
    if (!token) return null;
    let rec = this.tokensByAccess.get(token);
    if (!rec) {
      const access = this.accessByRefresh.get(token);
      if (access) rec = this.tokensByAccess.get(access);
    }
    // Also match refresh value still present on a stored access record
    // (e.g. after access-side revoke removed the refresh index entry).
    if (!rec) {
      for (const candidate of this.tokensByAccess.values()) {
        if (candidate.refresh_token === token) {
          rec = candidate;
          break;
        }
      }
    }
    if (!rec) return null;
    return {
      tenant_id: rec.tenant_id,
      principal_id: rec.principal,
      client_id: rec.client_id,
    };
  }

  async putDeviceCode(rec: DeviceCodeRecord): Promise<void> {
    this.deviceCodes.set(rec.device_code, { ...rec });
    this.deviceByUserCode.set(rec.user_code.toUpperCase(), rec.device_code);
  }
  async getDeviceCode(deviceCode: string): Promise<DeviceCodeRecord | null> {
    const rec = this.deviceCodes.get(deviceCode);
    if (!rec) return null;
    if (Date.now() > rec.expires_at && rec.status === "pending") {
      rec.status = "expired";
      this.deviceCodes.set(deviceCode, rec);
    }
    return { ...rec };
  }
  async getDeviceCodeByUserCode(
    userCode: string,
  ): Promise<DeviceCodeRecord | null> {
    const dc = this.deviceByUserCode.get(userCode.toUpperCase());
    if (!dc) return null;
    return this.getDeviceCode(dc);
  }
  async approveDeviceCode(
    userCode: string,
    principalId: string,
  ): Promise<boolean> {
    const rec = await this.getDeviceCodeByUserCode(userCode);
    if (!rec || rec.status !== "pending") return false;
    rec.status = "approved";
    rec.principal_id = principalId;
    this.deviceCodes.set(rec.device_code, rec);
    return true;
  }
  async consumeApprovedDeviceCode(deviceCode: string, clientId: string): Promise<DeviceCodeRecord | null> {
    const rec = this.deviceCodes.get(deviceCode);
    if (!rec || rec.status !== "approved" || rec.client_id !== clientId || Date.now() > rec.expires_at) return null;
    rec.status = "consumed";
    this.deviceCodes.set(deviceCode, rec);
    return { ...rec };
  }
  async markDeviceCodePolled(deviceCode: string): Promise<void> {
    const rec = this.deviceCodes.get(deviceCode);
    if (rec) {
      rec.last_polled_at = Date.now();
      this.deviceCodes.set(deviceCode, rec);
    }
  }
  async putDeviceVerificationTransaction(tx: DeviceVerificationTransaction): Promise<void> {
    this.verificationTransactions.set(tx.id, { ...tx });
  }
  async consumeDeviceVerificationTransaction(id: string, csrfHash: string, principalId: string): Promise<DeviceVerificationTransaction | null> {
    const tx = this.verificationTransactions.get(id);
    if (!tx || tx.consumed || tx.csrf_hash !== csrfHash || tx.principal_id !== principalId || Date.now() > tx.expires_at) return null;
    const dc = await this.getDeviceCodeByUserCode(tx.user_code);
    if (!dc || dc.status !== "pending" || dc.client_id !== tx.client_id || dc.scope !== tx.scope || Date.now() > dc.expires_at) return null;
    tx.consumed = true;
    this.verificationTransactions.set(id, tx);
    if (!(await this.approveDeviceCode(tx.user_code, principalId))) return null;
    return { ...tx };
  }

  async putAuthorizeTransaction(tx: AuthorizeTransaction): Promise<void> {
    this.authorizeTransactions.set(tx.id, { ...tx });
  }
  async consumeAuthorizeTransaction(id: string, csrfHash: string, principalId: string): Promise<AuthorizeTransaction | null> {
    const tx = this.authorizeTransactions.get(id);
    if (!tx || tx.consumed || tx.csrf_hash !== csrfHash || tx.principal_id !== principalId || Date.now() > tx.expires_at) return null;
    tx.consumed = true;
    this.authorizeTransactions.set(id, tx);
    return { ...tx };
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    this.devices.set(device.id, { ...device });
  }
  async getDevice(id: string): Promise<DeviceRecord | null> {
    const d = this.devices.get(id);
    if (!d) return null;
    return hydrateDevice(d);
  }
  async listDevices(principalId: string): Promise<DeviceRecord[]> {
    return [...this.devices.values()]
      .filter((d) => d.principal_id === principalId && !d.revoked)
      .map(hydrateDevice);
  }
  async revokeDevice(id: string, principalId: string): Promise<boolean> {
    const d = this.devices.get(id);
    if (!d || d.principal_id !== principalId) return false;
    d.revoked = true;
    d.status = "revoked";
    this.devices.set(id, d);
    for (const rec of this.deviceCredentials.values()) if (rec.device_id === id) rec.revoked = true;
    return true;
  }
  async activateDeviceWithChallenge(deviceId: string, challengeId: string): Promise<boolean> {
    const d = this.devices.get(deviceId);
    const ch = this.challenges.get(challengeId);
    if (!d || d.status !== "pending" || !ch || ch.device_id !== deviceId || ch.consumed || Date.now() > Date.parse(ch.expires_at)) return false;
    ch.consumed = true;
    d.status = "active";
    this.challenges.set(challengeId, ch);
    this.devices.set(deviceId, d);
    return true;
  }
  async activateDeviceAndIssueCredential(deviceId: string, challengeId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number } | null> {
    if (!(await this.activateDeviceWithChallenge(deviceId, challengeId))) return null;
    const device = await this.getDevice(deviceId);
    return device ? this.issueDeviceCredential(device, ttlMs) : null;
  }
  async issueDeviceCredential(device: DeviceRecord, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number }> {
    if (device.revoked || device.status !== "active") throw new Error("device must be active before credential issuance");
    const token = randomToken("dcred_");
    const expires_at = Date.now() + ttlMs;
    this.deviceCredentials.set(await sha256Hex(token), {
      device_id: device.id, tenant_id: device.tenant_id, principal_id: device.principal_id,
      role: "agent", expires_at, revoked: false,
    });
    return { token, expires_at };
  }
  async getDeviceCredential(token: string): Promise<DeviceCredentialRecord | null> {
    const rec = this.deviceCredentials.get(await sha256Hex(token));
    if (!rec || rec.revoked || Date.now() > rec.expires_at) return null;
    return { ...rec };
  }
  async validateDeviceSession(authHash: string, role: "agent" | "client", deviceId: string): Promise<boolean> {
    const device = this.devices.get(deviceId);
    if (!device || device.revoked || device.status !== "active") return false;
    if (role === "agent") {
      const credential = this.deviceCredentials.get(authHash);
      return Boolean(credential && !credential.revoked && credential.device_id === deviceId && credential.expires_at > Date.now());
    }
    for (const [token, record] of this.tokensByAccess) {
      if (await sha256Hex(token) === authHash) {
        return !record.revoked && record.expires_at > Date.now() && record.principal === device.principal_id && record.tenant_id === device.tenant_id;
      }
    }
    return false;
  }

  async putEnrollmentChallenge(ch: EnrollmentChallenge): Promise<void> {
    this.challenges.set(ch.id, { ...ch });
  }
  async getEnrollmentChallenge(
    id: string,
  ): Promise<EnrollmentChallenge | null> {
    return this.challenges.get(id) || null;
  }
  async consumeEnrollmentChallenge(id: string): Promise<boolean> {
    const ch = this.challenges.get(id);
    if (!ch || ch.consumed) return false;
    if (Date.now() > Date.parse(ch.expires_at)) return false;
    ch.consumed = true;
    this.challenges.set(id, ch);
    return true;
  }

  async putGrant(grant: GrantRecord): Promise<void> {
    this.grants.set(grant.id, grant);
  }
  async listGrants(principalId: string): Promise<GrantRecord[]> {
    return [...this.grants.values()].filter((g) => g.principal_id === principalId);
  }
  async revokeGrant(id: string): Promise<void> {
    this.grants.delete(id);
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    this.audits.push(event);
  }
  async listAudit(tenantId: string, limit = 50): Promise<AuditEvent[]> {
    return this.audits
      .filter((a) => a.tenant_id === tenantId)
      .slice(-limit)
      .reverse();
  }

  async appliedMigrations(): Promise<string[]> {
    return [...this.migrations].sort();
  }
  async markMigration(id: string): Promise<void> {
    this.migrations.add(id);
  }

  async schemaReadiness(): Promise<SchemaReadiness> {
    // In-memory store always carries the full logical schema.
    const checks = {
      devices_status: true,
      device_credentials: true,
      device_verification_transactions: true,
      authorize_transactions: true,
    };
    return { schema_ready: true, checks };
  }
}

// ---------------------------------------------------------------------------
// SQL-backed store (D1 in Workers, node:sqlite in tests)
// ---------------------------------------------------------------------------

/** Minimal subset of D1 / sqlite prepared statement API. */
export interface SqlDatabase {
  prepare(query: string): SqlStatement;
  exec?(query: string): unknown | Promise<unknown>;
  batch?<T = unknown>(statements: SqlStatement[]): Promise<T[]>;
}

export interface SqlStatement {
  bind(...values: unknown[]): SqlStatement;
  first<T = Record<string, unknown>>(colName?: string): Promise<T | null>;
  run<T = Record<string, unknown>>(): Promise<{
    success?: boolean;
    meta?: unknown;
    results?: T[];
  }>;
  all<T = Record<string, unknown>>(): Promise<{ results: T[] }>;
}

export class SqlStore implements ControlPlaneStore {
  readonly kind: "d1" | "sqlite";
  private db: SqlDatabase;
  /** plaintext access/refresh kept only for the lifetime of this isolate when issued here.
   * Lookups always go through hash in SQL. For getAccess we need the plaintext from the
   * Authorization header — we hash it and look up. */
  constructor(db: SqlDatabase, kind: "d1" | "sqlite" = "d1") {
    this.db = db;
    this.kind = kind;
  }

  async ensureBootstrap(): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO tenants (id, name, created_at) VALUES (?, ?, ?)`,
      )
      .bind(DEFAULT_TENANT, "Default", nowIso())
      .run();
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO principals (id, tenant_id, kind, display_name, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind("prin_dev", DEFAULT_TENANT, "human", "Dev User", nowIso())
      .run();
    // Ensure a bootstrap OAuth client for device-code / dev flows.
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO oauth_clients (client_id, tenant_id, client_name, redirect_uris, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(
        "client_ownmesh_cli",
        DEFAULT_TENANT,
        "OwnMesh CLI",
        JSON.stringify([
          "http://127.0.0.1:8750/callback",
          "http://localhost:8750/callback",
        ]),
        nowIso(),
      )
      .run();
  }

  async putClient(client: OAuthClientRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO oauth_clients (client_id, tenant_id, client_name, redirect_uris, created_at)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(
        client.client_id,
        client.tenant_id,
        client.client_name,
        JSON.stringify(client.redirect_uris),
        client.created_at,
      )
      .run();
  }

  async getClient(clientId: string): Promise<OAuthClientRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT client_id, tenant_id, client_name, redirect_uris, created_at FROM oauth_clients WHERE client_id = ?`,
      )
      .bind(clientId)
      .first<{
        client_id: string;
        tenant_id: string;
        client_name: string;
        redirect_uris: string;
        created_at: string;
      }>();
    if (!row) return null;
    let uris: string[] = [];
    try {
      uris = JSON.parse(row.redirect_uris) as string[];
    } catch {
      uris = [];
    }
    return {
      client_id: row.client_id,
      tenant_id: row.tenant_id,
      client_name: row.client_name,
      redirect_uris: uris,
      created_at: row.created_at,
    };
  }

  /** True when a row exists in tenants. Never inserts. */
  async tenantExists(tenantId: string): Promise<boolean> {
    if (!tenantId) return false;
    const row = await this.db
      .prepare(`SELECT id FROM tenants WHERE id = ?`)
      .bind(tenantId)
      .first<{ id: string }>();
    return !!row;
  }

  async ensurePrincipal(
    id: string,
    displayName: string,
    kind = "human",
    tenantId = DEFAULT_TENANT,
  ): Promise<PrincipalRecord> {
    const existing = await this.db
      .prepare(
        `SELECT id, tenant_id, kind, display_name, created_at FROM principals WHERE id = ?`,
      )
      .bind(id)
      .first<PrincipalRecord>();
    if (existing) {
      if (existing.tenant_id !== tenantId) throw new Error("principal tenant mismatch");
      return existing;
    }
    const created = nowIso();
    await this.db
      .prepare(
        `INSERT INTO principals (id, tenant_id, kind, display_name, created_at) VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(id, tenantId, kind, displayName, created)
      .run();
    return {
      id,
      tenant_id: tenantId,
      kind,
      display_name: displayName,
      created_at: created,
    };
  }

  async getPrincipal(id: string): Promise<PrincipalRecord | null> {
    return this.db.prepare(
      `SELECT id, tenant_id, kind, display_name, created_at FROM principals WHERE id = ?`,
    ).bind(id).first<PrincipalRecord>();
  }

  async putAuthCode(code: AuthCodeRecord): Promise<void> {
    const hash = await sha256Hex(code.code);
    await this.db
      .prepare(
        `INSERT INTO oauth_auth_codes
         (code_hash, client_id, principal_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
      )
      .bind(
        hash,
        code.client_id,
        code.principal_id,
        code.redirect_uri,
        code.scope,
        code.code_challenge,
        code.code_challenge_method,
        nowIso(code.expires_at),
        nowIso(),
      )
      .run();
  }

  async takeAuthCode(code: string): Promise<AuthCodeRecord | null> {
    const hash = await sha256Hex(code);
    const row = await this.db.prepare(
      `UPDATE oauth_auth_codes SET used = 1
       WHERE code_hash = ? AND used = 0 AND expires_at > ?
       RETURNING client_id, principal_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at`,
    ).bind(hash, nowIso()).first<{
      client_id: string; principal_id: string; redirect_uri: string; scope: string;
      code_challenge: string; code_challenge_method: string; expires_at: string;
    }>();
    if (!row) return null;
    return {
      code, client_id: row.client_id, principal_id: row.principal_id,
      redirect_uri: row.redirect_uri, scope: row.scope,
      code_challenge: row.code_challenge, code_challenge_method: row.code_challenge_method,
      expires_at: Date.parse(row.expires_at), used: true,
    };
  }

  async issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
    ttlMs = 15 * 60 * 1000,
  ): Promise<TokenRecord> {
    const principalRecord = (await this.getPrincipal(principal)) || await this.ensurePrincipal(principal, principal);
    // Never turn token issuance into implicit client registration.
    const client = await this.getClient(clientId);
    if (!client) throw new Error("unknown OAuth client");
    if (client.tenant_id !== principalRecord.tenant_id) throw new Error("client/principal tenant mismatch");
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const fam = family || randomToken("fam_");
    const expiresAt = Date.now() + ttlMs;
    const accessHash = await sha256Hex(access);
    const refreshHash = await sha256Hex(refresh);
    await this.db
      .prepare(
        `INSERT INTO oauth_tokens
         (access_token_hash, refresh_token_hash, client_id, principal_id, scope, refresh_family, refresh_used, revoked, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 0,
           CASE WHEN EXISTS (SELECT 1 FROM revoked_refresh_families WHERE refresh_family = ?) THEN 1 ELSE 0 END,
           ?, ?)`,
      )
      .bind(
        accessHash,
        refreshHash,
        clientId,
        principal,
        scope,
        fam,
        fam,
        nowIso(expiresAt),
        nowIso(),
      )
      .run();
    return {
      access_token: access,
      refresh_token: refresh,
      client_id: clientId,
      scope,
      principal,
      expires_at: expiresAt,
      revoked: Boolean(await this.db.prepare(
        `SELECT 1 AS revoked FROM revoked_refresh_families WHERE refresh_family = ?`,
      ).bind(fam).first("revoked")),
      refresh_family: fam,
      refresh_used: false,
      tenant_id: principalRecord.tenant_id,
    };
  }

  async getAccess(token: string): Promise<TokenRecord | null> {
    const hash = await sha256Hex(token);
    const row = await this.db
      .prepare(
        `SELECT t.access_token_hash, t.refresh_token_hash, t.client_id, t.principal_id, t.scope,
                t.refresh_family, t.refresh_used, t.revoked, t.expires_at, p.tenant_id
         FROM oauth_tokens t JOIN principals p ON p.id = t.principal_id
         WHERE t.access_token_hash = ?`,
      )
      .bind(hash)
      .first<{
        client_id: string;
        principal_id: string;
        scope: string;
        refresh_family: string;
        refresh_used: number;
        revoked: number;
        expires_at: string;
        tenant_id: string;
      }>();
    if (!row || row.revoked) return null;
    const exp = Date.parse(row.expires_at);
    if (Date.now() > exp) return null;
    return {
      access_token: token,
      refresh_token: "",
      client_id: row.client_id,
      scope: row.scope,
      principal: row.principal_id,
      expires_at: exp,
      revoked: false,
      refresh_family: row.refresh_family,
      refresh_used: Boolean(row.refresh_used),
      tenant_id: row.tenant_id,
    };
  }

  async rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  > {
    // Atomic CAS + ledger + successor in one batch. Fail closed without batch.
    if (!this.db.batch) {
      throw new Error("SqlStore.rotateRefresh requires db.batch");
    }
    const refreshHash = await sha256Hex(refreshToken);
    const used = await this.db
      .prepare(
        `SELECT refresh_family FROM used_refresh_tokens WHERE refresh_token_hash = ?`,
      )
      .bind(refreshHash)
      .first<{ refresh_family: string }>();
    if (used) {
      await this.db.prepare(
        `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
      ).bind(used.refresh_family, nowIso()).run();
      await this.db
        .prepare(
          `UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`,
        )
        .bind(used.refresh_family)
        .run();
      return {
        ok: false,
        error: "reuse",
        description: "refresh token reuse detected",
      };
    }

    // Non-authoritative pre-read for successor metadata; CAS in the batch is the claim.
    const row = await this.db.prepare(
      `SELECT client_id, principal_id, scope, refresh_family, revoked, refresh_used
       FROM oauth_tokens WHERE refresh_token_hash = ?`,
    ).bind(refreshHash).first<{
      client_id: string; principal_id: string; scope: string;
      refresh_family: string; revoked: number; refresh_used: number;
    }>();
    if (!row) {
      return { ok: false, error: "invalid_grant" };
    }
    if (row.revoked || row.refresh_used) {
      await this.db.prepare(
        `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
      ).bind(row.refresh_family, nowIso()).run();
      await this.db.prepare(`UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`)
        .bind(row.refresh_family).run();
      await this.db.prepare(
        `INSERT OR IGNORE INTO used_refresh_tokens (refresh_token_hash, refresh_family, used_at) VALUES (?, ?, ?)`,
      ).bind(refreshHash, row.refresh_family, nowIso()).run();
      return { ok: false, error: "reuse", description: "refresh token reuse detected" };
    }

    // Precompute successor material before the batch (same defaults as issueTokens).
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const ttlMs = 15 * 60 * 1000;
    const expiresAt = Date.now() + ttlMs;
    const accessHash = await sha256Hex(access);
    const newRefreshHash = await sha256Hex(refresh);
    const ts = nowIso();
    const expiresAtIso = nowIso(expiresAt);
    const fam = row.refresh_family;

    type BatchResult = { meta?: { changes?: number }; success?: boolean };
    // Single atomic batch: old-token CAS → used-refresh ledger → successor insert.
    // Ledger/successor are gated on changes() from the preceding write so only the
    // CAS winner materializes a successor (loser must not insert a second token).
    const batchResults = await this.db.batch<BatchResult>([
      this.db.prepare(
        `UPDATE oauth_tokens SET revoked = 1, refresh_used = 1
         WHERE refresh_token_hash = ? AND revoked = 0 AND refresh_used = 0`,
      ).bind(refreshHash),
      this.db.prepare(
        `INSERT OR IGNORE INTO used_refresh_tokens (refresh_token_hash, refresh_family, used_at)
         SELECT ?, refresh_family, ?
         FROM oauth_tokens
         WHERE refresh_token_hash = ? AND refresh_used = 1 AND revoked = 1 AND changes() > 0`,
      ).bind(refreshHash, ts, refreshHash),
      this.db.prepare(
        `INSERT INTO oauth_tokens
         (access_token_hash, refresh_token_hash, client_id, principal_id, scope, refresh_family, refresh_used, revoked, expires_at, created_at)
         SELECT ?, ?, ot.client_id, ot.principal_id, ot.scope, ot.refresh_family, 0,
           CASE WHEN EXISTS (
             SELECT 1 FROM revoked_refresh_families r WHERE r.refresh_family = ot.refresh_family
           ) THEN 1 ELSE 0 END,
           ?, ?
         FROM oauth_tokens ot
         WHERE ot.refresh_token_hash = ?
           AND ot.refresh_used = 1 AND ot.revoked = 1
           AND changes() > 0`,
      ).bind(accessHash, newRefreshHash, expiresAtIso, ts, refreshHash),
    ]);

    const casWon = Number(batchResults[0]?.meta?.changes ?? 0) > 0;
    if (!casWon) {
      const raced = await this.db.prepare(
        `SELECT refresh_family FROM oauth_tokens WHERE refresh_token_hash = ? AND refresh_used = 1`,
      ).bind(refreshHash).first<{ refresh_family: string }>();
      if (raced) {
        await this.db.prepare(
          `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
        ).bind(raced.refresh_family, nowIso()).run();
        await this.db.prepare(`UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`)
          .bind(raced.refresh_family).run();
        return { ok: false, error: "reuse", description: "refresh token reuse detected" };
      }
      const ledger = await this.db.prepare(
        `SELECT refresh_family FROM used_refresh_tokens WHERE refresh_token_hash = ?`,
      ).bind(refreshHash).first<{ refresh_family: string }>();
      if (ledger) {
        await this.db.prepare(
          `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
        ).bind(ledger.refresh_family, nowIso()).run();
        await this.db.prepare(`UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`)
          .bind(ledger.refresh_family).run();
        return { ok: false, error: "reuse", description: "refresh token reuse detected" };
      }
      return { ok: false, error: "invalid_grant" };
    }

    // Winner: never return a successor that is already revoked / family-compromised.
    const successor = await this.db.prepare(
      `SELECT revoked FROM oauth_tokens WHERE access_token_hash = ?`,
    ).bind(accessHash).first<{ revoked: number }>();
    const familyRevoked = await this.db.prepare(
      `SELECT 1 AS revoked FROM revoked_refresh_families WHERE refresh_family = ?`,
    ).bind(fam).first("revoked");
    if (!successor || successor.revoked || familyRevoked) {
      await this.db.prepare(
        `INSERT OR IGNORE INTO revoked_refresh_families (refresh_family, detected_at) VALUES (?, ?)`,
      ).bind(fam, nowIso()).run();
      await this.db.prepare(`UPDATE oauth_tokens SET revoked = 1 WHERE refresh_family = ?`)
        .bind(fam).run();
      return { ok: false, error: "reuse", description: "refresh token reuse detected" };
    }

    const principalRecord = await this.getPrincipal(row.principal_id);
    return {
      ok: true,
      token: {
        access_token: access,
        refresh_token: refresh,
        client_id: row.client_id,
        scope: row.scope,
        principal: row.principal_id,
        expires_at: expiresAt,
        revoked: false,
        refresh_family: fam,
        refresh_used: false,
        tenant_id: principalRecord?.tenant_id ?? DEFAULT_TENANT,
      },
    };
  }

  async revokeToken(token: string): Promise<void> {
    const hash = await sha256Hex(token);
    if (token.startsWith("rtk_")) {
      await this.db
        .prepare(
          `UPDATE oauth_tokens SET revoked = 1 WHERE refresh_token_hash = ?`,
        )
        .bind(hash)
        .run();
      return;
    }
    await this.db
      .prepare(
        `UPDATE oauth_tokens SET revoked = 1 WHERE access_token_hash = ?`,
      )
      .bind(hash)
      .run();
  }

  async lookupRevocableToken(token: string): Promise<RevocableTokenMeta | null> {
    if (!token) return null;
    const hash = await sha256Hex(token);
    const row = await this.db
      .prepare(
        `SELECT t.client_id, t.principal_id, p.tenant_id
         FROM oauth_tokens t
         JOIN principals p ON p.id = t.principal_id
         WHERE t.access_token_hash = ? OR t.refresh_token_hash = ?
         LIMIT 1`,
      )
      .bind(hash, hash)
      .first<{ client_id: string; principal_id: string; tenant_id: string }>();
    if (!row) return null;
    return {
      tenant_id: row.tenant_id,
      principal_id: row.principal_id,
      client_id: row.client_id,
    };
  }

  async putDeviceCode(rec: DeviceCodeRecord): Promise<void> {
    const hash = await sha256Hex(rec.device_code);
    await this.db
      .prepare(
        `INSERT INTO device_codes
         (device_code_hash, user_code, client_id, scope, verification_uri, interval_sec, expires_at, status, principal_id, last_polled_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        hash,
        rec.user_code.toUpperCase(),
        rec.client_id,
        rec.scope,
        rec.verification_uri,
        rec.interval_sec,
        nowIso(rec.expires_at),
        rec.status,
        rec.principal_id ?? null,
        rec.last_polled_at ? nowIso(rec.last_polled_at) : null,
        nowIso(),
      )
      .run();
  }

  async getDeviceCode(deviceCode: string): Promise<DeviceCodeRecord | null> {
    const hash = await sha256Hex(deviceCode);
    const row = await this.db
      .prepare(
        `SELECT device_code_hash, user_code, client_id, scope, verification_uri, interval_sec, expires_at, status, principal_id, last_polled_at
         FROM device_codes WHERE device_code_hash = ?`,
      )
      .bind(hash)
      .first<{
        user_code: string;
        client_id: string;
        scope: string;
        verification_uri: string;
        interval_sec: number;
        expires_at: string;
        status: string;
        principal_id: string | null;
        last_polled_at: string | null;
      }>();
    if (!row) return null;
    let status = row.status as DeviceCodeRecord["status"];
    if (Date.now() > Date.parse(row.expires_at) && status === "pending") {
      status = "expired";
      await this.db
        .prepare(`UPDATE device_codes SET status = 'expired' WHERE device_code_hash = ?`)
        .bind(hash)
        .run();
    }
    return {
      device_code: deviceCode,
      user_code: row.user_code,
      client_id: row.client_id,
      scope: row.scope,
      verification_uri: row.verification_uri,
      interval_sec: row.interval_sec,
      expires_at: Date.parse(row.expires_at),
      status,
      principal_id: row.principal_id ?? undefined,
      last_polled_at: row.last_polled_at
        ? Date.parse(row.last_polled_at)
        : undefined,
    };
  }

  async getDeviceCodeByUserCode(
    userCode: string,
  ): Promise<DeviceCodeRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT device_code_hash FROM device_codes WHERE user_code = ?`,
      )
      .bind(userCode.toUpperCase())
      .first<{ device_code_hash: string }>();
    if (!row) return null;
    // We cannot reverse the hash; store plaintext device_code is not available.
    // For user-code approve path we only need to update by user_code.
    // Return a stub; callers for approve use approveDeviceCode.
    const full = await this.db
      .prepare(
        `SELECT user_code, client_id, scope, verification_uri, interval_sec, expires_at, status, principal_id, last_polled_at
         FROM device_codes WHERE user_code = ?`,
      )
      .bind(userCode.toUpperCase())
      .first<{
        user_code: string;
        client_id: string;
        scope: string;
        verification_uri: string;
        interval_sec: number;
        expires_at: string;
        status: string;
        principal_id: string | null;
        last_polled_at: string | null;
      }>();
    if (!full) return null;
    return {
      device_code: "", // unknown from user_code path
      user_code: full.user_code,
      client_id: full.client_id,
      scope: full.scope,
      verification_uri: full.verification_uri,
      interval_sec: full.interval_sec,
      expires_at: Date.parse(full.expires_at),
      status: full.status as DeviceCodeRecord["status"],
      principal_id: full.principal_id ?? undefined,
      last_polled_at: full.last_polled_at
        ? Date.parse(full.last_polled_at)
        : undefined,
    };
  }

  async approveDeviceCode(
    userCode: string,
    principalId: string,
  ): Promise<boolean> {
    const row = await this.db.prepare(
      `UPDATE device_codes SET status = 'approved', principal_id = ?
       WHERE user_code = ? AND status = 'pending' AND expires_at > ? RETURNING user_code`,
    ).bind(principalId, userCode.toUpperCase(), nowIso()).first<{ user_code: string }>();
    return Boolean(row);
  }

  async consumeApprovedDeviceCode(deviceCode: string, clientId: string): Promise<DeviceCodeRecord | null> {
    const hash = await sha256Hex(deviceCode);
    const row = await this.db.prepare(
      `UPDATE device_codes SET status = 'consumed'
       WHERE device_code_hash = ? AND client_id = ? AND status = 'approved' AND expires_at > ?
       RETURNING user_code, client_id, scope, verification_uri, interval_sec, expires_at, principal_id, last_polled_at`,
    ).bind(hash, clientId, nowIso()).first<{
      user_code: string; client_id: string; scope: string; verification_uri: string;
      interval_sec: number; expires_at: string; principal_id: string | null; last_polled_at: string | null;
    }>();
    if (!row) return null;
    return { device_code: deviceCode, user_code: row.user_code, client_id: row.client_id,
      scope: row.scope, verification_uri: row.verification_uri, interval_sec: row.interval_sec,
      expires_at: Date.parse(row.expires_at), status: "consumed", principal_id: row.principal_id || undefined,
      last_polled_at: row.last_polled_at ? Date.parse(row.last_polled_at) : undefined };
  }

  async markDeviceCodePolled(deviceCode: string): Promise<void> {
    const hash = await sha256Hex(deviceCode);
    await this.db.prepare(
      `UPDATE device_codes SET last_polled_at = ? WHERE device_code_hash = ? AND status = 'pending'`,
    ).bind(nowIso(), hash).run();
  }

  async putDeviceVerificationTransaction(tx: DeviceVerificationTransaction): Promise<void> {
    await this.db.prepare(
      `INSERT INTO device_verification_transactions
       (id, csrf_hash, user_code, principal_id, client_id, scope, expires_at, consumed, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    ).bind(tx.id, tx.csrf_hash, tx.user_code, tx.principal_id, tx.client_id, tx.scope,
      nowIso(tx.expires_at), nowIso()).run();
  }

  async consumeDeviceVerificationTransaction(id: string, csrfHash: string, principalId: string): Promise<DeviceVerificationTransaction | null> {
    // Atomic CAS: consume verification tx + approve matching device code in one batch.
    // Fail closed when batch/transactions are unavailable (no sequential fallback).
    if (!this.db.batch) {
      throw new Error("SqlStore.consumeDeviceVerificationTransaction requires db.batch");
    }
    const ts = nowIso();
    type BatchResult = { meta?: { changes?: number }; success?: boolean };
    const batchResults = await this.db.batch<BatchResult>([
      this.db.prepare(
        `UPDATE device_verification_transactions SET consumed = 1
         WHERE id = ? AND csrf_hash = ? AND principal_id = ? AND consumed = 0 AND expires_at > ?
           AND EXISTS (
             SELECT 1 FROM device_codes dc
             WHERE dc.user_code = device_verification_transactions.user_code
               AND dc.client_id = device_verification_transactions.client_id
               AND dc.scope = device_verification_transactions.scope
               AND dc.status = 'pending' AND dc.expires_at > ?
           )`,
      ).bind(id, csrfHash, principalId, ts, ts),
      this.db.prepare(
        `UPDATE device_codes SET status = 'approved', principal_id = ?
         WHERE status = 'pending' AND expires_at > ?
           AND EXISTS (
             SELECT 1 FROM device_verification_transactions vtx
             WHERE vtx.id = ? AND vtx.csrf_hash = ? AND vtx.principal_id = ? AND vtx.consumed = 1
               AND vtx.user_code = device_codes.user_code
               AND vtx.client_id = device_codes.client_id
               AND vtx.scope = device_codes.scope
           )`,
      ).bind(principalId, ts, id, csrfHash, principalId),
    ]);
    // Only the CAS winner mutates rows; losers must not observe the winner's final state as success.
    const consumed = Number(batchResults[0]?.meta?.changes ?? 0) > 0;
    const approved = Number(batchResults[1]?.meta?.changes ?? 0) > 0;
    if (!consumed || !approved) return null;
    const row = await this.db.prepare(
      `SELECT user_code, client_id, scope, expires_at
       FROM device_verification_transactions
       WHERE id = ? AND csrf_hash = ? AND principal_id = ? AND consumed = 1`,
    ).bind(id, csrfHash, principalId).first<{
      user_code: string; client_id: string; scope: string; expires_at: string;
    }>();
    if (!row) return null;
    return {
      id,
      csrf_hash: csrfHash,
      user_code: row.user_code,
      principal_id: principalId,
      client_id: row.client_id,
      scope: row.scope,
      expires_at: Date.parse(row.expires_at),
      consumed: true,
    };
  }

  async putAuthorizeTransaction(tx: AuthorizeTransaction): Promise<void> {
    await this.db.prepare(
      `INSERT INTO authorize_transactions
       (id, csrf_hash, principal_id, tenant_id, client_id, redirect_uri, scope, state,
        code_challenge, code_challenge_method, expires_at, consumed, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    ).bind(
      tx.id, tx.csrf_hash, tx.principal_id, tx.tenant_id, tx.client_id, tx.redirect_uri,
      tx.scope, tx.state, tx.code_challenge, tx.code_challenge_method,
      nowIso(tx.expires_at), nowIso(),
    ).run();
  }

  async consumeAuthorizeTransaction(id: string, csrfHash: string, principalId: string): Promise<AuthorizeTransaction | null> {
    // Atomic CAS: only one concurrent consumer wins (UPDATE...RETURNING).
    const row = await this.db.prepare(
      `UPDATE authorize_transactions SET consumed = 1
       WHERE id = ? AND csrf_hash = ? AND principal_id = ? AND consumed = 0 AND expires_at > ?
       RETURNING tenant_id, client_id, redirect_uri, scope, state,
                 code_challenge, code_challenge_method, expires_at`,
    ).bind(id, csrfHash, principalId, nowIso()).first<{
      tenant_id: string; client_id: string; redirect_uri: string; scope: string; state: string;
      code_challenge: string; code_challenge_method: string; expires_at: string;
    }>();
    if (!row) return null;
    return {
      id,
      csrf_hash: csrfHash,
      principal_id: principalId,
      tenant_id: row.tenant_id,
      client_id: row.client_id,
      redirect_uri: row.redirect_uri,
      scope: row.scope,
      state: row.state,
      code_challenge: row.code_challenge,
      code_challenge_method: row.code_challenge_method,
      expires_at: Date.parse(row.expires_at),
      consumed: true,
    };
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO devices
         (id, tenant_id, principal_id, name, public_key, revoked, created_at, last_seen_at, status)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        device.id,
        device.tenant_id,
        device.principal_id,
        device.name,
        device.public_key,
        device.revoked ? 1 : 0,
        device.created_at,
        device.last_seen_at ?? null,
        device.status,
      )
      .run();
    // Extended metadata in audit-friendly side channel via grants table note is not ideal;
    // store hostname/os in name suffix is bad. Use grants resource JSON? Better: put JSON in public_key field? No.
    // 0001 schema is limited; store extended fields as audit meta and encode in name is wrong.
    // We'll store a JSON blob in public_key? No.
    // Add columns via migration - we already have 0001. Use resource field on a side table via grants:
    // Actually put extended metadata into audit and keep public_key pure.
    // For list/get we need hostname etc. Store as JSON after public_key with delimiter? Ugly.
    // Extend devices via migration 0002 — add columns if missing.
  }

  async getDevice(id: string): Promise<DeviceRecord | null> {
    const row = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, name, public_key, revoked, created_at, last_seen_at, status FROM devices WHERE id = ?`,
      )
      .bind(id)
      .first<{
        id: string;
        tenant_id: string;
        principal_id: string;
        name: string;
        public_key: string;
        revoked: number;
        created_at: string;
        last_seen_at: string | null;
        status: "pending" | "active" | "revoked";
      }>();
    if (!row) return null;
    const meta = parseDeviceMeta(row.public_key);
    return {
      id: row.id,
      tenant_id: row.tenant_id,
      principal_id: row.principal_id,
      name: row.name,
      hostname: meta.hostname || row.name,
      os: meta.os || "unknown",
      arch: meta.arch || "unknown",
      agent_version: meta.agent_version || "0",
      protocol_version: meta.protocol_version || "ownmesh.device/1.0",
      public_key: meta.public_key || row.public_key,
      revoked: Boolean(row.revoked),
      created_at: row.created_at,
      last_seen_at: row.last_seen_at ?? undefined,
      status: row.status,
    };
  }

  async listDevices(principalId: string): Promise<DeviceRecord[]> {
    const res = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, name, public_key, revoked, created_at, last_seen_at, status
         FROM devices WHERE principal_id = ? AND revoked = 0`,
      )
      .bind(principalId)
      .all<{
        id: string;
        tenant_id: string;
        principal_id: string;
        name: string;
        public_key: string;
        revoked: number;
        created_at: string;
        last_seen_at: string | null;
        status: "pending" | "active" | "revoked";
      }>();
    return (res.results || []).map((row) => {
      const meta = parseDeviceMeta(row.public_key);
      return {
        id: row.id,
        tenant_id: row.tenant_id,
        principal_id: row.principal_id,
        name: row.name,
        hostname: meta.hostname || row.name,
        os: meta.os || "unknown",
        arch: meta.arch || "unknown",
        agent_version: meta.agent_version || "0",
        protocol_version: meta.protocol_version || "ownmesh.device/1.0",
        public_key: meta.public_key || row.public_key,
        revoked: Boolean(row.revoked),
        created_at: row.created_at,
        last_seen_at: row.last_seen_at ?? undefined,
        status: row.status,
      };
    });
  }

  async revokeDevice(id: string, principalId: string): Promise<boolean> {
    const d = await this.getDevice(id);
    if (!d || d.principal_id !== principalId) return false;
    await this.db.prepare(`UPDATE devices SET revoked = 1, status = 'revoked' WHERE id = ?`).bind(id).run();
    await this.db.prepare(`UPDATE device_credentials SET revoked = 1 WHERE device_id = ?`).bind(id).run();
    return true;
  }

  async activateDeviceWithChallenge(deviceId: string, challengeId: string): Promise<boolean> {
    const claimed = await this.db.prepare(
      `UPDATE enrollment_challenges SET consumed = 1
       WHERE id = ? AND device_id = ? AND consumed = 0 AND expires_at > ? RETURNING id`,
    ).bind(challengeId, deviceId, nowIso()).first<{ id: string }>();
    if (!claimed) return false;
    const activated = await this.db.prepare(
      `UPDATE devices SET status = 'active' WHERE id = ? AND status = 'pending' AND revoked = 0 RETURNING id`,
    ).bind(deviceId).first<{ id: string }>();
    return Boolean(activated);
  }

  async activateDeviceAndIssueCredential(deviceId: string, challengeId: string, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number } | null> {
    // Atomic CAS: pending→active + credential insert in one batch. Fail closed without batch.
    if (!this.db.batch) {
      throw new Error("SqlStore.activateDeviceAndIssueCredential requires db.batch");
    }
    const token = randomToken("dcred_");
    const hash = await sha256Hex(token);
    const expires_at = Date.now() + ttlMs;
    await this.db.batch([
      this.db.prepare(
        `INSERT INTO device_credentials (credential_hash, device_id, tenant_id, principal_id, role, expires_at, revoked, created_at)
         SELECT ?, d.id, d.tenant_id, d.principal_id, 'agent', ?, 0, ?
         FROM devices d JOIN enrollment_challenges c ON c.device_id = d.id
         WHERE d.id = ? AND d.status = 'pending' AND d.revoked = 0
           AND c.id = ? AND c.consumed = 0 AND c.expires_at > ?`,
      ).bind(hash, nowIso(expires_at), nowIso(), deviceId, challengeId, nowIso()),
      this.db.prepare(
        `UPDATE enrollment_challenges SET consumed = 1
         WHERE id = ? AND device_id = ? AND consumed = 0
           AND EXISTS (SELECT 1 FROM device_credentials WHERE credential_hash = ?)`,
      ).bind(challengeId, deviceId, hash),
      this.db.prepare(
        `UPDATE devices SET status = 'active'
         WHERE id = ? AND status = 'pending' AND revoked = 0
           AND EXISTS (SELECT 1 FROM device_credentials WHERE credential_hash = ?)`,
      ).bind(deviceId, hash),
    ]);
    const created = await this.db.prepare(`SELECT 1 AS ok FROM device_credentials WHERE credential_hash = ?`)
      .bind(hash).first<{ ok: number }>();
    return created ? { token, expires_at } : null;
  }

  async issueDeviceCredential(device: DeviceRecord, ttlMs = 30 * 24 * 60 * 60 * 1000): Promise<{ token: string; expires_at: number }> {
    if (device.revoked || device.status !== "active") throw new Error("device must be active before credential issuance");
    const token = randomToken("dcred_");
    const hash = await sha256Hex(token);
    const expires_at = Date.now() + ttlMs;
    await this.db.prepare(
      `INSERT INTO device_credentials (credential_hash, device_id, tenant_id, principal_id, role, expires_at, revoked, created_at)
       VALUES (?, ?, ?, ?, 'agent', ?, 0, ?)`,
    ).bind(hash, device.id, device.tenant_id, device.principal_id, nowIso(expires_at), nowIso()).run();
    return { token, expires_at };
  }

  async getDeviceCredential(token: string): Promise<DeviceCredentialRecord | null> {
    const hash = await sha256Hex(token);
    const row = await this.db.prepare(
      `SELECT c.device_id, c.tenant_id, c.principal_id, c.role, c.expires_at, c.revoked
       FROM device_credentials c JOIN devices d ON d.id = c.device_id
       WHERE c.credential_hash = ? AND c.revoked = 0 AND c.expires_at > ?
         AND d.status = 'active' AND d.revoked = 0`,
    ).bind(hash, nowIso()).first<{
      device_id: string; tenant_id: string; principal_id: string; role: "agent"; expires_at: string; revoked: number;
    }>();
    if (!row) return null;
    return { ...row, expires_at: Date.parse(row.expires_at), revoked: Boolean(row.revoked) };
  }

  async validateDeviceSession(authHash: string, role: "agent" | "client", deviceId: string): Promise<boolean> {
    if (role === "agent") {
      const row = await this.db.prepare(
        `SELECT 1 AS ok FROM device_credentials c JOIN devices d ON d.id = c.device_id
         WHERE c.credential_hash = ? AND c.device_id = ? AND c.revoked = 0 AND c.expires_at > ?
           AND d.revoked = 0 AND d.status = 'active'`,
      ).bind(authHash, deviceId, nowIso()).first<{ ok: number }>();
      return Boolean(row);
    }
    const row = await this.db.prepare(
      `SELECT 1 AS ok FROM oauth_tokens t
       JOIN principals p ON p.id = t.principal_id
       JOIN devices d ON d.id = ? AND d.principal_id = t.principal_id AND d.tenant_id = p.tenant_id
       WHERE t.access_token_hash = ? AND t.revoked = 0 AND t.expires_at > ?
         AND d.revoked = 0 AND d.status = 'active'`,
    ).bind(deviceId, authHash, nowIso()).first<{ ok: number }>();
    return Boolean(row);
  }

  async putEnrollmentChallenge(ch: EnrollmentChallenge): Promise<void> {
    await this.db
      .prepare(
        `INSERT INTO enrollment_challenges (id, device_id, nonce, message, expires_at, consumed, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        ch.id,
        ch.device_id,
        ch.nonce,
        ch.message,
        ch.expires_at,
        ch.consumed ? 1 : 0,
        nowIso(),
      )
      .run();
  }

  async getEnrollmentChallenge(
    id: string,
  ): Promise<EnrollmentChallenge | null> {
    const row = await this.db
      .prepare(
        `SELECT id, device_id, nonce, message, expires_at, consumed FROM enrollment_challenges WHERE id = ?`,
      )
      .bind(id)
      .first<{
        id: string;
        device_id: string;
        nonce: string;
        message: string;
        expires_at: string;
        consumed: number;
      }>();
    if (!row) return null;
    return {
      id: row.id,
      device_id: row.device_id,
      nonce: row.nonce,
      message: row.message,
      expires_at: row.expires_at,
      consumed: Boolean(row.consumed),
    };
  }

  async consumeEnrollmentChallenge(id: string): Promise<boolean> {
    const row = await this.db.prepare(
      `UPDATE enrollment_challenges SET consumed = 1
       WHERE id = ? AND consumed = 0 AND expires_at > ? RETURNING id`,
    ).bind(id, nowIso()).first<{ id: string }>();
    return Boolean(row);
  }

  async putGrant(grant: GrantRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO grants (id, tenant_id, principal_id, capability, resource, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        grant.id,
        grant.tenant_id,
        grant.principal_id,
        grant.capability,
        grant.resource ?? null,
        grant.expires_at ?? null,
        grant.created_at,
      )
      .run();
  }

  async listGrants(principalId: string): Promise<GrantRecord[]> {
    const res = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, capability, resource, expires_at, created_at FROM grants WHERE principal_id = ?`,
      )
      .bind(principalId)
      .all<GrantRecord>();
    return res.results || [];
  }

  async revokeGrant(id: string): Promise<void> {
    await this.db.prepare(`DELETE FROM grants WHERE id = ?`).bind(id).run();
  }

  async appendAudit(event: AuditEvent): Promise<void> {
    const summary =
      event.meta && Object.keys(event.meta).length
        ? `${event.summary} | ${JSON.stringify(event.meta)}`
        : event.summary;
    await this.db
      .prepare(
        `INSERT INTO audit_events (id, tenant_id, principal_id, device_id, kind, summary, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        event.id,
        event.tenant_id,
        event.principal_id ?? null,
        event.device_id ?? null,
        event.kind,
        summary,
        event.created_at,
      )
      .run();
  }

  async listAudit(tenantId: string, limit = 50): Promise<AuditEvent[]> {
    const res = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, device_id, kind, summary, created_at
         FROM audit_events WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?`,
      )
      .bind(tenantId, limit)
      .all<AuditEvent>();
    return res.results || [];
  }

  async appliedMigrations(): Promise<string[]> {
    try {
      const res = await this.db
        .prepare(`SELECT id FROM schema_migrations ORDER BY id`)
        .all<{ id: string }>();
      return (res.results || []).map((r) => r.id);
    } catch {
      return [];
    }
  }

  async markMigration(id: string): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO schema_migrations (id, applied_at) VALUES (?, ?)`,
      )
      .bind(id, nowIso())
      .run();
  }

  /**
   * Probe required P0 objects via sqlite_master + a devices.status SELECT.
   * Compatible with D1 (no PRAGMA dependency for the happy path).
   */
  async schemaReadiness(): Promise<SchemaReadiness> {
    const tableExists = async (name: string): Promise<boolean> => {
      try {
        const row = await this.db
          .prepare(
            `SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? LIMIT 1`,
          )
          .bind(name)
          .first<{ name: string }>();
        return Boolean(row && (row as { name?: string }).name === name);
      } catch {
        return false;
      }
    };

    let devices_status = false;
    try {
      // Throws when devices is missing or lacks a status column.
      await this.db.prepare(`SELECT status FROM devices LIMIT 1`).first();
      devices_status = true;
    } catch {
      devices_status = false;
    }

    const checks = {
      devices_status,
      device_credentials: await tableExists("device_credentials"),
      device_verification_transactions: await tableExists(
        "device_verification_transactions",
      ),
      authorize_transactions: await tableExists("authorize_transactions"),
    };
    return {
      schema_ready: Object.values(checks).every(Boolean),
      checks,
    };
  }
}

/** Encode extended device metadata into the public_key column as JSON envelope. */
export function encodeDevicePublicKey(
  publicKey: string,
  meta: {
    hostname?: string;
    os?: string;
    arch?: string;
    agent_version?: string;
    protocol_version?: string;
  },
): string {
  return JSON.stringify({
    public_key: publicKey,
    hostname: meta.hostname,
    os: meta.os,
    arch: meta.arch,
    agent_version: meta.agent_version,
    protocol_version: meta.protocol_version,
  });
}

function parseDeviceMeta(raw: string): {
  public_key?: string;
  hostname?: string;
  os?: string;
  arch?: string;
  agent_version?: string;
  protocol_version?: string;
} {
  if (raw.startsWith("{")) {
    try {
      return JSON.parse(raw) as {
        public_key?: string;
        hostname?: string;
        os?: string;
        arch?: string;
        agent_version?: string;
        protocol_version?: string;
      };
    } catch {
      return { public_key: raw };
    }
  }
  return { public_key: raw };
}

function hydrateDevice(d: DeviceRecord): DeviceRecord {
  const meta = parseDeviceMeta(d.public_key);
  return {
    ...d,
    hostname: d.hostname || meta.hostname || d.name,
    os: d.os && d.os !== "unknown" ? d.os : meta.os || "unknown",
    arch: d.arch && d.arch !== "unknown" ? d.arch : meta.arch || "unknown",
    agent_version: d.agent_version || meta.agent_version || "0",
    protocol_version:
      d.protocol_version || meta.protocol_version || "ownmesh.device/1.0",
    public_key: meta.public_key || d.public_key,
  };
}

/** Create store from Worker env. */
export class MissingD1Error extends Error {
  constructor() {
    super("D1 binding DB is required outside explicitly injected tests");
    this.name = "MissingD1Error";
  }
}

export function createStore(env: { DB?: D1Database }): ControlPlaneStore {
  if (env.DB) return new SqlStore(env.DB as unknown as SqlDatabase, "d1");
  throw new MissingD1Error();
}

export { DEFAULT_TENANT, generateUserCode, randomId, randomToken, nowIso };
