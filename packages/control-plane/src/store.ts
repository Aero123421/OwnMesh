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
  status: "pending" | "approved" | "denied" | "expired";
  principal_id?: string;
  last_polled_at?: number;
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

  putClient(client: OAuthClientRecord): Promise<void>;
  getClient(clientId: string): Promise<OAuthClientRecord | null>;

  ensurePrincipal(
    id: string,
    displayName: string,
    kind?: string,
  ): Promise<PrincipalRecord>;

  putAuthCode(code: AuthCodeRecord): Promise<void>;
  takeAuthCode(code: string): Promise<AuthCodeRecord | null>;

  issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
  ): Promise<TokenRecord>;
  getAccess(token: string): Promise<TokenRecord | null>;
  rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  >;
  revokeToken(token: string): Promise<void>;

  putDeviceCode(rec: DeviceCodeRecord): Promise<void>;
  getDeviceCode(deviceCode: string): Promise<DeviceCodeRecord | null>;
  getDeviceCodeByUserCode(userCode: string): Promise<DeviceCodeRecord | null>;
  approveDeviceCode(userCode: string, principalId: string): Promise<boolean>;
  markDeviceCodePolled(deviceCode: string): Promise<void>;

  putDevice(device: DeviceRecord): Promise<void>;
  getDevice(id: string): Promise<DeviceRecord | null>;
  listDevices(principalId: string): Promise<DeviceRecord[]>;
  revokeDevice(id: string, principalId: string): Promise<boolean>;

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
}

const DEFAULT_TENANT = "ten_default";

// ---------------------------------------------------------------------------
// Memory store (also used when D1 is unbound in local smoke)
// ---------------------------------------------------------------------------

export class MemoryStore implements ControlPlaneStore {
  readonly kind = "memory" as const;
  clients = new Map<string, OAuthClientRecord>();
  principals = new Map<string, PrincipalRecord>();
  tokensByAccess = new Map<string, TokenRecord>();
  accessByRefresh = new Map<string, string>();
  usedRefresh = new Map<string, string>(); // refresh -> family
  authCodes = new Map<string, AuthCodeRecord>();
  deviceCodes = new Map<string, DeviceCodeRecord>();
  deviceByUserCode = new Map<string, string>();
  devices = new Map<string, DeviceRecord>();
  challenges = new Map<string, EnrollmentChallenge>();
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
  ): Promise<PrincipalRecord> {
    const existing = this.principals.get(id);
    if (existing) return existing;
    const p: PrincipalRecord = {
      id,
      tenant_id: DEFAULT_TENANT,
      kind,
      display_name: displayName,
      created_at: nowIso(),
    };
    this.principals.set(id, p);
    return p;
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
  ): Promise<TokenRecord> {
    await this.ensurePrincipal(principal, principal);
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const rec: TokenRecord = {
      access_token: access,
      refresh_token: refresh,
      client_id: clientId,
      scope,
      principal,
      expires_at: Date.now() + 15 * 60 * 1000,
      revoked: false,
      refresh_family: family || randomToken("fam_"),
      refresh_used: false,
    };
    this.tokensByAccess.set(access, rec);
    this.accessByRefresh.set(refresh, access);
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
  async markDeviceCodePolled(deviceCode: string): Promise<void> {
    const rec = this.deviceCodes.get(deviceCode);
    if (rec) {
      rec.last_polled_at = Date.now();
      this.deviceCodes.set(deviceCode, rec);
    }
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
    this.devices.set(id, d);
    return true;
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

  async ensurePrincipal(
    id: string,
    displayName: string,
    kind = "human",
  ): Promise<PrincipalRecord> {
    const existing = await this.db
      .prepare(
        `SELECT id, tenant_id, kind, display_name, created_at FROM principals WHERE id = ?`,
      )
      .bind(id)
      .first<PrincipalRecord>();
    if (existing) return existing;
    const created = nowIso();
    await this.db
      .prepare(
        `INSERT INTO principals (id, tenant_id, kind, display_name, created_at) VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(id, DEFAULT_TENANT, kind, displayName, created)
      .run();
    return {
      id,
      tenant_id: DEFAULT_TENANT,
      kind,
      display_name: displayName,
      created_at: created,
    };
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
    const row = await this.db
      .prepare(
        `SELECT code_hash, client_id, principal_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used
         FROM oauth_auth_codes WHERE code_hash = ?`,
      )
      .bind(hash)
      .first<{
        client_id: string;
        principal_id: string;
        redirect_uri: string;
        scope: string;
        code_challenge: string;
        code_challenge_method: string;
        expires_at: string;
        used: number;
      }>();
    if (!row || row.used) return null;
    if (Date.now() > Date.parse(row.expires_at)) return null;
    await this.db
      .prepare(`UPDATE oauth_auth_codes SET used = 1 WHERE code_hash = ?`)
      .bind(hash)
      .run();
    return {
      code,
      client_id: row.client_id,
      principal_id: row.principal_id,
      redirect_uri: row.redirect_uri,
      scope: row.scope,
      code_challenge: row.code_challenge,
      code_challenge_method: row.code_challenge_method,
      expires_at: Date.parse(row.expires_at),
      used: true,
    };
  }

  async issueTokens(
    clientId: string,
    principal: string,
    scope: string,
    family?: string,
  ): Promise<TokenRecord> {
    await this.ensurePrincipal(principal, principal);
    // Ensure client exists for FK.
    const client = await this.getClient(clientId);
    if (!client) {
      await this.putClient({
        client_id: clientId,
        tenant_id: DEFAULT_TENANT,
        client_name: clientId,
        redirect_uris: [],
        created_at: nowIso(),
      });
    }
    const access = randomToken("atk_");
    const refresh = randomToken("rtk_");
    const fam = family || randomToken("fam_");
    const expiresAt = Date.now() + 15 * 60 * 1000;
    const accessHash = await sha256Hex(access);
    const refreshHash = await sha256Hex(refresh);
    await this.db
      .prepare(
        `INSERT INTO oauth_tokens
         (access_token_hash, refresh_token_hash, client_id, principal_id, scope, refresh_family, refresh_used, revoked, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 0, 0, ?, ?)`,
      )
      .bind(
        accessHash,
        refreshHash,
        clientId,
        principal,
        scope,
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
      revoked: false,
      refresh_family: fam,
      refresh_used: false,
    };
  }

  async getAccess(token: string): Promise<TokenRecord | null> {
    const hash = await sha256Hex(token);
    const row = await this.db
      .prepare(
        `SELECT access_token_hash, refresh_token_hash, client_id, principal_id, scope, refresh_family, refresh_used, revoked, expires_at
         FROM oauth_tokens WHERE access_token_hash = ?`,
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
    };
  }

  async rotateRefresh(refreshToken: string): Promise<
    | { ok: true; token: TokenRecord }
    | { ok: false; error: "invalid_grant" | "reuse"; description?: string }
  > {
    const refreshHash = await sha256Hex(refreshToken);
    const used = await this.db
      .prepare(
        `SELECT refresh_family FROM used_refresh_tokens WHERE refresh_token_hash = ?`,
      )
      .bind(refreshHash)
      .first<{ refresh_family: string }>();
    if (used) {
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
    const row = await this.db
      .prepare(
        `SELECT access_token_hash, client_id, principal_id, scope, refresh_family, revoked
         FROM oauth_tokens WHERE refresh_token_hash = ?`,
      )
      .bind(refreshHash)
      .first<{
        access_token_hash: string;
        client_id: string;
        principal_id: string;
        scope: string;
        refresh_family: string;
        revoked: number;
      }>();
    if (!row || row.revoked) return { ok: false, error: "invalid_grant" };

    await this.db
      .prepare(
        `UPDATE oauth_tokens SET revoked = 1, refresh_used = 1 WHERE refresh_token_hash = ?`,
      )
      .bind(refreshHash)
      .run();
    await this.db
      .prepare(
        `INSERT OR IGNORE INTO used_refresh_tokens (refresh_token_hash, refresh_family, used_at) VALUES (?, ?, ?)`,
      )
      .bind(refreshHash, row.refresh_family, nowIso())
      .run();

    const next = await this.issueTokens(
      row.client_id,
      row.principal_id,
      row.scope,
      row.refresh_family,
    );
    return { ok: true, token: next };
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
    const row = await this.db
      .prepare(
        `SELECT status FROM device_codes WHERE user_code = ?`,
      )
      .bind(userCode.toUpperCase())
      .first<{ status: string }>();
    if (!row || row.status !== "pending") return false;
    await this.db
      .prepare(
        `UPDATE device_codes SET status = 'approved', principal_id = ? WHERE user_code = ?`,
      )
      .bind(principalId, userCode.toUpperCase())
      .run();
    return true;
  }

  async markDeviceCodePolled(deviceCode: string): Promise<void> {
    const hash = await sha256Hex(deviceCode);
    await this.db
      .prepare(
        `UPDATE device_codes SET last_polled_at = ? WHERE device_code_hash = ?`,
      )
      .bind(nowIso(), hash)
      .run();
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    await this.db
      .prepare(
        `INSERT OR REPLACE INTO devices
         (id, tenant_id, principal_id, name, public_key, revoked, created_at, last_seen_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
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
        `SELECT id, tenant_id, principal_id, name, public_key, revoked, created_at, last_seen_at FROM devices WHERE id = ?`,
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
    };
  }

  async listDevices(principalId: string): Promise<DeviceRecord[]> {
    const res = await this.db
      .prepare(
        `SELECT id, tenant_id, principal_id, name, public_key, revoked, created_at, last_seen_at
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
      };
    });
  }

  async revokeDevice(id: string, principalId: string): Promise<boolean> {
    const d = await this.getDevice(id);
    if (!d || d.principal_id !== principalId) return false;
    await this.db
      .prepare(`UPDATE devices SET revoked = 1 WHERE id = ?`)
      .bind(id)
      .run();
    return true;
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
    const ch = await this.getEnrollmentChallenge(id);
    if (!ch || ch.consumed) return false;
    if (Date.now() > Date.parse(ch.expires_at)) return false;
    await this.db
      .prepare(`UPDATE enrollment_challenges SET consumed = 1 WHERE id = ?`)
      .bind(id)
      .run();
    return true;
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
export function createStore(env: { DB?: D1Database }): ControlPlaneStore {
  if (env.DB) {
    return new SqlStore(env.DB as unknown as SqlDatabase, "d1");
  }
  return new MemoryStore();
}

export { DEFAULT_TENANT, generateUserCode, randomId, randomToken, nowIso };
