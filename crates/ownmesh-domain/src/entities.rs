//! Core domain entities (specification §12 / §20).

use crate::ids::{
    ApprovalId, AuditEventId, CapabilityGrantId, DeviceId, MembershipId, OperationId, PolicyId,
    PolicyRuleId, PrincipalId, SessionId, TenantId, WorkspaceId,
};
use crate::time::{Expiry, Timestamp};
use serde::{Deserialize, Serialize};

/// Lifecycle status shared by several entities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityStatus {
    Active,
    Disabled,
    Pending,
    Revoked,
}

/// Tenant authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthMode {
    CloudflareAccess,
    GenericOidc,
    Development,
}

/// Tenant (specification §20.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: TenantId,
    pub name: String,
    pub slug: String,
    pub status: EntityStatus,
    pub created_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_policy_id: Option<PolicyId>,
    pub auth_mode: AuthMode,
}

/// Principal type (Human / OAuth client / Device / local IPC).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    Human,
    OauthClient,
    Device,
    LocalIpc,
    Service,
}

/// Principal (specification §20.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub tenant_id: TenantId,
    #[serde(rename = "type")]
    pub principal_type: PrincipalType,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_subject: Option<String>,
    pub display_name: String,
    pub status: EntityStatus,
    pub created_at: Timestamp,
}

/// Convenience membership role (UI / initial grants only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRole {
    Owner,
    Admin,
    Member,
    Auditor,
}

/// Membership (specification §20.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Membership {
    pub id: MembershipId,
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub role: MembershipRole,
    pub status: EntityStatus,
    pub created_at: Timestamp,
}

/// Device operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceOs {
    Windows,
    Macos,
    Linux,
    Unknown,
}

/// Device (specification §20.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: DeviceId,
    pub tenant_id: TenantId,
    pub owner_principal_id: PrincipalId,
    pub name: String,
    pub hostname: String,
    pub os: DeviceOs,
    pub arch: String,
    pub agent_version: String,
    pub protocol_version: String,
    /// Device public key material (not a secret). Never store private keys here.
    pub public_key: String,
    #[serde(default)]
    pub labels: Vec<String>,
    pub status: EntityStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<Timestamp>,
    pub created_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<Timestamp>,
}

/// Workspace path mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceMode {
    ReadWrite,
    ReadOnly,
}

/// Workspace (specification §20.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub id: WorkspaceId,
    pub device_id: DeviceId,
    pub name: String,
    pub canonical_path: String,
    pub mode: WorkspaceMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    pub created_at: Timestamp,
}

/// Policy decision tri-state (specification §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Ask,
    Deny,
}

/// Mechanical operation classification (specification §7.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    Elevated,
    WritesOutsideWorkspace,
    ReadsSensitiveLocation,
    WritesSensitiveLocation,
    ExternalDataTransfer,
    RawShell,
    SystemPersistenceChange,
    PackageInstall,
    ServiceChange,
    UserAccountChange,
    DestructiveFileChange,
    PublicOrOpenWorldEffect,
}

/// Capability grant issued to a principal (temporary or standing).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub id: CapabilityGrantId,
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    pub status: EntityStatus,
    pub created_at: Timestamp,
    pub created_by: PrincipalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Expiry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Single policy rule in the **specification's** §7.3 shape.
///
/// This is the wire/schema model that `spec-bundle/schemas/policy.schema.json`
/// and the shared fixtures describe. It is not the rule the engine evaluates:
/// `ownmesh_policy::PolicyRule` is a deliberately narrower type carrying only
/// the conditions the device can decide, and it is what `policy.toml` stores.
/// The two are intentionally separate and must not be assumed interchangeable
/// (see `spec-bundle/README.md` for which artifacts are shipped contracts).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: PolicyRuleId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<PolicyId>,
    pub priority: i32,
    pub decision: PolicyDecision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub principal_ids: Vec<PrincipalId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub device_ids: Vec<DeviceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub workspace_ids: Vec<WorkspaceId>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub path_globs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub executables: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elevated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_shell: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_classes: Vec<OperationClass>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Expiry>,
}

/// Approval workflow state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

/// Scope remembered when a human approves (specification §7.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalScope {
    Once,
    OperationRetry,
    Session,
    Workspace,
    Device,
    Principal,
    Always,
    DenyOnce,
    DenyAlways,
}

/// Approval record linked to an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Approval {
    pub id: ApprovalId,
    pub tenant_id: TenantId,
    pub operation_id: OperationId,
    pub requester_principal_id: PrincipalId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approver_principal_id: Option<PrincipalId>,
    pub state: ApprovalState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ApprovalScope>,
    pub created_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Expiry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Operation execution status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    PendingApproval,
    Running,
    Completed,
    Failed,
    Cancelled,
    TimedOut,
}

/// Operation (specification §20.8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub id: OperationId,
    pub tenant_id: TenantId,
    pub requester_principal_id: PrincipalId,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    pub capability: String,
    pub status: OperationStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,
    pub approval_state: ApprovalState,
    pub created_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_summary: Option<serde_json::Value>,
}

/// Session kind (specification §12.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionType {
    Process,
    Terminal,
    LocalShell,
}

/// Session lifecycle state (specification §12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Starting,
    Running,
    WaitingInput,
    WaitingApproval,
    Completed,
    Failed,
    Cancelled,
    Detached,
    Orphaned,
    Unreachable,
}

/// Session metadata (specification §12.2 / §20.7). Output bodies stay on-device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub session_id: SessionId,
    pub session_type: SessionType,
    pub device_id: DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    pub state: SessionState,
    pub created_by: PrincipalId,
    pub created_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_principal: Option<PrincipalId>,
    #[serde(default)]
    pub controller_lease_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_lease_expires_at: Option<Expiry>,
    #[serde(default)]
    pub last_event_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_id: Option<u32>,
}

/// Audit event (specification §20.9). Metadata-oriented; no secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub tenant_id: TenantId,
    pub event_type: String,
    pub created_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_principal_id: Option<PrincipalId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<DeviceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<SessionId>,
    /// Content hash of detailed local payload when cloud stores metadata only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn ts() -> Timestamp {
        Timestamp::from_offset(datetime!(2026-08-06 00:00:00 UTC))
    }

    #[test]
    fn tenant_json_roundtrip() {
        let t = Tenant {
            id: TenantId::parse("ten_example").unwrap(),
            name: "Personal".into(),
            slug: "personal".into(),
            status: EntityStatus::Active,
            created_at: ts(),
            default_policy_id: Some(PolicyId::parse("pol_recommended").unwrap()),
            auth_mode: AuthMode::CloudflareAccess,
        };
        let json = serde_json::to_string_pretty(&t).unwrap();
        let back: Tenant = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);
    }
}
