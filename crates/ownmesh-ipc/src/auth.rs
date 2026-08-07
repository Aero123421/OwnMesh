//! Peer authentication and principal mapping for local IPC.
//!
//! Shared `daemon.token` authentication is **abolished**. The server authenticates
//! peers from OS credentials (Unix `SO_PEERCRED` / Windows named-pipe client PID+SID+exe)
//! and optionally from **server-managed, per-client, non-shared** credentials.
//! Self-reported HELLO `client_name` / `owner` are never trusted principal inputs.
//!
//! # Credential threat model
//!
//! Per-client credentials identify **cooperative** clients only. A malicious process
//! under the same OS user can read owner-only state files and present stolen secrets.
//! See [`crate::registry`] for the persistent store and the same limitation.

use crate::error::{IpcError, IpcResult};
use crate::registry::{
    canonical_client_id, managed_principal, BootstrapStatus, CredentialRegistry, RegistryEntry,
    MANAGEMENT_CLIENT_ID, MANAGEMENT_PRINCIPAL,
};
use crate::rpc::methods;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;

/// Filename historically used for the shared daemon auth token (legacy; not used for auth).
pub const AUTH_TOKEN_FILE_NAME: &str = "daemon.token";

/// Secret wrapper that never prints its contents via [`Debug`] / [`Display`].
///
/// Use [`RedactedSecret::expose`] only at the authentication boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactedSecret(String);

impl RedactedSecret {
    /// Wrap plaintext secret bytes (typically hex).
    #[must_use]
    pub fn new(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    /// Controlled expose for verification / persistence only — never log this.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Whether the wrapper holds no material.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl std::fmt::Debug for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactedSecret([REDACTED])")
    }
}

impl std::fmt::Display for RedactedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Constant-time equality for equal-length secret bytes.
///
/// Length is not secret (generated credentials have a fixed representation), so
/// malformed lengths are rejected before [`ConstantTimeEq::ct_eq`].
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// OS-attested peer identity captured on the server accept path.
///
/// Never accept a client-supplied structure as a substitute for this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsPeerIdentity {
    /// Peer process id.
    pub pid: u32,
    /// OS user key (Unix uid decimal, or Windows SID / username).
    pub user_id: String,
    /// Best-effort absolute peer executable path (normalized).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
}

impl OsPeerIdentity {
    /// Build the canonical, stable principal key used for ACL and revocation.
    ///
    /// The default principal is the OS user key. Executable paths remain attested
    /// metadata but are deliberately not identity-bearing: best-effort executable
    /// lookup must not change authorization identity between reconnects. Process ids
    /// are transient and likewise never become authorization identities.
    #[must_use]
    pub fn principal_key(&self) -> String {
        canonicalize_principal_key(&format!("user:{}", self.user_id))
    }
}

/// Material presented by a connecting peer (legacy shape retained for tests / redaction).
///
/// `token`, `client_name`, and `owner` are **not** trusted authentication inputs.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerCredential {
    /// Legacy shared secret field — must be empty; non-empty values are rejected.
    #[serde(default)]
    pub token: String,
    /// Untrusted client label (ignored for principal mapping).
    #[serde(default)]
    pub client_name: String,
    /// Untrusted owner claim (ignored for principal mapping).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Optional OS user id when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_user_id: Option<String>,
    /// Optional process id of the peer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Optional server-issued per-client credential (non-shared).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_credential: Option<String>,
}

impl std::fmt::Debug for PeerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerCredential")
            .field("token", &RedactedSecret::new(self.token.clone()))
            .field("client_name", &self.client_name)
            .field("owner", &self.owner)
            .field("os_user_id", &self.os_user_id)
            .field("pid", &self.pid)
            .field(
                "client_credential",
                &self
                    .client_credential
                    .as_ref()
                    .map(|_| RedactedSecret::new(String::new())),
            )
            .finish()
    }
}

/// Server-side record for a non-shared client credential (in-memory store).
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCredentialRecord {
    /// Stable client id (defaults to principal at issuance).
    pub client_id: String,
    /// Opaque secret presented at HELLO (redacted in Debug).
    pub secret: RedactedSecret,
    /// Principal key bound to this credential (server-assigned).
    pub principal_key: String,
    /// OS user id the credential is bound to at issuance.
    pub bound_user_id: String,
    /// Monotonic generation incremented by rotation.
    pub generation: u64,
    /// Revoked records never authenticate.
    pub revoked: bool,
}

impl std::fmt::Debug for ClientCredentialRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientCredentialRecord")
            .field("client_id", &self.client_id)
            .field("secret", &self.secret)
            .field("principal_key", &self.principal_key)
            .field("bound_user_id", &self.bound_user_id)
            .field("generation", &self.generation)
            .field("revoked", &self.revoked)
            .finish()
    }
}

/// Result of mapping an OS peer + optional client credential to a principal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthResolution {
    /// Server-assigned principal key.
    pub principal_key: String,
    /// True when a valid server-issued client credential was presented.
    pub credentialed: bool,
    /// Registry / in-memory client id when credentialed.
    pub client_id: Option<String>,
    /// Credential generation bound at HELLO (registry-backed clients).
    pub credential_generation: Option<u64>,
}

/// Expected ACL material held by the daemon.
///
/// # Default vs registry-backed behaviour
///
/// [`AuthGate::local_user`] / [`AuthGate::for_user`] keep the historical default:
/// same-uid OS peers authenticate as the OS principal without a client credential,
/// and method authorization is unrestricted at the gate (TUI / session-host /
/// ipc-client consumers). Attaching daemon state via
/// [`AuthGate::with_daemon_registry`] enables **strict uncredentialed policy**: only
/// `daemon.status` and `ipc.ping` are allowed without a valid client credential.
#[derive(Debug, Clone)]
pub struct AuthGate {
    /// When empty, only `own_user_id` is accepted.
    allowed_user_ids: Vec<String>,
    /// Daemon process user id.
    own_user_id: String,
    /// In-memory per-client credentials (secret never used as a map key).
    credentials: Arc<RwLock<Vec<ClientCredentialRecord>>>,
    /// Optional durable registry (daemon state directory). Presence enables strict policy.
    registry: Option<Arc<RwLock<CredentialRegistry>>>,
    /// When true, uncredentialed peers may only call ping/status.
    strict_uncredentialed: bool,
}

impl AuthGate {
    /// Construct a gate that accepts the current OS user (and optional allow-list).
    ///
    /// Default behaviour is preserved: no registry, no strict uncredentialed ACL.
    #[must_use]
    pub fn local_user() -> Self {
        Self {
            allowed_user_ids: Vec::new(),
            own_user_id: current_os_user_id(),
            credentials: Arc::new(RwLock::new(Vec::new())),
            registry: None,
            strict_uncredentialed: false,
        }
    }

    /// Construct a gate with an explicit own-user id (tests).
    ///
    /// Default behaviour is preserved: no registry, no strict uncredentialed ACL.
    #[must_use]
    pub fn for_user(own_user_id: impl Into<String>) -> Self {
        Self {
            allowed_user_ids: Vec::new(),
            own_user_id: normalize_principal_part(&own_user_id.into()),
            credentials: Arc::new(RwLock::new(Vec::new())),
            registry: None,
            strict_uncredentialed: false,
        }
    }

    /// Legacy constructor. Shared tokens are **not** used; this only seeds `own_user_id`.
    ///
    /// Kept so older call sites compile while migrating off `AuthGate::new(token)`.
    #[deprecated(note = "shared daemon tokens are abolished; use AuthGate::local_user()")]
    #[must_use]
    pub fn new(_ignored_shared_token: impl Into<String>) -> Self {
        Self::local_user()
    }

    /// Restrict accepted OS user ids (non-empty replace the default own-user policy).
    #[must_use]
    pub fn with_allowed_users(mut self, users: Vec<String>) -> Self {
        self.allowed_user_ids = users
            .into_iter()
            .map(|user| normalize_principal_part(&user))
            .collect();
        self
    }

    /// Attach daemon-owned durable credential state and ensure the fixed management
    /// bootstrap credential for this gate's OS user.
    ///
    /// This is the only public registry attachment surface: callers cannot obtain the
    /// registry, choose a persisted principal, or invoke its offline mutators.
    /// Registry-backed daemons treat uncredentialed same-uid peers as probe-only.
    ///
    /// # Errors
    ///
    /// Fails closed when state custody or fixed bootstrap validation fails.
    pub fn with_daemon_registry(
        mut self,
        state_dir: impl AsRef<Path>,
    ) -> IpcResult<(Self, BootstrapStatus)> {
        let mut registry = CredentialRegistry::open(state_dir)?;
        let status = registry.ensure_management_bootstrap(&self.own_user_id)?;
        self.registry = Some(Arc::new(RwLock::new(registry)));
        self.strict_uncredentialed = true;
        Ok((self, status))
    }

    #[cfg(test)]
    fn with_registry(mut self, registry: Arc<RwLock<CredentialRegistry>>) -> Self {
        self.registry = Some(registry);
        self.strict_uncredentialed = true;
        self
    }

    /// Whether this gate enforces the uncredentialed allow-list.
    #[must_use]
    pub fn strict_uncredentialed(&self) -> bool {
        self.strict_uncredentialed
    }

    /// Borrow the shared in-memory credential list (tests only).
    #[cfg(test)]
    #[must_use]
    fn credentials_handle(&self) -> Arc<RwLock<Vec<ClientCredentialRecord>>> {
        Arc::clone(&self.credentials)
    }

    /// Issue a server-managed, non-shared client credential bound to `bound_user_id`.
    ///
    /// When a registry is attached, the credential is provisioned durably under
    /// `client_id == principal_key`. Otherwise it is held in the process-local store.
    ///
    /// The returned secret is the only copy the caller receives; it is not a shared daemon token.
    ///
    /// This is a **daemon-local** bootstrap API — not an uncredentialed IPC method.
    pub(crate) fn issue_client_credential(
        &self,
        client_id: impl Into<String>,
        bound_user_id: impl Into<String>,
    ) -> IpcResult<String> {
        if self.registry.is_some() {
            return Err(IpcError::Unauthorized(
                "durable credentials may only be provisioned through authenticated management RPC"
                    .into(),
            ));
        }
        self.provision_client_credential(client_id, bound_user_id)
    }

    /// Internal provisioning primitive used by authenticated daemon dispatch and tests.
    pub(crate) fn provision_client_credential(
        &self,
        client_id: impl Into<String>,
        bound_user_id: impl Into<String>,
    ) -> IpcResult<String> {
        let client_id = canonical_client_id(&client_id.into())?;
        let principal_key = managed_principal(&client_id);
        let bound_user_id = normalize_principal_part(&bound_user_id.into());
        if bound_user_id.is_empty() {
            return Err(IpcError::Unauthorized(
                "credential bound OS user must be non-empty".into(),
            ));
        }
        if let Some(reg) = &self.registry {
            let mut guard = reg.write().map_err(|_| registry_lock_error())?;
            return guard.provision(client_id, bound_user_id);
        }
        let mut guard = self
            .credentials
            .write()
            .map_err(|_| IpcError::Unauthorized("credential store lock poisoned".into()))?;
        if guard.iter().any(|r| r.client_id == client_id && !r.revoked) {
            return Err(IpcError::Unauthorized(format!(
                "client credential '{client_id}' already provisioned"
            )));
        }
        let generation = guard
            .iter()
            .find(|record| record.client_id == client_id)
            .map_or(Ok(1), |record| {
                record.generation.checked_add(1).ok_or_else(|| {
                    IpcError::Protocol(format!("credential generation overflow for '{client_id}'"))
                })
            })?;
        guard.retain(|record| record.client_id != client_id);
        let secret = generate_token();
        guard.push(ClientCredentialRecord {
            client_id,
            secret: RedactedSecret::new(secret.clone()),
            principal_key,
            bound_user_id,
            generation,
            revoked: false,
        });
        Ok(secret)
    }

    /// Rotate the secret for `client_id` (daemon-local). Old secret becomes invalid.
    pub(crate) fn rotate_client_credential(&self, client_id: impl AsRef<str>) -> IpcResult<String> {
        let client_id = canonicalize_principal_key(client_id.as_ref());
        if let Some(reg) = &self.registry {
            let mut guard = reg.write().map_err(|_| registry_lock_error())?;
            return guard.rotate(&client_id);
        }
        let mut guard = self
            .credentials
            .write()
            .map_err(|_| IpcError::Unauthorized("credential store lock poisoned".into()))?;
        let record = guard
            .iter_mut()
            .find(|r| r.client_id == client_id && !r.revoked)
            .ok_or_else(|| {
                IpcError::Unauthorized(format!("no active credential for client '{client_id}'"))
            })?;
        let secret = generate_token();
        record.generation = record.generation.checked_add(1).ok_or_else(|| {
            IpcError::Protocol(format!("credential generation overflow for '{client_id}'"))
        })?;
        record.secret = RedactedSecret::new(secret.clone());
        Ok(secret)
    }

    /// Revoke `client_id` (daemon-local). Mapping stops authenticating immediately.
    pub(crate) fn revoke_client_credential(&self, client_id: impl AsRef<str>) -> IpcResult<()> {
        let client_id = canonicalize_principal_key(client_id.as_ref());
        if let Some(reg) = &self.registry {
            let mut guard = reg.write().map_err(|_| registry_lock_error())?;
            return guard.revoke(&client_id);
        }
        let mut guard = self
            .credentials
            .write()
            .map_err(|_| IpcError::Unauthorized("credential store lock poisoned".into()))?;
        let record = guard
            .iter_mut()
            .find(|r| r.client_id == client_id && !r.revoked)
            .ok_or_else(|| {
                IpcError::Unauthorized(format!("no credential for client '{client_id}'"))
            })?;
        record.revoked = true;
        record.secret = RedactedSecret::new(String::new());
        Ok(())
    }

    /// Validate OS peer identity (user allow-list / own user).
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Unauthorized`] when the peer user is not permitted.
    pub fn verify_os_peer(&self, peer: &OsPeerIdentity) -> IpcResult<()> {
        let peer_user = normalize_principal_part(&peer.user_id);
        if peer_user.is_empty() {
            return Err(IpcError::Unauthorized(
                "missing OS peer user identity".into(),
            ));
        }
        let allowed = if self.allowed_user_ids.is_empty() {
            peer_user == self.own_user_id
        } else {
            self.allowed_user_ids.iter().any(|u| u == &peer_user)
        };
        if !allowed {
            return Err(IpcError::Unauthorized(format!(
                "OS peer user '{}' is not permitted",
                peer.user_id
            )));
        }
        Ok(())
    }

    /// Map an authenticated OS peer (+ optional server-issued credential) to auth material.
    ///
    /// Shared `token` values are rejected. Self-reported `client_name` / `owner` are ignored
    /// for principal assignment — only OS peer + registry/in-memory credential map to a
    /// registered principal.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Unauthorized`] on failed OS checks, disabled shared tokens,
    /// or unknown / mismatched / revoked client credentials.
    pub fn resolve_auth(
        &self,
        os_peer: &OsPeerIdentity,
        presented: &PeerCredential,
    ) -> IpcResult<AuthResolution> {
        self.verify_os_peer(os_peer)?;

        // Shared daemon.token path is explicitly disabled.
        if !presented.token.trim().is_empty() {
            return Err(IpcError::Unauthorized(
                "shared daemon.token authentication is disabled; OS peer credentials are required"
                    .into(),
            ));
        }

        if let Some(secret) = presented
            .client_credential
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            return self.resolve_credentialed(os_peer, secret);
        }

        // Default: principal is derived solely from OS peer credentials.
        // Self-reported client_name/owner never mint a registered principal here.
        let _ = (&presented.client_name, &presented.owner);
        Ok(AuthResolution {
            principal_key: os_peer.principal_key(),
            credentialed: false,
            client_id: None,
            credential_generation: None,
        })
    }

    /// Map peer → principal key (compatibility wrapper around [`Self::resolve_auth`]).
    ///
    /// # Errors
    ///
    /// Same as [`Self::resolve_auth`].
    pub fn resolve_principal(
        &self,
        os_peer: &OsPeerIdentity,
        presented: &PeerCredential,
    ) -> IpcResult<String> {
        Ok(self.resolve_auth(os_peer, presented)?.principal_key)
    }

    fn resolve_credentialed(
        &self,
        os_peer: &OsPeerIdentity,
        secret: &str,
    ) -> IpcResult<AuthResolution> {
        if let Some(reg) = &self.registry {
            let guard = reg.read().map_err(|_| registry_lock_error())?;
            let Some(entry) = guard.find_by_secret(secret) else {
                return Err(IpcError::Unauthorized("unknown client credential".into()));
            };
            return bind_registry_entry(os_peer, entry);
        }

        let guard = self
            .credentials
            .read()
            .map_err(|_| IpcError::Unauthorized("credential store lock poisoned".into()))?;
        let Some(record) = find_memory_by_secret(&guard, secret) else {
            return Err(IpcError::Unauthorized("unknown client credential".into()));
        };
        if normalize_principal_part(&record.bound_user_id)
            != normalize_principal_part(&os_peer.user_id)
        {
            return Err(IpcError::Unauthorized(
                "client credential is not bound to this OS peer user".into(),
            ));
        }
        Ok(AuthResolution {
            principal_key: canonicalize_principal_key(&record.principal_key),
            credentialed: true,
            client_id: Some(record.client_id.clone()),
            credential_generation: Some(record.generation),
        })
    }

    /// Authorize an IPC method for a bound client identity.
    ///
    /// Default (`local_user` / `for_user`): uncredentialed behavior remains unrestricted
    /// (handler/policy decide), while issued credential lifecycle is still revalidated.
    /// Registry-backed strict mode revalidates credential revocation on every dispatch;
    /// uncredentialed peers may only call [`methods::PING`] and [`methods::STATUS`].
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Unauthorized`] when the method is denied.
    pub fn authorize_method(&self, method: &str, auth: &AuthResolution) -> IpcResult<()> {
        // Human-operator actions are fail-closed on ordinary IPC until a distinct
        // OS/UI user-presence proof exists. Same-UID uncredentialed connections are
        // forgeable and must not be treated as human presence.
        if human_operator_method(method) {
            return authorize_human_operator_method(auth);
        }
        if auth.credentialed {
            let client_id = auth.client_id.as_deref().ok_or_else(|| {
                IpcError::Unauthorized("credentialed identity has no registry client id".into())
            })?;
            let expected_generation = auth.credential_generation.unwrap_or(0);
            let expected_principal = canonicalize_principal_key(&auth.principal_key);
            if credential_lifecycle_method(method)
                && (client_id != MANAGEMENT_CLIENT_ID || expected_principal != MANAGEMENT_PRINCIPAL)
            {
                return Err(IpcError::Unauthorized(
                    "credential lifecycle requires the fixed credentialed management client".into(),
                ));
            }
            if let Some(registry) = &self.registry {
                let guard = registry.read().map_err(|_| registry_lock_error())?;
                let entry = guard.active_entry(client_id).ok_or_else(|| {
                    IpcError::Unauthorized(format!(
                        "client credential '{client_id}' is revoked or no longer registered"
                    ))
                })?;
                if entry.generation != expected_generation {
                    return Err(IpcError::Unauthorized(
                        "client credential rotated after HELLO; reconnect required".into(),
                    ));
                }
                if entry.principal_key != expected_principal {
                    return Err(IpcError::Unauthorized(
                        "registered principal changed after HELLO; reconnect required".into(),
                    ));
                }
                return Ok(());
            }

            let guard = self
                .credentials
                .read()
                .map_err(|_| IpcError::Unauthorized("credential store lock poisoned".into()))?;
            let record = guard
                .iter()
                .find(|record| record.client_id == client_id && !record.revoked)
                .ok_or_else(|| {
                    IpcError::Unauthorized(format!(
                        "client credential '{client_id}' is revoked or no longer registered"
                    ))
                })?;
            if record.generation != expected_generation
                || canonicalize_principal_key(&record.principal_key) != expected_principal
            {
                return Err(IpcError::Unauthorized(
                    "client credential changed after HELLO; reconnect required".into(),
                ));
            }
            return Ok(());
        }
        if !self.strict_uncredentialed {
            return Ok(());
        }
        if uncredentialed_method_allowed(method) {
            return Ok(());
        }
        Err(IpcError::Unauthorized(format!(
            "method '{method}' requires a server-issued client credential \
             (uncredentialed same-uid peers may only call ipc.ping/daemon.status)"
        )))
    }

    /// Legacy verify entry used by older unit tests — now enforces token abolition + OS mapping.
    ///
    /// # Errors
    ///
    /// Returns unauthorized when the legacy shared token is present or OS identity is missing.
    pub fn verify(&self, peer: &PeerCredential) -> IpcResult<()> {
        if !peer.token.trim().is_empty() {
            return Err(IpcError::Unauthorized(
                "shared daemon.token authentication is disabled".into(),
            ));
        }
        let os_peer = OsPeerIdentity {
            pid: peer.pid.unwrap_or(0),
            user_id: peer
                .os_user_id
                .clone()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| self.own_user_id.clone()),
            exe_path: None,
        };
        let _ = self.resolve_auth(&os_peer, peer)?;
        Ok(())
    }

    /// Own user id used when the allow-list is empty.
    #[must_use]
    pub fn own_user_id(&self) -> &str {
        &self.own_user_id
    }
}

fn registry_lock_error() -> IpcError {
    IpcError::Io(std::io::Error::other("credential registry lock poisoned"))
}

fn bind_registry_entry(
    os_peer: &OsPeerIdentity,
    entry: &RegistryEntry,
) -> IpcResult<AuthResolution> {
    if normalize_principal_part(&entry.bound_user_id) != normalize_principal_part(&os_peer.user_id)
    {
        return Err(IpcError::Unauthorized(
            "client credential is not bound to this OS peer user".into(),
        ));
    }
    Ok(AuthResolution {
        principal_key: canonicalize_principal_key(&entry.principal_key),
        credentialed: true,
        client_id: Some(entry.client_id.clone()),
        credential_generation: Some(entry.generation),
    })
}

fn find_memory_by_secret<'a>(
    records: &'a [ClientCredentialRecord],
    presented: &str,
) -> Option<&'a ClientCredentialRecord> {
    // Adapt memory records into the registry scan shape without HashMap-by-secret.
    let presented_bytes = presented.as_bytes();
    let mut found: Option<&ClientCredentialRecord> = None;
    for record in records {
        let matches = !record.revoked
            && !record.secret.is_empty()
            && constant_time_eq(record.secret.expose().as_bytes(), presented_bytes);
        if matches {
            found = Some(record);
        }
    }
    found
}

/// Whitelist for uncredentialed same-uid peers under strict (registry-backed) policy.
///
/// Human-operator methods are **not** included: same-UID uncredentialed IPC is forgeable
/// by any local process and is not a user-presence proof (see [`human_operator_method`]).
fn uncredentialed_method_allowed(method: &str) -> bool {
    matches!(method, methods::PING | methods::STATUS)
}

fn credential_lifecycle_method(method: &str) -> bool {
    matches!(
        method,
        methods::CREDENTIAL_PROVISION | methods::CREDENTIAL_ROTATE | methods::CREDENTIAL_REVOKE
    )
}

/// Methods that mutate human-boundary state (approve/deny, policy preset, unlock, revoke).
///
/// Until a distinct OS/UI user-presence proof is bound to the specific operation and
/// expiry, these methods are fail-closed for **all** ordinary IPC clients — including
/// uncredentialed same-UID peers. Same-UID unauthenticated connections are forgeable by
/// any local process (including a credentialed agent opening a second socket) and must
/// never be represented as human presence.
#[must_use]
pub fn human_operator_method(method: &str) -> bool {
    matches!(
        method,
        methods::APPROVAL_APPROVE
            | methods::APPROVAL_DENY
            | methods::POLICY_PRESET
            | methods::DAEMON_UNLOCK
            | methods::TOKEN_REVOKE
    )
}

/// Stable unauthorized message when human-operator IPC is disabled (no presence proof).
#[must_use]
pub fn human_operator_disabled_message() -> &'static str {
    "human-operator method disabled: no distinct OS/UI user-presence proof is bound to this \
operation; ordinary IPC clients (including uncredentialed same-uid peers and client \
credentials) cannot approve, deny, change policy preset, unlock, or revoke tokens"
}

/// True when `principal` is an OS-attested local human (`user:…`).
#[must_use]
pub fn is_human_os_principal(principal: &str) -> bool {
    canonicalize_principal_key(principal).starts_with("user:")
}

/// True when `principal` is a server-issued cooperative / service principal (`client:…`).
#[must_use]
pub fn is_credentialed_client_principal(principal: &str) -> bool {
    canonicalize_principal_key(principal).starts_with("client:")
}

fn authorize_human_operator_method(auth: &AuthResolution) -> IpcResult<()> {
    // Fail-closed for every ordinary IPC principal. Credentialed and uncredentialed
    // same-UID peers alike lack a distinct OS/UI presence proof bound to this op.
    let _ = auth;
    Err(IpcError::Unauthorized(
        human_operator_disabled_message().into(),
    ))
}

/// Normalize a principal key component (case-fold + trim + path separators and aliases).
#[must_use]
pub fn normalize_principal_part(raw: &str) -> String {
    normalize_path_aliases(
        &raw.trim()
            .trim_matches('"')
            .trim_matches('\'')
            .replace('\\', "/")
            .to_ascii_lowercase(),
    )
}

/// Canonicalize a complete principal key for issuance, revocation, persistence, and checks.
///
/// Legacy process-scoped `user:<id>:exe:<path>` and `user:<id>:pid:<n>` keys collapse
/// to the stable `user:<id>` principal. Opaque server-issued principal names are still
/// case-folded and normalized consistently.
#[must_use]
pub fn canonicalize_principal_key(raw: &str) -> String {
    let mut normalized = raw
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .replace('\\', "/")
        .to_ascii_lowercase();
    // Whitespace around structural separators is never identity-bearing.
    while normalized.contains(" :") || normalized.contains(": ") {
        normalized = normalized.replace(" :", ":").replace(": ", ":");
    }

    if let Some(rest) = normalized.strip_prefix("user:") {
        // Migrate every legacy process-scoped spelling to the stable user principal.
        // Choose the earliest marker so a crafted exe path containing `:pid:` (or vice
        // versa) cannot preserve a process-scoped alias and bypass a stored revocation.
        let legacy_suffix = [rest.find(":exe:"), rest.find(":pid:")]
            .into_iter()
            .flatten()
            .min();
        let user = normalize_principal_part(
            legacy_suffix.map_or(rest, |suffix_start| &rest[..suffix_start]),
        );
        return if user.is_empty() {
            String::new()
        } else {
            format!("user:{user}")
        };
    }

    normalize_principal_part(&normalized)
}

fn normalize_path_aliases(raw: &str) -> String {
    if raw.is_empty() || !raw.contains('/') {
        return raw.to_owned();
    }
    let drive_root = raw.as_bytes().get(1) == Some(&b':') && raw.as_bytes().get(2) == Some(&b'/');
    let absolute = raw.starts_with('/') || drive_root;
    let double_slash = raw.starts_with("//");
    let mut parts: Vec<&str> = Vec::new();
    for part in raw.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                let at_drive_root = drive_root && parts.len() == 1;
                if !at_drive_root && parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !absolute {
                    parts.push(part);
                }
            }
            _ => parts.push(part),
        }
    }
    let body = parts.join("/");
    if double_slash {
        format!("//{body}")
    } else if absolute && !drive_root {
        format!("/{body}")
    } else {
        body
    }
}

/// Current process OS user key (Unix uid or Windows username).
#[must_use]
pub fn current_os_user_id() -> String {
    #[cfg(unix)]
    {
        format!("{}", rustix::process::getuid().as_raw())
    }
    #[cfg(windows)]
    {
        // Match named-pipe peer attribution exactly. Environment usernames are
        // self-process configuration, not an OS-attested identity.
        unsafe { current_windows_user_sid() }.unwrap_or_default()
    }
    #[cfg(not(any(unix, windows)))]
    {
        // Unsupported platforms must fail OS-user verification rather than inventing
        // a reconnect-unstable PID identity.
        String::new()
    }
}

#[cfg(windows)]
unsafe fn current_windows_user_sid() -> Option<String> {
    use std::mem::{size_of, MaybeUninit};
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, IsValidSid, TokenUser, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = ptr::null_mut();
    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 || token.is_null() {
        return None;
    }
    let result = (|| {
        let mut required = 0_u32;
        let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required);
        let required = usize::try_from(required).ok()?;
        let element_size = size_of::<TOKEN_USER>();
        if required < element_size {
            return None;
        }
        let elements = required.checked_add(element_size - 1)? / element_size;
        // `TOKEN_USER` has pointer alignment. A byte Vec does not guarantee it, so
        // retain aligned, uninitialized TOKEN_USER slots for the variable-size result.
        let mut buffer: Vec<MaybeUninit<TOKEN_USER>> = Vec::new();
        buffer.try_reserve_exact(elements).ok()?;
        buffer.resize_with(elements, MaybeUninit::uninit);
        let buffer_bytes = buffer.len().checked_mul(element_size)?;
        let query_len = u32::try_from(required).ok()?;
        let mut returned = query_len;
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            query_len,
            &mut returned,
        ) == 0
        {
            return None;
        }
        let returned = usize::try_from(returned).ok()?;
        if returned < element_size || returned > required || returned > buffer_bytes {
            return None;
        }
        let token_user = buffer.first()?.assume_init_ref();
        let sid = token_user.User.Sid;
        if sid.is_null() {
            return None;
        }
        let buffer_start = buffer.as_ptr() as usize;
        let sid_start = sid as usize;
        let sid_offset = sid_start.checked_sub(buffer_start)?;
        // A SID header is 8 bytes before its variable u32 sub-authorities. Check
        // that header before asking Windows APIs to inspect the returned pointer.
        let sid_remaining = returned.checked_sub(sid_offset)?;
        if sid_remaining < 8 {
            return None;
        }
        let sub_authorities = usize::from(*sid.cast::<u8>().add(1));
        let sid_len = 8_usize.checked_add(sub_authorities.checked_mul(4)?)?;
        if sid_len > sid_remaining || IsValidSid(sid) == 0 || GetLengthSid(sid) as usize != sid_len
        {
            return None;
        }
        let bytes = std::slice::from_raw_parts(sid.cast::<u8>(), sid_len);
        Some(format!("sid:{}", hex_encode(bytes)))
    })();
    let _ = CloseHandle(token);
    result
}

/// Generate a high-entropy secret (hex). Used for per-client credentials, not shared tokens.
#[must_use]
pub fn generate_token() -> String {
    // `Uuid::new_v4` is backed by the platform CSPRNG. Two independent UUIDs
    // retain roughly 244 random bits after their fixed version/variant bits.
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();
    let mut raw = [0_u8; 32];
    raw[..16].copy_from_slice(first.as_bytes());
    raw[16..].copy_from_slice(second.as_bytes());
    hex_encode(&raw)
}

/// Persist a legacy token file (disabled auth path). Retained for migration cleanup tests.
///
/// # Errors
///
/// Returns IO errors when the directory/file cannot be written.
pub fn write_token_file(runtime_dir: &Path, token: &str) -> IpcResult<PathBuf> {
    fs::create_dir_all(runtime_dir)?;
    let path = runtime_dir.join(AUTH_TOKEN_FILE_NAME);
    let tmp = runtime_dir.join(format!("{AUTH_TOKEN_FILE_NAME}.tmp"));
    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(token.as_bytes())?;
        file.write_all(b"\n")?;
        file.sync_all()?;
    }
    fs::rename(&tmp, &path)?;
    restrict_file_mode(&path)?;
    Ok(path)
}

/// Read a previously written legacy token file.
///
/// # Errors
///
/// Returns IO / framing errors when the file is missing or empty.
pub fn read_token_file(runtime_dir: &Path) -> IpcResult<String> {
    let path = runtime_dir.join(AUTH_TOKEN_FILE_NAME);
    let raw = fs::read_to_string(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            IpcError::Disconnected(format!(
                "daemon token not found at {} (shared tokens are disabled; is ownmeshd running?)",
                path.display()
            ))
        } else {
            IpcError::Io(err)
        }
    })?;
    let token = raw.trim().to_owned();
    if token.is_empty() {
        return Err(IpcError::Protocol("daemon token file is empty".into()));
    }
    Ok(token)
}

/// Best-effort restrictive mode for sensitive files.
fn restrict_file_mode(path: &Path) -> IpcResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    {
        let _ = path;
    }
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Redact secrets from a free-form log/message string for defensive logging.
#[must_use]
pub fn redact_secrets(input: &str, secrets: &[&str]) -> String {
    let mut out = input.to_owned();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        if out.contains(secret) {
            out = out.replace(secret, "[REDACTED]");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn token_roundtrip_file() {
        let dir = tempdir().unwrap();
        let token = generate_token();
        write_token_file(dir.path(), &token).unwrap();
        let loaded = read_token_file(dir.path()).unwrap();
        assert_eq!(loaded, token);
    }

    #[test]
    fn auth_gate_rejects_shared_token() {
        let gate = AuthGate::local_user();
        let bad = PeerCredential {
            token: "any-shared-token".into(),
            client_name: "ownmesh".into(),
            owner: None,
            os_user_id: Some(gate.own_user_id().into()),
            pid: Some(1),
            client_credential: None,
        };
        let err = gate.verify(&bad).unwrap_err();
        assert_eq!(err.code(), "ipc_unauthorized");
    }

    #[test]
    fn principal_from_os_peer_ignores_client_name() {
        let gate = AuthGate::for_user("1000");
        let os = OsPeerIdentity {
            pid: 42,
            user_id: "1000".into(),
            exe_path: Some("/usr/bin/ownmesh".into()),
        };
        let a = PeerCredential {
            token: String::new(),
            client_name: "admin".into(),
            owner: Some("root".into()),
            os_user_id: None,
            pid: None,
            client_credential: None,
        };
        let b = PeerCredential {
            token: String::new(),
            client_name: "root".into(),
            owner: Some("admin".into()),
            os_user_id: None,
            pid: None,
            client_credential: None,
        };
        let pa = gate.resolve_principal(&os, &a).unwrap();
        let pb = gate.resolve_principal(&os, &b).unwrap();
        assert_eq!(pa, pb);
        assert_eq!(pa, os.principal_key());
        assert!(!pa.contains("admin"));
        assert!(!pa.contains("root"));
        let auth = gate.resolve_auth(&os, &a).unwrap();
        assert!(!auth.credentialed);
    }

    #[test]
    fn per_client_credential_maps_principal() {
        let gate = AuthGate::for_user("alice");
        let secret = gate
            .issue_client_credential("  Agent-ChatGPT  ", " ALICE ")
            .unwrap();
        let os = OsPeerIdentity {
            pid: 7,
            user_id: "alice".into(),
            exe_path: Some("C:/ownmesh.exe".into()),
        };
        let presented = PeerCredential {
            token: String::new(),
            client_name: "ignored-label".into(),
            owner: Some("spoofed-owner".into()),
            os_user_id: None,
            pid: None,
            client_credential: Some(secret.clone()),
        };
        let auth = gate.resolve_auth(&os, &presented).unwrap();
        assert_eq!(auth.principal_key, "client:agent-chatgpt");
        assert!(auth.credentialed);
        // Secret must not appear in Debug of gate credentials.
        let dbg = format!("{:?}", gate.credentials_handle());
        assert!(!dbg.contains(&secret));
    }

    #[test]
    fn legacy_process_scoped_principals_collapse_to_stable_user() {
        for legacy in [
            r#"  USER : ALICE : EXE : "C:\OwnMesh\bin\..\ownmesh.exe"  "#,
            "user:alice:exe:c:/ownmesh/ownmesh.exe",
            "USER:Alice:PID:12345",
            "user:alice:exe:c:/crafted:pid:99",
            "user:alice:pid:99:exe:c:/crafted",
        ] {
            assert_eq!(canonicalize_principal_key(legacy), "user:alice", "{legacy}");
        }
    }

    #[test]
    fn missing_executable_principal_is_stable_and_never_pid_based() {
        let a = OsPeerIdentity {
            pid: 10,
            user_id: " Alice ".into(),
            exe_path: None,
        };
        let b = OsPeerIdentity {
            pid: 99_999,
            user_id: "alice".into(),
            exe_path: Some("   ".into()),
        };
        assert_eq!(a.principal_key(), "user:alice");
        assert_eq!(a.principal_key(), b.principal_key());
        assert!(!a.principal_key().contains("pid"));
        assert_eq!(
            canonicalize_principal_key("USER:Alice:PID:12345"),
            "user:alice"
        );
    }

    #[test]
    fn credential_rejected_for_other_os_user() {
        let gate = AuthGate::for_user("alice");
        let secret = gate
            .issue_client_credential("agent-chatgpt", "alice")
            .unwrap();
        let os = OsPeerIdentity {
            pid: 7,
            user_id: "bob".into(),
            exe_path: None,
        };
        let presented = PeerCredential {
            token: String::new(),
            client_name: String::new(),
            owner: None,
            os_user_id: None,
            pid: None,
            client_credential: Some(secret),
        };
        // bob is not allowed by gate either; ensure credential path fails closed.
        let gate_bob = AuthGate::for_user("bob");
        // Move credential store is not shared — re-issue on bob gate with alice binding.
        let secret2 = gate_bob
            .issue_client_credential("agent-chatgpt", "alice")
            .unwrap();
        let presented2 = PeerCredential {
            client_credential: Some(secret2),
            ..presented
        };
        let err = gate_bob.resolve_principal(&os, &presented2).unwrap_err();
        assert_eq!(err.code(), "ipc_unauthorized");
    }

    #[test]
    fn redact_hides_token() {
        let msg = "token=super-secret value";
        assert_eq!(
            redact_secrets(msg, &["super-secret"]),
            "token=[REDACTED] value"
        );
    }

    #[test]
    fn redacted_secret_debug_display_hide_material() {
        let secret = RedactedSecret::new("top-secret-value");
        assert!(!format!("{secret:?}").contains("top-secret"));
        assert_eq!(format!("{secret}"), "[REDACTED]");
        assert_eq!(secret.expose(), "top-secret-value");
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abcdef", b"abcdef"));
        assert!(!constant_time_eq(b"abcdef", b"abcdeg"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn rotate_and_revoke_memory_store() {
        let gate = AuthGate::for_user("alice");
        let old = gate.issue_client_credential("agent", "alice").unwrap();
        let os = OsPeerIdentity {
            pid: 1,
            user_id: "alice".into(),
            exe_path: None,
        };
        let presented_old = PeerCredential {
            token: String::new(),
            client_name: "spoof".into(),
            owner: Some("other".into()),
            os_user_id: None,
            pid: None,
            client_credential: Some(old.clone()),
        };
        assert_eq!(
            gate.resolve_principal(&os, &presented_old).unwrap(),
            "client:agent"
        );
        let new = gate.rotate_client_credential("agent").unwrap();
        assert_ne!(old, new);
        assert!(gate.resolve_principal(&os, &presented_old).is_err());
        let presented_new = PeerCredential {
            client_credential: Some(new),
            ..presented_old.clone()
        };
        assert_eq!(
            gate.resolve_principal(&os, &presented_new).unwrap(),
            "client:agent"
        );
        gate.revoke_client_credential("agent").unwrap();
        assert!(gate.resolve_principal(&os, &presented_new).is_err());
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn registry_backed_gate_restores_and_enforces_strict_methods() {
        let dir = tempdir().unwrap();
        let reg = CredentialRegistry::open(dir.path()).unwrap();
        let reg = Arc::new(RwLock::new(reg));
        let gate = AuthGate::for_user("alice").with_registry(Arc::clone(&reg));
        assert!(gate.strict_uncredentialed());
        let secret = gate
            .provision_client_credential("chatgpt", "alice")
            .expect("authenticated provisioning into registry");

        let os = OsPeerIdentity {
            pid: 3,
            user_id: "alice".into(),
            exe_path: None,
        };
        // Spoofed HELLO name/owner cannot mint the registered principal without secret.
        let spoofed = PeerCredential {
            token: String::new(),
            client_name: "chatgpt".into(),
            owner: Some("chatgpt".into()),
            os_user_id: None,
            pid: None,
            client_credential: None,
        };
        let uncred = gate.resolve_auth(&os, &spoofed).unwrap();
        assert!(!uncred.credentialed);
        assert_eq!(uncred.principal_key, os.principal_key());
        assert_ne!(uncred.principal_key, "client:chatgpt");

        let presented = PeerCredential {
            client_credential: Some(secret.clone()),
            client_name: "ignored".into(),
            owner: Some("ignored-owner".into()),
            ..spoofed.clone()
        };
        let auth = gate.resolve_auth(&os, &presented).unwrap();
        assert!(auth.credentialed);
        assert_eq!(auth.principal_key, "client:chatgpt");

        // Strict method ACL.
        let uncred_id = uncred.clone();
        let cred_id = auth.clone();
        assert!(gate.authorize_method(methods::PING, &uncred_id).is_ok());
        assert!(gate.authorize_method(methods::STATUS, &uncred_id).is_ok());
        // Human-operator methods: fail-closed for every ordinary IPC principal
        // (uncredentialed same-UID is forgeable; not a presence proof).
        for method in [
            methods::APPROVAL_APPROVE,
            methods::APPROVAL_DENY,
            methods::POLICY_PRESET,
            methods::DAEMON_UNLOCK,
            methods::TOKEN_REVOKE,
        ] {
            assert!(
                gate.authorize_method(method, &uncred_id).is_err(),
                "{method} must deny uncredentialed same-uid (no presence proof)"
            );
            assert!(
                gate.authorize_method(method, &cred_id).is_err(),
                "{method} must deny credentialed agents"
            );
        }
        for method in [
            methods::OPS_EXEC,
            methods::OPS_FS_WRITE,
            methods::OPS_FS_READ,
            methods::POLICY_SHOW,
            methods::APPROVAL_LIST,
            methods::DAEMON_LOCKDOWN,
            "session.open",
            "session.write",
            "session.claim",
        ] {
            assert!(
                gate.authorize_method(method, &uncred_id).is_err(),
                "{method} must be denied for uncredentialed"
            );
            assert!(
                gate.authorize_method(method, &cred_id).is_ok(),
                "{method} allowed when credentialed"
            );
        }
        for method in [
            methods::CREDENTIAL_PROVISION,
            methods::CREDENTIAL_ROTATE,
            methods::CREDENTIAL_REVOKE,
        ] {
            assert!(gate.authorize_method(method, &uncred_id).is_err());
            assert!(
                gate.authorize_method(method, &cred_id).is_err(),
                "ordinary credential must not manage lifecycle: {method}"
            );
        }

        // Rotate + revoke + restart restore.
        let old = secret;
        let new = gate.rotate_client_credential("chatgpt").unwrap();
        assert!(gate
            .authorize_method(methods::POLICY_SHOW, &cred_id)
            .is_err());
        assert!(gate
            .resolve_auth(
                &os,
                &PeerCredential {
                    client_credential: Some(old),
                    ..presented.clone()
                }
            )
            .is_err());
        assert!(
            gate.resolve_auth(
                &os,
                &PeerCredential {
                    client_credential: Some(new.clone()),
                    ..presented.clone()
                }
            )
            .unwrap()
            .credentialed
        );

        // Restart: new gate from same state_dir.
        drop(gate);
        drop(reg);
        let reopened = CredentialRegistry::open(dir.path()).unwrap();
        let gate2 = AuthGate::for_user("alice").with_registry(Arc::new(RwLock::new(reopened)));
        let restored_auth = gate2
            .resolve_auth(
                &os,
                &PeerCredential {
                    client_credential: Some(new.clone()),
                    ..presented.clone()
                },
            )
            .unwrap();
        assert!(restored_auth.credentialed);
        let restored_id = restored_auth;
        assert!(gate2
            .authorize_method(methods::POLICY_SHOW, &restored_id)
            .is_ok());
        gate2.revoke_client_credential("chatgpt").unwrap();
        assert!(gate2
            .authorize_method(methods::POLICY_SHOW, &restored_id)
            .is_err());
        assert!(gate2
            .resolve_auth(
                &os,
                &PeerCredential {
                    client_credential: Some(new),
                    ..presented
                }
            )
            .is_err());
    }

    #[test]
    fn local_user_default_allows_uncredentialed_methods() {
        let gate = AuthGate::local_user();
        assert!(!gate.strict_uncredentialed());
        let id = AuthResolution {
            principal_key: format!("user:{}", gate.own_user_id()),
            credentialed: false,
            client_id: None,
            credential_generation: None,
        };
        // Default consumers (TUI / session-host) must not be locked down.
        assert!(gate.authorize_method(methods::OPS_EXEC, &id).is_ok());
        assert!(gate.authorize_method("session.open", &id).is_ok());
        assert!(gate.authorize_method(methods::POLICY_SHOW, &id).is_ok());
    }
}
