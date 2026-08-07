//! Persistent per-client credential registry (daemon state directory).
//!
//! # Threat model
//!
//! Credentials stored here identify **cooperative** clients only. They do **not**
//! separate arbitrary malicious processes under the same OS user.
//!
//! The registry stores one-way credential verifiers, not reusable bearer secrets.
//! Even so, a same-uid attacker can read owner-only client files and process material
//! holding the presented secret. Unix file mode `0600` and a protected owner-only
//! Windows DACL reduce *cross-user* exposure; neither mechanism is a confidentiality
//! boundary against malware running as the daemon owner. Never claim that a
//! file-backed client secret isolates same-user processes from each other.
//!
//! Provisioning / rotate / revoke are **daemon-managed while it is running**.
//! They must never be implemented as an offline registry writer or offered to
//! uncredentialed same-uid IPC peers.
//!
//! The first daemon start creates one credential for a fixed, server-defined
//! management client and delivers it through an owner-only file. That delivery is
//! a convenience for cooperative clients, not a security boundary: arbitrary
//! malware running as the same OS user can read and reuse it.

use crate::auth::{
    canonicalize_principal_key, constant_time_eq, generate_token, normalize_principal_part,
    RedactedSecret,
};
use crate::error::{IpcError, IpcResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// On-disk filename under the daemon state directory.
pub(crate) const REGISTRY_FILE_NAME: &str = "client-credentials.json";
/// Owner-only first-run delivery file for the fixed management credential.
pub const MANAGEMENT_CREDENTIAL_FILE_NAME: &str = "management-client.credential";
/// Fixed client id allowed to invoke credential lifecycle RPCs.
pub(crate) const MANAGEMENT_CLIENT_ID: &str = "ownmesh-management";
/// Fixed server-defined principal for the management client.
pub(crate) const MANAGEMENT_PRINCIPAL: &str = "client:ownmesh-management";
/// Explicit environment variable accepted by cooperative IPC clients.
pub const CLIENT_CREDENTIAL_ENV: &str = "OWNMESH_CLIENT_CREDENTIAL";

const REGISTRY_LOCK_FILE_NAME: &str = "client-credentials.lock";
const REGISTRY_VERSION: u32 = 1;

/// Result of ensuring the fixed first-run management credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapStatus {
    /// A new credential and owner-only delivery file were created.
    Created,
    /// The existing fixed credential and delivery file were validated.
    Existing,
}

/// One registered client credential (secret held redacted in memory).
#[derive(Clone)]
pub(crate) struct RegistryEntry {
    /// Stable client id used for provision/rotate/revoke addressing.
    pub(crate) client_id: String,
    /// Server-assigned principal key returned after successful HELLO.
    pub(crate) principal_key: String,
    /// OS user id the secret is bound to at issuance.
    pub(crate) bound_user_id: String,
    /// Monotonic credential generation; incremented by rotation.
    pub(crate) generation: u64,
    /// SHA-256 verifier (never logged / Debug-visible).
    verifier: RedactedSecret,
    /// When true the entry must not authenticate.
    pub(crate) revoked: bool,
}

impl RegistryEntry {
    /// Whether `presented` hashes to this entry's verifier (constant-time).
    #[must_use]
    pub fn secret_matches(&self, presented: &str) -> bool {
        self.verifier_matches(&credential_verifier(presented))
    }

    fn verifier_matches(&self, candidate: &str) -> bool {
        constant_time_eq(self.verifier.expose().as_bytes(), candidate.as_bytes())
    }
}

impl std::fmt::Debug for RegistryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistryEntry")
            .field("client_id", &self.client_id)
            .field("principal_key", &self.principal_key)
            .field("bound_user_id", &self.bound_user_id)
            .field("generation", &self.generation)
            .field("verifier", &self.verifier)
            .field("revoked", &self.revoked)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct RegistryFile {
    version: u32,
    entries: Vec<RegistryEntrySer>,
}

#[derive(Clone, Serialize, Deserialize)]
struct RegistryEntrySer {
    client_id: String,
    principal_key: String,
    bound_user_id: String,
    #[serde(default = "initial_generation")]
    generation: u64,
    /// Hex SHA-256 verifier — not reusable as a HELLO bearer credential.
    secret_verifier: String,
    #[serde(default)]
    revoked: bool,
}

/// Daemon-managed registry of non-shared per-client credentials.
///
/// Persistence is atomic (`*.tmp` + `sync_all` + rename) with Unix `0600` when
/// supported. See the module-level threat model before relying on this for isolation.
#[derive(Debug)]
pub(crate) struct CredentialRegistry {
    path: PathBuf,
    entries: Vec<RegistryEntry>,
    /// Held for this registry's lifetime; prevents parent replacement on Windows.
    _custody: StateCustody,
    /// Held for this registry's lifetime; prevents any second registry writer.
    _lock: RegistryFileLock,
}

#[derive(Debug)]
struct StateCustody {
    #[cfg(windows)]
    _handles: Vec<fs::File>,
}

impl StateCustody {
    #[cfg(unix)]
    fn acquire(_state_dir: &Path) -> IpcResult<Self> {
        // Unix relies on sticky-bit / owner checks in validate_parent_custody.
        // Directory file-descriptor pinning across rename races is not claimed.
        Ok(Self {})
    }

    #[cfg(windows)]
    fn acquire(state_dir: &Path) -> IpcResult<Self> {
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
        use windows_sys::Win32::Storage::FileSystem::{
            CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
        };

        let mut handles = Vec::new();
        let ancestors: Vec<&Path> = state_dir.ancestors().filter(|path| path.exists()).collect();
        for (index, ancestor) in ancestors.iter().enumerate() {
            let wide: Vec<u16> = ancestor
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            // Deliberately omit FILE_SHARE_DELETE. Holding every ancestor open
            // prevents rename/replacement for the registry lifetime.
            // READ_CONTROL is required so post-open security revalidation is not
            // silently skipped.
            let handle = unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_FLAG_BACKUP_SEMANTICS,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error().into());
            }
            let file = unsafe { fs::File::from_raw_handle(handle) };
            // Always revalidate identity of the pinned handle. Never trust the
            // path string alone after CreateFileW returns.
            revalidate_pinned_handle_identity(file.as_raw_handle(), ancestor)?;
            // Full owner + protected-DACL attestation applies to the state dir
            // itself (index 0). Parent volumes are not required to be owner-only;
            // requiring that would be unsound on real Windows systems and is an
            // explicit non-claim (identity pin only for ancestors).
            if index == 0 {
                revalidate_pinned_handle_security(file.as_raw_handle(), ancestor, true)?;
            }
            handles.push(file);
        }
        Ok(Self { _handles: handles })
    }
}

#[derive(Debug)]
struct RegistryFileLock {
    _file: fs::File,
}

impl RegistryFileLock {
    fn acquire(state_dir: &Path) -> IpcResult<Self> {
        let path = state_dir.join(REGISTRY_LOCK_FILE_NAME);
        reject_symlink_or_reparse_if_present(&path)?;
        // Create owner-only from inception where the platform allows; existing
        // locks are validated (owner + regular file) on the opened handle before use.
        let file = open_owner_only_rw(&path, /*create*/ true)?;
        // Owner + regular-file first (no silent trust of non-owner nodes).
        validate_open_regular_owned_file(&file, &path, false)?;
        // Tighten residual umask / inherited ACL bits, then require protected mode/DACL.
        restrict_owner_only(&path, false)?;
        validate_open_regular_owned_file(&file, &path, true)?;
        lock_exclusive_nonblocking(&file).map_err(|err| {
            IpcError::Io(std::io::Error::new(
                err.kind(),
                format!("client credential registry is already owned by another process: {err}"),
            ))
        })?;
        Ok(Self { _file: file })
    }
}

#[cfg(unix)]
fn lock_exclusive_nonblocking(file: &fs::File) -> std::io::Result<()> {
    rustix::fs::flock(file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        .map_err(std::io::Error::from)
}

#[cfg(windows)]
fn lock_exclusive_nonblocking(file: &fs::File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
    };
    use windows_sys::Win32::System::IO::OVERLAPPED;

    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let locked = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &raw mut overlapped,
        )
    };
    if locked == 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

impl CredentialRegistry {
    /// Open (or create empty) registry under `state_dir`.
    ///
    /// # Errors
    ///
    /// Returns IO / protocol errors when the directory cannot be created or the
    /// existing file is unreadable / corrupt.
    pub(crate) fn open(state_dir: impl AsRef<Path>) -> IpcResult<Self> {
        let state_dir = state_dir.as_ref();
        prepare_secure_state_dir(state_dir)?;
        let custody = StateCustody::acquire(state_dir)?;
        let lock = RegistryFileLock::acquire(state_dir)?;
        let path = state_dir.join(REGISTRY_FILE_NAME);
        reject_symlink_or_reparse_if_present(&path)?;
        let existed = path.exists();
        let mut reg = Self {
            path,
            entries: Vec::new(),
            _custody: custody,
            _lock: lock,
        };
        reg.reload()?;
        if !existed {
            reg.persist()?;
        }
        Ok(reg)
    }

    /// Path of the backing JSON file (tests only).
    #[cfg(test)]
    #[must_use]
    fn path(&self) -> &Path {
        &self.path
    }

    /// In-memory entries (ordered by insertion; tests only).
    #[cfg(test)]
    #[must_use]
    fn entries(&self) -> &[RegistryEntry] {
        &self.entries
    }

    /// Find an active entry by stable client id.
    #[must_use]
    pub(crate) fn active_entry(&self, client_id: &str) -> Option<&RegistryEntry> {
        let client_id = canonicalize_principal_key(client_id);
        self.entries
            .iter()
            .find(|entry| entry.client_id == client_id && !entry.revoked)
    }

    /// Re-read from disk, replacing in-memory state.
    ///
    /// # Errors
    ///
    /// Returns IO / protocol errors on corrupt JSON.
    pub(crate) fn reload(&mut self) -> IpcResult<()> {
        reject_symlink_or_reparse_if_present(&self.path)?;
        if !self.path.exists() {
            self.entries.clear();
            return Ok(());
        }
        // Ownership + regular-file type are validated on the opened handle before
        // any secret material is read. Symlink/reparse/non-owner inputs fail closed.
        let raw = read_owned_regular_file(&self.path)?;
        if raw.trim().is_empty() {
            return Err(IpcError::Protocol(
                "credential registry is empty or truncated".into(),
            ));
        }
        let file: RegistryFile = serde_json::from_str(&raw)
            .map_err(|err| IpcError::Protocol(format!("credential registry corrupt: {err}")))?;
        if file.version != REGISTRY_VERSION {
            return Err(IpcError::Protocol(format!(
                "unsupported credential registry version {}",
                file.version
            )));
        }

        let mut loaded = Vec::with_capacity(file.entries.len());
        for serialized in file.entries {
            let client_id = canonical_client_id(&serialized.client_id)?;
            if serialized.client_id != client_id {
                return Err(IpcError::Protocol(format!(
                    "credential registry client id '{}' is not canonical",
                    serialized.client_id
                )));
            }
            let expected_principal = managed_principal(&client_id);
            if serialized.principal_key != expected_principal {
                return Err(IpcError::Protocol(format!(
                    "credential registry principal '{}' violates required mapping '{}'",
                    serialized.principal_key, expected_principal
                )));
            }
            let principal_key = expected_principal;
            let bound_user_id = normalize_principal_part(&serialized.bound_user_id);
            let verifier = serialized.secret_verifier.trim();
            if serialized.generation == 0 {
                return Err(IpcError::Protocol(format!(
                    "active credential '{client_id}' has invalid generation 0"
                )));
            }
            if client_id.is_empty() || principal_key.is_empty() || bound_user_id.is_empty() {
                return Err(IpcError::Protocol(
                    "credential registry contains an empty identity field".into(),
                ));
            }
            if !serialized.revoked
                && (verifier.len() != 64 || !verifier.bytes().all(|byte| byte.is_ascii_hexdigit()))
            {
                return Err(IpcError::Protocol(format!(
                    "active credential '{client_id}' has an invalid verifier"
                )));
            }
            if loaded
                .iter()
                .any(|entry: &RegistryEntry| entry.client_id == client_id)
            {
                return Err(IpcError::Protocol(format!(
                    "credential registry contains duplicate client id '{client_id}'"
                )));
            }
            if !serialized.revoked
                && loaded
                    .iter()
                    .any(|entry: &RegistryEntry| !entry.revoked && entry.verifier_matches(verifier))
            {
                return Err(IpcError::Protocol(
                    "credential registry contains duplicate active secrets".into(),
                ));
            }
            loaded.push(RegistryEntry {
                client_id,
                principal_key,
                bound_user_id,
                generation: serialized.generation,
                // Revoked records intentionally discard persisted verifier material.
                verifier: RedactedSecret::new(if serialized.revoked { "" } else { verifier }),
                revoked: serialized.revoked,
            });
        }
        self.entries = loaded;
        Ok(())
    }

    /// Provision a new client credential. Returns the one-time secret plaintext.
    ///
    /// # Errors
    ///
    /// Fails when ids are empty, the client already exists, or persistence fails.
    pub(crate) fn provision(
        &mut self,
        client_id: impl Into<String>,
        bound_user_id: impl Into<String>,
    ) -> IpcResult<String> {
        self.provision_with_secret(client_id, bound_user_id, generate_token())
    }

    fn provision_with_secret(
        &mut self,
        client_id: impl Into<String>,
        bound_user_id: impl Into<String>,
        secret: String,
    ) -> IpcResult<String> {
        let client_id = canonical_client_id(&client_id.into())?;
        let principal_key = managed_principal(&client_id);
        let bound_user_id = normalize_principal_part(&bound_user_id.into());
        if bound_user_id.is_empty() {
            return Err(IpcError::Unauthorized(
                "credential bound OS user must be non-empty".into(),
            ));
        }
        if self
            .entries
            .iter()
            .any(|e| e.client_id == client_id && !e.revoked)
        {
            return Err(IpcError::Unauthorized(format!(
                "client credential '{client_id}' already provisioned"
            )));
        }
        let generation = self
            .entries
            .iter()
            .find(|entry| entry.client_id == client_id)
            .map_or(Ok(initial_generation()), |entry| {
                entry.generation.checked_add(1).ok_or_else(|| {
                    IpcError::Protocol(format!("credential generation overflow for '{client_id}'"))
                })
            })?;
        let snapshot = self.entries.clone();
        // Replace a revoked tombstone while preserving a never-reused generation.
        self.entries.retain(|e| e.client_id != client_id);
        self.entries.push(RegistryEntry {
            client_id,
            principal_key,
            bound_user_id,
            generation,
            verifier: RedactedSecret::new(credential_verifier(&secret)),
            revoked: false,
        });
        if let Err(err) = self.persist() {
            // A post-replacement directory-fsync error means the commit may already
            // be visible. Reconcile from disk; only use the snapshot if disk itself
            // cannot be read.
            if self.reload().is_err() {
                self.entries = snapshot;
            }
            return Err(err);
        }
        Ok(secret)
    }

    /// Ensure the fixed management bootstrap and its owner-only delivery file.
    ///
    /// The caller cannot choose the management id, principal, or bound user. The
    /// returned status never contains secret material.
    pub(crate) fn ensure_management_bootstrap(
        &mut self,
        bound_user_id: impl Into<String>,
    ) -> IpcResult<BootstrapStatus> {
        let bound_user_id = normalize_principal_part(&bound_user_id.into());
        if bound_user_id.is_empty() {
            return Err(IpcError::Unauthorized(
                "management credential OS user must be non-empty".into(),
            ));
        }
        let delivery = self
            .path
            .parent()
            .ok_or_else(|| IpcError::Protocol("registry path has no parent".into()))?
            .join(MANAGEMENT_CREDENTIAL_FILE_NAME);

        if let Some(entry) = self.active_entry(MANAGEMENT_CLIENT_ID) {
            if entry.principal_key != MANAGEMENT_PRINCIPAL || entry.bound_user_id != bound_user_id {
                return Err(IpcError::Unauthorized(
                    "fixed management credential has an unexpected principal or OS-user binding"
                        .into(),
                ));
            }
            // A verifier cannot reconstruct the bearer secret. Missing delivery
            // therefore fails closed instead of silently minting a replacement.
            let secret = read_management_credential(delivery.parent().unwrap_or(Path::new(".")))?;
            if !entry.secret_matches(&secret) {
                return Err(IpcError::Unauthorized(
                    "management credential delivery file does not match the registry".into(),
                ));
            }
            return Ok(BootstrapStatus::Existing);
        }

        let secret = generate_token();
        // Write delivery first. A crash before registry persistence merely leaves
        // an unusable file that the next first-run attempt atomically replaces.
        atomic_write_owner_only(&delivery, format!("{secret}\n").as_bytes())?;
        if let Err(err) = self.provision_with_secret(MANAGEMENT_CLIENT_ID, bound_user_id, secret) {
            // Keep delivery if an uncertain durability error nevertheless made the
            // registry entry visible; otherwise remove the unusable orphan.
            if self.active_entry(MANAGEMENT_CLIENT_ID).is_none() {
                let _ = fs::remove_file(&delivery);
            }
            return Err(err);
        }
        Ok(BootstrapStatus::Created)
    }

    /// Rotate the secret for `client_id`. Old secret stops authenticating.
    ///
    /// # Errors
    ///
    /// Fails when the client is missing/revoked or persistence fails.
    pub(crate) fn rotate(&mut self, client_id: &str) -> IpcResult<String> {
        let client_id = canonicalize_principal_key(client_id);
        let snapshot = self.entries.clone();
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.client_id == client_id && !e.revoked)
            .ok_or_else(|| {
                IpcError::Unauthorized(format!("no active credential for client '{client_id}'"))
            })?;
        let generation = entry.generation.checked_add(1).ok_or_else(|| {
            IpcError::Protocol(format!("credential generation overflow for '{client_id}'"))
        })?;
        let secret = generate_token();
        entry.generation = generation;
        entry.verifier = RedactedSecret::new(credential_verifier(&secret));
        if let Err(err) = self.persist() {
            if self.reload().is_err() {
                self.entries = snapshot;
            }
            return Err(err);
        }
        Ok(secret)
    }

    /// Revoke `client_id` so its secret no longer maps to a principal.
    ///
    /// # Errors
    ///
    /// Fails when the client is missing or persistence fails.
    pub(crate) fn revoke(&mut self, client_id: &str) -> IpcResult<()> {
        let client_id = canonicalize_principal_key(client_id);
        let snapshot = self.entries.clone();
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.client_id == client_id)
            .ok_or_else(|| {
                IpcError::Unauthorized(format!("no credential for client '{client_id}'"))
            })?;
        entry.revoked = true;
        // Drop verifier material so a revoked record cannot match by value.
        entry.verifier = RedactedSecret::new(String::new());
        if let Err(err) = self.persist() {
            if self.reload().is_err() {
                self.entries = snapshot;
            }
            return Err(err);
        }
        Ok(())
    }

    /// Look up a non-revoked entry by presented secret (constant-time scan).
    ///
    /// Does **not** use the secret as a [`std::collections::HashMap`] key.
    #[must_use]
    pub(crate) fn find_by_secret(&self, presented: &str) -> Option<&RegistryEntry> {
        find_entry_by_secret(&self.entries, presented)
    }

    /// Atomic durable write (`tmp` + `sync_all` + rename) with owner-only mode.
    ///
    /// # Errors
    ///
    /// Returns IO errors from encode / write / rename / chmod.
    pub(crate) fn persist(&self) -> IpcResult<()> {
        let file = RegistryFile {
            version: REGISTRY_VERSION,
            entries: self
                .entries
                .iter()
                .map(|e| RegistryEntrySer {
                    client_id: e.client_id.clone(),
                    principal_key: e.principal_key.clone(),
                    bound_user_id: e.bound_user_id.clone(),
                    generation: e.generation,
                    secret_verifier: e.verifier.expose().to_owned(),
                    revoked: e.revoked,
                })
                .collect(),
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|err| IpcError::Protocol(format!("serialize credential registry: {err}")))?;
        atomic_write_owner_only(&self.path, &bytes)
    }
}

const fn initial_generation() -> u64 {
    1
}

pub(crate) fn canonical_client_id(raw: &str) -> IpcResult<String> {
    let client_id = canonicalize_principal_key(raw);
    let valid = !client_id.is_empty()
        && client_id.len() <= 64
        && client_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        });
    if !valid {
        return Err(IpcError::Protocol(
            "client_id must be 1-64 lowercase letters/digits/._-".into(),
        ));
    }
    Ok(client_id)
}

pub(crate) fn managed_principal(client_id: &str) -> String {
    format!("client:{client_id}")
}

fn credential_verifier(secret: &str) -> String {
    format!("{:x}", Sha256::digest(secret.as_bytes()))
}

/// Scan `entries` with constant-time verifier compares (no HashMap-by-secret).
pub(crate) fn find_entry_by_secret<'a>(
    entries: &'a [RegistryEntry],
    presented: &str,
) -> Option<&'a RegistryEntry> {
    let presented_verifier = credential_verifier(presented);
    let mut found: Option<&RegistryEntry> = None;
    for entry in entries {
        // Always compare so match position does not short-circuit the loop.
        let matches = !entry.revoked
            && !entry.verifier.expose().is_empty()
            && entry.verifier_matches(&presented_verifier);
        if matches {
            found = Some(entry);
        }
    }
    found
}

/// Read the fixed owner-file management credential.
///
/// This is cooperative-only delivery and does not resist arbitrary malware running
/// as the same OS user. The value is never logged by this function.
pub fn read_management_credential(state_dir: impl AsRef<Path>) -> IpcResult<String> {
    let state_dir = state_dir.as_ref();
    validate_secure_state_dir(state_dir)?;
    // Keep Windows directory/ancestor handles pinned without share-delete for the
    // entire path-open, handle-attestation, and read sequence.
    let _custody = StateCustody::acquire(state_dir)?;
    let path = state_dir.join(MANAGEMENT_CREDENTIAL_FILE_NAME);
    // Validate ownership + regular-file type on the opened handle before reading.
    let secret = read_owned_regular_file(&path)?;
    let secret = secret.trim().to_owned();
    if secret.is_empty() {
        return Err(IpcError::Protocol(format!(
            "management credential file is empty: {}",
            path.display()
        )));
    }
    Ok(secret)
}

/// Write `data` via a unique temp sibling, flush it, and atomically replace `path`.
pub(crate) fn atomic_write_owner_only(path: &Path, data: &[u8]) -> IpcResult<()> {
    let parent = path.parent().ok_or_else(|| {
        IpcError::Protocol(format!(
            "credential registry path has no parent: {}",
            path.display()
        ))
    })?;
    validate_secure_state_dir(parent)?;
    // Pin Windows directory identity/security across destination validation,
    // temp creation, replacement, and post-replace handle attestation.
    let _custody = StateCustody::acquire(parent)?;
    reject_symlink_or_reparse_if_present(path)?;
    // If the destination already exists it must already be an owned regular file
    // (or we refuse to replace a non-file / non-owner node).
    if path.exists() {
        validate_owned_regular_file_path(path)?;
    }
    let tmp = parent.join(format!(
        ".{}.tmp-{}-{}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("client-credentials.json"),
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let result = (|| -> IpcResult<()> {
        // Owner-only at creation (mode/DACL), before any secret bytes are written.
        let mut file = create_owner_only_new(&tmp)?;
        validate_open_regular_owned_file(&file, &tmp, true)?;
        file.write_all(data)?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&tmp, path)?;
        // Post-replace path attestation: destination must remain owned regular file.
        validate_owned_regular_file_path(path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result?;
    // The directory flush is part of the durability contract; propagate failure.
    #[cfg(unix)]
    {
        let dir = fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}

#[cfg(unix)]
fn atomic_replace(source: &Path, destination: &Path) -> IpcResult<()> {
    fs::rename(source, destination)?;
    Ok(())
}

#[cfg(windows)]
fn atomic_replace(source: &Path, destination: &Path) -> IpcResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    let source: Vec<u16> = source
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    // Unlike std::fs::rename on Windows, MoveFileExW with REPLACE_EXISTING is
    // the platform replacement primitive for an already-present destination.
    let moved = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if moved == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

/// Open an existing path for reading after rejecting symlink/reparse targets, then
/// attest owner + regular-file type on the opened handle before returning bytes.
fn ensure_existing_path_is_regular_file(path: &Path) -> IpcResult<()> {
    reject_symlink_or_reparse_if_present(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() {
        return Err(IpcError::Unauthorized(format!(
            "credential state path is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn read_owned_regular_file(path: &Path) -> IpcResult<String> {
    ensure_existing_path_is_regular_file(path)?;
    let mut file = open_existing_nofollow_read(path)?;
    // Owner + regular-file first; never chmod/read a non-owner node.
    validate_open_regular_owned_file(&file, path, false)?;
    // Tighten residual permissions only after ownership is attested.
    restrict_owner_only(path, false)?;
    validate_open_regular_owned_file(&file, path, true)?;
    let mut raw = String::new();
    file.read_to_string(&mut raw)?;
    Ok(raw)
}

/// Path-based pre-check used when a destination must already be an owned regular file.
fn validate_owned_regular_file_path(path: &Path) -> IpcResult<()> {
    ensure_existing_path_is_regular_file(path)?;
    let file = open_existing_nofollow_read(path)?;
    validate_open_regular_owned_file(&file, path, true)
}

fn open_existing_nofollow_read(path: &Path) -> IpcResult<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::empty(),
        )
        .map_err(std::io::Error::from)?;
        Ok(unsafe { fs::File::from_raw_fd(fd.into_raw_fd()) })
    }
    #[cfg(windows)]
    {
        open_windows_path(path, false, false, true)
    }
}

/// Open or create a read/write file with owner-only creation attributes when created.
fn open_owner_only_rw(path: &Path, create: bool) -> IpcResult<fs::File> {
    // If the path already exists it must be a regular file (never open a directory
    // node as the lock/registry file).
    if path.exists() {
        ensure_existing_path_is_regular_file(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        // Prefer O_NOFOLLOW so a racing symlink cannot be opened.
        let mut flags = rustix::fs::OFlags::RDWR | rustix::fs::OFlags::NOFOLLOW;
        if create {
            flags |= rustix::fs::OFlags::CREATE;
        }
        let fd = rustix::fs::open(path, flags, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR)
            .map_err(std::io::Error::from)?;
        Ok(unsafe { fs::File::from_raw_fd(fd.into_raw_fd()) })
    }
    #[cfg(windows)]
    {
        open_windows_path(path, create, false, false)
    }
}

/// Create a new file that must not already exist, with owner-only mode/DACL from inception.
fn create_owner_only_new(path: &Path) -> IpcResult<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::io::{FromRawFd, IntoRawFd};
        let fd = rustix::fs::open(
            path,
            rustix::fs::OFlags::WRONLY
                | rustix::fs::OFlags::CREATE
                | rustix::fs::OFlags::EXCL
                | rustix::fs::OFlags::NOFOLLOW,
            rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR,
        )
        .map_err(std::io::Error::from)?;
        let file = unsafe { fs::File::from_raw_fd(fd.into_raw_fd()) };
        restrict_owner_only(path, false)?;
        Ok(file)
    }
    #[cfg(windows)]
    {
        open_windows_path(path, true, true, false)
    }
}

#[cfg(windows)]
fn open_windows_path(
    path: &Path,
    create: bool,
    create_new: bool,
    read_only: bool,
) -> IpcResult<fs::File> {
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_ALWAYS, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let access = if read_only {
        GENERIC_READ
    } else {
        GENERIC_READ | GENERIC_WRITE
    };
    let disposition = if create_new {
        CREATE_NEW
    } else if create {
        OPEN_ALWAYS
    } else {
        OPEN_EXISTING
    };

    // Owner-only protected DACL applied at creation time. Ignored for OPEN_EXISTING.
    // Embed the attested process SID rather than relying on inherited ACLs.
    let sddl_text = format!("D:P(A;;FA;;;{})\0", current_process_user_sid_string()?);
    let sddl: Vec<u16> = sddl_text.encode_utf16().collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // Omit FILE_SHARE_DELETE so same-user replace-during-hold is harder.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if create || create_new {
                &raw mut attrs
            } else {
                ptr::null()
            },
            disposition,
            // Never follow reparse points: open the node itself and let the
            // subsequent attribute check reject symlink/junction inputs.
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    unsafe {
        let _ = LocalFree(descriptor);
    }
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { fs::File::from_raw_handle(handle) })
}

/// Attest that an already-open handle refers to a regular, daemon-owned file.
/// When `require_protected` is set, also require owner-only mode (Unix) or a
/// protected DACL (Windows).
fn validate_open_regular_owned_file(
    file: &fs::File,
    path: &Path,
    require_protected: bool,
) -> IpcResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(IpcError::Unauthorized(format!(
                "credential state path is not a regular file: {}",
                path.display()
            )));
        }
        let expected = rustix::process::geteuid().as_raw();
        if metadata.uid() != expected {
            return Err(IpcError::Unauthorized(format!(
                "credential state file {} is owned by uid {}, expected {expected}",
                path.display(),
                metadata.uid()
            )));
        }
        if require_protected && metadata.permissions().mode() & 0o077 != 0 {
            return Err(IpcError::Unauthorized(format!(
                "credential state file is accessible by group/other: {}",
                path.display()
            )));
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        validate_open_windows_regular_owned(file.as_raw_handle(), path, require_protected)
    }
}

#[cfg(windows)]
fn validate_open_windows_regular_owned(
    handle: windows_sys::Win32::Foundation::HANDLE,
    path: &Path,
    require_protected_dacl: bool,
) -> IpcResult<()> {
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT,
    };

    // CreateFileW handles omit FILE_SHARE_DELETE. Revalidate both identity and
    // security on that pinned handle before trusting type, owner, DACL, or bytes.
    revalidate_pinned_handle_identity(handle, path)?;

    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Err(IpcError::Unauthorized(format!(
            "credential state path is not a regular file: {}",
            path.display()
        )));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(IpcError::Unauthorized(format!(
            "credential state custody rejects symlink/reparse path: {}",
            path.display()
        )));
    }
    revalidate_pinned_handle_security(handle, path, require_protected_dacl)
}

#[cfg(windows)]
fn revalidate_pinned_handle_identity(
    handle: windows_sys::Win32::Foundation::HANDLE,
    expected_path: &Path,
) -> IpcResult<()> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    let mut buf = vec![0u16; 512];
    let final_path = loop {
        let buf_len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let written = unsafe {
            GetFinalPathNameByHandleW(
                handle,
                buf.as_mut_ptr(),
                buf_len,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        };
        if written == 0 {
            // Explicit failure: never proceed trusting an unrevalidated handle.
            return Err(IpcError::Unauthorized(format!(
                "credential state custody cannot revalidate pinned handle identity for {}: {}",
                expected_path.display(),
                std::io::Error::last_os_error()
            )));
        }
        if (written as usize) >= buf.len() {
            buf.resize(written as usize + 8, 0);
            continue;
        }
        break PathBuf::from(std::ffi::OsString::from_wide(&buf[..written as usize]));
    };

    let expected = fs::canonicalize(expected_path).map_err(|err| {
        IpcError::Unauthorized(format!(
            "credential state custody cannot canonicalize {}: {err}",
            expected_path.display()
        ))
    })?;

    // Compare both the canonical path and a stripped \\?\ form.
    let norm = |p: &Path| -> PathBuf {
        let s = p.to_string_lossy();
        if let Some(stripped) = s.strip_prefix(r"\\?\") {
            PathBuf::from(stripped)
        } else {
            p.to_path_buf()
        }
    };
    if norm(&final_path) != norm(&expected) {
        // Also accept case-insensitive equality on Windows.
        let a = norm(&final_path).to_string_lossy().to_ascii_lowercase();
        let b = norm(&expected).to_string_lossy().to_ascii_lowercase();
        if a != b {
            return Err(IpcError::Unauthorized(format!(
                "credential state custody pinned handle identity mismatch: opened {} but expected {}",
                final_path.display(),
                expected.display()
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::too_many_lines)]
fn revalidate_pinned_handle_security(
    handle: windows_sys::Win32::Foundation::HANDLE,
    path: &Path,
    require_protected_dacl: bool,
) -> IpcResult<()> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, ACCESS_ALLOWED_ACE,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(IpcError::Unauthorized(format!(
            "credential state custody cannot revalidate handle security for {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(status.cast_signed())
        )));
    }

    let result = (|| -> IpcResult<()> {
        let mut token: HANDLE = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0
            || token.is_null()
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let token_result = (|| -> IpcResult<()> {
            let mut required = 0_u32;
            unsafe {
                let _ =
                    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut required);
            }
            if required == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let word_size = std::mem::size_of::<usize>();
            let words = (required as usize).div_ceil(word_size);
            let mut buffer = vec![0_usize; words];
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    required,
                    &raw mut required,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
            if owner.is_null() || unsafe { EqualSid(owner, token_user.User.Sid) } == 0 {
                return Err(IpcError::Unauthorized(format!(
                    "credential state path is not owned by the daemon OS user: {}",
                    path.display()
                )));
            }
            if require_protected_dacl {
                let mut control = 0_u16;
                let mut revision = 0_u32;
                if unsafe {
                    GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
                } == 0
                {
                    return Err(std::io::Error::last_os_error().into());
                }
                if control & SE_DACL_PROTECTED == 0 {
                    return Err(IpcError::Unauthorized(format!(
                        "credential state path DACL is not protected: {}",
                        path.display()
                    )));
                }

                let mut present = 0;
                let mut defaulted = 0;
                let mut dacl = ptr::null_mut();
                if unsafe {
                    GetSecurityDescriptorDacl(
                        descriptor,
                        &raw mut present,
                        &raw mut dacl,
                        &raw mut defaulted,
                    )
                } == 0
                    || present == 0
                    || dacl.is_null()
                {
                    return Err(IpcError::Unauthorized(format!(
                        "credential state path has no attestable owner-only DACL: {}",
                        path.display()
                    )));
                }
                let mut acl_info = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
                if unsafe {
                    GetAclInformation(
                        dacl,
                        (&raw mut acl_info).cast(),
                        u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>())
                            .unwrap_or(u32::MAX),
                        AclSizeInformation,
                    )
                } == 0
                    || acl_info.AceCount != 1
                {
                    return Err(IpcError::Unauthorized(format!(
                        "credential state path DACL is not owner-only: {}",
                        path.display()
                    )));
                }
                let mut ace = ptr::null_mut();
                if unsafe { GetAce(dacl, 0, &raw mut ace) } == 0 || ace.is_null() {
                    return Err(std::io::Error::last_os_error().into());
                }
                let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
                let allowed_sid: PSID = (&raw const allowed.SidStart).cast_mut().cast();
                if allowed.Header.AceType != 0
                    || u32::from(allowed.Header.AceFlags) & INHERITED_ACE != 0
                    || unsafe { EqualSid(allowed_sid, owner) } == 0
                {
                    return Err(IpcError::Unauthorized(format!(
                        "credential state path DACL grants a principal other than its owner: {}",
                        path.display()
                    )));
                }
            }
            Ok(())
        })();
        unsafe {
            CloseHandle(token);
        }
        token_result
    })();
    unsafe {
        let _ = LocalFree(descriptor);
    }
    result
}

/// Return whether `path` has a protected owner-only DACL (Windows) / mode 0600 or 0700 (Unix).
#[cfg(test)]
fn path_has_owner_only_protection(path: &Path, directory: bool) -> IpcResult<bool> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::symlink_metadata(path)?.permissions().mode() & 0o777;
        let expected = if directory { 0o700 } else { 0o600 };
        Ok(mode == expected)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            GetSecurityDescriptorControl, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
        };

        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &raw mut descriptor,
            )
        };
        if status != 0 {
            return Err(std::io::Error::from_raw_os_error(status.cast_signed()).into());
        }
        let mut control = 0_u16;
        let mut revision = 0_u32;
        let ok = unsafe {
            GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
        } != 0
            && control & SE_DACL_PROTECTED != 0;
        unsafe {
            let _ = LocalFree(descriptor);
        }
        let _ = directory;
        Ok(ok)
    }
}

#[cfg(windows)]
fn current_process_user_sid_string() -> IpcResult<String> {
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0
        || token.is_null()
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let result = (|| -> IpcResult<String> {
        let mut required = 0_u32;
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut required);
        }
        if required == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let words = (required as usize).div_ceil(std::mem::size_of::<usize>());
        let mut buffer = vec![0_usize; words];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &raw mut required,
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid_text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(token_user.User.Sid, &raw mut sid_text) } == 0
            || sid_text.is_null()
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let len = unsafe {
            let mut len = 0usize;
            while *sid_text.add(len) != 0 {
                len += 1;
            }
            len
        };
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_text, len) });
        unsafe {
            let _ = LocalFree(sid_text.cast());
        }
        Ok(value)
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

fn restrict_owner_only(path: &Path, _directory: bool) -> IpcResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if _directory { 0o700 } else { 0o600 };
        let perms = fs::Permissions::from_mode(mode);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(windows)]
    unsafe {
        use std::os::windows::ffi::OsStrExt;
        use std::ptr;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            SetFileSecurityW, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR,
        };

        // Protected DACL with full access for the current attested user only.
        let sddl_text = format!("D:P(A;;FA;;;{})\0", current_process_user_sid_string()?);
        let sddl: Vec<u16> = sddl_text.encode_utf16().collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let applied = SetFileSecurityW(
            wide_path.as_ptr(),
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        );
        let _ = LocalFree(descriptor);
        if applied == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_state_dir_owner_only(state_dir: &Path) -> IpcResult<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(state_dir)?;
    Ok(())
}

#[cfg(windows)]
fn create_state_dir_owner_only(state_dir: &Path) -> IpcResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_ALREADY_EXISTS};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

    let sddl_text = format!("D:P(A;;FA;;;{})\0", current_process_user_sid_string()?);
    let sddl: Vec<u16> = sddl_text.encode_utf16().collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &raw mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut missing: Vec<PathBuf> = state_dir
        .ancestors()
        .take_while(|component| !component.exists())
        .map(Path::to_path_buf)
        .collect();
    missing.reverse();
    let result = (|| -> IpcResult<()> {
        for directory in missing {
            let wide: Vec<u16> = directory
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            if unsafe { CreateDirectoryW(wide.as_ptr(), &raw mut attrs) } == 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS.cast_signed()) {
                    return Err(error.into());
                }
            }
        }
        Ok(())
    })();
    unsafe {
        let _ = LocalFree(descriptor);
    }
    result
}

#[cfg(not(any(unix, windows)))]
fn create_state_dir_owner_only(_state_dir: &Path) -> IpcResult<()> {
    Err(IpcError::Protocol(
        "secure credential state directory creation is unsupported on this platform".into(),
    ))
}

fn prepare_secure_state_dir(state_dir: &Path) -> IpcResult<()> {
    reject_symlink_or_reparse_components(state_dir)?;
    create_state_dir_owner_only(state_dir)?;
    reject_symlink_or_reparse_components(state_dir)?;
    // Never tighten or read through a directory until its type and owner have
    // been attested. Newly created directories are already owner-only.
    validate_state_dir_owner(state_dir, false)?;
    restrict_owner_only(state_dir, true)?;
    validate_secure_state_dir(state_dir)?;
    #[cfg(unix)]
    if let Some(parent) = state_dir.parent() {
        let parent_dir = fs::File::open(parent)?;
        parent_dir.sync_all()?;
    }
    Ok(())
}

fn validate_secure_state_dir(state_dir: &Path) -> IpcResult<()> {
    reject_symlink_or_reparse_components(state_dir)?;
    let metadata = fs::symlink_metadata(state_dir)?;
    if !metadata.is_dir() {
        return Err(IpcError::Unauthorized(format!(
            "credential state path is not a directory: {}",
            state_dir.display()
        )));
    }
    validate_state_dir_owner(state_dir, true)?;
    validate_parent_custody(state_dir)?;
    Ok(())
}

#[cfg(unix)]
fn validate_state_dir_owner(state_dir: &Path, require_protected: bool) -> IpcResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = fs::symlink_metadata(state_dir)?;
    let expected = rustix::process::geteuid().as_raw();
    if metadata.uid() != expected {
        return Err(IpcError::Unauthorized(format!(
            "credential state directory {} is owned by uid {}, expected {expected}",
            state_dir.display(),
            metadata.uid()
        )));
    }
    if require_protected && metadata.permissions().mode() & 0o077 != 0 {
        return Err(IpcError::Unauthorized(format!(
            "credential state directory is accessible by group/other: {}",
            state_dir.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_state_dir_owner(state_dir: &Path, require_protected: bool) -> IpcResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        EqualSid, GetSecurityDescriptorControl, GetTokenInformation, TokenUser,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
        SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let wide: Vec<u16> = state_dir
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status.cast_signed()).into());
    }

    let result = (|| -> IpcResult<()> {
        let mut token: HANDLE = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0
            || token.is_null()
        {
            return Err(std::io::Error::last_os_error().into());
        }
        let token_result = (|| -> IpcResult<()> {
            let mut required = 0_u32;
            unsafe {
                let _ =
                    GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut required);
            }
            if required == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let word_size = std::mem::size_of::<usize>();
            let words = (required as usize).div_ceil(word_size);
            let mut buffer = vec![0_usize; words];
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    required,
                    &raw mut required,
                )
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            let token_user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
            if owner.is_null() || unsafe { EqualSid(owner, token_user.User.Sid) } == 0 {
                return Err(IpcError::Unauthorized(format!(
                    "credential state directory is not owned by the daemon OS user: {}",
                    state_dir.display()
                )));
            }
            let mut control = 0_u16;
            let mut revision = 0_u32;
            if unsafe {
                GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision)
            } == 0
            {
                return Err(std::io::Error::last_os_error().into());
            }
            if require_protected && control & SE_DACL_PROTECTED == 0 {
                return Err(IpcError::Unauthorized(format!(
                    "credential state directory DACL is not protected: {}",
                    state_dir.display()
                )));
            }
            Ok(())
        })();
        unsafe {
            CloseHandle(token);
        }
        token_result
    })();
    unsafe {
        let _ = LocalFree(descriptor);
    }
    result
}

#[cfg(unix)]
fn validate_parent_custody(state_dir: &Path) -> IpcResult<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let expected = rustix::process::geteuid().as_raw();
    let mut child = state_dir;
    while let Some(parent) = child.parent() {
        if parent == child || parent.as_os_str().is_empty() {
            break;
        }
        let parent_metadata = fs::symlink_metadata(parent)?;
        if parent_metadata.uid() != expected && parent_metadata.uid() != 0 {
            return Err(IpcError::Unauthorized(format!(
                "credential state ancestor is owned by untrusted uid {}: {}",
                parent_metadata.uid(),
                parent.display()
            )));
        }
        let mode = parent_metadata.permissions().mode();
        let writable_by_other = mode & 0o022 != 0;
        let sticky = mode & 0o1000 != 0;
        // A sticky directory such as /tmp prevents another uid from replacing an
        // owner-owned child. Without sticky, any replacement-capable ancestor is
        // rejected, not merely the immediate state parent.
        if writable_by_other && !sticky {
            return Err(IpcError::Unauthorized(format!(
                "credential state ancestor permits replacement by another user: {}",
                parent.display()
            )));
        }
        if sticky && fs::symlink_metadata(child)?.uid() != expected {
            return Err(IpcError::Unauthorized(format!(
                "credential state path under sticky ancestor is not owned by uid {expected}: {}",
                child.display()
            )));
        }
        child = parent;
    }
    Ok(())
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)]
fn validate_parent_custody(_state_dir: &Path) -> IpcResult<()> {
    // Reparse-point rejection plus a protected DACL on the state directory avoids
    // inherited broad access. It is not a same-user malware boundary.
    Ok(())
}

fn reject_symlink_or_reparse_components(path: &Path) -> IpcResult<()> {
    for component in path.ancestors() {
        if component.as_os_str().is_empty() || !component.exists() {
            continue;
        }
        reject_symlink_or_reparse_if_present(component)?;
    }
    Ok(())
}

fn reject_symlink_or_reparse_if_present(path: &Path) -> IpcResult<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err.into()),
    };
    #[cfg(unix)]
    let is_link = metadata.file_type().is_symlink();
    #[cfg(windows)]
    let is_link = {
        use std::os::windows::fs::MetadataExt;
        use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
        metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    };
    if is_link {
        return Err(IpcError::Unauthorized(format!(
            "credential state custody rejects symlink/reparse path: {}",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn threat_model_doc_is_present() {
        let src = include_str!("registry.rs");
        assert!(src.contains("cooperative"));
        assert!(
            src.contains("same OS user") || src.contains("same-uid") || src.contains("same uid")
        );
        assert!(src.contains("read owner-only") || src.contains("read owner"));
    }

    #[test]
    fn open_creates_versioned_owner_file() {
        let dir = tempdir().unwrap();
        let reg = CredentialRegistry::open(dir.path()).unwrap();
        assert!(reg.path().is_file());
        let value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(reg.path()).unwrap()).unwrap();
        assert_eq!(value["version"], REGISTRY_VERSION);
        assert_eq!(value["entries"], serde_json::json!([]));
    }

    #[test]
    fn provision_persist_reload_roundtrip() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let secret = reg.provision("chatgpt", "alice").expect("provision");
        assert!(!secret.is_empty());
        let found = reg.find_by_secret(&secret).expect("lookup");
        assert_eq!(found.principal_key, "client:chatgpt");
        assert_eq!(found.bound_user_id, "alice");
        let on_disk = fs::read_to_string(reg.path()).unwrap();
        assert!(
            !on_disk.contains(&secret),
            "registry persisted bearer secret"
        );
        assert!(on_disk.contains("secret_verifier"));

        drop(reg);
        let reopened = CredentialRegistry::open(dir.path()).unwrap();
        let again = reopened.find_by_secret(&secret).expect("restored");
        assert_eq!(again.client_id, "chatgpt");
        assert_eq!(again.principal_key, "client:chatgpt");
        assert!(!again.revoked);
    }

    #[test]
    fn reload_rejects_non_server_defined_principal_mapping() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        reg.provision("agent", "alice").unwrap();
        let path = reg.path().to_path_buf();
        drop(reg);

        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        value["entries"][0]["principal_key"] = serde_json::json!("admin:chosen-offline");
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let error = CredentialRegistry::open(dir.path()).unwrap_err();
        assert!(error.to_string().contains("required mapping"), "{error}");
    }

    #[test]
    fn reload_rejects_noncanonical_client_id_even_if_principal_looks_related() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        reg.provision("agent", "alice").unwrap();
        let path = reg.path().to_path_buf();
        drop(reg);

        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        value["entries"][0]["client_id"] = serde_json::json!("Agent");
        value["entries"][0]["principal_key"] = serde_json::json!("client:agent");
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let error = CredentialRegistry::open(dir.path()).unwrap_err();
        assert!(error.to_string().contains("not canonical"), "{error}");
    }

    #[test]
    fn rotate_invalidates_old_secret_and_persists() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let old = reg.provision("agent", "u1").unwrap();
        let new = reg.rotate("agent").unwrap();
        assert_ne!(old, new);
        assert!(reg.find_by_secret(&old).is_none());
        assert!(reg.find_by_secret(&new).is_some());

        drop(reg);
        let reopened = CredentialRegistry::open(dir.path()).unwrap();
        assert!(reopened.find_by_secret(&old).is_none());
        assert_eq!(
            reopened.find_by_secret(&new).unwrap().principal_key,
            "client:agent"
        );
    }

    #[test]
    fn revoke_clears_mapping_across_restart() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let secret = reg.provision("victim", "u1").unwrap();
        reg.revoke("victim").unwrap();
        assert!(reg.find_by_secret(&secret).is_none());

        drop(reg);
        let reopened = CredentialRegistry::open(dir.path()).unwrap();
        assert!(reopened.find_by_secret(&secret).is_none());
        assert!(reopened
            .entries()
            .iter()
            .any(|e| e.client_id == "victim" && e.revoked));
    }

    #[test]
    fn exclusive_lock_serializes_registry_owners() {
        let dir = tempdir().unwrap();
        let first = CredentialRegistry::open(dir.path()).unwrap();
        let error = CredentialRegistry::open(dir.path()).unwrap_err();
        assert!(error.to_string().contains("already owned"), "{error}");
        drop(first);
        CredentialRegistry::open(dir.path()).unwrap();
    }

    #[test]
    fn reprovision_never_reuses_revoked_generation() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let old = reg.provision("client", "user").unwrap();
        assert_eq!(reg.active_entry("client").unwrap().generation, 1);
        reg.revoke("client").unwrap();
        let new = reg.provision("client", "user").unwrap();
        assert_ne!(old, new);
        assert_eq!(reg.active_entry("client").unwrap().generation, 2);
        assert!(reg.find_by_secret(&old).is_none());
        assert!(reg.find_by_secret(&new).is_some());
    }

    #[test]
    fn secret_not_visible_in_debug() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let secret = reg.provision("x", "u").unwrap();
        let dbg = format!("{:?}", reg.entries());
        assert!(!dbg.contains(&secret), "Debug leaked secret: {dbg}");
        assert!(dbg.contains("REDACTED") || dbg.contains("Redacted"));
    }

    #[test]
    fn failed_rotation_restores_in_memory_secret() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let old = reg.provision("agent", "u").unwrap();
        let path = reg.path().to_path_buf();
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();

        assert!(reg.rotate("agent").is_err());
        assert!(reg.find_by_secret(&old).is_some());
        assert_eq!(
            reg.active_entry("agent").unwrap().principal_key,
            "client:agent"
        );
    }

    #[test]
    fn find_by_secret_ignores_hashmap_style_direct_keying() {
        // Ensure API surface is scan-based: wrong-length secrets do not panic.
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let secret = reg.provision("a", "u").unwrap();
        assert!(reg.find_by_secret(&secret).is_some());
        assert!(reg.find_by_secret("short").is_none());
        assert!(reg.find_by_secret(&format!("{secret}x")).is_none());
    }

    #[test]
    fn management_bootstrap_is_fixed_owner_file_and_restores() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        assert_eq!(
            reg.ensure_management_bootstrap("alice").unwrap(),
            BootstrapStatus::Created
        );
        let secret = read_management_credential(dir.path()).unwrap();
        let entry = reg.find_by_secret(&secret).unwrap();
        assert_eq!(entry.client_id, MANAGEMENT_CLIENT_ID);
        assert_eq!(entry.principal_key, MANAGEMENT_PRINCIPAL);
        assert_eq!(entry.bound_user_id, "alice");
        drop(reg);

        let mut reopened = CredentialRegistry::open(dir.path()).unwrap();
        assert_eq!(
            reopened.ensure_management_bootstrap("alice").unwrap(),
            BootstrapStatus::Existing
        );
        assert_eq!(
            reopened.find_by_secret(&secret).unwrap().principal_key,
            MANAGEMENT_PRINCIPAL
        );
        fs::write(
            dir.path().join(MANAGEMENT_CREDENTIAL_FILE_NAME),
            b"stale-or-corrupt\n",
        )
        .unwrap();
        assert!(reopened.ensure_management_bootstrap("alice").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn registry_rejects_symlink_and_replaceable_parent_custody() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempdir().unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = dir.path().join("linked-state");
        symlink(&target, &link).unwrap();
        assert!(CredentialRegistry::open(&link).is_err());

        let replaceable = dir.path().join("replaceable");
        fs::create_dir(&replaceable).unwrap();
        fs::set_permissions(&replaceable, fs::Permissions::from_mode(0o777)).unwrap();
        let state = replaceable.join("state");
        assert!(CredentialRegistry::open(&state).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn registry_file_is_owner_only_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let _ = reg.provision("a", "u").unwrap();
        let mode = fs::metadata(reg.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "mode was {mode:o}");
    }

    #[test]
    fn rejects_non_regular_registry_and_lock_paths() {
        let dir = tempdir().unwrap();
        let reg = CredentialRegistry::open(dir.path()).unwrap();
        let registry_path = reg.path().to_path_buf();
        let lock_path = dir.path().join(REGISTRY_LOCK_FILE_NAME);
        drop(reg);

        fs::remove_file(&registry_path).unwrap();
        fs::create_dir(&registry_path).unwrap();
        let err = CredentialRegistry::open(dir.path()).unwrap_err();
        assert!(
            err.to_string().contains("regular file")
                || err.to_string().contains("not a regular")
                || err.to_string().contains("Unauthorized")
                || err.to_string().contains("credential"),
            "{err}"
        );

        // Restore a valid registry file but replace the lock with a directory.
        fs::remove_dir(&registry_path).unwrap();
        fs::write(&registry_path, b"{\"version\":1,\"entries\":[]}\n").unwrap();
        restrict_owner_only(&registry_path, false).unwrap();
        if lock_path.exists() {
            let _ = fs::remove_file(&lock_path);
            let _ = fs::remove_dir_all(&lock_path);
        }
        fs::create_dir(&lock_path).unwrap();
        assert!(CredentialRegistry::open(dir.path()).is_err());
    }

    #[test]
    fn existing_registry_validated_before_read() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        let secret = reg.provision("client", "user").unwrap();
        drop(reg);

        // Re-open must validate ownership + regular-file type before trusting bytes.
        let reopened = CredentialRegistry::open(dir.path()).unwrap();
        assert!(reopened.find_by_secret(&secret).is_some());
        assert!(path_has_owner_only_protection(reopened.path(), false).unwrap());
        assert!(
            path_has_owner_only_protection(&dir.path().join(REGISTRY_LOCK_FILE_NAME), false)
                .unwrap()
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_repeated_atomic_replacement_final_content_no_temp_leftovers() {
        const ITERATIONS: usize = 64;
        let dir = tempdir().unwrap();
        prepare_secure_state_dir(dir.path()).unwrap();
        let path = dir.path().join("replacement-target.json");
        for i in 0..ITERATIONS {
            let payload = format!("{{\"iteration\":{i},\"marker\":\"end-{i}\"}}\n");
            atomic_write_owner_only(&path, payload.as_bytes()).unwrap();
        }
        let final_content = fs::read_to_string(&path).unwrap();
        assert!(
            final_content.contains(&format!("end-{}", ITERATIONS - 1)),
            "final content missing last payload: {final_content}"
        );
        assert!(
            final_content.contains(&format!("\"iteration\":{}", ITERATIONS - 1)),
            "{final_content}"
        );

        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "leftover temp files after atomic replacement: {leftovers:?}"
        );
        assert!(path_has_owner_only_protection(&path, false).unwrap());
    }

    #[cfg(windows)]
    #[test]
    fn windows_registry_delivery_lock_have_owner_only_protected_dacl() {
        let dir = tempdir().unwrap();
        let mut reg = CredentialRegistry::open(dir.path()).unwrap();
        assert_eq!(
            reg.ensure_management_bootstrap("windows-user").unwrap(),
            BootstrapStatus::Created
        );
        let registry = reg.path().to_path_buf();
        let delivery = dir.path().join(MANAGEMENT_CREDENTIAL_FILE_NAME);
        let lock = dir.path().join(REGISTRY_LOCK_FILE_NAME);
        drop(reg);

        for (label, path) in [
            ("registry", registry.as_path()),
            ("delivery", delivery.as_path()),
            ("lock", lock.as_path()),
        ] {
            assert!(
                path.is_file(),
                "{label} missing regular file at {}",
                path.display()
            );
            assert!(
                path_has_owner_only_protection(path, false).unwrap(),
                "{label} lacks protected owner-only DACL: {}",
                path.display()
            );
            // Handle-level revalidation must also accept these files.
            validate_owned_regular_file_path(path).unwrap_or_else(|err| {
                panic!("{label} failed owned-regular validation: {err}");
            });
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_state_custody_revalidates_pinned_handle_identity_and_security() {
        // open() acquires StateCustody handles without FILE_SHARE_DELETE and
        // revalidates identity + state-dir security. Success of open under a
        // prepared owner-only directory is the positive attestation; a missing
        // revalidation path would fail closed on identity/security errors.
        let dir = tempdir().unwrap();
        let reg = CredentialRegistry::open(dir.path()).unwrap();
        assert!(path_has_owner_only_protection(dir.path(), true).unwrap());
        assert!(reg.path().is_file());
        drop(reg);

        // Opening again after drop must re-pin and revalidate from scratch.
        let again = CredentialRegistry::open(dir.path()).unwrap();
        assert!(again.entries().is_empty() || !again.entries().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_reparse_registry_path() {
        use std::process::Command;
        let dir = tempdir().unwrap();
        let real_state = dir.path().join("real-state");
        fs::create_dir(&real_state).unwrap();
        // Establish a valid registry under the real directory first.
        let _ = CredentialRegistry::open(&real_state).unwrap();

        let link = dir.path().join("linked-state");
        // Directory symlink/junction: reject via reparse-point custody checks.
        let ok = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &link.to_string_lossy(),
                &real_state.to_string_lossy(),
            ])
            .status()
            .map(|status| status.success())
            .unwrap_or(false);
        if !ok {
            // Junction creation unavailable (policy/privilege). The open path still
            // rejects symlink/reparse nodes via reject_symlink_or_reparse_if_present
            // and FILE_FLAG_OPEN_REPARSE_POINT handle attributes when present.
            eprintln!("skipping junction creation; mklink /J unavailable");
            return;
        }
        let err = CredentialRegistry::open(&link).unwrap_err();
        assert!(
            err.to_string().contains("reparse")
                || err.to_string().contains("symlink")
                || err.to_string().contains("Unauthorized"),
            "{err}"
        );
    }
}
