//! Root-owned, crash-conservative replay ledger for protocol v2 capabilities.
//!
//! Reservation is persisted and synced before an elevated process can start.
//! Therefore a crash after reserve is deliberately treated as uncertain: the
//! nonce stays denied after restart instead of risking a duplicate side effect.

use ownmesh_broker_client::{operation_facts_digest, BrokerRequestV2};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

const LEDGER_VERSION: u32 = 2;
const MAX_LEDGER_BYTES: u64 = 4 * 1024 * 1024;
const MAX_NONCE_BYTES: usize = 256;
const DIGEST_HEX_BYTES: usize = 64;

/// Persistent replay state. Every transition is durable before the next
/// side-effect boundary. Terminal states may be pruned after expiry; uncertain
/// states are never silently evicted.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplayState {
    ReservedPreSpawn,
    SpawnedUncertain,
    Completed,
    AbortedBeforeSpawn,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReconciliationRecord {
    actor: String,
    at_unix: i64,
    prior_state: ReplayState,
    new_state: ReplayState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerEntry {
    digest: String,
    #[serde(default)]
    reserved_at_unix: i64,
    expires_at_unix: i64,
    #[serde(default)]
    transition_seq: u64,
    state: ReplayState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_pid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_birth_id: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reconciliation: Option<ReconciliationRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LedgerFile {
    version: u32,
    entries: BTreeMap<String, LedgerEntry>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum LegacyReplayState {
    Reserved,
    Completed,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyLedgerEntry {
    digest: String,
    expires_at_unix: i64,
    state: LegacyReplayState,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyLedgerFile {
    version: u32,
    entries: BTreeMap<String, LegacyLedgerEntry>,
}

/// Bounded operator-facing capacity snapshot. No command, environment, or
/// result body is ever included.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ReplayLedgerStatus {
    pub schema_version: u32,
    pub max_entries: usize,
    pub total_entries: usize,
    pub completed_entries: usize,
    pub uncertain_entries: usize,
    pub recoverable_pre_spawn_entries: usize,
    pub durable_bytes: u64,
    pub oldest_uncertain_unix: Option<i64>,
    pub warning: bool,
    pub critical: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReconcileDecision {
    MarkAbortedBeforeSpawn,
    MarkCompleted,
}

/// A successful reservation permits exactly one spawn.  The nonce cannot be
/// reused even if the caller retries an otherwise identical request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReservation {
    Reserved,
}

/// Durable ledger errors are intentionally specific so callers can treat every
/// persistence/corruption/limit failure as a hard authorization failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReplayLedgerError {
    #[error("replay ledger nonce was already consumed")]
    Replay,
    #[error("replay ledger nonce conflicts with a different operation digest")]
    DigestConflict,
    #[error("replay ledger is full; refusing to evict live or uncertain entries")]
    Full,
    #[error("replay ledger is corrupt: {0}")]
    Corrupt(String),
    #[error("replay ledger custody failure: {0}")]
    Custody(String),
    #[error("replay ledger durable write failure: {0}")]
    Write(String),
    #[error("replay ledger is unavailable after a prior durable write failure")]
    FailedClosed,
    #[error("invalid replay reservation: {0}")]
    Invalid(String),
}

/// Owner-only durable replay ledger.  Production construction is deliberately
/// unavailable on platforms where this crate cannot verify root/SYSTEM custody.
pub struct ReplayLedger {
    path: PathBuf,
    max_entries: usize,
    entries: BTreeMap<String, LedgerEntry>,
    failed_closed: bool,
    _lock_file: File,
}

impl ReplayLedger {
    /// Open an existing root-owned ledger or create a fresh owner-only one.
    pub fn open(path: impl Into<PathBuf>, max_entries: usize) -> Result<Self, ReplayLedgerError> {
        if max_entries == 0 {
            return Err(ReplayLedgerError::Invalid(
                "max entries must be positive".into(),
            ));
        }
        let path = path.into();
        verify_ledger_parent(&path)?;
        let lock_file = acquire_ledger_lock(&path)?;
        let entries = if path.exists() {
            verify_ledger_file(&path)?;
            let metadata = std::fs::metadata(&path)
                .map_err(|e| ReplayLedgerError::Corrupt(format!("stat {}: {e}", path.display())))?;
            if metadata.len() > MAX_LEDGER_BYTES {
                return Err(ReplayLedgerError::Corrupt("file exceeds size limit".into()));
            }
            let bytes = std::fs::read(&path)
                .map_err(|e| ReplayLedgerError::Corrupt(format!("read {}: {e}", path.display())))?;
            let version = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|value| value.get("version").and_then(serde_json::Value::as_u64))
                .ok_or_else(|| ReplayLedgerError::Corrupt("missing ledger version".into()))?;
            let (entries, migrated) = match version {
                1 => {
                    let legacy: LegacyLedgerFile = serde_json::from_slice(&bytes)
                        .map_err(|e| ReplayLedgerError::Corrupt(e.to_string()))?;
                    if legacy.version != 1 || legacy.entries.len() > max_entries {
                        return Err(ReplayLedgerError::Corrupt(
                            "legacy version or entry count is invalid".into(),
                        ));
                    }
                    let entries = legacy
                        .entries
                        .into_iter()
                        .map(|(nonce, entry)| {
                            let state = match entry.state {
                                // v1 could not distinguish crash-before-spawn from
                                // crash-after-spawn; migrate conservatively.
                                LegacyReplayState::Reserved => ReplayState::SpawnedUncertain,
                                LegacyReplayState::Completed => ReplayState::Completed,
                            };
                            (
                                nonce,
                                LedgerEntry {
                                    digest: entry.digest,
                                    reserved_at_unix: 0,
                                    expires_at_unix: entry.expires_at_unix,
                                    transition_seq: 1,
                                    state,
                                    process_pid: None,
                                    process_birth_id: None,
                                    result_digest: None,
                                    reconciliation: None,
                                },
                            )
                        })
                        .collect::<BTreeMap<_, _>>();
                    (entries, true)
                }
                value if value == u64::from(LEDGER_VERSION) => {
                    let file: LedgerFile = serde_json::from_slice(&bytes)
                        .map_err(|e| ReplayLedgerError::Corrupt(e.to_string()))?;
                    if file.entries.len() > max_entries {
                        return Err(ReplayLedgerError::Corrupt("entry count exceeds limit".into()));
                    }
                    (file.entries, false)
                }
                _ => {
                    return Err(ReplayLedgerError::Corrupt(
                        "unsupported forward ledger version".into(),
                    ))
                }
            };
            for (nonce, entry) in &entries {
                validate_entry(nonce, entry)?;
            }
            if migrated {
                let ledger = Self {
                    path: path.clone(),
                    max_entries,
                    entries,
                    failed_closed: false,
                    _lock_file: lock_file,
                };
                ledger.persist()?;
                return Ok(ledger);
            }
            entries
        } else {
            let ledger = Self {
                path,
                max_entries,
                entries: BTreeMap::new(),
                failed_closed: false,
                _lock_file: lock_file,
            };
            ledger.persist()?;
            return Ok(ledger);
        };
        Ok(Self {
            path,
            max_entries,
            entries,
            failed_closed: false,
            _lock_file: lock_file,
        })
    }

    /// Persist and consume a nonce before side-effect execution.  A same-nonce
    /// different-digest request is a conflict, not a harmless retry.
    pub fn reserve(
        &mut self,
        nonce: &str,
        digest: &str,
        expires_at_unix: i64,
        now_unix: i64,
    ) -> Result<ReplayReservation, ReplayLedgerError> {
        self.ensure_available()?;
        validate_reservation(nonce, digest, expires_at_unix, now_unix)?;
        self.prune_completed(now_unix)?;
        if let Some(entry) = self.entries.get(nonce) {
            return if entry.digest == digest {
                Err(ReplayLedgerError::Replay)
            } else {
                Err(ReplayLedgerError::DigestConflict)
            };
        }
        if self.entries.len() >= self.max_entries {
            return Err(ReplayLedgerError::Full);
        }
        self.entries.insert(
            nonce.to_string(),
            LedgerEntry {
                digest: digest.to_string(),
                reserved_at_unix: now_unix,
                expires_at_unix,
                transition_seq: 1,
                state: ReplayState::ReservedPreSpawn,
                process_pid: None,
                process_birth_id: None,
                result_digest: None,
                reconciliation: None,
            },
        );
        if let Err(error) = self.persist() {
            self.failed_closed = true;
            return Err(error);
        }
        Ok(ReplayReservation::Reserved)
    }

    /// Consume a verified v2 request using its canonical action digest.  The
    /// caller must first run `verify_request_v2`; this method deliberately does
    /// not treat the daemon-readable request MAC as mint authority.
    pub fn reserve_verified_request(
        &mut self,
        request: &BrokerRequestV2,
        now_unix: i64,
    ) -> Result<ReplayReservation, ReplayLedgerError> {
        self.reserve(
            &request.nonce,
            &operation_facts_digest(&request.facts),
            request.expires_at_unix,
            now_unix,
        )
    }

    /// Durably cross the side-effect boundary before spawning/signalling.
    pub fn mark_spawned(
        &mut self,
        nonce: &str,
        digest: &str,
        process_identity: Option<(u32, u64)>,
    ) -> Result<(), ReplayLedgerError> {
        self.ensure_available()?;
        let entry = self.entries.get_mut(nonce).ok_or(ReplayLedgerError::Replay)?;
        if entry.digest != digest {
            return Err(ReplayLedgerError::DigestConflict);
        }
        if entry.state != ReplayState::ReservedPreSpawn {
            return Err(ReplayLedgerError::Replay);
        }
        entry.state = ReplayState::SpawnedUncertain;
        entry.transition_seq = entry.transition_seq.saturating_add(1);
        if let Some((pid, birth)) = process_identity {
            entry.process_pid = Some(pid);
            entry.process_birth_id = Some(birth);
        }
        if let Err(error) = self.persist() {
            self.failed_closed = true;
            return Err(error);
        }
        Ok(())
    }

    #[must_use]
    pub fn status(&self) -> ReplayLedgerStatus {
        let total_entries = self.entries.len();
        let completed_entries = self
            .entries
            .values()
            .filter(|entry| matches!(entry.state, ReplayState::Completed | ReplayState::AbortedBeforeSpawn))
            .count();
        let uncertain_entries = self
            .entries
            .values()
            .filter(|entry| entry.state == ReplayState::SpawnedUncertain)
            .count();
        let recoverable_pre_spawn_entries = self
            .entries
            .values()
            .filter(|entry| entry.state == ReplayState::ReservedPreSpawn)
            .count();
        let oldest_uncertain_unix = self
            .entries
            .values()
            .filter(|entry| matches!(entry.state, ReplayState::ReservedPreSpawn | ReplayState::SpawnedUncertain))
            .map(|entry| entry.reserved_at_unix)
            .min();
        let warning_threshold = self.max_entries.saturating_mul(3) / 5;
        let critical_threshold = self.max_entries.saturating_mul(4) / 5;
        ReplayLedgerStatus {
            schema_version: LEDGER_VERSION,
            max_entries: self.max_entries,
            total_entries,
            completed_entries,
            uncertain_entries,
            recoverable_pre_spawn_entries,
            durable_bytes: std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0),
            oldest_uncertain_unix,
            warning: total_entries >= warning_threshold,
            critical: total_entries >= critical_threshold,
        }
    }

    /// Apply an explicit operator disposition without ever re-running the operation.
    pub fn reconcile(
        &mut self,
        nonce: &str,
        decision: ReconcileDecision,
        actor: &str,
        now_unix: i64,
        acknowledge_uncertain: bool,
    ) -> Result<(), ReplayLedgerError> {
        self.ensure_available()?;
        if actor.is_empty() || actor.len() > 128 || actor.contains(['\n', '\r', '\0']) {
            return Err(ReplayLedgerError::Invalid("reconciliation actor is invalid".into()));
        }
        let entry = self.entries.get_mut(nonce).ok_or(ReplayLedgerError::Replay)?;
        let prior = entry.state;
        let next = match decision {
            ReconcileDecision::MarkAbortedBeforeSpawn
                if prior == ReplayState::ReservedPreSpawn => ReplayState::AbortedBeforeSpawn,
            ReconcileDecision::MarkCompleted
                if prior == ReplayState::SpawnedUncertain && acknowledge_uncertain => ReplayState::Completed,
            ReconcileDecision::MarkCompleted if prior == ReplayState::SpawnedUncertain => {
                return Err(ReplayLedgerError::Invalid(
                    "spawned-uncertain reconciliation requires explicit acknowledgement".into(),
                ))
            }
            _ => {
                return Err(ReplayLedgerError::Invalid(
                    "reconciliation decision is incompatible with durable state".into(),
                ))
            }
        };
        entry.state = next;
        entry.transition_seq = entry.transition_seq.saturating_add(1);
        entry.reconciliation = Some(ReconciliationRecord {
            actor: actor.to_owned(),
            at_unix: now_unix,
            prior_state: prior,
            new_state: next,
        });
        if let Err(error) = self.persist() {
            self.failed_closed = true;
            return Err(error);
        }
        Ok(())
    }

    /// Mark a known consumed nonce complete.  Failure leaves the ledger closed:
    /// a process may have run, so later authorization must not continue.
    pub fn mark_completed(&mut self, nonce: &str, digest: &str) -> Result<(), ReplayLedgerError> {
        self.ensure_available()?;
        let entry = self
            .entries
            .get_mut(nonce)
            .ok_or(ReplayLedgerError::Replay)?;
        if entry.digest != digest {
            return Err(ReplayLedgerError::DigestConflict);
        }
        if entry.state != ReplayState::SpawnedUncertain {
            return Err(ReplayLedgerError::Replay);
        }
        entry.state = ReplayState::Completed;
        entry.transition_seq = entry.transition_seq.saturating_add(1);
        if let Err(error) = self.persist() {
            self.failed_closed = true;
            return Err(error);
        }
        Ok(())
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn ensure_available(&self) -> Result<(), ReplayLedgerError> {
        if self.failed_closed {
            Err(ReplayLedgerError::FailedClosed)
        } else {
            Ok(())
        }
    }

    fn prune_completed(&mut self, now_unix: i64) -> Result<(), ReplayLedgerError> {
        let prior = self.entries.len();
        self.entries.retain(|_, entry| {
            matches!(entry.state, ReplayState::ReservedPreSpawn | ReplayState::SpawnedUncertain)
                || entry.expires_at_unix >= now_unix
        });
        if self.entries.len() != prior {
            if let Err(error) = self.persist() {
                self.failed_closed = true;
                return Err(error);
            }
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), ReplayLedgerError> {
        let serialized = serde_json::to_vec(&LedgerFile {
            version: LEDGER_VERSION,
            entries: self.entries.clone(),
        })
        .map_err(|e| ReplayLedgerError::Write(format!("serialize: {e}")))?;
        if serialized.len() as u64 > MAX_LEDGER_BYTES {
            return Err(ReplayLedgerError::Full);
        }
        let parent = self.path.parent().ok_or_else(|| {
            ReplayLedgerError::Custody("ledger requires a parent directory".into())
        })?;
        let temp = parent.join(format!(
            ".{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("ledger"),
            uuid::Uuid::new_v4().simple()
        ));
        let write = (|| -> Result<(), ReplayLedgerError> {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options
                .open(&temp)
                .map_err(|e| ReplayLedgerError::Write(format!("create {}: {e}", temp.display())))?;
            file.write_all(&serialized)
                .map_err(|e| ReplayLedgerError::Write(format!("write {}: {e}", temp.display())))?;
            file.sync_all()
                .map_err(|e| ReplayLedgerError::Write(format!("sync {}: {e}", temp.display())))?;
            std::fs::rename(&temp, &self.path).map_err(|e| {
                ReplayLedgerError::Write(format!("rename {}: {e}", self.path.display()))
            })?;
            sync_directory(parent)?;
            verify_ledger_file(&self.path)?;
            Ok(())
        })();
        if write.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        write
    }
}

fn validate_reservation(
    nonce: &str,
    digest: &str,
    expires_at_unix: i64,
    now_unix: i64,
) -> Result<(), ReplayLedgerError> {
    if nonce.is_empty() || nonce.len() > MAX_NONCE_BYTES || nonce.contains('\0') {
        return Err(ReplayLedgerError::Invalid("nonce".into()));
    }
    if !is_digest(digest) {
        return Err(ReplayLedgerError::Invalid("digest".into()));
    }
    if expires_at_unix < now_unix {
        return Err(ReplayLedgerError::Invalid("expired reservation".into()));
    }
    Ok(())
}

fn validate_entry(nonce: &str, entry: &LedgerEntry) -> Result<(), ReplayLedgerError> {
    validate_reservation(nonce, &entry.digest, entry.expires_at_unix, i64::MIN)?;
    if entry.transition_seq == 0 {
        return Err(ReplayLedgerError::Corrupt("zero transition sequence".into()));
    }
    if entry.process_pid.is_some() != entry.process_birth_id.is_some() {
        return Err(ReplayLedgerError::Corrupt(
            "partial process identity in replay ledger".into(),
        ));
    }
    if entry.result_digest.as_deref().is_some_and(|digest| !is_digest(digest)) {
        return Err(ReplayLedgerError::Corrupt("invalid result digest".into()));
    }
    if let Some(record) = &entry.reconciliation {
        if record.actor.is_empty()
            || record.actor.len() > 128
            || record.actor.contains(['\n', '\r', '\0'])
        {
            return Err(ReplayLedgerError::Corrupt(
                "invalid reconciliation metadata".into(),
            ));
        }
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == DIGEST_HEX_BYTES
        && value
            .as_bytes()
            .iter()
            .all(|b| b.is_ascii_digit() || (b.is_ascii_lowercase() && b.is_ascii_hexdigit()))
}

fn acquire_ledger_lock(path: &Path) -> Result<File, ReplayLedgerError> {
    use fs2::FileExt;
    let parent = path.parent().ok_or_else(|| {
        ReplayLedgerError::Custody("ledger requires a parent directory".into())
    })?;
    let lock_path = parent.join("replay-ledger.lock");
    #[cfg(unix)]
    if lock_path.exists() {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(&lock_path).map_err(|e| {
            ReplayLedgerError::Custody(format!("inspect replay ledger lock: {e}"))
        })?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(ReplayLedgerError::Custody(
                "replay ledger lock must be a root-owned 0600 regular file".into(),
            ));
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&lock_path)
        .map_err(|e| ReplayLedgerError::Custody(format!("open replay ledger lock: {e}")))?;
    file.try_lock_exclusive().map_err(|_| {
        ReplayLedgerError::Custody(
            "replay ledger is active in another broker process; stop the broker before reconciliation"
                .into(),
        )
    })?;
    Ok(file)
}

fn verify_ledger_parent(path: &Path) -> Result<(), ReplayLedgerError> {
    let parent = path.parent().ok_or_else(|| {
        ReplayLedgerError::Custody("ledger requires a root-controlled parent".into())
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if rustix::process::geteuid().as_raw() != 0 {
            return Err(ReplayLedgerError::Custody(
                "production replay ledger requires effective UID 0".into(),
            ));
        }
        let metadata = std::fs::symlink_metadata(parent).map_err(|e| {
            ReplayLedgerError::Custody(format!("inspect {}: {e}", parent.display()))
        })?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(ReplayLedgerError::Custody(
                "ledger parent must be root-owned, non-symlink, and not group/other writable"
                    .into(),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        Err(ReplayLedgerError::Custody(
            "production replay ledger custody is unsupported on this platform".into(),
        ))
    }
}

fn verify_ledger_file(path: &Path) -> Result<(), ReplayLedgerError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| ReplayLedgerError::Custody(format!("inspect {}: {e}", path.display())))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
        {
            return Err(ReplayLedgerError::Custody(
                "ledger must be a root-owned 0600 regular non-symlink file".into(),
            ));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ReplayLedgerError::Custody(
            "production replay ledger custody is unsupported on this platform".into(),
        ))
    }
}

fn sync_directory(path: &Path) -> Result<(), ReplayLedgerError> {
    #[cfg(unix)]
    {
        File::open(path)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| {
                ReplayLedgerError::Write(format!("sync directory {}: {e}", path.display()))
            })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(ReplayLedgerError::Custody(
            "directory sync is unsupported on this platform".into(),
        ))
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn digest(fill: char) -> String {
        std::iter::repeat_n(fill, DIGEST_HEX_BYTES).collect()
    }

    fn root_ledger() -> Option<(tempfile::TempDir, PathBuf)> {
        if rustix::process::geteuid().as_raw() != 0 {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.json");
        Some((dir, path))
    }

    #[test]
    fn reserve_survives_restart_and_rejects_nonce_conflicts() {
        let Some((_dir, path)) = root_ledger() else {
            return;
        };
        let mut ledger = ReplayLedger::open(&path, 4).unwrap();
        ledger.reserve("nonce-a", &digest('a'), 200, 100).unwrap();
        drop(ledger); // Models a crash after durable reserve and before spawn/finalize.

        let mut restarted = ReplayLedger::open(&path, 4).unwrap();
        assert_eq!(
            restarted.reserve("nonce-a", &digest('a'), 200, 100),
            Err(ReplayLedgerError::Replay)
        );
        assert_eq!(
            restarted.reserve("nonce-a", &digest('b'), 200, 100),
            Err(ReplayLedgerError::DigestConflict)
        );
    }

    #[test]
    fn completed_entries_prune_only_after_expiry_and_ledger_never_evicts_live_entries() {
        let Some((_dir, path)) = root_ledger() else {
            return;
        };
        let mut ledger = ReplayLedger::open(&path, 1).unwrap();
        ledger.reserve("nonce-a", &digest('a'), 100, 10).unwrap();
        assert_eq!(
            ledger.reserve("nonce-b", &digest('b'), 100, 10),
            Err(ReplayLedgerError::Full),
            "reserved/uncertain entries must never be evicted for capacity"
        );
        ledger
            .mark_spawned("nonce-a", &digest('a'), None)
            .unwrap();
        ledger.mark_completed("nonce-a", &digest('a')).unwrap();
        ledger.reserve("nonce-b", &digest('b'), 200, 101).unwrap();
    }

    #[test]
    fn pre_spawn_and_uncertain_reconciliation_require_explicit_safe_decisions() {
        let Some((_dir, path)) = root_ledger() else {
            return;
        };
        let mut ledger = ReplayLedger::open(&path, 8).unwrap();
        ledger.reserve("pre", &digest('a'), 500, 10).unwrap();
        ledger
            .reconcile(
                "pre",
                ReconcileDecision::MarkAbortedBeforeSpawn,
                "operator:test",
                11,
                false,
            )
            .unwrap();

        ledger.reserve("uncertain", &digest('b'), 500, 12).unwrap();
        ledger
            .mark_spawned("uncertain", &digest('b'), Some((42, 77)))
            .unwrap();
        assert!(matches!(
            ledger.reconcile(
                "uncertain",
                ReconcileDecision::MarkCompleted,
                "operator:test",
                13,
                false,
            ),
            Err(ReplayLedgerError::Invalid(_))
        ));
        ledger
            .reconcile(
                "uncertain",
                ReconcileDecision::MarkCompleted,
                "operator:test",
                14,
                true,
            )
            .unwrap();
        let status = ledger.status();
        assert_eq!(status.uncertain_entries, 0);
        assert_eq!(status.completed_entries, 2);
    }

    #[test]
    fn capacity_status_warns_before_full_without_pruning_uncertain_entries() {
        let Some((_dir, path)) = root_ledger() else {
            return;
        };
        let mut ledger = ReplayLedger::open(&path, 5).unwrap();
        for (index, character) in ['a', 'b', 'c', 'd'].into_iter().enumerate() {
            ledger
                .reserve(
                    &format!("nonce-{index}"),
                    &digest(character),
                    500,
                    10 + index as i64,
                )
                .unwrap();
        }
        let status = ledger.status();
        assert!(status.warning);
        assert!(status.critical);
        assert_eq!(status.total_entries, 4);
        assert_eq!(status.recoverable_pre_spawn_entries, 4);
        assert_eq!(status.oldest_uncertain_unix, Some(10));
    }

    #[test]
    fn corrupt_and_write_failure_are_fail_closed() {
        let Some((_dir, path)) = root_ledger() else {
            return;
        };
        let mut ledger = ReplayLedger::open(&path, 4).unwrap();
        // An unavailable replacement path simulates a disk/write failure after
        // a caller has attempted a new reservation. Subsequent calls stay shut.
        ledger.path = path.join("missing-parent").join("replay.json");
        assert!(ledger.reserve("nonce-a", &digest('a'), 100, 10).is_err());
        assert_eq!(
            ledger.reserve("nonce-b", &digest('b'), 100, 10),
            Err(ReplayLedgerError::FailedClosed)
        );

        let corrupt = path.with_file_name("corrupt.json");
        std::fs::write(&corrupt, b"not json").unwrap();
        std::fs::set_permissions(&corrupt, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(
            ReplayLedger::open(corrupt, 4),
            Err(ReplayLedgerError::Corrupt(_))
        ));
    }
}
