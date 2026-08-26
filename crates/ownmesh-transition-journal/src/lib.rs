//! Owner-only durable intent journal for sidecar controller transitions.
//!
//! A record is written before the sidecar mutation, updated with the returned
//! binding, then cleared only after the `SessionManager` persistence succeeds.
//! The next daemon can enumerate an `intent`/`applied` entry and retry its
//! idempotent transition without inventing a second host generation.
//!
//! The typed model and its validation live here (not in the daemon) so the
//! read-only `ownmesh doctor` observation performs *exactly* the same
//! validation as the daemon's loader: a journal the daemon would refuse to
//! open is never reported healthy by a diagnostic (P1-F).

#![allow(dead_code)] // persistence APIs are wired by the daemon runtime slice

use ownmesh_ipc::{
    atomic_write_owner_only, prepare_owner_only_state_dir, read_owner_only_file_bounded,
};
use ownmesh_session::SidecarHostBinding;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const VERSION: u32 = 1;
const MAX_BYTES: usize = 256 * 1024;
const MAX_ENTRIES: usize = 64;
const FILE: &str = "session-transition-journal.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionPhase {
    Intent,
    Applied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionKind {
    Detach,
    Claim,
    Give,
    Renew,
    Reclaim,
    Close,
    Terminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionTarget {
    pub principal: String,
    pub controller_epoch: u64,
    pub binding_expires_unix: i64,
    pub controller_attached: bool,
    /// Exact opaque controller lease id the handler minted for the target
    /// seat. Recovery restores the *full* controller mutation from the
    /// journal (principal + epoch + lease id + expiry + attached state), so
    /// a crash between the supervisor mutation and the `SessionManager`
    /// commit cannot leave a stale controller authorized against a
    /// successor's sidecar binding (P0-A review, crash window). For
    /// `detach` this is the released seat's lease id (no successor lease);
    /// for terminal transitions it is the closed seat's lease id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    /// A terminal transition has no successor binding: recovery must first
    /// replay the sidecar tombstone then persist the terminal session state.
    #[serde(default)]
    pub terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransitionRecord {
    pub transition_id: String,
    pub kind: TransitionKind,
    pub phase: TransitionPhase,
    pub session_id: String,
    pub device_id: String,
    pub workspace_id: String,
    pub authenticated_principal: String,
    pub old_binding: SidecarHostBinding,
    pub target: TransitionTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_binding: Option<SidecarHostBinding>,
    pub created_unix: i64,
    pub expires_unix: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disk {
    version: u32,
    entries: BTreeMap<String, TransitionRecord>,
}

/// A validated, immutable view of a transition journal on disk (read-only).
#[derive(Debug)]
pub struct ParsedJournal {
    pub entries: Vec<TransitionRecord>,
}

impl ParsedJournal {
    /// Records still present in the journal (pending resolution/cleanup).
    #[must_use]
    pub fn pending(&self) -> &[TransitionRecord] {
        &self.entries
    }
}

/// Parse and fully validate a transition journal file, read-only.
///
/// Mirrors every check the daemon's [`SessionTransitionJournal::open`]
/// performs — version, entry cap, map-key/record-id agreement, and per-record
/// invariants (identifier shape, epoch/expiry bounds, host-expiry coverage,
/// binding fields, phase consistency, unknown-field rejection) — without any
/// filesystem side effect. A journal that returns `Err` here is a journal the
/// daemon would refuse to open; diagnostics must not report it healthy.
///
/// # Errors
///
/// Returns the first validation failure (parse error, version mismatch, entry
/// cap, key/id mismatch, or a per-record invariant violation).
pub fn parse_and_validate(bytes: &[u8]) -> Result<ParsedJournal, String> {
    let disk: Disk =
        serde_json::from_slice(bytes).map_err(|e| format!("parse transition journal: {e}"))?;
    if disk.version != VERSION {
        return Err(format!(
            "invalid transition journal version (expected {VERSION}, got {})",
            disk.version
        ));
    }
    if disk.entries.len() > MAX_ENTRIES {
        return Err(format!(
            "transition journal entry cap exceeded ({}/{MAX_ENTRIES})",
            disk.entries.len()
        ));
    }
    let mut entries = Vec::with_capacity(disk.entries.len());
    for (id, record) in disk.entries {
        if id != record.transition_id {
            return Err(format!(
                "transition journal key/id mismatch ({id} != {})",
                record.transition_id
            ));
        }
        validate(&record)?;
        entries.push(record);
    }
    Ok(ParsedJournal { entries })
}

/// Bounded durable transition journal rooted in a custody-attested directory.
pub struct SessionTransitionJournal {
    dir: PathBuf,
    entries: BTreeMap<String, TransitionRecord>,
}

impl SessionTransitionJournal {
    /// # Errors
    ///
    /// Returns an error when the journal directory cannot be prepared or the
    /// existing journal file fails bounded read or full validation.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, String> {
        let dir = dir.as_ref().to_path_buf();
        prepare_owner_only_state_dir(&dir)
            .map_err(|e| format!("prepare transition journal: {e}"))?;
        let path = dir.join(FILE);
        if !path.exists() {
            return Ok(Self {
                dir,
                entries: BTreeMap::new(),
            });
        }
        let bytes = read_owner_only_file_bounded(&path, MAX_BYTES)
            .map_err(|e| format!("read transition journal: {e}"))?;
        let parsed = parse_and_validate(&bytes)?;
        let entries = parsed
            .entries
            .into_iter()
            .map(|record| (record.transition_id.clone(), record))
            .collect();
        Ok(Self { dir, entries })
    }

    /// # Errors
    ///
    /// Returns an error on id reuse conflicts, entry-cap exhaustion, or a
    /// persist failure. The in-memory entry is rolled back on persist
    /// failure so the durable file stays authoritative: a non-durable intent
    /// must never be left behind for supervisor bootstrap recovery to
    /// execute (P0-A review).
    pub fn begin(&mut self, record: TransitionRecord) -> Result<TransitionRecord, String> {
        validate(&record)?;
        match self.entries.get(&record.transition_id) {
            Some(existing) if existing == &record => Ok(existing.clone()),
            Some(_) => Err("transition journal id reuse conflict".into()),
            None => {
                if self.entries.len() >= MAX_ENTRIES {
                    return Err("transition journal entry cap reached".into());
                }
                self.entries
                    .insert(record.transition_id.clone(), record.clone());
                if let Err(e) = self.persist() {
                    self.entries.remove(&record.transition_id);
                    return Err(e);
                }
                Ok(record)
            }
        }
    }
    /// # Errors
    ///
    /// Returns an error when the record is missing, the applied binding
    /// conflicts with a previously recorded one, or validation/persist fails.
    /// The in-memory mutation is rolled back on any failure so the durable
    /// file stays authoritative.
    pub fn mark_applied(&mut self, id: &str, binding: SidecarHostBinding) -> Result<(), String> {
        let original = self
            .entries
            .get(id)
            .cloned()
            .ok_or("transition journal record not found")?;
        if original.phase == TransitionPhase::Applied {
            if original.new_binding.as_ref() == Some(&binding) {
                return Ok(());
            }
            return Err("transition journal applied binding conflict".into());
        }
        // Validate the would-be state before mutating memory: a validation
        // failure must not leave a non-durable mutation behind.
        let mut candidate = original.clone();
        candidate.phase = TransitionPhase::Applied;
        candidate.new_binding = Some(binding);
        validate(&candidate)?;
        // Commit to memory only after validation; roll back on persist
        // failure so the durable file stays authoritative.
        self.entries.insert(id.to_string(), candidate);
        if let Err(e) = self.persist() {
            self.entries.insert(id.to_string(), original);
            return Err(e);
        }
        Ok(())
    }
    /// # Errors
    ///
    /// Returns an error when the record is missing, is not terminal, already
    /// carries a successor binding, or validation/persist fails. The
    /// in-memory mutation is rolled back on any failure so the durable file
    /// stays authoritative.
    pub fn mark_terminal_applied(&mut self, id: &str) -> Result<(), String> {
        let original = self
            .entries
            .get(id)
            .cloned()
            .ok_or("transition journal record not found")?;
        if !original.target.terminal {
            return Err("non-terminal transition cannot record terminal receipt".into());
        }
        if original.phase == TransitionPhase::Applied {
            return if original.new_binding.is_none() {
                Ok(())
            } else {
                Err("terminal transition applied binding conflict".into())
            };
        }
        // Validate the would-be state before mutating memory: a validation
        // failure must not leave a non-durable mutation behind.
        let mut candidate = original.clone();
        candidate.phase = TransitionPhase::Applied;
        candidate.new_binding = None;
        validate(&candidate)?;
        // Commit to memory only after validation; roll back on persist
        // failure so the durable file stays authoritative.
        self.entries.insert(id.to_string(), candidate);
        if let Err(e) = self.persist() {
            self.entries.insert(id.to_string(), original);
            return Err(e);
        }
        Ok(())
    }
    /// # Errors
    ///
    /// Returns an error when persisting the removal fails. The in-memory
    /// entry is restored on failure so the durable file stays authoritative:
    /// recovery refreshes health from the in-memory journal, and a failed
    /// durable removal must not make the daemon report a stale row as gone
    /// until restart (P0-A/P1-F).
    pub fn clear(&mut self, id: &str) -> Result<(), String> {
        let Some(removed) = self.entries.remove(id) else {
            return Ok(());
        };
        if let Err(e) = self.persist() {
            self.entries.insert(id.to_string(), removed);
            return Err(e);
        }
        Ok(())
    }
    #[must_use]
    pub fn pending(&self) -> Vec<TransitionRecord> {
        self.entries.values().cloned().collect()
    }
    /// Test-only: insert a record without validation so fail-closed reconcile
    /// paths can be exercised against crash-interleaved/inconsistent state
    /// that a real `begin` would reject.
    #[cfg(feature = "test-support")]
    pub fn insert_unvalidated_for_test(&mut self, record: TransitionRecord) {
        self.entries.insert(record.transition_id.clone(), record);
    }
    fn persist(&self) -> Result<(), String> {
        let disk = Disk {
            version: VERSION,
            entries: self.entries.clone(),
        };
        let bytes =
            serde_json::to_vec(&disk).map_err(|e| format!("encode transition journal: {e}"))?;
        if bytes.len() > MAX_BYTES {
            return Err("transition journal byte cap reached".into());
        }
        atomic_write_owner_only(&self.dir.join(FILE), &bytes)
            .map_err(|e| format!("persist transition journal: {e}"))
    }
}

fn validate(record: &TransitionRecord) -> Result<(), String> {
    for value in [
        &record.transition_id,
        &record.session_id,
        &record.device_id,
        &record.workspace_id,
        &record.authenticated_principal,
        &record.target.principal,
    ] {
        valid(value)?;
    }
    if record.target.controller_epoch == 0
        || record.created_unix <= 0
        || record.expires_unix <= record.created_unix
        || record.target.binding_expires_unix <= record.created_unix
        || record.target.binding_expires_unix > record.expires_unix
    {
        return Err("invalid transition journal epoch or expiry".into());
    }
    // The record's `expires_unix` is the host-TTL bound: recovery treats an
    // expired record as provably moot only because the supervisor sweeps
    // hosts whose TTL passed. A record whose expiry is *earlier* than the
    // host it references could be cleared while that host is still alive, so
    // the bound must cover every binding the record can touch (P0-A).
    if record.expires_unix < record.old_binding.host_expires_unix
        || record
            .new_binding
            .as_ref()
            .is_some_and(|binding| record.expires_unix < binding.host_expires_unix)
    {
        return Err("invalid transition journal host-expiry bound".into());
    }
    for binding in std::iter::once(&record.old_binding).chain(record.new_binding.iter()) {
        for value in [
            &binding.device_id,
            &binding.workspace_id,
            &binding.owner_principal,
            &binding.host_nonce,
        ] {
            valid(value)?;
        }
        if binding.controller_epoch == 0
            || binding.binding_expires_unix <= 0
            || binding.host_expires_unix <= binding.binding_expires_unix
        {
            return Err("invalid transition journal binding".into());
        }
        if binding.child_pid.is_some() != binding.child_process_birth.is_some() {
            return Err("transition journal binding has incomplete child identity".into());
        }
    }
    if record.phase == TransitionPhase::Applied
        && record.new_binding.is_none()
        && !record.target.terminal
    {
        return Err("applied transition missing binding".into());
    }
    // Cross-field invariant (ADR 0011 / P0-A): `target.terminal` and `kind`
    // must agree. Recovery derives terminality from `kind`
    // (Close|Terminate) while the journal records it on the target; a
    // structurally valid non-terminal kind with `terminal=true` would be
    // replayed as non-terminal (expecting a successor binding) while
    // `mark_terminal_applied` would accept a terminal receipt with none, and
    // a terminal kind with `terminal=false` would be replayed as a
    // non-terminal mutation. Both shapes are rejected fail-closed.
    let kind_is_terminal = matches!(
        record.kind,
        TransitionKind::Close | TransitionKind::Terminate
    );
    if record.target.terminal != kind_is_terminal {
        return Err("transition kind/target.terminal mismatch".into());
    }
    Ok(())
}
fn valid(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 256
        || value
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
    {
        Err("invalid transition journal identifier".into())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Owner-only tempdir: `tempfile` respects the process umask, and the
    /// daemon custody attestation rejects group/world-writable ancestors, so
    /// tests pin mode 0700 to stay umask-independent.
    fn tempdir() -> std::io::Result<tempfile::TempDir> {
        let dir = tempfile::tempdir()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
        }
        Ok(dir)
    }
    fn binding() -> SidecarHostBinding {
        SidecarHostBinding {
            device_id: "dev".into(),
            workspace_id: "ws".into(),
            owner_principal: "owner".into(),
            host_nonce: "nonce".into(),
            controller_epoch: 1,
            binding_expires_unix: 200,
            host_expires_unix: 300,
            child_pid: None,
            child_process_birth: None,
        }
    }
    fn record() -> TransitionRecord {
        TransitionRecord {
            transition_id: "tr_1".into(),
            kind: TransitionKind::Renew,
            phase: TransitionPhase::Intent,
            session_id: "ses_1".into(),
            device_id: "dev".into(),
            workspace_id: "ws".into(),
            authenticated_principal: "owner".into(),
            old_binding: binding(),
            target: TransitionTarget {
                principal: "owner".into(),
                controller_epoch: 1,
                binding_expires_unix: 200,
                controller_attached: true,
                lease_id: Some("lease_1".into()),
                terminal: false,
            },
            new_binding: None,
            created_unix: 100,
            expires_unix: 300,
        }
    }
    fn encode(entries: BTreeMap<String, TransitionRecord>) -> Vec<u8> {
        let disk = Disk {
            version: VERSION,
            entries,
        };
        serde_json::to_vec(&disk).unwrap()
    }
    fn record_disk() -> (String, TransitionRecord) {
        let r = record();
        (r.transition_id.clone(), r)
    }

    #[test]
    fn begin_applied_clear_is_atomic_and_recoverable() {
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        assert_eq!(j.begin(record()).unwrap().phase, TransitionPhase::Intent);
        let mut next = binding();
        next.host_nonce = "next".into();
        j.mark_applied("tr_1", next.clone()).unwrap();
        let reopened = SessionTransitionJournal::open(dir.path()).unwrap();
        assert_eq!(reopened.pending()[0].new_binding, Some(next));
        j.clear("tr_1").unwrap();
        assert!(SessionTransitionJournal::open(dir.path())
            .unwrap()
            .pending()
            .is_empty());
    }

    /// P0-A/P1-F: `clear` must not remove the in-memory entry when the
    /// durable removal fails — otherwise recovery refreshes health from an
    /// empty in-memory journal while the durable stale row remains, and the
    /// daemon reports no pending transition until restart. The failed clear
    /// must roll back, and a later successful clear must still work.
    #[cfg(unix)]
    #[test]
    fn clear_rolls_back_in_memory_entry_when_persist_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        j.begin(record()).unwrap();
        // Make the journal directory read-only so the atomic persist fails.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = j.clear("tr_1").unwrap_err();
        assert!(err.contains("persist transition journal"), "{err}");
        // The in-memory entry is restored: health observations cannot diverge
        // from the durable file.
        assert_eq!(
            j.pending().len(),
            1,
            "in-memory entry must be restored after a failed durable removal"
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // The durable file still contains the record (the failed clear wrote
        // nothing), and a later successful clear removes it for good.
        let reopened = SessionTransitionJournal::open(dir.path()).unwrap();
        assert_eq!(
            reopened.pending().len(),
            1,
            "durable row must survive the failed clear"
        );
        j.clear("tr_1").unwrap();
        assert!(SessionTransitionJournal::open(dir.path())
            .unwrap()
            .pending()
            .is_empty());
    }

    /// P0-A review: `begin` must roll back the in-memory insert when the
    /// durable persist fails. A pre-commit failure must not leave a
    /// non-durable intent behind that later supervisor bootstrap recovery
    /// would execute even though the caller aborted the transition.
    #[cfg(unix)]
    #[test]
    fn begin_rolls_back_in_memory_entry_when_persist_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        // Make the journal directory read-only so the atomic persist fails.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = j.begin(record()).unwrap_err();
        assert!(err.contains("persist transition journal"), "{err}");
        // The in-memory entry is rolled back: recovery must not see an intent
        // that was never durably committed.
        assert!(
            j.pending().is_empty(),
            "failed begin must not leave a non-durable intent in memory"
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // The durable file has no entry, and a later begin still works.
        assert!(SessionTransitionJournal::open(dir.path())
            .unwrap()
            .pending()
            .is_empty());
        j.begin(record()).unwrap();
        assert_eq!(j.pending().len(), 1);
    }

    /// P0-A review: `mark_applied` must roll back the in-memory mutation
    /// when the durable persist fails, and must validate the would-be state
    /// before mutating memory — a failed or invalid receipt must not leave a
    /// non-durable `Applied` phase behind.
    #[cfg(unix)]
    #[test]
    fn mark_applied_rolls_back_when_persist_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        j.begin(record()).unwrap();
        let mut next = binding();
        next.host_nonce = "next".into();
        // Make the journal directory read-only so the atomic persist fails.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = j.mark_applied("tr_1", next.clone()).unwrap_err();
        assert!(err.contains("persist transition journal"), "{err}");
        // The in-memory record is rolled back to the durable state (Intent,
        // no successor binding): recovery must not see an applied receipt
        // that was never durably committed.
        let pending = j.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].phase, TransitionPhase::Intent);
        assert!(pending[0].new_binding.is_none());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // The durable file still holds the Intent record, and a later
        // successful mark_applied works.
        let reopened = SessionTransitionJournal::open(dir.path()).unwrap();
        assert_eq!(reopened.pending()[0].phase, TransitionPhase::Intent);
        j.mark_applied("tr_1", next.clone()).unwrap();
        assert_eq!(j.pending()[0].new_binding, Some(next));
    }

    /// P0-A review: `mark_applied` must validate the would-be state before
    /// mutating memory — an invalid successor binding must be rejected
    /// without leaving a non-durable mutation behind.
    #[test]
    fn mark_applied_validation_failure_leaves_record_unchanged() {
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        j.begin(record()).unwrap();
        let mut invalid = binding();
        invalid.controller_epoch = 0; // violates the binding invariant
        assert!(j.mark_applied("tr_1", invalid).is_err());
        let pending = j.pending();
        assert_eq!(pending[0].phase, TransitionPhase::Intent);
        assert!(pending[0].new_binding.is_none());
        // The durable file is unchanged too.
        let reopened = SessionTransitionJournal::open(dir.path()).unwrap();
        assert_eq!(reopened.pending()[0].phase, TransitionPhase::Intent);
    }

    /// P0-A review: `mark_terminal_applied` must roll back the in-memory
    /// mutation when the durable persist fails.
    #[cfg(unix)]
    #[test]
    fn mark_terminal_applied_rolls_back_when_persist_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        let mut terminal = record();
        terminal.transition_id = "tr_terminal".into();
        terminal.kind = TransitionKind::Terminate;
        terminal.target.terminal = true;
        j.begin(terminal).unwrap();
        // Make the journal directory read-only so the atomic persist fails.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let err = j.mark_terminal_applied("tr_terminal").unwrap_err();
        assert!(err.contains("persist transition journal"), "{err}");
        // The in-memory record is rolled back to the durable state (Intent).
        let pending = j.pending();
        assert_eq!(pending[0].phase, TransitionPhase::Intent);
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        // The durable file still holds the Intent record, and a later
        // successful receipt works.
        let reopened = SessionTransitionJournal::open(dir.path()).unwrap();
        assert_eq!(reopened.pending()[0].phase, TransitionPhase::Intent);
        j.mark_terminal_applied("tr_terminal").unwrap();
        assert_eq!(j.pending()[0].phase, TransitionPhase::Applied);
    }

    /// P1-F: the read-only parser performs the same full validation as the
    /// daemon loader — a journal the daemon would refuse to open is never
    /// reported healthy by a diagnostic.
    #[test]
    fn parse_and_validate_mirrors_daemon_loader() {
        // Baseline valid journal parses.
        let valid = encode(BTreeMap::from([record_disk()]));
        let parsed = parse_and_validate(&valid).expect("valid journal parses");
        assert_eq!(parsed.pending().len(), 1);

        // Wrong version.
        let mut disk: serde_json::Value =
            serde_json::from_slice(&encode(BTreeMap::from([record_disk()]))).unwrap();
        disk["version"] = serde_json::json!(2);
        assert!(parse_and_validate(&serde_json::to_vec(&disk).unwrap()).is_err());

        // Entry cap exceeded.
        let mut big = BTreeMap::new();
        for i in 0..=(MAX_ENTRIES) {
            let mut r = record();
            r.transition_id = format!("tr_{i}");
            big.insert(r.transition_id.clone(), r);
        }
        assert!(parse_and_validate(&encode(big)).is_err());

        // Key/id mismatch.
        let (_, r) = record_disk();
        let mismatched = BTreeMap::from([("tr_other".to_string(), r)]);
        assert!(parse_and_validate(&encode(mismatched)).is_err());

        // Unknown field (deny_unknown_fields) → parse error.
        let mut raw: serde_json::Value =
            serde_json::from_slice(&encode(BTreeMap::from([record_disk()]))).unwrap();
        raw["entries"]["tr_1"]["sneaky"] = serde_json::json!(true);
        assert!(parse_and_validate(&serde_json::to_vec(&raw).unwrap()).is_err());

        // Invalid enum value (kind/phase) → parse error.
        let mut raw: serde_json::Value =
            serde_json::from_slice(&encode(BTreeMap::from([record_disk()]))).unwrap();
        raw["entries"]["tr_1"]["kind"] = serde_json::json!("teleport");
        assert!(parse_and_validate(&serde_json::to_vec(&raw).unwrap()).is_err());

        // Binding invariant violation (controller_epoch 0) → validation error.
        let mut raw: serde_json::Value =
            serde_json::from_slice(&encode(BTreeMap::from([record_disk()]))).unwrap();
        raw["entries"]["tr_1"]["old_binding"]["controller_epoch"] = serde_json::json!(0);
        assert!(parse_and_validate(&serde_json::to_vec(&raw).unwrap()).is_err());

        // Host-expiry bound violation → validation error.
        let mut raw: serde_json::Value =
            serde_json::from_slice(&encode(BTreeMap::from([record_disk()]))).unwrap();
        raw["entries"]["tr_1"]["expires_unix"] = serde_json::json!(250);
        assert!(parse_and_validate(&serde_json::to_vec(&raw).unwrap()).is_err());

        // Applied non-terminal record missing its successor binding → error.
        let mut r = record();
        r.phase = TransitionPhase::Applied;
        assert!(
            parse_and_validate(&encode(BTreeMap::from([(r.transition_id.clone(), r)]))).is_err()
        );

        // Non-object / garbage bytes → parse error.
        assert!(parse_and_validate(b"not json").is_err());
        assert!(parse_and_validate(b"[]").is_err());
    }

    #[test]
    fn corrupt_oversize_and_id_reuse_fail_closed() {
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        j.begin(record()).unwrap();
        let mut altered = record();
        altered.target.principal = "other".into();
        assert!(j.begin(altered).is_err());
        std::fs::write(dir.path().join(FILE), b"bad").unwrap();
        assert!(SessionTransitionJournal::open(dir.path()).is_err());
        std::fs::write(dir.path().join(FILE), vec![0_u8; MAX_BYTES + 1]).unwrap();
        assert!(SessionTransitionJournal::open(dir.path()).is_err());
    }
    #[test]
    fn terminal_receipt_has_no_successor_binding_and_survives_reload() {
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        let mut terminal = record();
        terminal.transition_id = "tr_terminal".into();
        terminal.kind = TransitionKind::Terminate;
        terminal.target.terminal = true;
        j.begin(terminal).unwrap();
        j.mark_terminal_applied("tr_terminal").unwrap();
        let pending = SessionTransitionJournal::open(dir.path())
            .unwrap()
            .pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].phase, TransitionPhase::Applied);
        assert!(pending[0].new_binding.is_none());
        assert!(j.mark_applied("tr_terminal", binding()).is_err());
    }

    /// P0-A: a record whose `expires_unix` is earlier than the host TTL of a
    /// binding it references is inconsistent — clearing it as "expired" could
    /// strand a still-live sidecar. `begin` must reject it fail-closed, and
    /// `open`/`parse_and_validate` must refuse a journal containing one.
    #[test]
    fn record_with_early_expiry_bound_is_rejected_fail_closed() {
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();
        let mut bad = record();
        bad.transition_id = "tr_bad_bound".into();
        // expires_unix (250) < old_binding.host_expires_unix (300).
        bad.expires_unix = 250;
        assert!(
            j.begin(bad).is_err(),
            "begin must reject a record whose expiry precedes its host TTL"
        );
        // A successor binding with a later host TTL is equally inconsistent.
        let mut bad_successor = record();
        bad_successor.transition_id = "tr_bad_successor".into();
        bad_successor.phase = TransitionPhase::Applied;
        let mut successor = binding();
        successor.host_nonce = "next".into();
        successor.host_expires_unix = 400;
        bad_successor.new_binding = Some(successor);
        assert!(
            j.begin(bad_successor).is_err(),
            "begin must reject a successor binding outliving the record expiry"
        );
        // A journal file containing such a record must not load.
        let mut on_disk = record();
        on_disk.transition_id = "tr_on_disk_bad".into();
        on_disk.expires_unix = 250;
        let disk = Disk {
            version: VERSION,
            entries: BTreeMap::from([(on_disk.transition_id.clone(), on_disk)]),
        };
        std::fs::write(dir.path().join(FILE), serde_json::to_vec(&disk).unwrap()).unwrap();
        assert!(
            SessionTransitionJournal::open(dir.path()).is_err(),
            "open must refuse a journal with an inconsistent host-expiry bound"
        );
    }

    /// P0-A cross-field invariant: recovery derives terminality from `kind`
    /// (Close|Terminate) while the journal records it on `target.terminal`.
    /// A structurally valid record whose `kind` and `target.terminal`
    /// disagree would be replayed one way and receipted another; both shapes
    /// must be rejected by `begin`, `open`, and the read-only parser used by
    /// doctor (P1-F), never accepted as a provably-terminal or provably-
    /// non-terminal record.
    #[test]
    fn kind_terminal_mismatch_is_rejected_fail_closed() {
        let dir = tempdir().unwrap();
        let mut j = SessionTransitionJournal::open(dir.path()).unwrap();

        // Non-terminal kind (Renew) stamped terminal: recovery would replay
        // `renew` (non-terminal, expecting a successor binding) but
        // `mark_terminal_applied` would accept a terminal receipt with none.
        let mut nonterminal_kind_terminal = record();
        nonterminal_kind_terminal.transition_id = "tr_kind_terminal".into();
        nonterminal_kind_terminal.target.terminal = true;
        assert!(
            j.begin(nonterminal_kind_terminal).is_err(),
            "begin must reject a non-terminal kind marked terminal"
        );

        // Terminal kind (Close) stamped non-terminal: recovery would replay
        // `close` as a terminal mutation but `mark_applied` would demand a
        // successor binding.
        let mut terminal_kind_nonterminal = record();
        terminal_kind_nonterminal.transition_id = "tr_kind_nonterminal".into();
        terminal_kind_nonterminal.kind = TransitionKind::Close;
        terminal_kind_nonterminal.target.terminal = false;
        assert!(
            j.begin(terminal_kind_nonterminal).is_err(),
            "begin must reject a terminal kind marked non-terminal"
        );

        // A journal file containing such a record must not load, and the
        // read-only parser doctor uses must refuse it the same way.
        for (id, record) in [
            ("tr_disk_terminal".to_string(), {
                let mut r = record();
                r.transition_id = "tr_disk_terminal".into();
                r.target.terminal = true;
                r
            }),
            ("tr_disk_close".to_string(), {
                let mut r = record();
                r.transition_id = "tr_disk_close".into();
                r.kind = TransitionKind::Terminate;
                r.target.terminal = false;
                r
            }),
        ] {
            let disk = Disk {
                version: VERSION,
                entries: BTreeMap::from([(id.clone(), record)]),
            };
            let bytes = serde_json::to_vec(&disk).unwrap();
            assert!(
                parse_and_validate(&bytes).is_err(),
                "parse_and_validate must refuse kind/terminal mismatch {id}"
            );
            std::fs::write(dir.path().join(FILE), bytes).unwrap();
            assert!(
                SessionTransitionJournal::open(dir.path()).is_err(),
                "open must refuse kind/terminal mismatch {id}"
            );
        }
    }
}
