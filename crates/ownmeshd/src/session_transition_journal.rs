//! Owner-only durable intent journal for sidecar controller transitions.
//!
//! A record is written before the sidecar mutation, updated with the returned
//! binding, then cleared only after the SessionManager persistence succeeds.
//! The next daemon can enumerate an `intent`/`applied` entry and retry its
//! idempotent transition without inventing a second host generation.

#![allow(dead_code)] // wired by the following runtime transition slice

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

/// Bounded durable transition journal rooted in a custody-attested directory.
pub struct SessionTransitionJournal {
    dir: PathBuf,
    entries: BTreeMap<String, TransitionRecord>,
}

impl SessionTransitionJournal {
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
        let disk: Disk =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse transition journal: {e}"))?;
        if disk.version != VERSION || disk.entries.len() > MAX_ENTRIES {
            return Err("invalid transition journal version or entry cap".into());
        }
        for (id, record) in &disk.entries {
            if id != &record.transition_id {
                return Err("transition journal key/id mismatch".into());
            }
            validate(record)?;
        }
        Ok(Self {
            dir,
            entries: disk.entries,
        })
    }

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
                self.persist()?;
                Ok(record)
            }
        }
    }
    pub fn mark_applied(&mut self, id: &str, binding: SidecarHostBinding) -> Result<(), String> {
        let record = self
            .entries
            .get_mut(id)
            .ok_or("transition journal record not found")?;
        if record.phase == TransitionPhase::Applied {
            if record.new_binding.as_ref() == Some(&binding) {
                return Ok(());
            }
            return Err("transition journal applied binding conflict".into());
        }
        record.phase = TransitionPhase::Applied;
        record.new_binding = Some(binding);
        validate(record)?;
        self.persist()
    }
    pub fn mark_terminal_applied(&mut self, id: &str) -> Result<(), String> {
        let record = self
            .entries
            .get_mut(id)
            .ok_or("transition journal record not found")?;
        if !record.target.terminal {
            return Err("non-terminal transition cannot record terminal receipt".into());
        }
        if record.phase == TransitionPhase::Applied {
            return if record.new_binding.is_none() {
                Ok(())
            } else {
                Err("terminal transition applied binding conflict".into())
            };
        }
        record.phase = TransitionPhase::Applied;
        record.new_binding = None;
        validate(record)?;
        self.persist()
    }
    pub fn clear(&mut self, id: &str) -> Result<(), String> {
        self.entries.remove(id);
        self.persist()
    }
    pub fn pending(&self) -> Vec<TransitionRecord> {
        self.entries.values().cloned().collect()
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
    use tempfile::tempdir;
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
                terminal: false,
            },
            new_binding: None,
            created_unix: 100,
            expires_unix: 250,
        }
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
}
