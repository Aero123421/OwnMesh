//! SYSTEM-owned durable replay fence for the Windows privileged broker.
//!
//! This deliberately uses the IPC crate's no-follow, owner-only Windows file
//! primitives.  The broker service runs as LocalSystem, so the ledger is
//! created only after SCM has started the service; an interactive installer
//! cannot pre-create or replace it.  A record left `reserved` by a crash is
//! never retried automatically.

use crate::windows::WindowsReplayLedger;
use ownmesh_broker_client::{operation_facts_digest, BrokerRequestV2};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

const VERSION: u32 = 1;
const MAX_BYTES: usize = 4 * 1024 * 1024;
const MAX_NONCE: usize = 256;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum State {
    Reserved,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Entry {
    digest: String,
    expires_at_unix: i64,
    state: State,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct File {
    version: u32,
    entries: BTreeMap<String, Entry>,
}

/// The replay ledger is owner-only at rest and has no best-effort recovery.
pub struct WindowsDurableReplayLedger {
    path: PathBuf,
    max_entries: usize,
    entries: BTreeMap<String, Entry>,
    failed_closed: bool,
}

impl WindowsDurableReplayLedger {
    pub fn open(path: impl Into<PathBuf>, max_entries: usize) -> Result<Self, String> {
        if max_entries == 0 {
            return Err("Windows replay ledger max entries must be positive".into());
        }
        let path = path.into();
        let parent = path.parent().ok_or("Windows replay ledger has no parent")?;
        ownmesh_ipc::prepare_owner_only_state_dir(parent)
            .map_err(|error| format!("Windows replay ledger parent custody: {error}"))?;
        let entries = if path.exists() {
            let bytes = ownmesh_ipc::read_owner_only_file_bounded(&path, MAX_BYTES)
                .map_err(|error| format!("Windows replay ledger custody/read: {error}"))?;
            let file: File = serde_json::from_slice(&bytes)
                .map_err(|error| format!("Windows replay ledger parse: {error}"))?;
            if file.version != VERSION || file.entries.len() > max_entries {
                return Err("Windows replay ledger version or entry count is invalid".into());
            }
            for (nonce, entry) in &file.entries {
                validate_entry(nonce, entry)?;
            }
            file.entries
        } else {
            BTreeMap::new()
        };
        let mut ledger = Self {
            path,
            max_entries,
            entries,
            failed_closed: false,
        };
        if !ledger.path.exists() {
            ledger.persist()?;
        }
        Ok(ledger)
    }

    fn persist(&mut self) -> Result<(), String> {
        if self.failed_closed {
            return Err("Windows replay ledger is unavailable after a failed write".into());
        }
        let bytes = serde_json::to_vec(&File {
            version: VERSION,
            entries: self.entries.clone(),
        })
        .map_err(|error| format!("serialize Windows replay ledger: {error}"))?;
        if bytes.len() > MAX_BYTES {
            self.failed_closed = true;
            return Err("Windows replay ledger exceeds byte ceiling".into());
        }
        if let Err(error) = ownmesh_ipc::atomic_write_owner_only(&self.path, &bytes) {
            self.failed_closed = true;
            return Err(format!("durably write Windows replay ledger: {error}"));
        }
        // Reopen via a pinned, no-follow owner-only handle before allowing a
        // spawn. This catches replacement/custody loss after publication.
        ownmesh_ipc::read_owner_only_file_bounded(&self.path, MAX_BYTES).map_err(|error| {
            self.failed_closed = true;
            format!("re-attest Windows replay ledger after write: {error}")
        })?;
        Ok(())
    }

    fn prune_completed(&mut self, now_unix: i64) {
        self.entries
            .retain(|_, entry| entry.state == State::Reserved || entry.expires_at_unix >= now_unix);
    }
}

impl WindowsReplayLedger for WindowsDurableReplayLedger {
    fn reserve(&mut self, request: &BrokerRequestV2, now_unix: i64) -> Result<(), String> {
        if self.failed_closed {
            return Err("Windows replay ledger is failed closed".into());
        }
        validate_request(request, now_unix)?;
        self.prune_completed(now_unix);
        if self.entries.contains_key(&request.nonce) {
            return Err("Windows replay nonce was already consumed".into());
        }
        if self.entries.len() >= self.max_entries {
            return Err("Windows replay ledger is full".into());
        }
        self.entries.insert(
            request.nonce.clone(),
            Entry {
                digest: operation_facts_digest(&request.facts),
                expires_at_unix: request.expires_at_unix,
                state: State::Reserved,
            },
        );
        self.persist()
    }

    fn complete(&mut self, nonce: &str, digest: &str) -> Result<(), String> {
        let Some(entry) = self.entries.get_mut(nonce) else {
            return Err("Windows replay completion lacks a reservation".into());
        };
        if entry.digest != digest {
            return Err("Windows replay completion digest differs from reservation".into());
        }
        entry.state = State::Completed;
        self.persist()
    }
}

fn validate_request(request: &BrokerRequestV2, now_unix: i64) -> Result<(), String> {
    if request.nonce.is_empty() || request.nonce.len() > MAX_NONCE || request.nonce.contains('\0') {
        return Err("Windows replay nonce is invalid".into());
    }
    if request.expires_at_unix < now_unix {
        return Err("Windows replay reservation is expired".into());
    }
    let digest = operation_facts_digest(&request.facts);
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
    {
        return Err("Windows replay digest is invalid".into());
    }
    Ok(())
}

fn validate_entry(nonce: &str, entry: &Entry) -> Result<(), String> {
    if nonce.is_empty()
        || nonce.len() > MAX_NONCE
        || nonce.contains('\0')
        || entry.digest.len() != 64
        || !entry
            .digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte.is_ascii_lowercase())
    {
        return Err("Windows replay ledger contains an invalid entry".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_broker_client::{ExecutablePinV2, OperationFactsV2};

    fn request(nonce: &str) -> BrokerRequestV2 {
        BrokerRequestV2 {
            protocol_version: 2,
            request_id: "request".into(),
            operation_id: "operation".into(),
            nonce: nonce.into(),
            issued_at_unix: 1,
            expires_at_unix: 100,
            facts: OperationFactsV2 {
                operation: "command".into(),
                remote_payload_sha256: "a".repeat(64),
                principal_id: "p".into(),
                tenant_id: "t".into(),
                principal_credential_generation: 1,
                timeout_ms: 1,
                max_output_bytes: 1,
                device_id: "d".into(),
                workspace_id: "w".into(),
                argv: vec!["x".into()],
                canonical_cwd: None,
                sanitized_env: BTreeMap::new(),
                executable: ExecutablePinV2 {
                    canonical_path: "x".into(),
                    image_sha256: "b".repeat(64),
                    image_len: 1,
                },
            },
            capability: None,
            mac: "m".into(),
        }
    }

    #[test]
    fn reserve_survives_restart_and_never_replays() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state").join("replay.json");
        let req = request("nonce");
        let mut ledger = WindowsDurableReplayLedger::open(&path, 4).unwrap();
        ledger.reserve(&req, 1).unwrap();
        drop(ledger);
        let mut reopened = WindowsDurableReplayLedger::open(&path, 4).unwrap();
        assert!(reopened.reserve(&req, 1).is_err());
    }
}
