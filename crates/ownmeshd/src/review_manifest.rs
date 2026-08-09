//! Durable, bounded E7 review-flow receipts.
//!
//! A review is an explicit snapshot of one workspace/repository and its
//! argv-only test requests. It never records a shell string, commit/push/merge
//! request, or unbounded diff/test output. Runtime wiring consumes this
//! manifest before running a review and pages the underlying bounded spools.

#![allow(dead_code)] // Runtime review RPC wiring follows this durable substrate.

use ownmesh_ipc::{
    atomic_write_owner_only, prepare_owner_only_state_dir, read_owner_only_file_bounded,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const VERSION: u32 = 1;
const MAX_BYTES: usize = 256 * 1024;
const MAX_REVIEWS: usize = 64;
const MAX_TESTS: usize = 16;
const MAX_ARGV_ITEMS: usize = 64;
const MAX_ARG_BYTES: usize = 8 * 1024;
const FILE: &str = "review-manifests.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewPhase {
    Planned,
    Running,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestRequest {
    pub program: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewManifest {
    pub review_id: String,
    /// Verified Agent device id; never supplied by an MCP caller as authority.
    pub device_id: String,
    pub workspace_id: String,
    /// Canonical absolute repository root pinned before status/diff/test work.
    pub repo_root: String,
    /// Exact HEAD object ID observed at start; a changed ref makes results stale.
    pub head_oid: String,
    pub principal: String,
    pub phase: ReviewPhase,
    pub tests: Vec<TestRequest>,
    /// Absolute cursors and digests bind any paged result spool to this receipt.
    #[serde(default)]
    pub status_cursor: u64,
    #[serde(default)]
    pub diff_cursor: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_sha256: Option<String>,
    pub created_unix: i64,
    pub expires_unix: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disk {
    version: u32,
    entries: BTreeMap<String, ReviewManifest>,
}

/// Owner-only bounded manifest registry. It intentionally stores metadata only;
/// status/diff/test bytes stay in their own bounded spools.
pub struct ReviewManifestStore {
    dir: PathBuf,
    entries: BTreeMap<String, ReviewManifest>,
}

impl ReviewManifestStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, String> {
        let dir = dir.as_ref().to_path_buf();
        prepare_owner_only_state_dir(&dir).map_err(|e| format!("prepare review manifests: {e}"))?;
        let path = dir.join(FILE);
        if !path.exists() {
            return Ok(Self {
                dir,
                entries: BTreeMap::new(),
            });
        }
        let bytes = read_owner_only_file_bounded(&path, MAX_BYTES)
            .map_err(|e| format!("read review manifests: {e}"))?;
        let disk: Disk =
            serde_json::from_slice(&bytes).map_err(|e| format!("parse review manifests: {e}"))?;
        if disk.version != VERSION || disk.entries.len() > MAX_REVIEWS {
            return Err("invalid review manifest version or cap".into());
        }
        for (id, entry) in &disk.entries {
            if id != &entry.review_id {
                return Err("review manifest key/id mismatch".into());
            }
            validate(entry)?;
        }
        Ok(Self {
            dir,
            entries: disk.entries,
        })
    }

    pub fn begin(&mut self, manifest: ReviewManifest) -> Result<ReviewManifest, String> {
        validate(&manifest)?;
        match self.entries.get(&manifest.review_id) {
            Some(old) if old == &manifest => Ok(old.clone()),
            Some(_) => Err("review_id payload conflict".into()),
            None => {
                let mut candidate = self.entries.clone();
                // History cannot permanently brick new work; only expired,
                // terminal receipts are evicted. Live/planned work is never
                // silently discarded.
                candidate.retain(|_, entry| {
                    !(entry.expires_unix < manifest.created_unix
                        && matches!(
                            entry.phase,
                            ReviewPhase::Completed | ReviewPhase::Failed | ReviewPhase::Cancelled
                        ))
                });
                if candidate.len() >= MAX_REVIEWS {
                    return Err("review manifest quota reached".into());
                }
                candidate.insert(manifest.review_id.clone(), manifest.clone());
                self.persist_entries(&candidate)?;
                self.entries = candidate;
                Ok(manifest)
            }
        }
    }

    pub fn set_phase(&mut self, id: &str, phase: ReviewPhase) -> Result<ReviewManifest, String> {
        let entry = self.entries.get(id).ok_or("review manifest not found")?;
        let valid = entry.phase == phase
            || matches!(
                (entry.phase, phase),
                (
                    ReviewPhase::Planned,
                    ReviewPhase::Running | ReviewPhase::Cancelled
                ) | (
                    ReviewPhase::Running,
                    ReviewPhase::Completed | ReviewPhase::Failed | ReviewPhase::Cancelled
                )
            );
        if !valid {
            return Err("invalid review phase transition".into());
        }
        let mut candidate = self.entries.clone();
        let out = candidate.get_mut(id).ok_or("review manifest not found")?;
        out.phase = phase;
        let out = out.clone();
        self.persist_entries(&candidate)?;
        self.entries = candidate;
        Ok(out)
    }

    pub fn get(&self, id: &str) -> Option<&ReviewManifest> {
        self.entries.get(id)
    }
    fn persist_entries(&self, entries: &BTreeMap<String, ReviewManifest>) -> Result<(), String> {
        let raw = serde_json::to_vec(&Disk {
            version: VERSION,
            entries: entries.clone(),
        })
        .map_err(|e| e.to_string())?;
        if raw.len() > MAX_BYTES {
            return Err("review manifests exceed byte cap".into());
        }
        atomic_write_owner_only(&self.dir.join(FILE), &raw)
            .map_err(|e| format!("persist review manifests: {e}"))
    }
}

fn validate(m: &ReviewManifest) -> Result<(), String> {
    for (name, value, max) in [
        ("review_id", &m.review_id, 128),
        ("device_id", &m.device_id, 256),
        ("workspace_id", &m.workspace_id, 128),
        ("principal", &m.principal, 512),
        ("head_oid", &m.head_oid, 128),
    ] {
        if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
            return Err(format!("invalid {name}"));
        }
    }
    if !Path::new(&m.repo_root).is_absolute()
        || m.repo_root.len() > 4096
        || m.expires_unix <= m.created_unix
    {
        return Err("invalid review repository or ttl".into());
    }
    if m.result_sha256.as_deref().is_some_and(|digest| {
        digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    }) {
        return Err("invalid review result digest".into());
    }
    if m.tests.len() > MAX_TESTS {
        return Err("review test count exceeds cap".into());
    }
    for test in &m.tests {
        if test.program.is_empty()
            || test.program.len() > MAX_ARG_BYTES
            || test.program.chars().any(char::is_control)
            || test.args.len() > MAX_ARGV_ITEMS
            || !(1..=300_000).contains(&test.timeout_ms)
        {
            return Err("invalid argv-only review test".into());
        }
        if test
            .args
            .iter()
            .any(|arg| arg.len() > MAX_ARG_BYTES || arg.chars().any(char::is_control))
        {
            return Err("invalid review test argument".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> ReviewManifest {
        ReviewManifest {
            review_id: "rev_1".into(),
            device_id: "dev_test".into(),
            workspace_id: "ws_default".into(),
            repo_root: std::env::current_dir()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            head_oid: "a".repeat(40),
            principal: "client:remote:test".into(),
            phase: ReviewPhase::Planned,
            tests: vec![TestRequest {
                program: "cargo".into(),
                args: vec!["test".into()],
                timeout_ms: 60_000,
            }],
            status_cursor: 0,
            diff_cursor: 0,
            result_sha256: None,
            created_unix: 10,
            expires_unix: 100,
        }
    }
    #[test]
    fn durable_idempotent_and_phase_bound() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ReviewManifestStore::open(dir.path()).unwrap();
        let m = manifest();
        assert_eq!(store.begin(m.clone()).unwrap(), m);
        assert!(store
            .begin(ReviewManifest {
                head_oid: "b".repeat(40),
                ..m.clone()
            })
            .is_err());
        assert_eq!(
            store
                .set_phase("rev_1", ReviewPhase::Running)
                .unwrap()
                .phase,
            ReviewPhase::Running
        );
        assert!(store.set_phase("rev_1", ReviewPhase::Planned).is_err());
        assert_eq!(
            ReviewManifestStore::open(dir.path())
                .unwrap()
                .get("rev_1")
                .unwrap()
                .phase,
            ReviewPhase::Running
        );
    }
    #[test]
    fn argv_bounds_and_shell_like_control_reject() {
        let mut m = manifest();
        m.tests[0].args = vec!["ok\nno".into()];
        assert!(validate(&m).is_err());
        m.tests[0].args = vec!["x".repeat(MAX_ARG_BYTES + 1)];
        assert!(validate(&m).is_err());
    }
}
