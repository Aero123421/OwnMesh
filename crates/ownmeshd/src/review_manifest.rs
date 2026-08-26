//! Durable, bounded E7 review-flow receipts.
//!
//! A review is an explicit snapshot of one workspace/repository and its
//! argv-only test requests. It never records a shell string, commit/push/merge
//! request, or unbounded diff/test output. Runtime wiring consumes this
//! manifest before running a review and pages the underlying bounded spools.

use ownmesh_exec::ExecutablePin;
use ownmesh_ipc::{
    atomic_write_owner_only, prepare_owner_only_state_dir, read_owner_only_file_bounded,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const VERSION: u32 = 1;
const MAX_BYTES: usize = 256 * 1024;
const MAX_REVIEWS: usize = 64;
const MAX_TESTS: usize = 16;
const MAX_ARGV_ITEMS: usize = 64;
const MAX_ARG_BYTES: usize = 8 * 1024;
const FILE: &str = "review-manifests.json";
const MAX_RESULT_BYTES: usize = 512 * 1024;
const MAX_RESULT_FILE_BYTES: usize = 900 * 1024;

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
    /// The non-canonical executable path used for spawning when its filename
    /// has proxy semantics. Legacy manifests omit this and require program=pin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_pin: Option<ExecutablePin>,
    pub pin: ExecutablePin,
}

/// Optional primary agent/direct command; shell strings are intentionally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewCommand {
    pub program: String,
    pub args: Vec<String>,
    pub timeout_ms: u64,
    /// See [`TestRequest::invocation_pin`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_pin: Option<ExecutablePin>,
    pub pin: ExecutablePin,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<ReviewCommand>,
    pub tests: Vec<TestRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_operation_id: Option<String>,
    /// Exact control-plane payload binding; never supplied by the review DTO.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_payload_hash: Option<String>,
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

/// Typed, owner-only bounded output spool. Command and each test retain their
/// own stdout/stderr chunks; callers page with absolute byte cursors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultKind {
    GitStatus,
    GitDiff,
    CommandStdout,
    CommandStderr,
    TestStdout,
    TestStderr,
    System,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResultChunk {
    pub kind: ResultKind,
    pub test_index: Option<u8>,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewResultPage {
    pub base_cursor: u64,
    pub next_cursor: u64,
    pub total_bytes: u64,
    pub truncated: bool,
    pub sha256: String,
    pub chunks: Vec<ReviewResultChunk>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultDisk {
    version: u32,
    expires_unix: i64,
    chunks: Vec<ReviewResultChunk>,
}
pub struct ReviewResultStore {
    dir: PathBuf,
}
impl ReviewResultStore {
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, String> {
        let dir = dir.as_ref().to_path_buf();
        prepare_owner_only_state_dir(&dir).map_err(|e| format!("prepare review results: {e}"))?;
        Ok(Self { dir })
    }
    pub fn write(
        &self,
        review_id: &str,
        expires_unix: i64,
        chunks: Vec<ReviewResultChunk>,
    ) -> Result<(), String> {
        if !valid_review_id(review_id)
            || chunks.len() > 64
            || chunks.iter().any(|chunk| {
                chunk.bytes.len() > 64 * 1024
                    || chunk.test_index.is_some_and(|i| i as usize >= MAX_TESTS)
                    || !kind_index_valid(chunk)
            })
        {
            return Err("invalid bounded review result chunks".into());
        }
        let total: usize = chunks.iter().map(|chunk| chunk.bytes.len()).sum();
        if total > MAX_RESULT_BYTES {
            return Err("review result aggregate cap exceeded".into());
        }
        let raw = serde_json::to_vec(&ResultDisk {
            version: VERSION,
            expires_unix,
            chunks,
        })
        .map_err(|e| e.to_string())?;
        if raw.len() > MAX_RESULT_FILE_BYTES {
            return Err("encoded review result cap exceeded".into());
        }
        atomic_write_owner_only(&self.dir.join(format!("{review_id}.json")), &raw)
            .map_err(|e| format!("persist review result: {e}"))
    }
    pub fn page(
        &self,
        review_id: &str,
        cursor: u64,
        max_bytes: usize,
        now_unix: i64,
    ) -> Result<ReviewResultPage, String> {
        if !valid_review_id(review_id) {
            return Err("invalid review id".into());
        }
        let path = self.dir.join(format!("{review_id}.json"));
        let raw = read_owner_only_file_bounded(&path, MAX_RESULT_FILE_BYTES)
            .map_err(|e| format!("read review result: {e}"))?;
        let disk: ResultDisk =
            serde_json::from_slice(&raw).map_err(|e| format!("parse review result: {e}"))?;
        if disk.version != VERSION || disk.expires_unix < now_unix {
            return Err("expired or invalid review result".into());
        }
        if disk.chunks.len() > 64
            || disk.chunks.iter().any(|chunk| {
                chunk.bytes.len() > 64 * 1024
                    || chunk.test_index.is_some_and(|i| i as usize >= MAX_TESTS)
                    || !kind_index_valid(chunk)
            })
        {
            return Err("invalid typed review result".into());
        }
        let total_usize: usize = disk.chunks.iter().map(|chunk| chunk.bytes.len()).sum();
        if total_usize > MAX_RESULT_BYTES {
            return Err("oversized review result".into());
        }
        let total = total_usize as u64;
        if cursor > total {
            return Err("future review cursor".into());
        }
        let cap = max_bytes.clamp(1, 64 * 1024);
        let mut remaining = cap;
        let mut offset = 0usize;
        let mut chunks = Vec::new();
        for chunk in &disk.chunks {
            let chunk_end = offset + chunk.bytes.len();
            if cursor as usize >= chunk_end {
                offset = chunk_end;
                continue;
            }
            if remaining == 0 {
                break;
            }
            let start = (cursor as usize).saturating_sub(offset);
            let take = remaining.min(chunk.bytes.len() - start);
            chunks.push(ReviewResultChunk {
                kind: chunk.kind.clone(),
                test_index: chunk.test_index,
                bytes: chunk.bytes[start..start + take].to_vec(),
            });
            remaining -= take;
            offset = chunk_end;
        }
        let end = cursor + (cap - remaining) as u64;
        let canonical = serde_json::to_vec(&disk.chunks).map_err(|e| e.to_string())?;
        let sha256 = format!("{:x}", Sha256::digest(canonical));
        Ok(ReviewResultPage {
            base_cursor: cursor,
            next_cursor: end,
            total_bytes: total,
            truncated: end < total,
            sha256,
            chunks,
        })
    }
}

fn valid_review_id(id: &str) -> bool {
    id.len() <= 128
        && id.starts_with("rev_")
        && id
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
}
fn kind_index_valid(chunk: &ReviewResultChunk) -> bool {
    matches!(chunk.kind, ResultKind::TestStdout | ResultKind::TestStderr)
        == chunk.test_index.is_some()
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

    #[allow(dead_code)]
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

    /// Atomically record a terminal phase and the digest of its already-durable
    /// result spool. The spool is written first; a crash can leave `Running`,
    /// but can never claim a terminal digest for unwritten bytes.
    pub fn finish(
        &mut self,
        id: &str,
        phase: ReviewPhase,
        result_sha256: String,
    ) -> Result<ReviewManifest, String> {
        if !matches!(
            phase,
            ReviewPhase::Completed | ReviewPhase::Failed | ReviewPhase::Cancelled
        ) || result_sha256.len() != 64
            || !result_sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err("invalid terminal review result".into());
        }
        let entry = self.entries.get(id).ok_or("review manifest not found")?;
        if entry.phase != ReviewPhase::Running {
            return Err("review is not running".into());
        }
        let mut candidate = self.entries.clone();
        let out = candidate.get_mut(id).ok_or("review manifest not found")?;
        out.phase = phase;
        out.result_sha256 = Some(result_sha256);
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
    if m.remote_payload_hash.as_deref().is_some_and(|digest| {
        digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err("invalid review payload digest".into());
    }
    if m.tests.len() > MAX_TESTS {
        return Err("review test count exceeds cap".into());
    }
    if let Some(command) = &m.command {
        validate_command(&command.program, &command.args, command.timeout_ms)?;
        validate_pin(&command.pin)?;
        if let Some(invocation_pin) = &command.invocation_pin {
            validate_pin(invocation_pin)?;
            if command.program != invocation_pin.path {
                return Err("review command invocation/pin mismatch".into());
            }
        } else if command.program != command.pin.path {
            return Err("review command program/pin mismatch".into());
        }
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
        validate_pin(&test.pin)?;
        if let Some(invocation_pin) = &test.invocation_pin {
            validate_pin(invocation_pin)?;
            if test.program != invocation_pin.path {
                return Err("review test invocation/pin mismatch".into());
            }
        } else if test.program != test.pin.path {
            return Err("review test program/pin mismatch".into());
        }
    }
    Ok(())
}

fn validate_command(program: &str, args: &[String], timeout_ms: u64) -> Result<(), String> {
    if program.is_empty()
        || program.len() > MAX_ARG_BYTES
        || program.chars().any(char::is_control)
        || args.len() > MAX_ARGV_ITEMS
        || !(1..=300_000).contains(&timeout_ms)
        || args
            .iter()
            .any(|arg| arg.len() > MAX_ARG_BYTES || arg.chars().any(char::is_control))
    {
        return Err("invalid argv-only review command".into());
    }
    Ok(())
}
fn validate_pin(pin: &ExecutablePin) -> Result<(), String> {
    if !Path::new(&pin.path).is_absolute()
        || pin.len == 0
        || pin.content_sha256.len() != 64
        || !pin
            .content_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || pin.policy_kind != "structured"
    {
        return Err("invalid review executable pin".into());
    }
    Ok(())
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
    fn pin() -> ExecutablePin {
        ExecutablePin {
            path: std::env::current_exe()
                .unwrap()
                .to_string_lossy()
                .into_owned(),
            content_sha256: "a".repeat(64),
            len: 1,
            device: None,
            inode: None,
            path_device: None,
            path_inode: None,
            link_target: None,
            policy_kind: "structured".into(),
        }
    }
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
            command: None,
            tests: vec![TestRequest {
                program: pin().path.clone(),
                args: vec!["test".into()],
                timeout_ms: 60_000,
                invocation_pin: None,
                pin: pin(),
            }],
            remote_operation_id: None,
            remote_payload_hash: None,
            status_cursor: 0,
            diff_cursor: 0,
            result_sha256: None,
            created_unix: 10,
            expires_unix: 100,
        }
    }
    #[test]
    fn durable_idempotent_and_phase_bound() {
        let dir = tempdir().unwrap();
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
    #[test]
    fn pin_substitution_and_uppercase_digest_reject() {
        let mut m = manifest();
        m.tests[0].program = "C:/substituted.exe".into();
        assert!(validate(&m).is_err());
        let mut m = manifest();
        m.tests[0].pin.content_sha256 = "A".repeat(64);
        assert!(validate(&m).is_err());
        let mut m = manifest();
        m.tests[0].invocation_pin = Some(pin());
        m.tests[0].program = "C:/substituted.exe".into();
        assert!(validate(&m).is_err());
    }
    #[test]
    fn result_spool_pages_and_rejects_future_cursor() {
        let dir = tempdir().unwrap();
        let store = ReviewResultStore::open(dir.path()).unwrap();
        store
            .write(
                "rev_1",
                100,
                vec![ReviewResultChunk {
                    kind: ResultKind::TestStdout,
                    test_index: Some(0),
                    bytes: b"abcdef".to_vec(),
                }],
            )
            .unwrap();
        let page = store.page("rev_1", 0, 3, 10).unwrap();
        assert_eq!(page.next_cursor, 3);
        assert!(page.truncated);
        assert!(store.page("rev_1", 7, 3, 10).is_err());
    }
}
