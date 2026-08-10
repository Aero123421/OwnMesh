//! Bounded authenticated file-transfer primitives.
//!
//! This crate deliberately has no relay, LAN discovery, caller supplied consent,
//! or whole-file copy API.  A production caller authenticates a grant, pins both
//! workspaces with `ownmesh-fs`, then uses this core to move one checked chunk at
//! a time.  Destination path custody remains with that caller; `publish_part_no_replace`
//! only performs the final no-replace link after such custody has been established.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines,
    clippy::too_many_arguments
)]

use fs2::FileExt;
use ownmesh_fs::WorkspaceReadHandle;
use ownmesh_ipc::{
    atomic_write_owner_only, create_owner_only_file_new, open_owner_only_file_append,
    open_owner_only_file_append_linkable, open_owner_only_file_read, prepare_owner_only_state_dir,
    read_owner_only_file_bounded, remove_owner_only_file,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;

/// Maximum payload held by the transfer core at once.
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
const SHA256_HEX_LEN: usize = 64;
const JOURNAL_SCHEMA: u8 = 1;

/// Stable crate name used by diagnostics and tests.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Crate version string from Cargo package metadata.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Transfer failures are explicit and fail closed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransferError {
    #[error("legacy transfer surface is disabled")]
    LegacySurfaceDisabled,
    #[error("invalid transfer binding: {0}")]
    InvalidBinding(String),
    #[error("invalid transfer plan: {0}")]
    InvalidPlan(String),
    #[error("source changed while transfer was being prepared or read")]
    SourceChanged,
    #[error("source or destination custody is unavailable on this platform")]
    CustodyUnavailable,
    #[error("source exceeds the configured transfer quota")]
    QuotaExceeded,
    #[error("chunk exceeds the 64 KiB limit")]
    ChunkTooLarge,
    #[error("malformed chunk")]
    MalformedChunk,
    #[error("chunk hash mismatch")]
    ChunkHashMismatch,
    #[error("chunk sequence replayed")]
    Replay,
    #[error("chunk sequence or offset has a gap")]
    Gap,
    #[error("checked arithmetic overflow")]
    Overflow,
    #[error("final content hash mismatch")]
    HashMismatch,
    #[error("destination already exists")]
    DestinationExists,
    #[error("transfer is in a terminal state")]
    Terminal,
    #[error("transfer lease is held by another owner")]
    LeaseBusy,
    #[error("journal is corrupt or exceeds its byte budget")]
    CorruptJournal,
    #[error("journal quota exceeded")]
    JournalQuotaExceeded,
    #[error("journal lease or fence is stale")]
    StaleFence,
    #[error("io: {0}")]
    Io(String),
    #[error("sink: {0}")]
    Sink(String),
}

pub type TransferResult<T> = Result<T, TransferError>;

fn io_error(error: std::io::Error) -> TransferError {
    TransferError::Io(error.to_string())
}

fn open_owner_only_file_append_retry(path: &Path) -> TransferResult<File> {
    for _ in 0..200 {
        if let Ok(file) = open_owner_only_file_append(path) {
            return Ok(file);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(TransferError::CustodyUnavailable)
}

fn open_owner_only_file_read_retry(path: &Path) -> TransferResult<File> {
    for _ in 0..200 {
        if let Ok(file) = open_owner_only_file_read(path) {
            return Ok(file);
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(TransferError::CustodyUnavailable)
}

fn remove_owner_only_file_retry(path: &Path) -> TransferResult<()> {
    for _ in 0..200 {
        if remove_owner_only_file(path).is_ok() {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
    Err(TransferError::CustodyUnavailable)
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value)
        .map(|parsed| parsed.hyphenated().to_string() == value)
        .unwrap_or(false)
}

fn lease_record(plan_id: &str, expires_at_unix: u64) -> Vec<u8> {
    format!(
        "{plan_id}\n{expires_at_unix}\n{}\n",
        Uuid::new_v4().hyphenated()
    )
    .into_bytes()
}

fn parse_lease_expiry(bytes: &[u8], plan_id: &str) -> Option<u64> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split_terminator('\n');
    let record_plan = lines.next()?;
    let expiry = lines.next()?.parse::<u64>().ok()?;
    let nonce = lines.next()?;
    if record_plan != plan_id || !canonical_uuid(nonce) || lines.next().is_some() {
        return None;
    }
    (text == format!("{record_plan}\n{expiry}\n{nonce}\n")).then_some(expiry)
}

fn source_reservation_record(plan: &TransferPlan) -> Vec<u8> {
    format!(
        "{}\n{}\n{}\n{}\n",
        plan.id(),
        plan.grant().expires_at_unix,
        plan.size_bytes,
        Uuid::new_v4().hyphenated()
    )
    .into_bytes()
}

fn parse_source_reservation(bytes: &[u8], plan_id: &str) -> Option<SourceReservation> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.split_terminator('\n');
    let record_plan = lines.next()?;
    let expires_at_unix = lines.next()?.parse::<u64>().ok()?;
    let bytes = lines.next()?.parse::<u64>().ok()?;
    let nonce = lines.next()?;
    if record_plan != plan_id || !canonical_uuid(nonce) || lines.next().is_some() {
        return None;
    }
    (text == format!("{record_plan}\n{expires_at_unix}\n{bytes}\n{nonce}\n")).then_some(
        SourceReservation {
            expires_at_unix,
            bytes,
        },
    )
}

fn valid_id(value: &str, field: &str) -> TransferResult<()> {
    if value.is_empty() || value.len() > 256 || value.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(TransferError::InvalidBinding(field.into()));
    }
    Ok(())
}

fn validate_hash(value: &str, field: &str) -> TransferResult<()> {
    if value.len() != SHA256_HEX_LEN
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return Err(TransferError::InvalidPlan(field.into()));
    }
    Ok(())
}

fn validate_relative_path(value: &str, field: &str) -> TransferResult<()> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err(TransferError::InvalidBinding(field.into()));
    }
    let path = Path::new(value);
    if path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(TransferError::InvalidBinding(field.into()));
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn hash_reader(reader: &mut impl Read, max_bytes: u64) -> TransferResult<(u64, String)> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
    loop {
        let read = reader.read(&mut buffer).map_err(io_error)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(read).map_err(|_| TransferError::Overflow)?)
            .ok_or(TransferError::Overflow)?;
        if total > max_bytes {
            return Err(TransferError::QuotaExceeded);
        }
        hasher.update(&buffer[..read]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}

/// Identity and path facts authenticated by the control plane, not by a caller's
/// transport preference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferBinding {
    pub tenant_id: String,
    pub source_principal_id: String,
    pub destination_principal_id: String,
    pub source_device_id: String,
    pub destination_device_id: String,
    pub source_workspace_id: String,
    pub destination_workspace_id: String,
    pub source_relative_path: String,
    pub destination_relative_path: String,
}

impl TransferBinding {
    pub fn validate(&self) -> TransferResult<()> {
        for (value, name) in [
            (&self.tenant_id, "tenant_id"),
            (&self.source_principal_id, "source_principal_id"),
            (&self.destination_principal_id, "destination_principal_id"),
            (&self.source_device_id, "source_device_id"),
            (&self.destination_device_id, "destination_device_id"),
            (&self.source_workspace_id, "source_workspace_id"),
            (&self.destination_workspace_id, "destination_workspace_id"),
        ] {
            valid_id(value, name)?;
        }
        if self.source_device_id == self.destination_device_id
            && self.source_workspace_id == self.destination_workspace_id
            && self.source_relative_path == self.destination_relative_path
        {
            return Err(TransferError::InvalidBinding(
                "source and destination are identical".into(),
            ));
        }
        validate_relative_path(&self.source_relative_path, "source_relative_path")?;
        validate_relative_path(&self.destination_relative_path, "destination_relative_path")
    }
}

/// An authenticated control-plane authorization bound to the exact action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferGrant {
    pub grant_id: String,
    pub operation_id: String,
    /// SHA-256 of the canonical authorized action payload.
    pub payload_sha256: String,
    pub expires_at_unix: u64,
}

impl TransferGrant {
    pub fn validate(&self) -> TransferResult<()> {
        valid_id(&self.grant_id, "grant_id")?;
        valid_id(&self.operation_id, "operation_id")?;
        validate_hash(&self.payload_sha256, "grant payload_sha256")?;
        if self.expires_at_unix == 0 {
            return Err(TransferError::InvalidBinding("grant expiry".into()));
        }
        Ok(())
    }

    /// Verify this authenticated grant at a live side-effect boundary.
    pub fn validate_at(&self, now_unix: u64) -> TransferResult<()> {
        self.validate()?;
        if self.expires_at_unix <= now_unix {
            return Err(TransferError::InvalidPlan("expired transfer grant".into()));
        }
        Ok(())
    }
}

/// Limits fixed when an immutable plan is created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlanLimits {
    pub max_bytes: u64,
}

impl Default for PlanLimits {
    fn default() -> Self {
        Self {
            max_bytes: 5 * 1024 * 1024 * 1024,
        }
    }
}

/// Immutable transfer metadata. Fields are private so code cannot alter a plan
/// after the grant/content hash has been bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferPlan {
    id: String,
    binding: TransferBinding,
    grant: TransferGrant,
    size_bytes: u64,
    sha256: String,
    plan_sha256: String,
}

impl TransferPlan {
    /// Stream-hash an already custody-verified source handle and create its
    /// immutable plan. This never uses `read_to_end`, `fs::read`, or a path
    /// reopen after the workspace authority check.
    pub fn for_workspace_source(
        source: WorkspaceReadHandle,
        binding: TransferBinding,
        grant: TransferGrant,
        limits: PlanLimits,
        now_unix: u64,
    ) -> TransferResult<Self> {
        binding.validate()?;
        grant.validate()?;
        if grant.expires_at_unix <= now_unix || limits.max_bytes == 0 {
            return Err(TransferError::InvalidPlan(
                "expired grant or zero quota".into(),
            ));
        }
        let mut file = source.into_file();
        let (size_bytes, sha256) = hash_reader(&mut file, limits.max_bytes)?;
        if file.metadata().map_err(io_error)?.len() != size_bytes {
            return Err(TransferError::SourceChanged);
        }
        Self::from_verified(binding, grant, size_bytes, sha256)
    }

    pub fn from_verified(
        binding: TransferBinding,
        grant: TransferGrant,
        size_bytes: u64,
        sha256: String,
    ) -> TransferResult<Self> {
        binding.validate()?;
        grant.validate()?;
        validate_hash(&sha256, "content sha256")?;
        let mut canonical = String::new();
        for value in [
            &binding.tenant_id,
            &binding.source_principal_id,
            &binding.destination_principal_id,
            &binding.source_device_id,
            &binding.destination_device_id,
            &binding.source_workspace_id,
            &binding.destination_workspace_id,
            &binding.source_relative_path,
            &binding.destination_relative_path,
            &grant.grant_id,
            &grant.operation_id,
            &grant.payload_sha256,
            &size_bytes.to_string(),
            &sha256,
        ] {
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(value);
            canonical.push('|');
        }
        canonical.push_str(&grant.expires_at_unix.to_string());
        let plan_sha256 = hash_bytes(canonical.as_bytes());
        Ok(Self {
            id: format!("xfer_{}", &plan_sha256[..32]),
            binding,
            grant,
            size_bytes,
            sha256,
            plan_sha256,
        })
    }

    /// Validate a plan after deserialization before it is used at a side-effect
    /// boundary. This recomputes the immutable binding digest rather than
    /// trusting private serde fields.
    pub fn validate(&self) -> TransferResult<()> {
        let expected = Self::from_verified(
            self.binding.clone(),
            self.grant.clone(),
            self.size_bytes,
            self.sha256.clone(),
        )?;
        if self.id != expected.id || self.plan_sha256 != expected.plan_sha256 {
            return Err(TransferError::InvalidPlan("plan binding digest".into()));
        }
        Ok(())
    }

    /// Verify immutable metadata and that its authenticated grant is still live.
    pub fn validate_at(&self, now_unix: u64) -> TransferResult<()> {
        self.validate()?;
        self.grant.validate_at(now_unix)
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    #[must_use]
    pub fn binding(&self) -> &TransferBinding {
        &self.binding
    }
    #[must_use]
    pub fn grant(&self) -> &TransferGrant {
        &self.grant
    }
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
    #[must_use]
    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }
}

fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn validate_retained_file(file: &File) -> TransferResult<()> {
    let meta = file.metadata().map_err(io_error)?;
    if !meta.is_file() || is_reparse_or_symlink(&meta) {
        return Err(TransferError::CustodyUnavailable);
    }
    Ok(())
}

/// A bounded binary frame. Header: sequence (u64 BE), offset (u64 BE), length
/// (u32 BE), SHA-256 (32 bytes), then payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferChunk {
    pub sequence: u64,
    pub offset: u64,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

impl TransferChunk {
    pub fn new(sequence: u64, offset: u64, bytes: Vec<u8>) -> TransferResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES {
            return Err(TransferError::ChunkTooLarge);
        }
        let chunk = Self {
            sha256: hash_bytes(&bytes),
            sequence,
            offset,
            bytes,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn encode(&self) -> TransferResult<Vec<u8>> {
        self.validate()?;
        let length = u32::try_from(self.bytes.len()).map_err(|_| TransferError::ChunkTooLarge)?;
        let mut out = Vec::with_capacity(52 + self.bytes.len());
        out.extend_from_slice(&self.sequence.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&length.to_be_bytes());
        out.extend_from_slice(
            &hex::decode(&self.sha256).map_err(|_| TransferError::MalformedChunk)?,
        );
        out.extend_from_slice(&self.bytes);
        Ok(out)
    }

    pub fn decode(frame: &[u8]) -> TransferResult<Self> {
        if frame.len() < 52 {
            return Err(TransferError::MalformedChunk);
        }
        let sequence = u64::from_be_bytes(
            frame[0..8]
                .try_into()
                .map_err(|_| TransferError::MalformedChunk)?,
        );
        let offset = u64::from_be_bytes(
            frame[8..16]
                .try_into()
                .map_err(|_| TransferError::MalformedChunk)?,
        );
        let length = u32::from_be_bytes(
            frame[16..20]
                .try_into()
                .map_err(|_| TransferError::MalformedChunk)?,
        );
        let length = usize::try_from(length).map_err(|_| TransferError::MalformedChunk)?;
        if length == 0
            || length > MAX_CHUNK_BYTES
            || frame.len() != 52usize.checked_add(length).ok_or(TransferError::Overflow)?
        {
            return Err(TransferError::MalformedChunk);
        }
        let sha256 = hex::encode(&frame[20..52]);
        let chunk = Self {
            sequence,
            offset,
            bytes: frame[52..].to_vec(),
            sha256,
        };
        chunk.validate()?;
        Ok(chunk)
    }

    pub fn validate(&self) -> TransferResult<()> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_CHUNK_BYTES {
            return Err(TransferError::ChunkTooLarge);
        }
        validate_hash(&self.sha256, "chunk sha256")?;
        if self.sha256 != hash_bytes(&self.bytes) {
            return Err(TransferError::ChunkHashMismatch);
        }
        let _ = self
            .offset
            .checked_add(u64::try_from(self.bytes.len()).map_err(|_| TransferError::Overflow)?)
            .ok_or(TransferError::Overflow)?;
        Ok(())
    }
}

/// Reads an already-planned source in fixed, bounded chunks.
pub struct TransferSender {
    plan: TransferPlan,
    file: File,
    sequence: u64,
    offset: u64,
    remaining: u64,
    hasher: Sha256,
    done: bool,
}

impl TransferSender {
    fn from_retained_file(
        plan: TransferPlan,
        mut file: File,
        sequence: u64,
        offset: u64,
    ) -> TransferResult<Self> {
        plan.validate_at(now_unix())?;
        validate_retained_file(&file)?;
        if offset > plan.size_bytes {
            return Err(TransferError::Overflow);
        }
        let (size, digest) = hash_reader(&mut file, plan.size_bytes)?;
        if size != plan.size_bytes || digest != plan.sha256 {
            return Err(TransferError::SourceChanged);
        }
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let mut hasher = Sha256::new();
        let mut remaining_prefix = offset;
        let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
        while remaining_prefix != 0 {
            let want = usize::try_from(remaining_prefix.min(MAX_CHUNK_BYTES as u64))
                .map_err(|_| TransferError::Overflow)?;
            file.read_exact(&mut buffer[..want]).map_err(io_error)?;
            hasher.update(&buffer[..want]);
            remaining_prefix = remaining_prefix
                .checked_sub(u64::try_from(want).map_err(|_| TransferError::Overflow)?)
                .ok_or(TransferError::Overflow)?;
        }
        Ok(Self {
            remaining: plan
                .size_bytes
                .checked_sub(offset)
                .ok_or(TransferError::Overflow)?,
            plan,
            file,
            sequence,
            offset,
            hasher,
            done: false,
        })
    }

    pub fn next_chunk(&mut self) -> TransferResult<Option<TransferChunk>> {
        self.plan.validate_at(now_unix())?;
        if self.done {
            return Ok(None);
        }
        if self.remaining == 0 {
            self.done = true;
            if hex::encode(self.hasher.clone().finalize()) != self.plan.sha256 {
                return Err(TransferError::SourceChanged);
            }
            return Ok(None);
        }
        let expected = usize::try_from(self.remaining.min(MAX_CHUNK_BYTES as u64))
            .map_err(|_| TransferError::Overflow)?;
        let mut bytes = vec![0_u8; expected];
        self.file.read_exact(&mut bytes).map_err(|error| {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                TransferError::SourceChanged
            } else {
                io_error(error)
            }
        })?;
        self.hasher.update(&bytes);
        let next_remaining = self
            .remaining
            .checked_sub(u64::try_from(expected).map_err(|_| TransferError::Overflow)?)
            .ok_or(TransferError::Overflow)?;
        let chunk = TransferChunk::new(self.sequence, self.offset, bytes)?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(TransferError::Overflow)?;
        self.offset = self
            .offset
            .checked_add(u64::try_from(expected).map_err(|_| TransferError::Overflow)?)
            .ok_or(TransferError::Overflow)?;
        self.remaining = next_remaining;
        if self.remaining == 0 && hex::encode(self.hasher.clone().finalize()) != self.plan.sha256 {
            return Err(TransferError::SourceChanged);
        }
        Ok(Some(chunk))
    }
}

/// Durable transfer terminal/progress state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalState {
    Pending,
    Receiving,
    Cancelled,
    Failed,
    Completed,
    /// The destination was published no-replace and its exact immutable plan
    /// digest was durably receipted. This makes a reply-loss retry idempotent.
    Published,
}

impl JournalState {
    fn terminal(self) -> bool {
        matches!(
            self,
            Self::Cancelled | Self::Failed | Self::Completed | Self::Published
        )
    }
}

/// Owner-bound, bounded transfer state. It records only a contiguous ack, never
/// an unbounded list of chunks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransferJournal {
    schema: u8,
    plan_id: String,
    plan_sha256: String,
    owner_id: String,
    epoch: u64,
    fence: u64,
    state: JournalState,
    contiguous_ack: Option<u64>,
    bytes_received: u64,
    expires_at_unix: u64,
    #[serde(default)]
    published_size: Option<u64>,
    #[serde(default)]
    published_sha256: Option<String>,
}

impl TransferJournal {
    fn fresh(
        plan: &TransferPlan,
        owner_id: &str,
        epoch: u64,
        fence: u64,
        expires_at_unix: u64,
    ) -> TransferResult<Self> {
        valid_id(owner_id, "journal owner")?;
        if epoch == 0 || fence == 0 {
            return Err(TransferError::StaleFence);
        }
        Ok(Self {
            schema: JOURNAL_SCHEMA,
            plan_id: plan.id.clone(),
            plan_sha256: plan.plan_sha256.clone(),
            owner_id: owner_id.into(),
            epoch,
            fence,
            state: JournalState::Pending,
            contiguous_ack: None,
            bytes_received: 0,
            expires_at_unix,
            published_size: None,
            published_sha256: None,
        })
    }
    fn validate_for(&self, plan: &TransferPlan) -> TransferResult<()> {
        if self.schema != JOURNAL_SCHEMA
            || self.plan_id != plan.id
            || self.plan_sha256 != plan.plan_sha256
            || self.epoch == 0
            || self.fence == 0
        {
            return Err(TransferError::CorruptJournal);
        }
        match self.state {
            JournalState::Published
                if self.published_size == Some(plan.size_bytes)
                    && self.published_sha256.as_deref() == Some(plan.sha256.as_str()) => {}
            JournalState::Published => return Err(TransferError::CorruptJournal),
            _ if self.published_size.is_some() || self.published_sha256.is_some() => {
                return Err(TransferError::CorruptJournal)
            }
            _ => {}
        }
        Ok(())
    }
    #[must_use]
    pub const fn state(&self) -> JournalState {
        self.state
    }
    #[must_use]
    pub const fn contiguous_ack(&self) -> Option<u64> {
        self.contiguous_ack
    }
    #[must_use]
    pub const fn bytes_received(&self) -> u64 {
        self.bytes_received
    }
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }
    #[must_use]
    pub const fn fence(&self) -> u64 {
        self.fence
    }

    #[must_use]
    pub const fn published(&self) -> bool {
        matches!(self.state, JournalState::Published)
    }

    /// Convert a completed receiver journal into the durable publication
    /// receipt. The caller must first verify the pinned destination artifact.
    pub fn mark_published(&mut self, plan: &TransferPlan) -> TransferResult<()> {
        if self.state != JournalState::Completed || self.bytes_received != plan.size_bytes {
            return Err(TransferError::Terminal);
        }
        self.state = JournalState::Published;
        self.published_size = Some(plan.size_bytes);
        self.published_sha256 = Some(plan.sha256.clone());
        self.validate_for(plan)
    }
}

/// Production senders emit exactly one full 64 KiB chunk until the final
/// chunk. This makes the relay's bounded `(next_sequence, next_offset)` pair
/// independently checkable without retaining an unbounded chunk history.
fn validate_room_cursor(
    plan: &TransferPlan,
    next_sequence: u64,
    next_offset: u64,
) -> TransferResult<()> {
    if next_offset > plan.size_bytes {
        return Err(TransferError::Gap);
    }
    let chunk_bytes = u64::try_from(MAX_CHUNK_BYTES).map_err(|_| TransferError::Overflow)?;
    if next_offset < plan.size_bytes && !next_offset.is_multiple_of(chunk_bytes) {
        return Err(TransferError::Gap);
    }
    let expected_sequence = if next_offset == 0 {
        0
    } else {
        next_offset
            .checked_add(chunk_bytes - 1)
            .ok_or(TransferError::Overflow)?
            / chunk_bytes
    };
    if next_sequence != expected_sequence {
        return Err(TransferError::Gap);
    }
    Ok(())
}

/// A sink receives exactly one bounded chunk per call. It must durably write a
/// chunk before returning success; the journal is advanced only afterwards.
pub trait ChunkSink {
    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String>;
    fn finalize(&mut self) -> Result<(), String>;
    fn cancel(&mut self) -> Result<(), String>;
}

/// One-in-flight receiver. `receive` is synchronous: the next chunk cannot be
/// accepted until the sink has acknowledged the previous one.
pub struct TransferReceiver {
    plan: TransferPlan,
    journal: TransferJournal,
    next_sequence: u64,
    next_offset: u64,
    hasher: Sha256,
    in_flight: bool,
}

impl TransferReceiver {
    pub fn new(
        plan: TransferPlan,
        owner_id: &str,
        epoch: u64,
        fence: u64,
        expires_at_unix: u64,
    ) -> TransferResult<Self> {
        plan.validate_at(now_unix())?;
        let journal = TransferJournal::fresh(&plan, owner_id, epoch, fence, expires_at_unix)?;
        Ok(Self {
            plan,
            journal,
            next_sequence: 0,
            next_offset: 0,
            hasher: Sha256::new(),
            in_flight: false,
        })
    }

    /// Rebuild the rolling hash from a bounded prefix (normally the private
    /// `.part` file) before accepting the next resumed chunk.
    pub fn resume_from_reader(
        plan: TransferPlan,
        journal: TransferJournal,
        reader: &mut impl Read,
    ) -> TransferResult<Self> {
        plan.validate_at(now_unix())?;
        journal.validate_for(&plan)?;
        if journal.state.terminal() {
            return Err(TransferError::Terminal);
        }
        let (bytes, _digest) = hash_reader(reader, plan.size_bytes)?;
        if bytes != journal.bytes_received {
            return Err(TransferError::CorruptJournal);
        }
        let mut hasher = Sha256::new();
        // Hash state cannot be serialized safely; stream the prefix a second time
        // only when the reader is seekable in the concrete custody adapter.
        // For generic readers, use a verified empty prefix or reject non-empty resume.
        if bytes != 0 {
            return Err(TransferError::InvalidPlan(
                "resume requires a seekable custody reader".into(),
            ));
        }
        hasher.update([]);
        let next_sequence = match journal.contiguous_ack {
            Some(ack) => ack.checked_add(1).ok_or(TransferError::Overflow)?,
            None => 0,
        };
        Ok(Self {
            plan,
            next_sequence,
            next_offset: journal.bytes_received,
            journal,
            hasher,
            in_flight: false,
        })
    }

    /// Resume specifically from the private part file without buffering it.
    pub fn resume_from_part(
        plan: TransferPlan,
        journal: TransferJournal,
        part: &Path,
    ) -> TransferResult<Self> {
        plan.validate_at(now_unix())?;
        let mut file =
            open_owner_only_file_read(part).map_err(|_| TransferError::CustodyUnavailable)?;
        let bytes = file.metadata().map_err(io_error)?.len();
        if bytes != journal.bytes_received {
            return Err(TransferError::CorruptJournal);
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
        loop {
            let count = file.read(&mut buffer).map_err(io_error)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        journal.validate_for(&plan)?;
        if journal.state.terminal() {
            return Err(TransferError::Terminal);
        }
        let next_sequence = match journal.contiguous_ack {
            Some(ack) => ack.checked_add(1).ok_or(TransferError::Overflow)?,
            None => 0,
        };
        Ok(Self {
            plan,
            next_sequence,
            next_offset: journal.bytes_received,
            journal,
            hasher,
            in_flight: false,
        })
    }

    pub fn receive(
        &mut self,
        sink: &mut impl ChunkSink,
        chunk: TransferChunk,
    ) -> TransferResult<()> {
        self.plan.validate_at(now_unix())?;
        if self.journal.state.terminal() || self.in_flight {
            return Err(TransferError::Terminal);
        }
        chunk.validate()?;
        if chunk.sequence < self.next_sequence || chunk.offset < self.next_offset {
            return Err(TransferError::Replay);
        }
        if chunk.sequence != self.next_sequence || chunk.offset != self.next_offset {
            return Err(TransferError::Gap);
        }
        let length = u64::try_from(chunk.bytes.len()).map_err(|_| TransferError::Overflow)?;
        let end = chunk
            .offset
            .checked_add(length)
            .ok_or(TransferError::Overflow)?;
        if end > self.plan.size_bytes {
            return Err(TransferError::Overflow);
        }
        self.in_flight = true;
        if let Err(error) = sink.write_chunk(chunk.offset, &chunk.bytes) {
            self.in_flight = false;
            let _ = sink.cancel();
            self.journal.state = JournalState::Failed;
            return Err(TransferError::Sink(error));
        }
        self.hasher.update(&chunk.bytes);
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(TransferError::Overflow)?;
        self.next_offset = end;
        self.journal.contiguous_ack = Some(chunk.sequence);
        self.journal.bytes_received = end;
        self.journal.state = JournalState::Receiving;
        self.in_flight = false;
        if end == self.plan.size_bytes {
            if hex::encode(self.hasher.clone().finalize()) != self.plan.sha256 {
                let _ = sink.cancel();
                self.journal.state = JournalState::Failed;
                return Err(TransferError::HashMismatch);
            }
            if let Err(error) = sink.finalize() {
                let _ = sink.cancel();
                self.journal.state = JournalState::Failed;
                return Err(TransferError::Sink(error));
            }
            self.journal.state = JournalState::Completed;
        }
        Ok(())
    }

    /// Complete a verified empty artifact without manufacturing a zero-length
    /// chunk. The private sink is finalized before the completed journal can
    /// be persisted by the caller.
    pub fn complete_empty(&mut self, sink: &mut impl ChunkSink) -> TransferResult<()> {
        self.plan.validate_at(now_unix())?;
        if self.plan.size_bytes != 0
            || self.journal.state.terminal()
            || self.journal.bytes_received != 0
        {
            return Err(TransferError::InvalidPlan(
                "empty completion binding".into(),
            ));
        }
        if hex::encode(self.hasher.clone().finalize()) != self.plan.sha256 {
            self.journal.state = JournalState::Failed;
            return Err(TransferError::HashMismatch);
        }
        if let Err(error) = sink.finalize() {
            let _ = sink.cancel();
            self.journal.state = JournalState::Failed;
            return Err(TransferError::Sink(error));
        }
        self.journal.state = JournalState::Completed;
        Ok(())
    }

    pub fn cancel(&mut self, sink: &mut impl ChunkSink) -> TransferResult<()> {
        self.plan.validate_at(now_unix())?;
        if self.journal.state.terminal() {
            return Err(TransferError::Terminal);
        }
        sink.cancel().map_err(TransferError::Sink)?;
        self.journal.state = JournalState::Cancelled;
        Ok(())
    }

    #[must_use]
    pub fn journal(&self) -> &TransferJournal {
        &self.journal
    }

    /// Snapshot suitable for an owner-only durable journal write or a restart.
    #[must_use]
    pub fn journal_snapshot(&self) -> TransferJournal {
        self.journal.clone()
    }
}

/// Journal storage limits; both count and JSON byte size are capped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalLimits {
    pub max_journals: usize,
    pub max_bytes: usize,
    /// Maximum number of retained immutable source snapshots.
    pub max_snapshots: usize,
    /// Aggregate byte ceiling for retained immutable source snapshots.
    pub max_snapshot_bytes: u64,
    /// Maximum number of immutable plan records, including source-only retries.
    pub max_plans: usize,
    /// Aggregate byte ceiling for immutable plan records.
    pub max_plan_bytes: usize,
}
impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            max_journals: 1024,
            max_bytes: 16 * 1024,
            max_snapshots: 64,
            max_snapshot_bytes: 10 * 1024 * 1024 * 1024,
            max_plans: 256,
            max_plan_bytes: 1024 * 1024,
        }
    }
}

/// A process-local lease backed by an owner-only lock file. It prevents two
/// local writers from advancing a journal simultaneously and expires safely.
pub struct JournalLease {
    plan_id: String,
    path: PathBuf,
    store_lock_path: PathBuf,
    body: Vec<u8>,
}

struct SourceReservation {
    expires_at_unix: u64,
    bytes: u64,
}
impl Drop for JournalLease {
    fn drop(&mut self) {
        // A stale holder must never unlink a newly acquired lease. Serialize
        // release with stale-lock replacement and remove only our exact nonce.
        let Ok(store_lock) = open_owner_only_file_append(&self.store_lock_path) else {
            return;
        };
        if FileExt::try_lock_exclusive(&store_lock).is_err() {
            return;
        }
        let is_ours =
            read_owner_only_file_bounded(&self.path, 512).is_ok_and(|current| current == self.body);
        if is_ours {
            let _ = remove_owner_only_file(&self.path);
        }
        let _ = FileExt::unlock(&store_lock);
    }
}

/// Owner-only durable journal directory. Each mutation uses the custody-hardened
/// atomic write primitive from `ownmesh-ipc`.
#[derive(Clone)]
pub struct JournalStore {
    root: PathBuf,
    limits: JournalLimits,
}

/// Held OS-level lock for mutations whose admission depends on aggregate
/// directory counts or byte budgets. Cloned stores and separate processes
/// therefore cannot both observe spare capacity and over-admit state.
struct StoreLock {
    file: File,
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

impl JournalStore {
    pub fn open(root: impl Into<PathBuf>, limits: JournalLimits) -> TransferResult<Self> {
        if limits.max_journals == 0
            || limits.max_bytes < 512
            || limits.max_snapshots == 0
            || limits.max_snapshot_bytes == 0
            || limits.max_plans == 0
            || limits.max_plan_bytes < 512
        {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let root = root.into();
        prepare_owner_only_state_dir(&root).map_err(|_| TransferError::CustodyUnavailable)?;
        let store = Self { root, limits };
        store.cleanup_expired(now_unix())?;
        Ok(store)
    }
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
    fn path(&self, plan_id: &str, suffix: &str) -> TransferResult<PathBuf> {
        if !plan_id.starts_with("xfer_")
            || plan_id.len() != 37
            || !plan_id[5..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err(TransferError::InvalidPlan("plan id".into()));
        }
        Ok(self.root.join(format!(".{plan_id}{suffix}")))
    }

    fn part_path(&self, plan_id: &str, epoch: u64) -> TransferResult<PathBuf> {
        if epoch == 0 {
            return Err(TransferError::StaleFence);
        }
        self.path(plan_id, &format!(".{epoch}.part"))
    }

    fn generation_parts(&self, plan_id: &str) -> TransferResult<Vec<(u64, PathBuf)>> {
        let prefix = format!(".{plan_id}.");
        let mut parts = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
                continue;
            };
            let Some(epoch) = name
                .strip_prefix(&prefix)
                .and_then(|value| value.strip_suffix(".part"))
                .and_then(|value| value.parse::<u64>().ok())
            else {
                continue;
            };
            if epoch == 0 || self.part_path(plan_id, epoch)? != path {
                return Err(TransferError::CustodyUnavailable);
            }
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
                return Err(TransferError::CustodyUnavailable);
            }
            parts.push((epoch, path));
        }
        parts.sort_by_key(|(epoch, _)| *epoch);
        Ok(parts)
    }

    fn lock_store(&self) -> TransferResult<StoreLock> {
        self.lock_store_with_attempts(20)
    }

    fn lock_store_with_attempts(&self, attempts: usize) -> TransferResult<StoreLock> {
        let path = self.root.join(".store.lock");
        if !path.exists() {
            // Creation races are harmless: the winner creates the owner-only
            // inode and every contender verifies it before opening it.
            let _ = create_owner_only_file_new(&path, b"");
        }
        let file =
            open_owner_only_file_append(&path).map_err(|_| TransferError::CustodyUnavailable)?;
        // Snapshot staging releases this lock before copying bytes. Use only a
        // small bounded retry window for those short reservation transactions;
        // never block an IPC/cleanup worker behind a multi-gigabyte copy.
        for _ in 0..attempts {
            if FileExt::try_lock_exclusive(&file).is_ok() {
                return Ok(StoreLock { file });
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        Err(TransferError::LeaseBusy)
    }

    fn snapshot_usage(&self) -> TransferResult<(usize, u64)> {
        let mut count = 0_usize;
        let mut bytes = 0_u64;
        for entry in fs::read_dir(&self.root).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(".xfer_") {
                continue;
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(io_error)?;
            if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
                return Err(TransferError::CustodyUnavailable);
            }
            let Some(name) = name.strip_prefix('.') else {
                continue;
            };
            let reserved = name.strip_suffix(".source.reserve");
            let source = name.strip_suffix(".source");
            let accounted_bytes = if let Some(plan_id) = reserved {
                if self.path(plan_id, ".source.reserve")? != entry.path() {
                    continue;
                }
                let record = read_owner_only_file_bounded(&entry.path(), 512)
                    .map_err(|_| TransferError::CustodyUnavailable)?;
                parse_source_reservation(&record, plan_id)
                    .ok_or(TransferError::CustodyUnavailable)?
                    .bytes
            } else if let Some(plan_id) = source {
                if self.path(plan_id, ".source")? != entry.path() {
                    continue;
                }
                // A source reservation is authoritative while copy is in
                // progress; the partial file must not count a second time.
                if self.path(plan_id, ".source.reserve")?.exists() {
                    continue;
                }
                metadata.len()
            } else {
                continue;
            };
            count = count.checked_add(1).ok_or(TransferError::Overflow)?;
            bytes = bytes
                .checked_add(accounted_bytes)
                .ok_or(TransferError::Overflow)?;
        }
        Ok((count, bytes))
    }

    fn ensure_snapshot_capacity(&self, additional_bytes: u64) -> TransferResult<()> {
        let (count, bytes) = self.snapshot_usage()?;
        if count >= self.limits.max_snapshots
            || bytes
                .checked_add(additional_bytes)
                .ok_or(TransferError::Overflow)?
                > self.limits.max_snapshot_bytes
        {
            return Err(TransferError::JournalQuotaExceeded);
        }
        Ok(())
    }

    fn plan_usage(&self) -> TransferResult<(usize, usize)> {
        let mut count = 0_usize;
        let mut bytes = 0_usize;
        for entry in fs::read_dir(&self.root).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(plan_id) = name
                .strip_prefix('.')
                .and_then(|value| value.strip_suffix(".plan.json"))
            else {
                continue;
            };
            if self.path(plan_id, ".plan.json")? != path {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).map_err(io_error)?;
            if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
                return Err(TransferError::CustodyUnavailable);
            }
            let len = usize::try_from(metadata.len()).map_err(|_| TransferError::Overflow)?;
            count = count.checked_add(1).ok_or(TransferError::Overflow)?;
            bytes = bytes.checked_add(len).ok_or(TransferError::Overflow)?;
        }
        Ok((count, bytes))
    }
    pub fn acquire(
        &self,
        plan: &TransferPlan,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> TransferResult<JournalLease> {
        self.acquire_inner(plan, now_unix, expires_at_unix, None)
    }

    /// Acquire a destination mutation lease for an exact transfer fence.
    /// A strictly newer epoch/fence may retire a crash-or-disconnect orphaned
    /// lease even while the immutable transfer grant is still live. Every
    /// subsequent save verifies the lease nonce, so the retired holder cannot
    /// overwrite the newly claimed journal if it resumes late.
    pub fn acquire_for_fence(
        &self,
        plan: &TransferPlan,
        now_unix: u64,
        expires_at_unix: u64,
        epoch: u64,
        fence: u64,
    ) -> TransferResult<JournalLease> {
        if epoch == 0 || fence == 0 {
            return Err(TransferError::StaleFence);
        }
        self.acquire_inner(plan, now_unix, expires_at_unix, Some((epoch, fence)))
    }

    fn acquire_inner(
        &self,
        plan: &TransferPlan,
        now_unix: u64,
        expires_at_unix: u64,
        requested_fence: Option<(u64, u64)>,
    ) -> TransferResult<JournalLease> {
        let _store_lock = self.lock_store()?;
        plan.validate_at(now_unix)?;
        if expires_at_unix <= now_unix {
            return Err(TransferError::Terminal);
        }
        let path = self.path(plan.id(), ".lock")?;
        let body = lease_record(plan.id(), expires_at_unix);
        if create_owner_only_file_new(&path, &body).is_ok() {
            Ok(JournalLease {
                plan_id: plan.id.clone(),
                path,
                store_lock_path: self.root.join(".store.lock"),
                body,
            })
        } else {
            let existing =
                read_owner_only_file_bounded(&path, 512).map_err(|_| TransferError::LeaseBusy)?;
            let expired =
                parse_lease_expiry(&existing, plan.id()).is_some_and(|expiry| expiry <= now_unix);
            let fenced_reclaim = requested_fence.is_some_and(|(epoch, fence)| {
                match self.load(plan) {
                    Ok(Some(journal)) => epoch > journal.epoch && fence > journal.fence,
                    // No journal means the old process died before its first
                    // durable claim. Only a post-initial generation may retire it.
                    Ok(None) => epoch > 1 && fence > 1,
                    Err(_) => false,
                }
            });
            if !expired && !fenced_reclaim {
                return Err(TransferError::LeaseBusy);
            }
            remove_owner_only_file(&path).map_err(|_| TransferError::LeaseBusy)?;
            create_owner_only_file_new(&path, &body).map_err(|_| TransferError::LeaseBusy)?;
            Ok(JournalLease {
                plan_id: plan.id.clone(),
                path,
                store_lock_path: self.root.join(".store.lock"),
                body,
            })
        }
    }
    pub fn load(&self, plan: &TransferPlan) -> TransferResult<Option<TransferJournal>> {
        plan.validate_at(now_unix())?;
        let path = self.path(plan.id(), ".json")?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_owner_only_file_bounded(&path, self.limits.max_bytes)
            .map_err(|_| TransferError::CorruptJournal)?;
        let journal: TransferJournal =
            serde_json::from_slice(&bytes).map_err(|_| TransferError::CorruptJournal)?;
        journal.validate_for(plan)?;
        Ok(Some(journal))
    }

    /// Load progress only when the caller presents the currently held epoch and
    /// fence.  This is deliberately narrower than `load`: a stale retry must
    /// not append, publish, or cancel a newer receiver's part file.
    pub fn load_for_fence(
        &self,
        plan: &TransferPlan,
        epoch: u64,
        fence: u64,
    ) -> TransferResult<TransferJournal> {
        let journal = self.load(plan)?.ok_or(TransferError::Terminal)?;
        if journal.epoch != epoch || journal.fence != fence {
            return Err(TransferError::StaleFence);
        }
        Ok(journal)
    }

    /// Create or reopen the owner-only immutable source snapshot used by the
    /// live data plane. The caller provides a workspace-custody verified
    /// retained handle; it is copied in bounded chunks and checked against the
    /// immutable plan before any network chunk can be emitted. Later reads use
    /// only the retained owner-only file handle, never a pathname reopen.
    pub fn open_source_sender_at(
        &self,
        plan: TransferPlan,
        source: WorkspaceReadHandle,
        sequence: u64,
        offset: u64,
    ) -> TransferResult<TransferSender> {
        plan.validate_at(now_unix())?;
        let snapshot = self.path(plan.id(), ".source")?;
        let reservation = self.path(plan.id(), ".source.reserve")?;
        {
            let _store_lock = self.lock_store()?;
            self.cleanup_expired_unlocked(now_unix())?;
            if reservation.exists() {
                let record = read_owner_only_file_bounded(&reservation, 512)
                    .map_err(|_| TransferError::CustodyUnavailable)?;
                let active = parse_source_reservation(&record, plan.id())
                    .ok_or(TransferError::CustodyUnavailable)?;
                if active.expires_at_unix > now_unix() {
                    // Do not inspect/remove the matching partial snapshot: a
                    // concurrent owner has already reserved this exact plan.
                    return Err(TransferError::LeaseBusy);
                }
                remove_owner_only_file_retry(&reservation)?;
            }
            if snapshot.exists() {
                match open_owner_only_file_read(&snapshot)
                    .map_err(|_| TransferError::CustodyUnavailable)
                    .and_then(|file| {
                        TransferSender::from_retained_file(plan.clone(), file, sequence, offset)
                    }) {
                    Ok(sender) => return Ok(sender),
                    Err(_) => {
                        // A crash while staging can leave only a partial snapshot.
                        remove_owner_only_file(&snapshot)
                            .map_err(|_| TransferError::CustodyUnavailable)?;
                    }
                }
            }
            // Account for a plan-bound reservation before copy, then release
            // the store lock. Other plans can stage concurrently whenever the
            // aggregate quotas allow it; the exact reservation path makes a
            // duplicate staging attempt for this plan retryable instead.
            self.ensure_snapshot_capacity(plan.size_bytes)?;
            create_owner_only_file_new(&reservation, &source_reservation_record(&plan))
                .map_err(|_| TransferError::LeaseBusy)?;
            if create_owner_only_file_new(&snapshot, &[]).is_err() {
                let _ = remove_owner_only_file_retry(&reservation);
                return Err(TransferError::CustodyUnavailable);
            }
        }
        let mut input = source.into_file();
        let copy_result = (|| -> TransferResult<()> {
            let mut output = open_owner_only_file_append_retry(&snapshot)?;
            let mut hasher = Sha256::new();
            let mut total = 0_u64;
            let mut buffer = vec![0_u8; MAX_CHUNK_BYTES];
            loop {
                let read = input.read(&mut buffer).map_err(io_error)?;
                if read == 0 {
                    break;
                }
                total = total
                    .checked_add(u64::try_from(read).map_err(|_| TransferError::Overflow)?)
                    .ok_or(TransferError::Overflow)?;
                if total > plan.size_bytes {
                    return Err(TransferError::SourceChanged);
                }
                output.write_all(&buffer[..read]).map_err(io_error)?;
                hasher.update(&buffer[..read]);
            }
            output.sync_all().map_err(io_error)?;
            if total != plan.size_bytes || hex::encode(hasher.finalize()) != plan.sha256 {
                return Err(TransferError::SourceChanged);
            }
            Ok(())
        })();
        if let Err(error) = copy_result {
            let _ = remove_owner_only_file_retry(&snapshot);
            let _ = remove_owner_only_file_retry(&reservation);
            return Err(error);
        }
        {
            // Completion must converge a valid snapshot and its reservation.
            // The store lock is never held during the copy itself, so this
            // longer-but-bounded window only contends with short metadata
            // transactions or an exact cleanup scan.
            let _store_lock = self.lock_store_with_attempts(2_000)?;
            if let Err(error) = plan.validate_at(now_unix()) {
                let _ = remove_owner_only_file_retry(&snapshot);
                let _ = remove_owner_only_file_retry(&reservation);
                return Err(error);
            }
            remove_owner_only_file_retry(&reservation)?;
        }
        let file = open_owner_only_file_read_retry(&snapshot)?;
        TransferSender::from_retained_file(plan, file, sequence, offset)
    }

    /// Remove the exact owner-only source snapshot after terminal completion or
    /// cancellation. It cannot select a caller-controlled path.
    pub fn remove_source_snapshot(&self, plan: &TransferPlan) -> TransferResult<()> {
        let _store_lock = self.lock_store()?;
        self.remove_source_snapshot_unlocked(plan)
    }

    fn remove_source_snapshot_unlocked(&self, plan: &TransferPlan) -> TransferResult<()> {
        let path = self.path(plan.id(), ".source")?;
        if path.exists() {
            remove_owner_only_file(&path).map_err(|_| TransferError::CustodyUnavailable)?;
        }
        let reservation = self.path(plan.id(), ".source.reserve")?;
        if reservation.exists() {
            remove_owner_only_file(&reservation).map_err(|_| TransferError::CustodyUnavailable)?;
        }
        Ok(())
    }

    /// Remove exact source-side terminal state. Destination completion records
    /// intentionally remain for bounded artifact retrieval and reply-loss
    /// convergence; source snapshots/plans never need to survive terminal EOF
    /// or an authenticated source cancellation.
    pub fn remove_source_terminal_state(&self, plan: &TransferPlan) -> TransferResult<()> {
        let _store_lock = self.lock_store()?;
        self.remove_source_snapshot_unlocked(plan)?;
        let plan_path = self.path(plan.id(), ".plan.json")?;
        if plan_path.exists() {
            remove_owner_only_file(&plan_path).map_err(|_| TransferError::CustodyUnavailable)?;
        }
        Ok(())
    }

    /// Persist immutable plan metadata separately from progress so a restarted
    /// daemon can reopen only the exact authorized transfer id.
    pub fn save_plan(&self, plan: &TransferPlan) -> TransferResult<()> {
        let _store_lock = self.lock_store()?;
        plan.validate_at(now_unix())?;
        self.cleanup_expired_unlocked(now_unix())?;
        let bytes = serde_json::to_vec(plan)
            .map_err(|_| TransferError::InvalidPlan("serialize plan".into()))?;
        if bytes.len() > self.limits.max_bytes {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let path = self.path(plan.id(), ".plan.json")?;
        let existing_len = if path.exists() {
            read_owner_only_file_bounded(&path, self.limits.max_bytes)
                .map_err(|_| TransferError::CustodyUnavailable)?
                .len()
        } else {
            0
        };
        let (count, total_bytes) = self.plan_usage()?;
        if (existing_len == 0 && count >= self.limits.max_plans)
            || total_bytes
                .checked_sub(existing_len)
                .and_then(|used| used.checked_add(bytes.len()))
                .ok_or(TransferError::Overflow)?
                > self.limits.max_plan_bytes
        {
            return Err(TransferError::JournalQuotaExceeded);
        }
        atomic_write_owner_only(&path, &bytes).map_err(|_| TransferError::CustodyUnavailable)
    }

    /// Load and revalidate immutable plan metadata from owner-only storage.
    pub fn load_plan(&self, plan_id: &str, now_unix: u64) -> TransferResult<Option<TransferPlan>> {
        let path = self.path(plan_id, ".plan.json")?;
        if !path.exists() {
            return Ok(None);
        }
        let bytes = read_owner_only_file_bounded(&path, self.limits.max_bytes)
            .map_err(|_| TransferError::CorruptJournal)?;
        let plan: TransferPlan =
            serde_json::from_slice(&bytes).map_err(|_| TransferError::CorruptJournal)?;
        plan.validate_at(now_unix)?;
        if plan.id() != plan_id {
            return Err(TransferError::CorruptJournal);
        }
        Ok(Some(plan))
    }

    /// Return only immutable plans whose bounded owner-only records validate at
    /// `now_unix`.  This is intended for status/list presentation; it never
    /// exposes private part paths or journal ownership fields.
    pub fn list_plans(&self, now_unix: u64) -> TransferResult<Vec<TransferPlan>> {
        let entries: Vec<PathBuf> = fs::read_dir(&self.root)
            .map_err(io_error)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".plan.json"))
            })
            .collect();
        if entries.len() > self.limits.max_journals {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let mut plans = Vec::with_capacity(entries.len());
        for path in entries {
            let bytes = read_owner_only_file_bounded(&path, self.limits.max_bytes)
                .map_err(|_| TransferError::CorruptJournal)?;
            let plan: TransferPlan =
                serde_json::from_slice(&bytes).map_err(|_| TransferError::CorruptJournal)?;
            plan.validate_at(now_unix)?;
            if self.path(plan.id(), ".plan.json")? != path {
                return Err(TransferError::CorruptJournal);
            }
            plans.push(plan);
        }
        plans.sort_by(|left, right| left.id().cmp(right.id()));
        Ok(plans)
    }
    pub fn claim(
        &self,
        lease: &JournalLease,
        plan: &TransferPlan,
        owner_id: &str,
        epoch: u64,
        fence: u64,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> TransferResult<TransferJournal> {
        self.claim_inner(
            lease,
            plan,
            owner_id,
            epoch,
            fence,
            now_unix,
            expires_at_unix,
            None,
        )
    }

    /// Claim a fresh destination generation at the relay's durable ACK
    /// cursor. A process can crash after saving one local chunk but before the
    /// Room commits its ACK; only the Room cursor is safe for both peers to
    /// resume. The new journal may therefore roll local progress back, never
    /// forward, and the generation-bound part copies only that prefix.
    pub fn claim_at_room_cursor(
        &self,
        lease: &JournalLease,
        plan: &TransferPlan,
        owner_id: &str,
        epoch: u64,
        fence: u64,
        now_unix: u64,
        expires_at_unix: u64,
        next_sequence: u64,
        next_offset: u64,
    ) -> TransferResult<TransferJournal> {
        self.claim_inner(
            lease,
            plan,
            owner_id,
            epoch,
            fence,
            now_unix,
            expires_at_unix,
            Some((next_sequence, next_offset)),
        )
    }

    fn claim_inner(
        &self,
        lease: &JournalLease,
        plan: &TransferPlan,
        owner_id: &str,
        epoch: u64,
        fence: u64,
        now_unix: u64,
        expires_at_unix: u64,
        room_cursor: Option<(u64, u64)>,
    ) -> TransferResult<TransferJournal> {
        let _store_lock = self.lock_store()?;
        plan.validate_at(now_unix)?;
        if lease.plan_id != plan.id || expires_at_unix <= now_unix {
            return Err(TransferError::StaleFence);
        }
        let journal = if let Some(mut existing) = self.load(plan)? {
            if matches!(
                existing.state,
                JournalState::Cancelled | JournalState::Failed | JournalState::Published
            ) || (existing.state == JournalState::Completed && room_cursor.is_none())
                || existing.expires_at_unix <= now_unix
                || epoch <= existing.epoch
                || fence <= existing.fence
            {
                return Err(TransferError::StaleFence);
            }
            existing.owner_id = owner_id.into();
            existing.epoch = epoch;
            existing.fence = fence;
            existing.expires_at_unix = expires_at_unix;
            if let Some((next_sequence, next_offset)) = room_cursor {
                let local_next_sequence = existing
                    .contiguous_ack
                    .map(|sequence| sequence.checked_add(1).ok_or(TransferError::Overflow))
                    .transpose()?
                    .unwrap_or(0);
                validate_room_cursor(plan, local_next_sequence, existing.bytes_received)?;
                validate_room_cursor(plan, next_sequence, next_offset)?;
                if next_sequence > local_next_sequence || next_offset > existing.bytes_received {
                    return Err(TransferError::Gap);
                }
                existing.contiguous_ack = next_sequence.checked_sub(1);
                existing.bytes_received = next_offset;
                existing.state = if next_offset == plan.size_bytes {
                    JournalState::Completed
                } else {
                    JournalState::Receiving
                };
            }
            existing
        } else {
            let count = fs::read_dir(&self.root)
                .map_err(io_error)?
                .filter_map(Result::ok)
                .filter(|entry| {
                    let name = entry.file_name();
                    let name = name.to_string_lossy();
                    name.ends_with(".json") && !name.ends_with(".plan.json")
                })
                .count();
            if count >= self.limits.max_journals {
                return Err(TransferError::JournalQuotaExceeded);
            }
            let mut fresh = TransferJournal::fresh(plan, owner_id, epoch, fence, expires_at_unix)?;
            if let Some((next_sequence, next_offset)) = room_cursor {
                validate_room_cursor(plan, next_sequence, next_offset)?;
                if next_sequence != 0 || next_offset != 0 {
                    return Err(TransferError::Gap);
                }
                fresh.state = if plan.size_bytes == 0 {
                    JournalState::Completed
                } else {
                    JournalState::Receiving
                };
            }
            fresh
        };
        self.save_unlocked(lease, &journal)?;
        Ok(journal)
    }
    pub fn save(&self, lease: &JournalLease, journal: &TransferJournal) -> TransferResult<()> {
        let _store_lock = self.lock_store()?;
        self.save_unlocked(lease, journal)
    }

    fn save_unlocked(&self, lease: &JournalLease, journal: &TransferJournal) -> TransferResult<()> {
        if lease.plan_id != journal.plan_id {
            return Err(TransferError::StaleFence);
        }
        let current = read_owner_only_file_bounded(&lease.path, 512)
            .map_err(|_| TransferError::StaleFence)?;
        if current != lease.body {
            return Err(TransferError::StaleFence);
        }
        let bytes = serde_json::to_vec(journal).map_err(|_| TransferError::CorruptJournal)?;
        if bytes.len() > self.limits.max_bytes {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let path = self.path(&journal.plan_id, ".json")?;
        atomic_write_owner_only(&path, &bytes).map_err(|_| TransferError::CustodyUnavailable)
    }

    /// Publish a fully received private part without replacing an existing
    /// destination.  The completed journal, immutable plan, and part hash are
    /// all revalidated here so a daemon restart cannot turn a path supplied by
    /// a later caller into authority to publish an incomplete transfer.
    pub fn publish_completed_no_replace(
        &self,
        plan: &TransferPlan,
        destination_workspace: &ownmesh_fs::WorkspaceRoot,
    ) -> TransferResult<()> {
        plan.validate_at(now_unix())?;
        let journal = self.load(plan)?.ok_or(TransferError::Terminal)?;
        if journal.state != JournalState::Completed || journal.bytes_received != plan.size_bytes {
            return Err(TransferError::Terminal);
        }
        let part = self.part_path(plan.id(), journal.epoch)?;
        let mut file = open_owner_only_file_append_linkable(&part)
            .map_err(|_| TransferError::CustodyUnavailable)?;
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        let (size, digest) = hash_reader(&mut file, plan.size_bytes)?;
        if size != plan.size_bytes || digest != plan.sha256 {
            return Err(TransferError::HashMismatch);
        }
        destination_workspace
            .publish_retained_transfer_file_no_replace(
                Path::new(&plan.binding().destination_relative_path),
                &file,
            )
            .map_err(|error| match error {
                ownmesh_fs::FsError::Io { source, .. }
                    if source.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    TransferError::DestinationExists
                }
                _ => TransferError::CustodyUnavailable,
            })
    }

    /// Verify that an already custody-verified retained destination handle
    /// contains exactly the artifact authorized by `plan`. The runtime must
    /// pass the same handle onward for paging, never reopen its pathname.
    pub fn verify_published_destination_handle(
        &self,
        plan: &TransferPlan,
        file: &mut File,
    ) -> TransferResult<()> {
        plan.validate_at(now_unix())?;
        let metadata = file.metadata().map_err(io_error)?;
        if !metadata.is_file()
            || is_reparse_or_symlink(&metadata)
            || metadata.len() != plan.size_bytes
        {
            return Err(TransferError::DestinationExists);
        }
        let (size, digest) = hash_reader(file, plan.size_bytes)?;
        if size != plan.size_bytes || digest != plan.sha256 {
            return Err(TransferError::DestinationExists);
        }
        file.seek(SeekFrom::Start(0)).map_err(io_error)?;
        Ok(())
    }

    /// Startup/TTL cleanup. It first validates every journal within the bounded
    /// directory; a corrupt journal stops cleanup before any part is removed.
    /// Only the exact private part name derived from an expired journal is ever
    /// deleted.
    pub fn cleanup_expired(&self, now_unix: u64) -> TransferResult<usize> {
        let _store_lock = self.lock_store()?;
        self.cleanup_expired_unlocked(now_unix)
    }

    fn cleanup_expired_unlocked(&self, now_unix: u64) -> TransferResult<usize> {
        let entries: Vec<PathBuf> = fs::read_dir(&self.root)
            .map_err(io_error)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name().is_some_and(|name| {
                    let name = name.to_string_lossy();
                    name.ends_with(".json") && !name.ends_with(".plan.json")
                })
            })
            .collect();
        if entries.len() > self.limits.max_journals {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let mut expired = Vec::new();
        for path in entries {
            let bytes = read_owner_only_file_bounded(&path, self.limits.max_bytes)
                .map_err(|_| TransferError::CorruptJournal)?;
            let journal: TransferJournal =
                serde_json::from_slice(&bytes).map_err(|_| TransferError::CorruptJournal)?;
            if journal.schema != JOURNAL_SCHEMA
                || self.path(&journal.plan_id, ".json")? != path
                || journal.epoch == 0
                || journal.fence == 0
            {
                return Err(TransferError::CorruptJournal);
            }
            if journal.expires_at_unix <= now_unix {
                expired.push((path, journal));
            }
        }
        let mut removed = 0;
        for (journal_path, journal) in expired {
            for (_, part) in self.generation_parts(&journal.plan_id)? {
                remove_owner_only_file(&part).map_err(|_| TransferError::CustodyUnavailable)?;
            }
            let source = self.path(&journal.plan_id, ".source")?;
            if let Ok(metadata) = fs::symlink_metadata(&source) {
                if !metadata.is_file() || is_reparse_or_symlink(&metadata) {
                    return Err(TransferError::CustodyUnavailable);
                }
                remove_owner_only_file(&source).map_err(|_| TransferError::CustodyUnavailable)?;
            }
            let reservation = self.path(&journal.plan_id, ".source.reserve")?;
            if reservation.exists() {
                remove_owner_only_file(&reservation)
                    .map_err(|_| TransferError::CustodyUnavailable)?;
            }
            remove_owner_only_file(&journal_path).map_err(|_| TransferError::CustodyUnavailable)?;
            let plan = self.path(&journal.plan_id, ".plan.json")?;
            if plan.exists() {
                remove_owner_only_file(&plan).map_err(|_| TransferError::CustodyUnavailable)?;
            }
            removed += 1;
        }
        // Source-side transfers do not create a receiver journal. Sweep their
        // owner-only plan/snapshot pair on expiry, and remove a `.source` whose
        // matching plan is absent. Names are strictly generated plan IDs and
        // every delete revalidates owner-only/reparse-safe custody.
        let mut live_plan_ids = std::collections::HashSet::new();
        for entry in fs::read_dir(&self.root).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(plan_id) = name
                .strip_prefix('.')
                .and_then(|value| value.strip_suffix(".plan.json"))
            else {
                continue;
            };
            let expected = self.path(plan_id, ".plan.json")?;
            if expected != path {
                continue;
            }
            let bytes = read_owner_only_file_bounded(&path, self.limits.max_bytes)
                .map_err(|_| TransferError::CorruptJournal)?;
            let plan: TransferPlan =
                serde_json::from_slice(&bytes).map_err(|_| TransferError::CorruptJournal)?;
            if plan.id() != plan_id {
                return Err(TransferError::CorruptJournal);
            }
            if plan.grant().expires_at_unix <= now_unix {
                let source = self.path(plan_id, ".source")?;
                if source.exists() {
                    remove_owner_only_file(&source)
                        .map_err(|_| TransferError::CustodyUnavailable)?;
                }
                let reservation = self.path(plan_id, ".source.reserve")?;
                if reservation.exists() {
                    remove_owner_only_file(&reservation)
                        .map_err(|_| TransferError::CustodyUnavailable)?;
                }
                remove_owner_only_file(&path).map_err(|_| TransferError::CustodyUnavailable)?;
                removed += 1;
            } else {
                live_plan_ids.insert(plan_id.to_owned());
            }
        }
        for entry in fs::read_dir(&self.root).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(plan_id) = name
                .strip_prefix('.')
                .and_then(|value| value.strip_suffix(".source"))
            else {
                continue;
            };
            if self.path(plan_id, ".source")? != path
                || live_plan_ids.contains(plan_id)
                || self.path(plan_id, ".source.reserve")?.exists()
            {
                continue;
            }
            remove_owner_only_file(&path).map_err(|_| TransferError::CustodyUnavailable)?;
            removed += 1;
        }
        // A crash can strand a source-staging reservation before its snapshot
        // exists. It is bounded, plan-addressed state: discard it only when its
        // own canonical expiry passed or its matching immutable plan vanished.
        for entry in fs::read_dir(&self.root).map_err(io_error)? {
            let path = entry.map_err(io_error)?.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(plan_id) = name
                .strip_prefix('.')
                .and_then(|value| value.strip_suffix(".source.reserve"))
            else {
                continue;
            };
            if self.path(plan_id, ".source.reserve")? != path {
                continue;
            }
            let bytes = read_owner_only_file_bounded(&path, 512)
                .map_err(|_| TransferError::CustodyUnavailable)?;
            let reservation = parse_source_reservation(&bytes, plan_id)
                .ok_or(TransferError::CustodyUnavailable)?;
            if reservation.expires_at_unix <= now_unix {
                remove_owner_only_file(&path).map_err(|_| TransferError::CustodyUnavailable)?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

/// Private generation-bound part sink. A newer fence copies only the prior
/// durable ACK prefix into a new inode/path, so a retired process holding the
/// old file handle cannot append into the active generation.
pub struct PartFileSink {
    path: PathBuf,
    file: Option<File>,
    expected_offset: u64,
    expected_size: u64,
    expected_sha256: String,
    expires_at_unix: u64,
    closed: bool,
    verified: bool,
}
impl PartFileSink {
    pub fn create(
        store: &JournalStore,
        plan: &TransferPlan,
        epoch: u64,
        resume_at: u64,
    ) -> TransferResult<Self> {
        plan.validate_at(now_unix())?;
        if resume_at > plan.size_bytes {
            return Err(TransferError::CorruptJournal);
        }
        let path = store.part_path(plan.id(), epoch)?;
        let existing = store.generation_parts(plan.id())?;
        if existing.len() > 1 {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let retired_bytes = existing.iter().try_fold(0_u64, |total, (_, candidate)| {
            let len = fs::metadata(candidate).map_err(io_error)?.len();
            if len > plan.size_bytes {
                return Err(TransferError::JournalQuotaExceeded);
            }
            total.checked_add(len).ok_or(TransferError::Overflow)
        })?;
        if retired_bytes > plan.size_bytes
            || retired_bytes
                .checked_add(resume_at)
                .ok_or(TransferError::Overflow)?
                > plan.size_bytes.saturating_mul(2)
        {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let current_exists = existing.iter().any(|(_, candidate)| candidate == &path);
        if !current_exists {
            let predecessor = if resume_at > 0 {
                Some(
                    existing
                        .iter()
                        .rev()
                        .find(|(candidate_epoch, _)| *candidate_epoch < epoch)
                        .ok_or(TransferError::CorruptJournal)?,
                )
            } else {
                None
            };
            create_owner_only_file_new(&path, &[]).map_err(|_| TransferError::LeaseBusy)?;
            let staged = (|| -> TransferResult<()> {
                let mut file = open_owner_only_file_append(&path)
                    .map_err(|_| TransferError::CustodyUnavailable)?;
                if let Some((_, predecessor)) = predecessor {
                    let mut prior = open_owner_only_file_read_retry(predecessor)
                        .map_err(|_| TransferError::CustodyUnavailable)?;
                    if prior.metadata().map_err(io_error)?.len() < resume_at {
                        return Err(TransferError::CorruptJournal);
                    }
                    let copied = std::io::copy(
                        &mut std::io::Read::by_ref(&mut prior).take(resume_at),
                        &mut file,
                    )
                    .map_err(io_error)?;
                    if copied != resume_at {
                        return Err(TransferError::CorruptJournal);
                    }
                }
                file.sync_all().map_err(io_error)
            })();
            if let Err(error) = staged {
                let _ = remove_owner_only_file_retry(&path);
                return Err(error);
            }
            for (_, retired) in &existing {
                if remove_owner_only_file_retry(retired).is_err() {
                    let _ = remove_owner_only_file_retry(&path);
                    return Err(TransferError::LeaseBusy);
                }
            }
        }
        let mut file =
            open_owner_only_file_append(&path).map_err(|_| TransferError::CustodyUnavailable)?;
        if file.metadata().map_err(io_error)?.len() != resume_at {
            return Err(TransferError::CorruptJournal);
        }
        file.seek(SeekFrom::End(0)).map_err(io_error)?;
        Ok(Self {
            path,
            file: Some(file),
            expected_offset: resume_at,
            expected_size: plan.size_bytes,
            expected_sha256: plan.sha256.clone(),
            expires_at_unix: plan.grant.expires_at_unix,
            closed: false,
            verified: false,
        })
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verify a fully staged generation before treating an at-size Room cursor
    /// as completed. This hashes the new generation part; journal metadata
    /// alone is never sufficient to resume directly into publication.
    pub fn verify_complete(&mut self) -> TransferResult<()> {
        self.finalize().map_err(TransferError::Sink)
    }
}
impl ChunkSink for PartFileSink {
    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        if self.closed || offset != self.expected_offset || bytes.len() > MAX_CHUNK_BYTES {
            return Err("invalid part write".into());
        }
        let file = self.file.as_mut().ok_or_else(|| "closed part".to_owned())?;
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_data().map_err(|error| error.to_string())?;
        self.expected_offset = self
            .expected_offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| "overflow")?)
            .ok_or("overflow")?;
        Ok(())
    }
    fn finalize(&mut self) -> Result<(), String> {
        if self.expires_at_unix <= now_unix() {
            return Err("expired transfer grant".into());
        }
        if self.expected_offset != self.expected_size {
            return Err("incomplete part".into());
        }
        let file = self.file.as_mut().ok_or_else(|| "closed part".to_owned())?;
        file.sync_all().map_err(|error| error.to_string())?;
        file.seek(SeekFrom::Start(0))
            .map_err(|error| error.to_string())?;
        let (bytes, sha256) =
            hash_reader(file, self.expected_size).map_err(|error| error.to_string())?;
        if bytes != self.expected_size || sha256 != self.expected_sha256 {
            return Err("part hash mismatch".into());
        }
        self.verified = true;
        Ok(())
    }
    fn cancel(&mut self) -> Result<(), String> {
        self.closed = true;
        let file = self.file.take().ok_or_else(|| "closed part".to_owned())?;
        file.sync_all().map_err(|error| error.to_string())?;
        drop(file);
        remove_owner_only_file(&self.path).map_err(|error| error.to_string())
    }
}

/// Legacy names remain only to make old callers fail closed during migration.
#[deprecated(note = "use TransferPlan::for_source with an authenticated TransferGrant")]
pub fn plan_transfer() -> TransferResult<()> {
    Err(TransferError::LegacySurfaceDisabled)
}

#[deprecated(note = "whole-file local copy is not a production transfer surface")]
pub fn execute_local_copy() -> TransferResult<()> {
    Err(TransferError::LegacySurfaceDisabled)
}
