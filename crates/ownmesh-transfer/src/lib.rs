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

use ownmesh_ipc::{
    atomic_write_owner_only, create_owner_only_file_new, prepare_owner_only_state_dir,
    read_owner_only_file_bounded,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;

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
    /// Stream-hash a source and create its immutable plan. This never uses
    /// `read_to_end` or `fs::read`.
    pub fn for_source(
        source: &Path,
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
        validate_source_custody(source)?;
        let before = fs::metadata(source).map_err(io_error)?;
        let mut file = File::open(source).map_err(io_error)?;
        let (size_bytes, sha256) = hash_reader(&mut file, limits.max_bytes)?;
        let after = fs::metadata(source).map_err(io_error)?;
        if !before.is_file() || before.len() != size_bytes || after.len() != size_bytes {
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

fn validate_source_custody(source: &Path) -> TransferResult<()> {
    let meta = fs::symlink_metadata(source).map_err(io_error)?;
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Err(TransferError::CustodyUnavailable);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.nlink() != 1 {
            return Err(TransferError::CustodyUnavailable);
        }
    }
    // Windows reparse/hardlink identity is pinned by the handle-rooted
    // `ownmesh-fs` integration before it supplies this source path. This core
    // still rejects a visible symlink/reparse node above, but does not pretend
    // to replace that stronger custody boundary.
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
    source: PathBuf,
    file: File,
    sequence: u64,
    offset: u64,
    remaining: u64,
    hasher: Sha256,
    done: bool,
}

impl TransferSender {
    pub fn open(plan: TransferPlan, source: &Path) -> TransferResult<Self> {
        plan.validate()?;
        validate_source_custody(source)?;
        let metadata = fs::metadata(source).map_err(io_error)?;
        if metadata.len() != plan.size_bytes {
            return Err(TransferError::SourceChanged);
        }
        let file = File::open(source).map_err(io_error)?;
        Ok(Self {
            remaining: plan.size_bytes,
            plan,
            source: source.to_path_buf(),
            file,
            sequence: 0,
            offset: 0,
            hasher: Sha256::new(),
            done: false,
        })
    }

    pub fn next_chunk(&mut self) -> TransferResult<Option<TransferChunk>> {
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
        if self.remaining == 0 {
            let metadata = fs::metadata(&self.source).map_err(io_error)?;
            if metadata.len() != self.plan.size_bytes
                || hex::encode(self.hasher.clone().finalize()) != self.plan.sha256
            {
                return Err(TransferError::SourceChanged);
            }
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
}

impl JournalState {
    fn terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Failed | Self::Completed)
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
        plan.validate()?;
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
        plan.validate()?;
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
        plan.validate()?;
        let mut file = File::open(part).map_err(io_error)?;
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

    pub fn cancel(&mut self, sink: &mut impl ChunkSink) -> TransferResult<()> {
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
}
impl Default for JournalLimits {
    fn default() -> Self {
        Self {
            max_journals: 1024,
            max_bytes: 16 * 1024,
        }
    }
}

/// A process-local lease backed by an owner-only lock file. It prevents two
/// local writers from advancing a journal simultaneously and expires safely.
pub struct JournalLease {
    plan_id: String,
    path: PathBuf,
}
impl Drop for JournalLease {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Owner-only durable journal directory. Each mutation uses the custody-hardened
/// atomic write primitive from `ownmesh-ipc`.
#[derive(Clone)]
pub struct JournalStore {
    root: PathBuf,
    limits: JournalLimits,
}

impl JournalStore {
    pub fn open(root: impl Into<PathBuf>, limits: JournalLimits) -> TransferResult<Self> {
        if limits.max_journals == 0 || limits.max_bytes < 512 {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let root = root.into();
        prepare_owner_only_state_dir(&root).map_err(|_| TransferError::CustodyUnavailable)?;
        Ok(Self { root, limits })
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
    pub fn acquire(
        &self,
        plan: &TransferPlan,
        now_unix: u64,
        expires_at_unix: u64,
    ) -> TransferResult<JournalLease> {
        plan.validate()?;
        if expires_at_unix <= now_unix {
            return Err(TransferError::Terminal);
        }
        let path = self.path(plan.id(), ".lock")?;
        let body = format!("{}\n{}\n", plan.id(), expires_at_unix);
        if create_owner_only_file_new(&path, body.as_bytes()).is_ok() {
            Ok(JournalLease {
                plan_id: plan.id.clone(),
                path,
            })
        } else {
            let existing =
                read_owner_only_file_bounded(&path, 512).map_err(|_| TransferError::LeaseBusy)?;
            let text = std::str::from_utf8(&existing).map_err(|_| TransferError::LeaseBusy)?;
            let stale = text
                .lines()
                .nth(1)
                .and_then(|value| value.parse::<u64>().ok())
                .is_some_and(|expiry| expiry <= now_unix);
            if !stale {
                return Err(TransferError::LeaseBusy);
            }
            fs::remove_file(&path).map_err(io_error)?;
            create_owner_only_file_new(&path, body.as_bytes())
                .map_err(|_| TransferError::LeaseBusy)?;
            Ok(JournalLease {
                plan_id: plan.id.clone(),
                path,
            })
        }
    }
    pub fn load(&self, plan: &TransferPlan) -> TransferResult<Option<TransferJournal>> {
        plan.validate()?;
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
        plan.validate()?;
        if lease.plan_id != plan.id || expires_at_unix <= now_unix {
            return Err(TransferError::StaleFence);
        }
        let journal = if let Some(mut existing) = self.load(plan)? {
            if existing.state.terminal()
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
            existing
        } else {
            let count = fs::read_dir(&self.root)
                .map_err(io_error)?
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
                .count();
            if count >= self.limits.max_journals {
                return Err(TransferError::JournalQuotaExceeded);
            }
            TransferJournal::fresh(plan, owner_id, epoch, fence, expires_at_unix)?
        };
        self.save(lease, &journal)?;
        Ok(journal)
    }
    pub fn save(&self, lease: &JournalLease, journal: &TransferJournal) -> TransferResult<()> {
        if lease.plan_id != journal.plan_id {
            return Err(TransferError::StaleFence);
        }
        let bytes = serde_json::to_vec(journal).map_err(|_| TransferError::CorruptJournal)?;
        if bytes.len() > self.limits.max_bytes {
            return Err(TransferError::JournalQuotaExceeded);
        }
        let path = self.path(&journal.plan_id, ".json")?;
        atomic_write_owner_only(&path, &bytes).map_err(|_| TransferError::CustodyUnavailable)
    }

    /// Startup/TTL cleanup. It first validates every journal within the bounded
    /// directory; a corrupt journal stops cleanup before any part is removed.
    /// Only the exact private part name derived from an expired journal is ever
    /// deleted.
    pub fn cleanup_expired(&self, now_unix: u64) -> TransferResult<usize> {
        let entries: Vec<PathBuf> = fs::read_dir(&self.root)
            .map_err(io_error)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().ends_with(".json"))
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
            let part = self.path(&journal.plan_id, &format!(".{}.part", journal.epoch))?;
            if let Ok(metadata) = fs::symlink_metadata(&part) {
                if !metadata.is_file() || metadata.file_type().is_symlink() {
                    return Err(TransferError::CustodyUnavailable);
                }
                fs::remove_file(&part).map_err(io_error)?;
            }
            fs::remove_file(journal_path).map_err(io_error)?;
            removed += 1;
        }
        Ok(removed)
    }
}

/// Private `.part` sink. It writes in-order, syncs before acknowledgement, and
/// deletes only its exact generated part on cancellation.
pub struct PartFileSink {
    path: PathBuf,
    file: File,
    expected_offset: u64,
    expected_size: u64,
    expected_sha256: String,
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
        plan.validate()?;
        let path = store.path(plan.id(), &format!(".{epoch}.part"))?;
        if !path.exists() {
            create_owner_only_file_new(&path, &[])
                .map_err(|_| TransferError::CustodyUnavailable)?;
        }
        let meta = fs::symlink_metadata(&path).map_err(io_error)?;
        if !meta.is_file() || meta.file_type().is_symlink() || meta.len() != resume_at {
            return Err(TransferError::CorruptJournal);
        }
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(io_error)?;
        Ok(Self {
            path,
            file,
            expected_offset: resume_at,
            expected_size: plan.size_bytes,
            expected_sha256: plan.sha256.clone(),
            closed: false,
            verified: false,
        })
    }
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Publish only after this sink has streamed and verified the complete part.
    pub fn publish_no_replace(&mut self, destination: &Path) -> TransferResult<()> {
        if !self.verified {
            return Err(TransferError::HashMismatch);
        }
        publish_part_no_replace(&self.path, destination)
    }
}
impl ChunkSink for PartFileSink {
    fn write_chunk(&mut self, offset: u64, bytes: &[u8]) -> Result<(), String> {
        if self.closed || offset != self.expected_offset || bytes.len() > MAX_CHUNK_BYTES {
            return Err("invalid part write".into());
        }
        self.file
            .write_all(bytes)
            .map_err(|error| error.to_string())?;
        self.file.sync_data().map_err(|error| error.to_string())?;
        self.expected_offset = self
            .expected_offset
            .checked_add(u64::try_from(bytes.len()).map_err(|_| "overflow")?)
            .ok_or("overflow")?;
        Ok(())
    }
    fn finalize(&mut self) -> Result<(), String> {
        if self.expected_offset != self.expected_size {
            return Err("incomplete part".into());
        }
        self.file.sync_all().map_err(|error| error.to_string())?;
        let mut verification = File::open(&self.path).map_err(|error| error.to_string())?;
        let (bytes, sha256) = hash_reader(&mut verification, self.expected_size)
            .map_err(|error| error.to_string())?;
        if bytes != self.expected_size || sha256 != self.expected_sha256 {
            return Err("part hash mismatch".into());
        }
        self.verified = true;
        Ok(())
    }
    fn cancel(&mut self) -> Result<(), String> {
        self.closed = true;
        self.file.sync_all().map_err(|error| error.to_string())?;
        fs::remove_file(&self.path).map_err(|error| error.to_string())
    }
}

/// Atomically publish a verified private part without replacing an existing
/// destination. A custody-aware integration must pass an already pinned,
/// workspace-authorized destination path. Hard-link publication is no-replace on
/// supported local filesystems; if unavailable it fails rather than copying.
fn publish_part_no_replace(part: &Path, destination: &Path) -> TransferResult<()> {
    let metadata = fs::symlink_metadata(part).map_err(io_error)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(TransferError::CustodyUnavailable);
    }
    match fs::hard_link(part, destination) {
        Ok(()) => fs::remove_file(part).map_err(io_error),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(TransferError::DestinationExists)
        }
        Err(error) => Err(io_error(error)),
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
