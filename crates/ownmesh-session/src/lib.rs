//! `OwnMesh` interactive session model and handoff primitives.
//!
//! Multiple observers, single controller lease, claim/release/give,
//! detached persistence across daemon restarts, PTY size/view metadata.

#![allow(
    clippy::doc_markdown,
    clippy::ignored_unit_patterns,
    clippy::let_unit_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::unnecessary_wraps
)]

mod persist;
mod pty;

pub use persist::{load_manager, save_manager, PersistError};
pub use pty::{
    PtyBackend, PtyCommand, PtySize, PtyViewMode, SessionHostHandle, DEFAULT_REPLAY_BYTES_HINT,
};

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;

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

/// Session errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SessionError {
    #[error("session not found")]
    NotFound,
    #[error("controller lease held by {0}")]
    LeaseHeld(String),
    #[error("not controller")]
    NotController,
    #[error("not a session reader")]
    NotReader,
    #[error("observer cannot write stdin")]
    ObserverCannotWrite,
    #[error("session closed")]
    Closed,
    #[error("invalid argument: {0}")]
    Invalid(String),
    #[error("persist: {0}")]
    Persist(String),
    #[error("session limit exceeded")]
    SessionLimit,
    #[error("chunk too large")]
    ChunkTooLarge,
    #[error("replay budget exceeded")]
    ReplayBudget,
    #[error("stale {kind} sequence {got} (last applied {last})")]
    SequenceStale { kind: String, got: u64, last: u64 },
    #[error("gap in {kind} sequence: got {got}, expected {expected}")]
    SequenceGap {
        kind: String,
        got: u64,
        expected: u64,
    },
    #[error("{kind} sequence {seq} payload digest mismatch (exact-once receipt already bound)")]
    SequenceConflict { kind: String, seq: u64 },
    #[error("{0} sequence required")]
    SequenceRequired(String),
}

/// Outcome of reserving a controller input/resize sequence before side effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeqReserveOutcome {
    /// First time this sequence is seen; caller must deliver then finalize.
    Deliver { seq: u64 },
    /// Prior attempt reserved but may not have finalized. Callers MUST NOT
    /// re-deliver the side effect (at-most-once). Surface an uncertain outcome
    /// or reconcile via durable host state instead of rewriting the PTY.
    RetryPending { seq: u64 },
    /// Durable applied receipt matches; caller must not re-deliver.
    Replayed { seq: u64 },
}

/// Durable receipt state for the last reserved controller sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SeqReceiptState {
    #[default]
    None,
    Pending,
    Applied,
}

pub type SessionResult<T> = Result<T, SessionError>;

/// Hard cap on concurrent sessions retained by one manager (memory + disk).
pub const MAX_SESSIONS: usize = 64;
/// Default max replay chunks retained per session (ring).
pub const DEFAULT_REPLAY_CHUNK_LIMIT: usize = 256;
/// Hard cap on a single push/write chunk payload (UTF-8 bytes).
pub const MAX_CHUNK_BYTES: usize = 64 * 1024;
/// Aggregate UTF-8 byte budget for one session's replay ring.
pub const MAX_REPLAY_BYTES: usize = 1024 * 1024;
/// Default max chunks returned from one replay call.
pub const DEFAULT_REPLAY_PAGE_LIMIT: usize = 64;
/// Hard cap on chunks returned from one replay call.
pub const MAX_REPLAY_PAGE_LIMIT: usize = 256;
/// Hard cap on aggregate UTF-8 bytes returned from one replay call.
pub const MAX_REPLAY_PAGE_BYTES: usize = 256 * 1024;
/// Refuse to load a sessions file larger than this (fail closed).
pub const MAX_SESSIONS_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Session lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Starting,
    Running,
    Detached,
    Closed,
}

/// Kind of session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Pty,
    Process,
    ProfileAgent,
}

/// Output chunk with sequence for replay.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputChunk {
    pub seq: u64,
    pub data: String,
    pub stream: StreamKind,
}

/// Bounded replay page (never builds an unbounded Vec of attacker-controlled data).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReplayPage {
    pub chunks: Vec<OutputChunk>,
    /// True when more chunks exist beyond this page (use `next_seq`).
    pub truncated: bool,
    /// Inclusive sequence cursor for the next page when truncated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_seq: Option<u64>,
    /// Aggregate UTF-8 bytes in `chunks`.
    pub returned_bytes: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamKind {
    Stdout,
    Stderr,
    System,
}

/// Controller lease.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ControllerLease {
    pub principal_id: String,
    pub lease_id: String,
    /// Monotonic generation for this session's controller seat. A request must
    /// echo both lease_id and epoch; an old controller cannot mutate after a
    /// handoff, expiry reclaim, or reconnect claim.
    #[serde(default)]
    pub epoch: u64,
    pub expires_unix: i64,
}

impl ControllerLease {
    /// `true` when the lease is still valid at `now_unix` (strictly future expiry).
    #[must_use]
    pub fn is_active(&self, now_unix: i64) -> bool {
        self.expires_unix > now_unix
    }
}

/// Session snapshot for API/TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub kind: SessionKind,
    pub state: SessionState,
    pub title: String,
    pub controller: Option<ControllerLease>,
    /// Last issued controller generation, retained even while detached so the
    /// next claim cannot reuse an epoch after restart.
    #[serde(default)]
    pub controller_epoch: u64,
    pub observers: Vec<String>,
    pub cols: u16,
    pub rows: u16,
    pub next_seq: u64,
    pub profile_id: Option<String>,
    /// Profile / coding-CLI native session id (distinct from OwnMesh id).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_session_id: Option<String>,
    /// View mode preference (raw/cooked).
    #[serde(default)]
    pub view_mode: PtyViewMode,
    /// Host process id when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_pid: Option<u32>,
    /// Command argv snapshot for restart recovery metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Tenant/device workspace this session is bound to (`ws_...`).
    /// Always recorded for audit; enforced as a path boundary only in restricted modes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Last reserved/applied controller input sequence (0 = none). Monotonic, gap-free.
    #[serde(default)]
    pub last_input_seq: u64,
    /// SHA-256 hex of the last reserved input payload (exact-once binding).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_input_digest: Option<String>,
    /// Durable receipt state for `last_input_seq`.
    #[serde(default)]
    pub last_input_state: SeqReceiptState,
    /// Last reserved/applied controller resize sequence (0 = none). Monotonic, gap-free.
    #[serde(default)]
    pub last_resize_seq: u64,
    /// Digest of last resize facts (`cols:rows`) as a short stable string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_resize_digest: Option<String>,
    /// Durable receipt state for `last_resize_seq`.
    #[serde(default)]
    pub last_resize_state: SeqReceiptState,
}

impl SessionInfo {
    /// Active (non-expired) controller lease at `now_unix`, if any.
    #[must_use]
    pub fn active_controller(&self, now_unix: i64) -> Option<&ControllerLease> {
        self.controller.as_ref().filter(|c| c.is_active(now_unix))
    }
}

/// In-memory session record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Session {
    info: SessionInfo,
    replay: VecDeque<OutputChunk>,
    replay_limit: usize,
    /// Aggregate UTF-8 bytes currently held in `replay`.
    #[serde(default)]
    replay_bytes: usize,
}

/// Session manager (process-local; daemon owns one; can persist to disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionManager {
    sessions: HashMap<String, Session>,
    default_replay_limit: usize,
    default_lease_ttl_secs: i64,
    /// Max concurrent sessions (open refuses beyond this).
    #[serde(default = "default_max_sessions")]
    max_sessions: usize,
    /// Aggregate replay byte budget per session.
    #[serde(default = "default_max_replay_bytes")]
    max_replay_bytes: usize,
}

fn default_max_sessions() -> usize {
    MAX_SESSIONS
}

fn default_max_replay_bytes() -> usize {
    MAX_REPLAY_BYTES
}

impl Default for SessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            default_replay_limit: DEFAULT_REPLAY_CHUNK_LIMIT,
            default_lease_ttl_secs: 3600,
            max_sessions: MAX_SESSIONS,
            max_replay_bytes: MAX_REPLAY_BYTES,
        }
    }

    /// Enforce load-time caps after deserializing untrusted durable state.
    pub fn enforce_loaded_budgets(&mut self) {
        self.max_sessions = self.max_sessions.clamp(1, MAX_SESSIONS);
        self.max_replay_bytes = self.max_replay_bytes.clamp(1, MAX_REPLAY_BYTES);
        self.default_replay_limit = self
            .default_replay_limit
            .clamp(1, DEFAULT_REPLAY_CHUNK_LIMIT.max(1024));
        // Drop excess sessions deterministically (oldest by id order).
        if self.sessions.len() > self.max_sessions {
            let mut ids: Vec<String> = self.sessions.keys().cloned().collect();
            ids.sort();
            let drop_n = self.sessions.len() - self.max_sessions;
            for id in ids.into_iter().take(drop_n) {
                self.sessions.remove(&id);
            }
        }
        for session in self.sessions.values_mut() {
            session.replay_limit = session
                .replay_limit
                .clamp(1, self.default_replay_limit.max(DEFAULT_REPLAY_CHUNK_LIMIT));
            // Recompute byte total and trim ring to chunk + byte budgets.
            session.replay_bytes = session.replay.iter().map(|c| c.data.len()).sum();
            while session.replay.len() > session.replay_limit {
                if let Some(front) = session.replay.pop_front() {
                    session.replay_bytes = session.replay_bytes.saturating_sub(front.data.len());
                }
            }
            while session.replay_bytes > self.max_replay_bytes {
                if let Some(front) = session.replay.pop_front() {
                    session.replay_bytes = session.replay_bytes.saturating_sub(front.data.len());
                } else {
                    break;
                }
            }
        }
    }

    /// Open a new session; `creator` becomes initial controller.
    pub fn open(
        &mut self,
        kind: SessionKind,
        title: impl Into<String>,
        creator: impl Into<String>,
        now_unix: i64,
        profile_id: Option<String>,
    ) -> SessionResult<SessionInfo> {
        self.open_with(
            kind, title, creator, now_unix, profile_id, None, None, None, None, None,
        )
    }

    /// Open with optional command/cwd/native id/workspace binding.
    #[allow(clippy::too_many_arguments)]
    pub fn open_with(
        &mut self,
        kind: SessionKind,
        title: impl Into<String>,
        creator: impl Into<String>,
        now_unix: i64,
        profile_id: Option<String>,
        native_session_id: Option<String>,
        command: Option<Vec<String>>,
        cwd: Option<String>,
        size: Option<PtySize>,
        workspace_id: Option<String>,
    ) -> SessionResult<SessionInfo> {
        if self.sessions.len() >= self.max_sessions {
            return Err(SessionError::SessionLimit);
        }
        let id = format!("ses_{}", Uuid::new_v4().simple());
        let creator = creator.into();
        let lease = ControllerLease {
            principal_id: creator.clone(),
            lease_id: format!("lease_{}", Uuid::new_v4().simple()),
            epoch: 1,
            expires_unix: now_unix + self.default_lease_ttl_secs,
        };
        let size = size.unwrap_or_default();
        let info = SessionInfo {
            id: id.clone(),
            kind,
            state: SessionState::Running,
            title: title.into(),
            controller: Some(lease),
            controller_epoch: 1,
            observers: vec![],
            cols: size.cols,
            rows: size.rows,
            next_seq: 1,
            profile_id,
            native_session_id,
            view_mode: PtyViewMode::Raw,
            host_pid: None,
            command,
            cwd,
            workspace_id,
            last_input_seq: 0,
            last_input_digest: None,
            last_input_state: SeqReceiptState::None,
            last_resize_seq: 0,
            last_resize_digest: None,
            last_resize_state: SeqReceiptState::None,
        };
        self.sessions.insert(
            id,
            Session {
                info: info.clone(),
                replay: VecDeque::new(),
                replay_limit: self.default_replay_limit,
                replay_bytes: 0,
            },
        );
        Ok(info)
    }

    pub fn get(&self, id: &str) -> SessionResult<&SessionInfo> {
        self.sessions
            .get(id)
            .map(|s| &s.info)
            .ok_or(SessionError::NotFound)
    }

    pub fn list(&self) -> Vec<SessionInfo> {
        self.sessions.values().map(|s| s.info.clone()).collect()
    }

    /// Whether `principal` holds a non-expired controller lease.
    pub fn is_controller(&self, id: &str, principal: &str, now_unix: i64) -> SessionResult<bool> {
        let info = self.get(id)?;
        Ok(matches!(
            info.active_controller(now_unix),
            Some(c) if c.principal_id == principal
        ))
    }

    /// Fail-closed gate: principal must hold an active controller lease.
    pub fn authorize_controller(
        &self,
        id: &str,
        principal: &str,
        now_unix: i64,
    ) -> SessionResult<()> {
        if self.is_controller(id, principal, now_unix)? {
            Ok(())
        } else {
            Err(SessionError::NotController)
        }
    }

    /// Fail-closed controller authorization for remote mutations. Both the
    /// opaque lease token and generation must match the currently active seat.
    pub fn authorize_controller_lease(
        &self,
        id: &str,
        principal: &str,
        lease_id: &str,
        epoch: u64,
        now_unix: i64,
    ) -> SessionResult<()> {
        let info = self.get(id)?;
        match info.active_controller(now_unix) {
            Some(lease)
                if lease.principal_id == principal
                    && lease.lease_id == lease_id
                    && lease.epoch == epoch =>
            {
                Ok(())
            }
            _ => Err(SessionError::NotController),
        }
    }

    pub fn renew_controller_lease(
        &mut self,
        id: &str,
        principal: &str,
        lease_id: &str,
        epoch: u64,
        now: i64,
        ttl: i64,
    ) -> SessionResult<ControllerLease> {
        if !(1..=3600).contains(&ttl) {
            return Err(SessionError::Invalid("lease ttl out of bounds".into()));
        }
        self.authorize_controller_lease(id, principal, lease_id, epoch, now)?;
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        let lease = s
            .info
            .controller
            .as_mut()
            .ok_or(SessionError::NotController)?;
        lease.expires_unix = now
            .checked_add(ttl)
            .ok_or_else(|| SessionError::Invalid("lease expiry overflow".into()))?;
        Ok(lease.clone())
    }

    pub fn detach_controller_lease(
        &mut self,
        id: &str,
        principal: &str,
        lease_id: &str,
        epoch: u64,
        now: i64,
    ) -> SessionResult<()> {
        self.authorize_controller_lease(id, principal, lease_id, epoch, now)?;
        self.release_controller(id, principal, now)
    }

    /// Attach as observer (no stdin). `now_unix` is part of the uniform ACL surface.
    pub fn attach_observer(
        &mut self,
        id: &str,
        principal: impl Into<String>,
        now_unix: i64,
    ) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        let p = principal.into();
        // Do not treat an expired controller as still holding the seat for attach bookkeeping.
        let active_controller = s
            .info
            .active_controller(now_unix)
            .map(|c| c.principal_id.as_str());
        if !s.info.observers.contains(&p) && active_controller != Some(p.as_str()) {
            // If this principal is the expired controller still listed on the lease field,
            // keep them as observer once demoted; attach is a no-op until expire runs.
            let is_expired_controller = matches!(
                &s.info.controller,
                Some(c) if c.principal_id == p && !c.is_active(now_unix)
            );
            if !is_expired_controller {
                s.info.observers.push(p);
            }
        }
        Ok(())
    }

    /// Claim controller lease (fails if held by someone else and not expired).
    pub fn claim_controller(
        &mut self,
        id: &str,
        principal: impl Into<String>,
        now_unix: i64,
    ) -> SessionResult<ControllerLease> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        let principal = principal.into();
        if let Some(cur) = &s.info.controller {
            if cur.principal_id != principal && cur.is_active(now_unix) {
                return Err(SessionError::LeaseHeld(cur.principal_id.clone()));
            }
        }
        s.info.observers.retain(|o| o != &principal);
        let epoch = s
            .info
            .controller_epoch
            .checked_add(1)
            .ok_or_else(|| SessionError::Invalid("controller epoch exhausted".into()))?;
        let lease = ControllerLease {
            principal_id: principal,
            lease_id: format!("lease_{}", Uuid::new_v4().simple()),
            epoch,
            expires_unix: now_unix + self.default_lease_ttl_secs,
        };
        s.info.controller = Some(lease.clone());
        s.info.controller_epoch = epoch;
        s.info.state = SessionState::Running;
        Ok(lease)
    }

    /// Give controller to another principal (requires active lease held by `from`).
    pub fn give_controller(
        &mut self,
        id: &str,
        from: &str,
        to: impl Into<String>,
        now_unix: i64,
    ) -> SessionResult<ControllerLease> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        match &s.info.controller {
            Some(c) if c.principal_id == from && c.is_active(now_unix) => {}
            // Expired former controller loses mutation rights (fail closed).
            Some(c) if c.principal_id == from => return Err(SessionError::NotController),
            Some(c) => return Err(SessionError::LeaseHeld(c.principal_id.clone())),
            None => return Err(SessionError::NotController),
        }
        if !s.info.observers.iter().any(|o| o == from) {
            s.info.observers.push(from.to_string());
        }
        let to = to.into();
        s.info.observers.retain(|o| o != &to);
        let epoch = s
            .info
            .controller_epoch
            .checked_add(1)
            .ok_or_else(|| SessionError::Invalid("controller epoch exhausted".into()))?;
        let lease = ControllerLease {
            principal_id: to,
            lease_id: format!("lease_{}", Uuid::new_v4().simple()),
            epoch,
            expires_unix: now_unix + self.default_lease_ttl_secs,
        };
        s.info.controller = Some(lease.clone());
        s.info.controller_epoch = epoch;
        Ok(lease)
    }

    /// Release controller (session becomes detached; observers remain).
    /// Requires an active lease; expired controllers cannot release (fail closed).
    pub fn release_controller(
        &mut self,
        id: &str,
        principal: &str,
        now_unix: i64,
    ) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        match &s.info.controller {
            Some(c) if c.principal_id == principal && c.is_active(now_unix) => {
                if !s.info.observers.iter().any(|o| o == principal) {
                    s.info.observers.push(principal.to_string());
                }
                s.info.controller = None;
                s.info.state = SessionState::Detached;
                Ok(())
            }
            Some(c) if c.principal_id == principal => Err(SessionError::NotController),
            Some(_) => Err(SessionError::NotController),
            None => Ok(()),
        }
    }

    /// Append output visible to controller + observers.
    ///
    /// Chunks larger than [`MAX_CHUNK_BYTES`] are rejected (fail closed, never
    /// silently truncated). The ring is trimmed by chunk count and aggregate bytes.
    pub fn push_output(
        &mut self,
        id: &str,
        data: impl Into<String>,
        stream: StreamKind,
    ) -> SessionResult<OutputChunk> {
        let data = data.into();
        if data.len() > MAX_CHUNK_BYTES {
            return Err(SessionError::ChunkTooLarge);
        }
        let max_bytes = self.max_replay_bytes;
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        // Single chunk larger than the whole budget cannot be retained.
        if data.len() > max_bytes {
            return Err(SessionError::ReplayBudget);
        }
        let chunk = OutputChunk {
            seq: s.info.next_seq,
            data,
            stream,
        };
        s.info.next_seq += 1;
        s.replay_bytes = s.replay_bytes.saturating_add(chunk.data.len());
        s.replay.push_back(chunk.clone());
        while s.replay.len() > s.replay_limit {
            if let Some(front) = s.replay.pop_front() {
                s.replay_bytes = s.replay_bytes.saturating_sub(front.data.len());
            }
        }
        while s.replay_bytes > max_bytes {
            if let Some(front) = s.replay.pop_front() {
                s.replay_bytes = s.replay_bytes.saturating_sub(front.data.len());
            } else {
                break;
            }
        }
        Ok(chunk)
    }

    /// Controller-only stdin gate (active lease required).
    pub fn authorize_stdin(&self, id: &str, principal: &str, now_unix: i64) -> SessionResult<()> {
        let s = self.sessions.get(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        match &s.info.controller {
            Some(c) if c.principal_id == principal && c.is_active(now_unix) => Ok(()),
            Some(c) if c.principal_id == principal => Err(SessionError::NotController),
            Some(_) => Err(SessionError::ObserverCannotWrite),
            None => Err(SessionError::NotController),
        }
    }

    /// Principals that can read output at `now_unix`.
    ///
    /// Includes observers and the controller principal. An expired controller remains a
    /// reader (logical observer) until [`expire_stale_leases`] demotes them in storage.
    pub fn readers(&self, id: &str, now_unix: i64) -> SessionResult<HashSet<String>> {
        let s = self.sessions.get(id).ok_or(SessionError::NotFound)?;
        let mut set: HashSet<String> = s.info.observers.iter().cloned().collect();
        if let Some(c) = &s.info.controller {
            // Always retain read access for the controller principal; lease expiry only
            // strips control/stdin rights (fail closed on mutations), not observation.
            set.insert(c.principal_id.clone());
            let _ = c.is_active(now_unix);
        }
        Ok(set)
    }

    /// Fail-closed read ACL.
    pub fn authorize_reader(&self, id: &str, principal: &str, now_unix: i64) -> SessionResult<()> {
        if self.readers(id, now_unix)?.contains(principal) {
            Ok(())
        } else {
            Err(SessionError::NotReader)
        }
    }

    /// Replay from sequence (inclusive). Requires read ACL at `now_unix`.
    ///
    /// Always bounded: `limit` caps chunk count and aggregate page bytes are capped
    /// by [`MAX_REPLAY_PAGE_BYTES`]. Callers page with the next missing `seq`.
    pub fn replay_from(
        &self,
        id: &str,
        principal: &str,
        from_seq: u64,
        now_unix: i64,
    ) -> SessionResult<Vec<OutputChunk>> {
        self.replay_from_bounded(
            id,
            principal,
            from_seq,
            now_unix,
            DEFAULT_REPLAY_PAGE_LIMIT,
            MAX_REPLAY_PAGE_BYTES,
        )
        .map(|page| page.chunks)
    }

    /// Bounded replay page with explicit limits and visible truncation facts.
    pub fn replay_from_bounded(
        &self,
        id: &str,
        principal: &str,
        from_seq: u64,
        now_unix: i64,
        limit: usize,
        max_bytes: usize,
    ) -> SessionResult<ReplayPage> {
        self.authorize_reader(id, principal, now_unix)?;
        let s = self.sessions.get(id).ok_or(SessionError::NotFound)?;
        let limit = limit.clamp(1, MAX_REPLAY_PAGE_LIMIT);
        let max_bytes = max_bytes.clamp(1, MAX_REPLAY_PAGE_BYTES);
        let mut chunks = Vec::new();
        let mut bytes = 0usize;
        let mut truncated = false;
        let mut next_seq = None;
        for c in s.replay.iter().filter(|c| c.seq >= from_seq) {
            if chunks.len() >= limit || bytes.saturating_add(c.data.len()) > max_bytes {
                truncated = true;
                next_seq = Some(c.seq);
                break;
            }
            bytes = bytes.saturating_add(c.data.len());
            chunks.push(c.clone());
        }
        Ok(ReplayPage {
            chunks,
            truncated,
            next_seq,
            returned_bytes: bytes,
        })
    }

    /// Resize terminal; active controller only.
    pub fn resize(
        &mut self,
        id: &str,
        principal: &str,
        cols: u16,
        rows: u16,
        now_unix: i64,
    ) -> SessionResult<()> {
        self.authorize_controller(id, principal, now_unix)?;
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        s.info.cols = cols;
        s.info.rows = rows;
        Ok(())
    }

    /// Legacy helper: reserve+finalize input seq without a payload digest.
    /// Prefer [`Self::reserve_input_seq`] + [`Self::finalize_input_seq`] on the
    /// remote path so delivery cannot precede a durable receipt.
    pub fn advance_input_seq(&mut self, id: &str, seq: u64) -> SessionResult<u64> {
        match self.reserve_input_seq(id, seq, "")? {
            SeqReserveOutcome::Deliver { seq } | SeqReserveOutcome::RetryPending { seq } => {
                self.finalize_input_seq(id, seq)?;
                Ok(seq)
            }
            SeqReserveOutcome::Replayed { seq } => Ok(seq),
        }
    }

    /// Legacy helper: reserve+finalize resize seq without a payload digest.
    pub fn advance_resize_seq(&mut self, id: &str, seq: u64) -> SessionResult<u64> {
        match self.reserve_resize_seq(id, seq, "")? {
            SeqReserveOutcome::Deliver { seq } | SeqReserveOutcome::RetryPending { seq } => {
                self.finalize_resize_seq(id, seq)?;
                Ok(seq)
            }
            SeqReserveOutcome::Replayed { seq } => Ok(seq),
        }
    }

    /// Durably reserve the next controller input sequence **before** PTY mutation.
    ///
    /// - `seq == last+1` → `Deliver` (caller writes stdin, then finalizes)
    /// - same `seq` + same digest + `Applied` → `Replayed` (no write)
    /// - same `seq` + same digest + `Pending` → `RetryPending` (may re-write once)
    /// - same `seq` + different digest → `SequenceConflict`
    /// - stale/gap → error
    pub fn reserve_input_seq(
        &mut self,
        id: &str,
        seq: u64,
        digest: &str,
    ) -> SessionResult<SeqReserveOutcome> {
        self.reserve_controller_seq(id, seq, digest, "input", true)
    }

    /// Mark a previously reserved input sequence as applied (after successful delivery).
    pub fn finalize_input_seq(&mut self, id: &str, seq: u64) -> SessionResult<()> {
        self.finalize_controller_seq(id, seq, "input", true)
    }

    /// Durably reserve the next controller resize sequence **before** PTY mutation.
    pub fn reserve_resize_seq(
        &mut self,
        id: &str,
        seq: u64,
        digest: &str,
    ) -> SessionResult<SeqReserveOutcome> {
        self.reserve_controller_seq(id, seq, digest, "resize", false)
    }

    /// Mark a previously reserved resize sequence as applied.
    pub fn finalize_resize_seq(&mut self, id: &str, seq: u64) -> SessionResult<()> {
        self.finalize_controller_seq(id, seq, "resize", false)
    }

    fn reserve_controller_seq(
        &mut self,
        id: &str,
        seq: u64,
        digest: &str,
        kind: &str,
        input: bool,
    ) -> SessionResult<SeqReserveOutcome> {
        if seq == 0 {
            return Err(SessionError::Invalid(format!("{kind}_seq must be >= 1")));
        }
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        let (last, last_digest, last_state) = if input {
            (
                s.info.last_input_seq,
                s.info.last_input_digest.clone(),
                s.info.last_input_state,
            )
        } else {
            (
                s.info.last_resize_seq,
                s.info.last_resize_digest.clone(),
                s.info.last_resize_state,
            )
        };

        // Exact-once receipt for the current reserved/applied sequence.
        if last > 0 && seq == last {
            let prior = last_digest.unwrap_or_default();
            // Empty digest on either side only matches empty (legacy helper path).
            if prior == digest {
                return Ok(match last_state {
                    SeqReceiptState::Applied => SeqReserveOutcome::Replayed { seq },
                    SeqReceiptState::Pending | SeqReceiptState::None => {
                        SeqReserveOutcome::RetryPending { seq }
                    }
                });
            }
            return Err(SessionError::SequenceConflict {
                kind: kind.to_owned(),
                seq,
            });
        }

        let expected = last.saturating_add(1);
        if seq < expected {
            return Err(SessionError::SequenceStale {
                kind: kind.to_owned(),
                got: seq,
                last,
            });
        }
        if seq > expected {
            return Err(SessionError::SequenceGap {
                kind: kind.to_owned(),
                got: seq,
                expected,
            });
        }

        // Reserve before side effects. Digest is bound into the durable receipt.
        if input {
            s.info.last_input_seq = seq;
            s.info.last_input_digest = Some(digest.to_owned());
            s.info.last_input_state = SeqReceiptState::Pending;
        } else {
            s.info.last_resize_seq = seq;
            s.info.last_resize_digest = Some(digest.to_owned());
            s.info.last_resize_state = SeqReceiptState::Pending;
        }
        Ok(SeqReserveOutcome::Deliver { seq })
    }

    fn finalize_controller_seq(
        &mut self,
        id: &str,
        seq: u64,
        kind: &str,
        input: bool,
    ) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        let last = if input {
            s.info.last_input_seq
        } else {
            s.info.last_resize_seq
        };
        if last != seq {
            return Err(SessionError::Invalid(format!(
                "{kind}_seq finalize mismatch: reserved {last}, got {seq}"
            )));
        }
        if input {
            s.info.last_input_state = SeqReceiptState::Applied;
        } else {
            s.info.last_resize_state = SeqReceiptState::Applied;
        }
        Ok(())
    }

    /// Set view mode; active controller only.
    pub fn set_view_mode(
        &mut self,
        id: &str,
        principal: &str,
        mode: PtyViewMode,
        now_unix: i64,
    ) -> SessionResult<()> {
        self.authorize_controller(id, principal, now_unix)?;
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        s.info.view_mode = mode;
        Ok(())
    }

    pub fn set_host_pid(&mut self, id: &str, pid: Option<u32>) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        s.info.host_pid = pid;
        Ok(())
    }

    pub fn set_native_session_id(
        &mut self,
        id: &str,
        native_id: impl Into<String>,
    ) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        s.info.native_session_id = Some(native_id.into());
        Ok(())
    }

    /// Test/recovery helper: overwrite controller lease expiry without extending TTL policy.
    pub fn set_controller_expires_unix(
        &mut self,
        id: &str,
        expires_unix: i64,
    ) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        match &mut s.info.controller {
            Some(c) => {
                c.expires_unix = expires_unix;
                Ok(())
            }
            None => Err(SessionError::NotController),
        }
    }

    pub fn close(&mut self, id: &str) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        s.info.state = SessionState::Closed;
        s.info.controller = None;
        Ok(())
    }

    pub fn terminate(&mut self, id: &str) -> SessionResult<()> {
        self.close(id)?;
        self.sessions.remove(id);
        Ok(())
    }

    pub fn terminate_all(&mut self) -> usize {
        let n = self.sessions.len();
        self.sessions.clear();
        n
    }

    /// Recover stale controller leases: demote expired controllers to observers.
    pub fn expire_stale_leases(&mut self, now_unix: i64) -> usize {
        let mut n = 0;
        for s in self.sessions.values_mut() {
            if let Some(c) = &s.info.controller {
                if !c.is_active(now_unix) {
                    let p = c.principal_id.clone();
                    s.info.controller = None;
                    s.info.state = SessionState::Detached;
                    if !s.info.observers.contains(&p) {
                        s.info.observers.push(p);
                    }
                    n += 1;
                }
            }
        }
        n
    }

    /// After daemon restart: mark running PTY sessions detached (FD not preserved).
    pub fn mark_hosts_detached_after_restart(&mut self) -> usize {
        let mut n = 0;
        for s in self.sessions.values_mut() {
            if s.info.state == SessionState::Closed {
                continue;
            }
            if s.info.host_pid.is_some() || s.info.kind == SessionKind::Pty {
                s.info.host_pid = None;
                if s.info.state == SessionState::Running {
                    s.info.state = SessionState::Detached;
                    n += 1;
                }
                let _ = s.replay.push_back(OutputChunk {
                    seq: s.info.next_seq,
                    data: "[system] session host disconnected after daemon restart\n".into(),
                    stream: StreamKind::System,
                });
                s.info.next_seq += 1;
            }
        }
        n
    }

    /// Persist to JSON path.
    pub fn save_to_path(&self, path: &Path) -> SessionResult<()> {
        save_manager(path, self).map_err(|e| SessionError::Persist(e.to_string()))
    }

    /// Load from JSON path (empty manager if missing).
    pub fn load_from_path(path: &Path) -> SessionResult<Self> {
        load_manager(path).map_err(|e| SessionError::Persist(e.to_string()))
    }
}

/// Context bundle metadata for handoff between agents/humans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextBundle {
    pub session_id: String,
    pub summary: String,
    pub cwd: Option<String>,
    pub files: Vec<String>,
    pub notes: Vec<String>,
}

impl ContextBundle {
    #[must_use]
    pub fn new(session_id: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            session_id: session_id.into(),
            summary: summary.into(),
            cwd: None,
            files: vec![],
            notes: vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn handoff_human_claims_while_agent_observes() {
        let mut mgr = SessionManager::new();
        let now = 1_700_000_000;
        let ses = mgr
            .open(SessionKind::Pty, "agent-work", "chatgpt", now, None)
            .unwrap();
        mgr.push_output(&ses.id, "hello from agent\n", StreamKind::Stdout)
            .unwrap();

        let lease = mgr
            .give_controller(&ses.id, "chatgpt", "human", now + 1)
            .unwrap();
        assert_eq!(lease.principal_id, "human");
        let readers = mgr.readers(&ses.id, now + 1).unwrap();
        assert!(readers.contains("human"));
        assert!(readers.contains("chatgpt"));

        assert_eq!(
            mgr.authorize_stdin(&ses.id, "chatgpt", now + 2),
            Err(SessionError::ObserverCannotWrite)
        );
        mgr.authorize_stdin(&ses.id, "human", now + 2).unwrap();

        let replay = mgr.replay_from(&ses.id, "human", 1, now + 2).unwrap();
        assert_eq!(replay.len(), 1);
        assert!(replay[0].data.contains("hello from agent"));
    }

    #[test]
    fn give_and_release() {
        let mut mgr = SessionManager::new();
        let now = 100;
        let ses = mgr.open(SessionKind::Process, "t", "a", now, None).unwrap();
        mgr.give_controller(&ses.id, "a", "b", now).unwrap();
        assert_eq!(
            mgr.get(&ses.id)
                .unwrap()
                .controller
                .as_ref()
                .unwrap()
                .principal_id,
            "b"
        );
        mgr.release_controller(&ses.id, "b", now).unwrap();
        assert!(mgr.get(&ses.id).unwrap().controller.is_none());
        assert_eq!(mgr.get(&ses.id).unwrap().state, SessionState::Detached);
    }

    #[test]
    fn stale_lease_recovery() {
        let mut mgr = SessionManager::new();
        let ses = mgr.open(SessionKind::Pty, "t", "a", 0, None).unwrap();
        let n = mgr.expire_stale_leases(10_000_000);
        assert_eq!(n, 1);
        assert!(mgr.get(&ses.id).unwrap().controller.is_none());
        assert!(mgr.readers(&ses.id, 10_000_000).unwrap().contains("a"));
    }

    #[test]
    fn expired_controller_loses_mutations_and_stdin_fail_closed() {
        let mut mgr = SessionManager::new();
        let open_at = 1_000i64;
        let ses = mgr
            .open(SessionKind::Pty, "t", "ctrl", open_at, None)
            .unwrap();
        mgr.attach_observer(&ses.id, "obs", open_at).unwrap();
        mgr.push_output(&ses.id, "line\n", StreamKind::Stdout)
            .unwrap();

        // Force lease into the past without going through expire_stale_leases.
        mgr.set_controller_expires_unix(&ses.id, open_at + 10)
            .unwrap();
        let expired_now = open_at + 11;

        // Control / stdin mutations fail closed.
        assert_eq!(
            mgr.authorize_stdin(&ses.id, "ctrl", expired_now),
            Err(SessionError::NotController)
        );
        assert_eq!(
            mgr.give_controller(&ses.id, "ctrl", "obs", expired_now),
            Err(SessionError::NotController)
        );
        assert_eq!(
            mgr.release_controller(&ses.id, "ctrl", expired_now),
            Err(SessionError::NotController)
        );
        assert_eq!(
            mgr.resize(&ses.id, "ctrl", 80, 24, expired_now),
            Err(SessionError::NotController)
        );
        assert_eq!(
            mgr.set_view_mode(&ses.id, "ctrl", PtyViewMode::Cooked, expired_now),
            Err(SessionError::NotController)
        );
        assert_eq!(
            mgr.authorize_controller(&ses.id, "ctrl", expired_now),
            Err(SessionError::NotController)
        );

        // Read paths still allow former controller + observers.
        mgr.authorize_reader(&ses.id, "ctrl", expired_now).unwrap();
        mgr.authorize_reader(&ses.id, "obs", expired_now).unwrap();
        let replay = mgr.replay_from(&ses.id, "ctrl", 1, expired_now).unwrap();
        assert_eq!(replay.len(), 1);
        assert!(mgr.readers(&ses.id, expired_now).unwrap().contains("ctrl"));

        // Stranger cannot read.
        assert_eq!(
            mgr.authorize_reader(&ses.id, "stranger", expired_now),
            Err(SessionError::NotReader)
        );
        assert_eq!(
            mgr.replay_from(&ses.id, "stranger", 1, expired_now),
            Err(SessionError::NotReader)
        );

        // Observer may claim the expired seat.
        let lease = mgr.claim_controller(&ses.id, "obs", expired_now).unwrap();
        assert_eq!(lease.principal_id, "obs");
        mgr.authorize_stdin(&ses.id, "obs", expired_now).unwrap();
    }

    #[test]
    fn push_output_rejects_oversized_chunk_and_bounds_replay_page() {
        let mut mgr = SessionManager::new();
        let now = 1i64;
        let ses = mgr.open(SessionKind::Pty, "bound", "a", now, None).unwrap();
        let huge = "x".repeat(MAX_CHUNK_BYTES + 1);
        assert_eq!(
            mgr.push_output(&ses.id, huge, StreamKind::Stdout),
            Err(SessionError::ChunkTooLarge)
        );
        // Fill with many medium chunks; ring must not retain unbounded memory.
        for i in 0..500 {
            let data = format!("{i}:{}", "y".repeat(4096));
            let _ = mgr.push_output(&ses.id, data, StreamKind::Stdout);
        }
        let page = mgr
            .replay_from_bounded(&ses.id, "a", 1, now, 10_000, 10 * 1024 * 1024)
            .unwrap();
        assert!(page.chunks.len() <= MAX_REPLAY_PAGE_LIMIT);
        assert!(page.returned_bytes <= MAX_REPLAY_PAGE_BYTES);
        // Manager ring itself stays under budgets.
        let total: usize = page.chunks.iter().map(|c| c.data.len()).sum();
        assert!(total <= MAX_REPLAY_PAGE_BYTES);
    }

    #[test]
    fn session_count_limit_fail_closed() {
        let mut mgr = SessionManager::new();
        mgr.max_sessions = 2;
        mgr.open(SessionKind::Pty, "a", "p", 1, None).unwrap();
        mgr.open(SessionKind::Pty, "b", "p", 1, None).unwrap();
        assert_eq!(
            mgr.open(SessionKind::Pty, "c", "p", 1, None).unwrap_err(),
            SessionError::SessionLimit
        );
    }

    #[test]
    fn persistence_survives_restart_and_observer_reads() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let now = 1_000i64;

        let mut mgr = SessionManager::new();
        let ses = mgr
            .open(
                SessionKind::Pty,
                "persist-me",
                "chatgpt",
                now,
                Some("codex".into()),
            )
            .unwrap();
        mgr.push_output(&ses.id, "line-1\n", StreamKind::Stdout)
            .unwrap();
        mgr.give_controller(&ses.id, "chatgpt", "human", now + 1)
            .unwrap();
        mgr.push_output(&ses.id, "line-2-from-human\n", StreamKind::Stdout)
            .unwrap();
        mgr.set_native_session_id(&ses.id, "native_abc").unwrap();
        mgr.save_to_path(&path).unwrap();

        // Simulate daemon restart.
        let mut restored = SessionManager::load_from_path(&path).unwrap();
        restored.mark_hosts_detached_after_restart();
        let info = restored.get(&ses.id).unwrap().clone();
        assert_eq!(info.title, "persist-me");
        assert_eq!(
            info.controller.as_ref().map(|c| c.principal_id.as_str()),
            Some("human")
        );
        assert!(info.observers.iter().any(|o| o == "chatgpt"));
        assert_eq!(info.native_session_id.as_deref(), Some("native_abc"));

        let readers = restored.readers(&ses.id, now + 10).unwrap();
        assert!(readers.contains("chatgpt"));
        assert!(readers.contains("human"));

        let replay = restored
            .replay_from(&ses.id, "chatgpt", 1, now + 10)
            .unwrap();
        assert!(replay.iter().any(|c| c.data.contains("line-1")));
        assert!(replay.iter().any(|c| c.data.contains("line-2-from-human")));

        // Observer still cannot write after restore.
        assert_eq!(
            restored.authorize_stdin(&ses.id, "chatgpt", now + 10),
            Err(SessionError::ObserverCannotWrite)
        );
    }

    #[test]
    fn resize_and_view_mode() {
        let mut mgr = SessionManager::new();
        let now = 1i64;
        let ses = mgr.open(SessionKind::Pty, "t", "a", now, None).unwrap();
        mgr.resize(&ses.id, "a", 120, 40, now).unwrap();
        mgr.set_view_mode(&ses.id, "a", PtyViewMode::Cooked, now)
            .unwrap();
        let info = mgr.get(&ses.id).unwrap();
        assert_eq!(info.cols, 120);
        assert_eq!(info.rows, 40);
        assert_eq!(info.view_mode, PtyViewMode::Cooked);
    }

    #[test]
    fn input_and_resize_sequences_are_monotonic_gap_free() {
        let mut mgr = SessionManager::new();
        let ses = mgr.open(SessionKind::Pty, "t", "a", 1, None).unwrap();
        assert_eq!(mgr.advance_input_seq(&ses.id, 1).unwrap(), 1);
        assert_eq!(mgr.advance_input_seq(&ses.id, 2).unwrap(), 2);
        // Same seq + empty digest after apply is an exact-once replay, not stale.
        assert_eq!(mgr.advance_input_seq(&ses.id, 2).unwrap(), 2);
        assert_eq!(
            mgr.advance_input_seq(&ses.id, 4).unwrap_err(),
            SessionError::SequenceGap {
                kind: "input".into(),
                got: 4,
                expected: 3,
            }
        );
        assert_eq!(mgr.advance_resize_seq(&ses.id, 1).unwrap(), 1);
        assert_eq!(
            mgr.advance_resize_seq(&ses.id, 3).unwrap_err(),
            SessionError::SequenceGap {
                kind: "resize".into(),
                got: 3,
                expected: 2,
            }
        );
        let info = mgr.get(&ses.id).unwrap();
        assert_eq!(info.last_input_seq, 2);
        assert_eq!(info.last_resize_seq, 1);
    }

    #[test]
    fn input_seq_binds_payload_digest_before_side_effects() {
        let mut mgr = SessionManager::new();
        let ses = mgr.open(SessionKind::Pty, "t", "a", 1, None).unwrap();
        assert_eq!(
            mgr.reserve_input_seq(&ses.id, 1, "digest-a").unwrap(),
            SeqReserveOutcome::Deliver { seq: 1 }
        );
        // Stale/gap still rejected while pending.
        assert!(matches!(
            mgr.reserve_input_seq(&ses.id, 1, "digest-b").unwrap_err(),
            SessionError::SequenceConflict { seq: 1, .. }
        ));
        assert_eq!(
            mgr.reserve_input_seq(&ses.id, 1, "digest-a").unwrap(),
            SeqReserveOutcome::RetryPending { seq: 1 }
        );
        mgr.finalize_input_seq(&ses.id, 1).unwrap();
        assert_eq!(
            mgr.reserve_input_seq(&ses.id, 1, "digest-a").unwrap(),
            SeqReserveOutcome::Replayed { seq: 1 }
        );
        assert!(matches!(
            mgr.reserve_input_seq(&ses.id, 1, "digest-other")
                .unwrap_err(),
            SessionError::SequenceConflict { .. }
        ));
        assert_eq!(
            mgr.reserve_input_seq(&ses.id, 2, "digest-c").unwrap(),
            SeqReserveOutcome::Deliver { seq: 2 }
        );
    }
}
