//! OwnMesh interactive session model and handoff primitives.
//!
//! Multiple observers, single controller lease, claim/release/give.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
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
    #[error("observer cannot write stdin")]
    ObserverCannotWrite,
    #[error("session closed")]
    Closed,
    #[error("invalid argument: {0}")]
    Invalid(String),
}

pub type SessionResult<T> = Result<T, SessionError>;

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
    pub expires_unix: i64,
}

/// Session snapshot for API/TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    pub kind: SessionKind,
    pub state: SessionState,
    pub title: String,
    pub controller: Option<ControllerLease>,
    pub observers: Vec<String>,
    pub cols: u16,
    pub rows: u16,
    pub next_seq: u64,
    pub profile_id: Option<String>,
}

/// In-memory session record.
#[derive(Debug)]
struct Session {
    info: SessionInfo,
    replay: VecDeque<OutputChunk>,
    replay_limit: usize,
}

/// Session manager (process-local; daemon owns one).
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: HashMap<String, Session>,
    default_replay_limit: usize,
    default_lease_ttl_secs: i64,
}

impl SessionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            default_replay_limit: 10_000,
            default_lease_ttl_secs: 3600,
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
    ) -> SessionInfo {
        let id = format!("ses_{}", Uuid::new_v4().simple());
        let creator = creator.into();
        let lease = ControllerLease {
            principal_id: creator.clone(),
            lease_id: format!("lease_{}", Uuid::new_v4().simple()),
            expires_unix: now_unix + self.default_lease_ttl_secs,
        };
        let info = SessionInfo {
            id: id.clone(),
            kind,
            state: SessionState::Running,
            title: title.into(),
            controller: Some(lease),
            observers: vec![],
            cols: 80,
            rows: 24,
            next_seq: 1,
            profile_id,
        };
        self.sessions.insert(
            id,
            Session {
                info: info.clone(),
                replay: VecDeque::new(),
                replay_limit: self.default_replay_limit,
            },
        );
        info
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

    /// Attach as observer (no stdin).
    pub fn attach_observer(&mut self, id: &str, principal: impl Into<String>) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        let p = principal.into();
        if !s.info.observers.contains(&p)
            && s.info
                .controller
                .as_ref()
                .map(|c| c.principal_id != p)
                .unwrap_or(true)
        {
            s.info.observers.push(p);
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
            if cur.principal_id != principal && cur.expires_unix > now_unix {
                return Err(SessionError::LeaseHeld(cur.principal_id.clone()));
            }
        }
        // Remove from observers if present.
        s.info.observers.retain(|o| o != &principal);
        let lease = ControllerLease {
            principal_id: principal,
            lease_id: format!("lease_{}", Uuid::new_v4().simple()),
            expires_unix: now_unix + self.default_lease_ttl_secs,
        };
        s.info.controller = Some(lease.clone());
        s.info.state = SessionState::Running;
        Ok(lease)
    }

    /// Give controller to another principal.
    pub fn give_controller(
        &mut self,
        id: &str,
        from: &str,
        to: impl Into<String>,
        now_unix: i64,
    ) -> SessionResult<ControllerLease> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        match &s.info.controller {
            Some(c) if c.principal_id == from => {}
            Some(c) => return Err(SessionError::LeaseHeld(c.principal_id.clone())),
            None => return Err(SessionError::NotController),
        }
        // Previous controller becomes observer.
        if !s.info.observers.iter().any(|o| o == from) {
            s.info.observers.push(from.to_string());
        }
        let to = to.into();
        s.info.observers.retain(|o| o != &to);
        let lease = ControllerLease {
            principal_id: to,
            lease_id: format!("lease_{}", Uuid::new_v4().simple()),
            expires_unix: now_unix + self.default_lease_ttl_secs,
        };
        s.info.controller = Some(lease.clone());
        Ok(lease)
    }

    /// Release controller (session becomes detached; observers remain).
    pub fn release_controller(&mut self, id: &str, principal: &str) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        match &s.info.controller {
            Some(c) if c.principal_id == principal => {
                if !s.info.observers.iter().any(|o| o == principal) {
                    s.info.observers.push(principal.to_string());
                }
                s.info.controller = None;
                s.info.state = SessionState::Detached;
                Ok(())
            }
            Some(_) => Err(SessionError::NotController),
            None => Ok(()),
        }
    }

    /// Append output visible to controller + observers.
    pub fn push_output(
        &mut self,
        id: &str,
        data: impl Into<String>,
        stream: StreamKind,
    ) -> SessionResult<OutputChunk> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        let chunk = OutputChunk {
            seq: s.info.next_seq,
            data: data.into(),
            stream,
        };
        s.info.next_seq += 1;
        s.replay.push_back(chunk.clone());
        while s.replay.len() > s.replay_limit {
            s.replay.pop_front();
        }
        Ok(chunk)
    }

    /// Controller-only stdin gate.
    pub fn authorize_stdin(&self, id: &str, principal: &str, now_unix: i64) -> SessionResult<()> {
        let s = self.sessions.get(id).ok_or(SessionError::NotFound)?;
        if s.info.state == SessionState::Closed {
            return Err(SessionError::Closed);
        }
        match &s.info.controller {
            Some(c) if c.principal_id == principal && c.expires_unix > now_unix => Ok(()),
            Some(c) if c.principal_id == principal => Err(SessionError::NotController),
            Some(_) => Err(SessionError::ObserverCannotWrite),
            None => Err(SessionError::NotController),
        }
    }

    /// Replay from sequence (inclusive).
    pub fn replay_from(&self, id: &str, from_seq: u64) -> SessionResult<Vec<OutputChunk>> {
        let s = self.sessions.get(id).ok_or(SessionError::NotFound)?;
        Ok(s.replay
            .iter()
            .filter(|c| c.seq >= from_seq)
            .cloned()
            .collect())
    }

    pub fn resize(&mut self, id: &str, cols: u16, rows: u16) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        s.info.cols = cols;
        s.info.rows = rows;
        Ok(())
    }

    pub fn close(&mut self, id: &str) -> SessionResult<()> {
        let s = self.sessions.get_mut(id).ok_or(SessionError::NotFound)?;
        s.info.state = SessionState::Closed;
        s.info.controller = None;
        Ok(())
    }

    /// Recover stale controller leases.
    pub fn expire_stale_leases(&mut self, now_unix: i64) -> usize {
        let mut n = 0;
        for s in self.sessions.values_mut() {
            if let Some(c) = &s.info.controller {
                if c.expires_unix <= now_unix {
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

    /// Principals that can read output.
    pub fn readers(&self, id: &str) -> SessionResult<HashSet<String>> {
        let s = self.sessions.get(id).ok_or(SessionError::NotFound)?;
        let mut set: HashSet<String> = s.info.observers.iter().cloned().collect();
        if let Some(c) = &s.info.controller {
            set.insert(c.principal_id.clone());
        }
        Ok(set)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_human_claims_while_agent_observes() {
        let mut mgr = SessionManager::new();
        let now = 1_700_000_000;
        let ses = mgr.open(SessionKind::Pty, "agent-work", "chatgpt", now, None);
        mgr.push_output(&ses.id, "hello from agent\n", StreamKind::Stdout)
            .unwrap();

        // Agent hands controller to human (give); agent remains readable as observer.
        let lease = mgr
            .give_controller(&ses.id, "chatgpt", "human", now + 1)
            .unwrap();
        assert_eq!(lease.principal_id, "human");
        let readers = mgr.readers(&ses.id).unwrap();
        assert!(readers.contains("human"));
        assert!(readers.contains("chatgpt"));

        // Observer cannot write stdin.
        assert_eq!(
            mgr.authorize_stdin(&ses.id, "chatgpt", now + 2),
            Err(SessionError::ObserverCannotWrite)
        );
        mgr.authorize_stdin(&ses.id, "human", now + 2).unwrap();

        let replay = mgr.replay_from(&ses.id, 1).unwrap();
        assert_eq!(replay.len(), 1);
        assert!(replay[0].data.contains("hello from agent"));
    }

    #[test]
    fn give_and_release() {
        let mut mgr = SessionManager::new();
        let now = 100;
        let ses = mgr.open(SessionKind::Process, "t", "a", now, None);
        mgr.give_controller(&ses.id, "a", "b", now).unwrap();
        assert_eq!(
            mgr.get(&ses.id).unwrap().controller.as_ref().unwrap().principal_id,
            "b"
        );
        mgr.release_controller(&ses.id, "b").unwrap();
        assert!(mgr.get(&ses.id).unwrap().controller.is_none());
        assert_eq!(mgr.get(&ses.id).unwrap().state, SessionState::Detached);
    }

    #[test]
    fn stale_lease_recovery() {
        let mut mgr = SessionManager::new();
        let ses = mgr.open(SessionKind::Pty, "t", "a", 0, None);
        // Force expire
        let n = mgr.expire_stale_leases(10_000_000);
        assert_eq!(n, 1);
        assert!(mgr.get(&ses.id).unwrap().controller.is_none());
    }
}
