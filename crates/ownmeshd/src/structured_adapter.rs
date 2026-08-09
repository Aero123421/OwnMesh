//! Bounded, explicit child-stdio protocol drivers for official adapters.
//!
//! This module deliberately does not execute a child or open a network socket.
//! The persistent session supervisor owns both; this state machine only turns
//! documented protocol responses into the next <=64KiB LF frame.

use ownmesh_profiles::AdapterDialect;
use serde_json::{json, Value};

pub const MAX_STRUCTURED_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
enum DriverPhase {
    ArgvOnly,
    PiPrompted,
    CodexAwaitInitialize,
    CodexAwaitThread,
    CodexAwaitTurn,
    AcpAwaitInitialize,
    AcpAwaitSession,
    AcpAwaitPrompt,
    Complete,
}

/// Stateful, correlation-checked bootstrap for a structured vendor child.
/// Native ids and prompt text never enter shell syntax: every value is encoded
/// in a JSON request body and every produced frame is LF terminated.
#[derive(Debug, Clone)]
pub struct StructuredAdapterDriver {
    prompt: String,
    native_session_id: Option<String>,
    phase: DriverPhase,
    thread_or_session_id: Option<String>,
}

impl StructuredAdapterDriver {
    pub fn new(
        dialect: AdapterDialect,
        prompt: Option<&str>,
        native_session_id: Option<&str>,
    ) -> Result<Self, String> {
        let prompt = prompt.unwrap_or_default();
        if prompt.len() > MAX_STRUCTURED_FRAME_BYTES / 2 || prompt.contains('\0') {
            return Err("structured adapter prompt exceeds bounded frame policy".into());
        }
        if native_session_id.is_some_and(|id| {
            id.is_empty() || id.len() > 512 || id.chars().any(char::is_control)
        }) {
            return Err("invalid structured adapter native session id".into());
        }
        let phase = match dialect {
            AdapterDialect::CodexAppServer => DriverPhase::CodexAwaitInitialize,
            AdapterDialect::PiRpc => DriverPhase::PiPrompted,
            AdapterDialect::KimiAcp
            | AdapterDialect::QwenAcp
            | AdapterDialect::HermesAcp
            | AdapterDialect::QoderAcp => DriverPhase::AcpAwaitInitialize,
            // These profiles receive their documented prompt as one argv item;
            // their stdout still travels through the structured pipe/spool.
            AdapterDialect::ClaudeStreamJson | AdapterDialect::AgyStreamJson => DriverPhase::ArgvOnly,
            // OpenCode's documented API is local HTTP.  The sidecar does not
            // create listeners, so it remains explicitly unavailable here.
            AdapterDialect::OpenCodeServer => return Err("OpenCode local HTTP driver is not enabled".into()),
        };
        Ok(Self {
            prompt: prompt.into(),
            native_session_id: native_session_id.map(str::to_owned),
            phase,
            thread_or_session_id: None,
        })
    }

    /// Produce the initial protocol frames.  Caller writes each frame through
    /// `SupervisorClient::write`, which enforces the same 64KiB LF boundary.
    pub fn start(&self) -> Result<Vec<Vec<u8>>, String> {
        match self.phase {
            DriverPhase::ArgvOnly => Ok(vec![]),
            DriverPhase::PiPrompted => Ok(vec![frame(json!({
                "id": "ownmesh-prompt-1", "type": "prompt", "message": self.prompt,
            }))?]),
            DriverPhase::CodexAwaitInitialize => Ok(vec![
                frame(json!({
                    "jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {"clientInfo": {"name": "ownmesh", "version": "1.2"}},
                }))?,
                frame(json!({"jsonrpc": "2.0", "method": "initialized", "params": {}}))?,
            ]),
            DriverPhase::AcpAwaitInitialize => Ok(vec![frame(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "ownmesh", "version": "1.2"}},
            }))?]),
            _ => Err("structured adapter bootstrap already started".into()),
        }
    }

    /// Accept precisely one child LF record and return any correlated successor
    /// requests.  Notifications are retained by the caller's raw spool but do
    /// not advance state. Unknown permission/approval requests fail closed.
    pub fn on_record(&mut self, record: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if record.len() > MAX_STRUCTURED_FRAME_BYTES || !record.ends_with(b"\n") {
            return Err("structured adapter record must be LF terminated and <= 64KiB".into());
        }
        let value: Value = serde_json::from_slice(&record[..record.len() - 1])
            .map_err(|_| "malformed structured adapter JSON record")?;
        if let Some(method) = value.get("method").and_then(Value::as_str) {
            if method.contains("permission") || method.contains("approval") {
                return Err("structured adapter requested unapproved permission".into());
            }
        }
        match self.phase {
            DriverPhase::CodexAwaitInitialize if response_id(&value) == Some(1) => {
                self.phase = DriverPhase::CodexAwaitThread;
                let request = match &self.native_session_id {
                    Some(id) => json!({"jsonrpc":"2.0","id":2,"method":"thread/resume","params":{"threadId":id}}),
                    None => json!({"jsonrpc":"2.0","id":2,"method":"thread/start","params":{}}),
                };
                Ok(vec![frame(request)?])
            }
            DriverPhase::CodexAwaitThread if response_id(&value) == Some(2) => {
                let id = extract_id(&value, &["thread", "id"])
                    .or_else(|| extract_string(&value, "threadId"))
                    .ok_or("Codex thread response omitted thread id")?;
                self.thread_or_session_id = Some(id.clone());
                self.phase = DriverPhase::CodexAwaitTurn;
                Ok(vec![frame(json!({
                    "jsonrpc":"2.0", "id":3, "method":"turn/start",
                    "params":{"threadId":id, "input":[{"type":"text","text":self.prompt}]},
                }))?])
            }
            DriverPhase::CodexAwaitTurn | DriverPhase::AcpAwaitPrompt
                if response_id(&value) == Some(3) =>
            {
                self.phase = DriverPhase::Complete;
                Ok(vec![])
            }
            DriverPhase::AcpAwaitInitialize if response_id(&value) == Some(1) => {
                let method = if self.native_session_id.is_some() {
                    if !acp_supports_load(&value) {
                        return Err("ACP peer did not negotiate session/load".into());
                    }
                    "session/load"
                } else {
                    "session/new"
                };
                self.phase = DriverPhase::AcpAwaitSession;
                let params = match &self.native_session_id {
                    Some(id) => json!({"sessionId":id}),
                    None => json!({}),
                };
                Ok(vec![frame(json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}))?])
            }
            DriverPhase::AcpAwaitSession if response_id(&value) == Some(2) => {
                let id = extract_string(&value, "sessionId")
                    .or_else(|| extract_id(&value, &["session", "id"]))
                    .ok_or("ACP session response omitted session id")?;
                self.thread_or_session_id = Some(id.clone());
                self.phase = DriverPhase::AcpAwaitPrompt;
                Ok(vec![frame(json!({
                    "jsonrpc":"2.0", "id":3, "method":"session/prompt",
                    "params":{"sessionId":id, "prompt":[{"type":"text","text":self.prompt}]},
                }))?])
            }
            // Non-correlated events are output, not control replies.
            _ => Ok(vec![]),
        }
    }

    #[must_use]
    pub fn native_session_id(&self) -> Option<&str> {
        self.thread_or_session_id.as_deref().or(self.native_session_id.as_deref())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(self.phase, DriverPhase::ArgvOnly | DriverPhase::PiPrompted | DriverPhase::Complete)
    }

}

fn frame(value: Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(&value).map_err(|e| format!("encode structured request: {e}"))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_STRUCTURED_FRAME_BYTES {
        return Err("structured adapter request exceeds 64KiB".into());
    }
    Ok(bytes)
}

fn response_id(value: &Value) -> Option<u64> {
    value.get("id").and_then(Value::as_u64)
}

fn extract_string(value: &Value, key: &str) -> Option<String> {
    value.get("result")?.get(key)?.as_str().map(str::to_owned)
}

fn extract_id(value: &Value, path: &[&str]) -> Option<String> {
    let mut current = value.get("result")?;
    for key in path {
        current = current.get(*key)?;
    }
    current.as_str().map(str::to_owned)
}

fn acp_supports_load(value: &Value) -> bool {
    value
        .get("result")
        .and_then(|result| result.get("capabilities"))
        .and_then(Value::as_object)
        .is_some_and(|caps| {
            caps.get("session/load").and_then(Value::as_bool) == Some(true)
                || caps.get("loadSession").and_then(Value::as_bool) == Some(true)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi_uses_documented_strict_lf_prompt_frame() {
        let driver = StructuredAdapterDriver::new(AdapterDialect::PiRpc, Some("hello"), None).unwrap();
        assert_eq!(driver.start().unwrap(), vec![b"{\"id\":\"ownmesh-prompt-1\",\"message\":\"hello\",\"type\":\"prompt\"}\n"]);
        assert!(driver.is_complete());
    }

    #[test]
    fn codex_waits_for_thread_id_before_turn() {
        let mut driver = StructuredAdapterDriver::new(AdapterDialect::CodexAppServer, Some("ship it"), None).unwrap();
        assert_eq!(driver.start().unwrap().len(), 2);
        let thread = driver.on_record(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n").unwrap();
        assert!(String::from_utf8_lossy(&thread[0]).contains("thread/start"));
        let turn = driver.on_record(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"thread\":{\"id\":\"thr_1\"}}}\n").unwrap();
        assert!(String::from_utf8_lossy(&turn[0]).contains("turn/start"));
        assert_eq!(driver.native_session_id(), Some("thr_1"));
    }

    #[test]
    fn acp_resume_is_capability_gated_and_permissions_fail_closed() {
        let mut driver = StructuredAdapterDriver::new(AdapterDialect::KimiAcp, Some("hello"), Some("native_1")).unwrap();
        driver.start().unwrap();
        assert!(driver.on_record(b"{\"id\":1,\"result\":{\"capabilities\":{}}}\n").is_err());
        assert!(driver.on_record(b"{\"method\":\"session/request_permission\",\"params\":{}}\n").is_err());
    }
}
