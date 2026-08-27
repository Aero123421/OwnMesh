//! Bounded, explicit child-stdio protocol drivers for official adapters.
//!
//! This module deliberately does not execute a child or open a network socket.
//! The persistent session supervisor owns both; this state machine only turns
//! documented protocol responses into the next <=64KiB LF frame.

use ownmesh_profiles::AdapterDialect;
use serde_json::{json, Value};
use std::path::Path;

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
    dialect: AdapterDialect,
    prompt: Option<String>,
    native_session_id: Option<String>,
    cwd: String,
    phase: DriverPhase,
    thread_or_session_id: Option<String>,
}

impl StructuredAdapterDriver {
    pub fn new(
        dialect: AdapterDialect,
        prompt: Option<&str>,
        native_session_id: Option<&str>,
        cwd: &str,
    ) -> Result<Self, String> {
        if prompt.is_some_and(|value| {
            value.len() > MAX_STRUCTURED_FRAME_BYTES / 2 || value.contains('\0')
        }) {
            return Err("structured adapter prompt exceeds bounded frame policy".into());
        }
        if matches!(
            dialect,
            AdapterDialect::ClaudeStreamJson | AdapterDialect::AgyStreamJson
        ) && prompt.is_none()
        {
            return Err("one-shot structured adapter requires an explicit prompt".into());
        }
        if native_session_id
            .is_some_and(|id| id.is_empty() || id.len() > 512 || id.chars().any(char::is_control))
        {
            return Err("invalid structured adapter native session id".into());
        }
        if !Path::new(cwd).is_absolute() {
            return Err("ACP structured adapter requires an absolute cwd".into());
        }
        let phase = match dialect {
            AdapterDialect::CodexAppServer => DriverPhase::CodexAwaitInitialize,
            AdapterDialect::PiRpc => DriverPhase::PiPrompted,
            AdapterDialect::KimiAcp
            | AdapterDialect::OpenCodeServer
            | AdapterDialect::QwenAcp
            | AdapterDialect::HermesAcp
            | AdapterDialect::QoderAcp => DriverPhase::AcpAwaitInitialize,
            // These profiles receive their documented prompt as one argv item;
            // their stdout still travels through the structured pipe/spool.
            AdapterDialect::ClaudeStreamJson | AdapterDialect::AgyStreamJson => {
                DriverPhase::ArgvOnly
            }
        };
        Ok(Self {
            dialect,
            prompt: prompt.map(str::to_owned),
            native_session_id: native_session_id.map(str::to_owned),
            cwd: cwd.into(),
            phase,
            thread_or_session_id: None,
        })
    }

    /// Produce the initial protocol frames.  Caller writes each frame through
    /// `SupervisorClient::write`, which enforces the same 64KiB LF boundary.
    pub fn start(&self) -> Result<Vec<Vec<u8>>, String> {
        match self.phase {
            DriverPhase::ArgvOnly => Ok(vec![]),
            DriverPhase::PiPrompted => self.prompt.as_ref().map_or_else(
                || Ok(vec![]),
                |prompt| {
                    Ok(vec![frame(json!({
                        "id": "ownmesh-prompt-1", "type": "prompt", "message": prompt,
                    }))?])
                },
            ),
            // App-server uses JSON-RPC semantics but explicitly omits the
            // `jsonrpc` member on its stdio JSONL wire format.
            DriverPhase::CodexAwaitInitialize => Ok(vec![frame(json!({
                "id": 1, "method": "initialize",
                "params": {"clientInfo": {"name": "ownmesh", "version": "1.2"}},
            }))?]),
            DriverPhase::AcpAwaitInitialize => Ok(vec![frame(json!({
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": 1,
                    "clientCapabilities": {
                        "fs": {"readTextFile": false, "writeTextFile": false},
                        "terminal": false,
                    },
                    "clientInfo": {"name": "ownmesh", "version": "1.2"},
                },
            }))?]),
            _ => Err("structured adapter bootstrap already started".into()),
        }
    }

    /// Accept precisely one child LF record and return any correlated successor
    /// requests. Notifications are retained by the caller's raw spool but do
    /// not advance state. Permission/client-capability requests receive a
    /// correlated, typed fail-closed response and never advance bootstrap.
    pub fn on_record(&mut self, record: &[u8]) -> Result<Vec<Vec<u8>>, String> {
        if record.len() > MAX_STRUCTURED_FRAME_BYTES || !record.ends_with(b"\n") {
            return Err("structured adapter record must be LF terminated and <= 64KiB".into());
        }
        let value: Value = serde_json::from_slice(&record[..record.len() - 1])
            .map_err(|_| "malformed structured adapter JSON record")?;
        if let Some(response) = fail_closed_protocol_response(self.dialect, &value) {
            return Ok(vec![frame(response)?]);
        }
        if value.get("error").is_some() {
            return Err("structured adapter returned a JSON-RPC error".into());
        }
        match self.phase {
            DriverPhase::CodexAwaitInitialize if response_id(&value) == Some(1) => {
                require_result_object(&value, "Codex initialize")?;
                self.phase = DriverPhase::CodexAwaitThread;
                let request = match &self.native_session_id {
                    Some(id) => json!({"id":2,"method":"thread/resume","params":{"threadId":id}}),
                    None => json!({"id":2,"method":"thread/start","params":{}}),
                };
                Ok(vec![
                    frame(json!({"method":"initialized","params":{}}))?,
                    frame(request)?,
                ])
            }
            DriverPhase::CodexAwaitThread if response_id(&value) == Some(2) => {
                let id = extract_id(&value, &["thread", "id"])
                    .or_else(|| extract_string(&value, "threadId"))
                    .ok_or("Codex thread response omitted thread id")?;
                self.thread_or_session_id = Some(id.clone());
                if let Some(prompt) = self.prompt.as_deref() {
                    self.phase = DriverPhase::CodexAwaitTurn;
                    Ok(vec![frame(json!({
                        "id":3, "method":"turn/start",
                        "params":{"threadId":id, "input":[{"type":"text","text":prompt}]},
                    }))?])
                } else {
                    self.phase = DriverPhase::Complete;
                    Ok(vec![])
                }
            }
            DriverPhase::CodexAwaitTurn | DriverPhase::AcpAwaitPrompt
                if response_id(&value) == Some(3) =>
            {
                if matches!(self.phase, DriverPhase::CodexAwaitTurn) {
                    require_result_object(&value, "Codex turn/start")?;
                } else if value
                    .get("result")
                    .and_then(|r| r.get("stopReason"))
                    .and_then(Value::as_str)
                    .is_none()
                {
                    return Err("ACP session/prompt response omitted stopReason".into());
                }
                self.phase = DriverPhase::Complete;
                Ok(vec![])
            }
            DriverPhase::AcpAwaitInitialize if response_id(&value) == Some(1) => {
                let result = require_result_object(&value, "ACP initialize")?;
                if result.get("protocolVersion").and_then(Value::as_u64) != Some(1) {
                    return Err("ACP peer did not negotiate protocolVersion 1".into());
                }
                let capabilities = result
                    .get("agentCapabilities")
                    .and_then(Value::as_object)
                    .ok_or("ACP initialize response omitted agentCapabilities")?;
                let method = if self.native_session_id.is_some() {
                    if capabilities.get("loadSession").and_then(Value::as_bool) != Some(true) {
                        return Err("ACP peer did not negotiate session/load".into());
                    }
                    "session/load"
                } else {
                    "session/new"
                };
                self.phase = DriverPhase::AcpAwaitSession;
                let params = match &self.native_session_id {
                    Some(id) => json!({"sessionId":id, "cwd": self.cwd, "mcpServers": []}),
                    None => json!({"cwd": self.cwd, "mcpServers": []}),
                };
                Ok(vec![frame(
                    json!({"jsonrpc":"2.0","id":2,"method":method,"params":params}),
                )?])
            }
            DriverPhase::AcpAwaitSession if response_id(&value) == Some(2) => {
                let id = if self.native_session_id.is_some() {
                    require_result_object(&value, "ACP session/load")?;
                    self.native_session_id
                        .clone()
                        .ok_or("ACP native session id disappeared")?
                } else {
                    extract_string(&value, "sessionId")
                        .ok_or("ACP session/new response omitted sessionId")?
                };
                self.thread_or_session_id = Some(id.clone());
                if let Some(prompt) = self.prompt.as_deref() {
                    self.phase = DriverPhase::AcpAwaitPrompt;
                    Ok(vec![frame(json!({
                        "jsonrpc":"2.0", "id":3, "method":"session/prompt",
                        "params":{"sessionId":id, "prompt":[{"type":"text","text":prompt}]},
                    }))?])
                } else {
                    self.phase = DriverPhase::Complete;
                    Ok(vec![])
                }
            }
            // Non-correlated events are output, not control replies.
            _ => Ok(vec![]),
        }
    }

    #[must_use]
    pub fn native_session_id(&self) -> Option<&str> {
        self.thread_or_session_id
            .as_deref()
            .or(self.native_session_id.as_deref())
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        matches!(
            self.phase,
            DriverPhase::ArgvOnly | DriverPhase::PiPrompted | DriverPhase::Complete
        )
    }

    /// Session open is ready once the bounded prompt request has been accepted
    /// for delivery. A `turn/start`/`session/prompt` response represents model
    /// completion and may take arbitrarily longer than the handshake.
    #[must_use]
    pub fn is_open_ready(&self) -> bool {
        self.is_complete()
            || matches!(
                self.phase,
                DriverPhase::CodexAwaitTurn | DriverPhase::AcpAwaitPrompt
            )
    }
}

/// Build the only automatic responses OwnMesh may send to agent-initiated
/// requests. These responses are deliberately denial-only: vendor payloads
/// are output facts, never authority to execute a device operation.
#[must_use]
pub fn fail_closed_protocol_response(dialect: AdapterDialect, value: &Value) -> Option<Value> {
    let method = value.get("method")?.as_str()?;
    let id = value.get("id")?.clone();
    match dialect {
        AdapterDialect::KimiAcp
        | AdapterDialect::OpenCodeServer
        | AdapterDialect::QwenAcp
        | AdapterDialect::HermesAcp
        | AdapterDialect::QoderAcp => {
            if method == "session/request_permission" {
                let reject_id = value
                    .pointer("/params/options")
                    .and_then(Value::as_array)
                    .and_then(|options| {
                        options.iter().find_map(|option| {
                            let kind = option.get("kind")?.as_str()?;
                            kind.starts_with("reject_")
                                .then(|| option.get("optionId")?.as_str().map(str::to_owned))
                                .flatten()
                        })
                    });
                let outcome = reject_id.map_or_else(
                    || json!({"outcome":"cancelled"}),
                    |option_id| json!({"outcome":"selected","optionId":option_id}),
                );
                return Some(json!({"jsonrpc":"2.0","id":id,"result":{"outcome":outcome}}));
            }
            if method.starts_with("fs/") || method.starts_with("terminal/") {
                return Some(json!({
                    "jsonrpc":"2.0",
                    "id":id,
                    "error":{"code":-32601,"message":"capability_not_advertised"}
                }));
            }
            None
        }
        AdapterDialect::CodexAppServer => {
            if method.ends_with("/requestApproval") {
                Some(json!({"id":id,"result":{"decision":"decline"}}))
            } else if method == "item/tool/requestUserInput"
                || method == "mcpServer/elicitation/request"
            {
                Some(json!({
                    "id":id,
                    "error":{"code":-32601,"message":"capability_not_advertised"}
                }))
            } else {
                None
            }
        }
        AdapterDialect::ClaudeStreamJson
        | AdapterDialect::PiRpc
        | AdapterDialect::AgyStreamJson => None,
    }
}

/// Parse one bounded LF record and encode a correlated denial when it is an
/// agent-initiated permission or unadvertised client-capability request.
pub fn fail_closed_protocol_frame(
    dialect: AdapterDialect,
    record: &[u8],
) -> Result<Option<Vec<u8>>, String> {
    if record.len() > MAX_STRUCTURED_FRAME_BYTES || !record.ends_with(b"\n") {
        return Err("structured adapter record must be LF terminated and <= 64KiB".into());
    }
    let value: Value = serde_json::from_slice(&record[..record.len() - 1])
        .map_err(|_| "malformed structured adapter JSON record")?;
    fail_closed_protocol_response(dialect, &value)
        .map(frame)
        .transpose()
}

/// Encode the documented reusable-session cancellation operation. One-shot
/// stream-json adapters deliberately return a typed degraded reason instead of
/// inventing a wire command.
pub fn cancel_protocol_frame(
    dialect: AdapterDialect,
    native_session_id: &str,
    active_turn_id: Option<&str>,
    request_id: &str,
) -> Result<Vec<u8>, String> {
    if native_session_id.is_empty()
        || native_session_id.len() > 512
        || native_session_id.chars().any(char::is_control)
        || request_id.is_empty()
        || request_id.len() > 128
        || request_id.chars().any(char::is_control)
    {
        return Err("invalid structured adapter cancellation binding".into());
    }
    match dialect {
        AdapterDialect::CodexAppServer => {
            let turn_id = active_turn_id
                .filter(|id| !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control))
                .ok_or("capability_not_advertised: active Codex turn id unavailable")?;
            frame(json!({
                "id":request_id,
                "method":"turn/interrupt",
                "params":{"threadId":native_session_id,"turnId":turn_id}
            }))
        }
        AdapterDialect::KimiAcp
        | AdapterDialect::OpenCodeServer
        | AdapterDialect::QwenAcp
        | AdapterDialect::HermesAcp
        | AdapterDialect::QoderAcp => frame(json!({
            "jsonrpc":"2.0",
            "method":"session/cancel",
            "params":{"sessionId":native_session_id}
        })),
        AdapterDialect::PiRpc => frame(json!({"id":request_id,"type":"abort"})),
        AdapterDialect::ClaudeStreamJson | AdapterDialect::AgyStreamJson => {
            Err("capability_not_advertised: reusable cancellation is not documented".into())
        }
    }
}

/// Recover the latest public Codex turn id from a bounded replay page. This is
/// used only to bind `turn/interrupt`; no item content is retained or emitted.
#[must_use]
pub fn latest_codex_turn_id(page: &[u8]) -> Option<String> {
    page.split(|byte| *byte == b'\n').rev().find_map(|record| {
        if record.is_empty() || record.len() > MAX_STRUCTURED_FRAME_BYTES {
            return None;
        }
        let value: Value = serde_json::from_slice(record).ok()?;
        if value.get("method").and_then(Value::as_str) != Some("turn/started") {
            return None;
        }
        value
            .pointer("/params/turn/id")
            .or_else(|| value.pointer("/params/turnId"))
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control))
            .map(str::to_owned)
    })
}

fn frame(value: Value) -> Result<Vec<u8>, String> {
    let mut bytes =
        serde_json::to_vec(&value).map_err(|e| format!("encode structured request: {e}"))?;
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

fn require_result_object<'a>(
    value: &'a Value,
    what: &str,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    value
        .get("result")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{what} response omitted object result"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi_uses_documented_strict_lf_prompt_frame() {
        let driver =
            StructuredAdapterDriver::new(AdapterDialect::PiRpc, Some("hello"), None, &cwd())
                .unwrap();
        assert_eq!(
            driver.start().unwrap(),
            vec![b"{\"id\":\"ownmesh-prompt-1\",\"message\":\"hello\",\"type\":\"prompt\"}\n"]
        );
        assert!(driver.is_complete());
    }

    #[test]
    fn codex_waits_for_thread_id_before_turn() {
        let mut driver = StructuredAdapterDriver::new(
            AdapterDialect::CodexAppServer,
            Some("ship it"),
            None,
            &cwd(),
        )
        .unwrap();
        let initial = driver.start().unwrap();
        assert_eq!(initial.len(), 1);
        assert!(!String::from_utf8_lossy(&initial[0]).contains("jsonrpc"));
        let thread = driver.on_record(b"{\"id\":1,\"result\":{}}\n").unwrap();
        assert!(String::from_utf8_lossy(&thread[0]).contains("initialized"));
        assert!(String::from_utf8_lossy(&thread[1]).contains("thread/start"));
        let turn = driver
            .on_record(b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thr_1\"}}}\n")
            .unwrap();
        assert!(String::from_utf8_lossy(&turn[0]).contains("turn/start"));
        assert_eq!(driver.native_session_id(), Some("thr_1"));
    }

    #[test]
    fn reusable_drivers_can_open_without_a_hidden_model_turn() {
        let mut codex =
            StructuredAdapterDriver::new(AdapterDialect::CodexAppServer, None, None, &cwd())
                .unwrap();
        codex.start().unwrap();
        codex.on_record(b"{\"id\":1,\"result\":{}}\n").unwrap();
        let next = codex
            .on_record(b"{\"id\":2,\"result\":{\"thread\":{\"id\":\"thread-1\"}}}\n")
            .unwrap();
        assert!(next.is_empty());
        assert!(codex.is_complete());
        assert_eq!(codex.native_session_id(), Some("thread-1"));

        let mut acp =
            StructuredAdapterDriver::new(AdapterDialect::OpenCodeServer, None, None, &cwd())
                .unwrap();
        acp.start().unwrap();
        acp.on_record(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":1,\"agentCapabilities\":{}}}\n",
        )
        .unwrap();
        let next = acp
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"sessionId\":\"session-1\"}}\n")
            .unwrap();
        assert!(next.is_empty());
        assert!(acp.is_complete());
        assert_eq!(acp.native_session_id(), Some("session-1"));

        assert!(
            StructuredAdapterDriver::new(AdapterDialect::ClaudeStreamJson, None, None, &cwd())
                .unwrap_err()
                .contains("explicit prompt")
        );
    }

    #[test]
    fn acp_resume_is_capability_gated_and_permissions_are_typed_denials() {
        let mut driver = StructuredAdapterDriver::new(
            AdapterDialect::KimiAcp,
            Some("hello"),
            Some("native_1"),
            &cwd(),
        )
        .unwrap();
        driver.start().unwrap();
        assert!(driver
            .on_record(b"{\"id\":1,\"result\":{\"protocolVersion\":1,\"agentCapabilities\":{}}}\n")
            .is_err());
        let denied = driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"session/request_permission\",\"params\":{\"options\":[{\"optionId\":\"allow\",\"name\":\"Allow\",\"kind\":\"allow_once\"},{\"optionId\":\"deny\",\"name\":\"Deny\",\"kind\":\"reject_once\"}]}}\n")
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&denied[0]).unwrap(),
            json!({"jsonrpc":"2.0","id":42,"result":{"outcome":{"outcome":"selected","optionId":"deny"}}})
        );
    }

    #[test]
    fn permission_responses_never_auto_approve_or_echo_vendor_payloads() {
        let acp = json!({
            "jsonrpc":"2.0", "id":"req-secret", "method":"session/request_permission",
            "params":{"toolCall":{"title":"SECRET_VENDOR_ACTION"},"options":[
                {"optionId":"yes","name":"Do it","kind":"allow_always"}
            ]}
        });
        let response = fail_closed_protocol_response(AdapterDialect::QwenAcp, &acp).unwrap();
        assert_eq!(response["result"]["outcome"]["outcome"], "cancelled");
        let encoded = response.to_string();
        assert!(!encoded.contains("SECRET_VENDOR_ACTION"));
        assert!(!encoded.contains("allow"));

        let codex = json!({
            "id":7,"method":"item/commandExecution/requestApproval",
            "params":{"command":"cat /private/token"}
        });
        let response =
            fail_closed_protocol_response(AdapterDialect::CodexAppServer, &codex).unwrap();
        assert_eq!(response, json!({"id":7,"result":{"decision":"decline"}}));
        assert!(!response.to_string().contains("/private/token"));
    }

    #[test]
    fn unadvertised_acp_client_capabilities_return_stable_typed_errors() {
        let request = json!({
            "jsonrpc":"2.0","id":"fs-1","method":"fs/read_text_file",
            "params":{"path":"/private/secret"}
        });
        let response =
            fail_closed_protocol_response(AdapterDialect::OpenCodeServer, &request).unwrap();
        assert_eq!(response["id"], "fs-1");
        assert_eq!(response["error"]["code"], -32601);
        assert_eq!(response["error"]["message"], "capability_not_advertised");
        assert!(!response.to_string().contains("/private/secret"));
    }

    #[test]
    fn cancellation_is_dialect_exact_and_unsupported_modes_are_degraded() {
        let acp = cancel_protocol_frame(
            AdapterDialect::OpenCodeServer,
            "session-1",
            None,
            "cancel-1",
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&acp).unwrap(),
            json!({"jsonrpc":"2.0","method":"session/cancel","params":{"sessionId":"session-1"}})
        );
        let codex = cancel_protocol_frame(
            AdapterDialect::CodexAppServer,
            "thread-1",
            Some("turn-1"),
            "cancel-2",
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&codex).unwrap(),
            json!({"id":"cancel-2","method":"turn/interrupt","params":{"threadId":"thread-1","turnId":"turn-1"}})
        );
        let pi =
            cancel_protocol_frame(AdapterDialect::PiRpc, "pi-session", None, "cancel-3").unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&pi).unwrap(),
            json!({"id":"cancel-3","type":"abort"})
        );
        assert!(cancel_protocol_frame(
            AdapterDialect::ClaudeStreamJson,
            "claude-session",
            None,
            "cancel-4"
        )
        .unwrap_err()
        .starts_with("capability_not_advertised:"));

        assert_eq!(
            latest_codex_turn_id(
                b"{\"method\":\"turn/started\",\"params\":{\"turn\":{\"id\":\"older\"}}}\n{\"method\":\"turn/started\",\"params\":{\"turn\":{\"id\":\"latest\"}}}\n"
            )
            .as_deref(),
            Some("latest")
        );
    }

    #[test]
    fn acp_v1_requests_required_session_facts_and_validates_result_shape() {
        let mut driver = StructuredAdapterDriver::new(
            AdapterDialect::OpenCodeServer,
            Some("hello"),
            None,
            &cwd(),
        )
        .unwrap();
        let mut initial = driver.start().unwrap();
        let init = String::from_utf8(initial.remove(0)).unwrap();
        assert!(init.contains("\"jsonrpc\":\"2.0\""));
        assert!(init.contains("\"protocolVersion\":1"));
        assert!(init.contains("\"clientCapabilities\""));
        assert!(driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n")
            .unwrap()
            .is_empty());
        let mut new = driver.on_record(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":1,\"agentCapabilities\":{\"loadSession\":false}}}\n").unwrap();
        let new = String::from_utf8(new.remove(0)).unwrap();
        assert!(new.contains("\"session/new\""));
        assert!(new.contains("\"cwd\""));
        assert!(new.contains("\"mcpServers\":[]"));
        assert!(driver
            .on_record(b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{}}\n")
            .is_err());
    }

    #[test]
    fn correlated_errors_fail_closed_without_state_advance() {
        let mut driver = StructuredAdapterDriver::new(
            AdapterDialect::CodexAppServer,
            Some("hello"),
            None,
            &cwd(),
        )
        .unwrap();
        driver.start().unwrap();
        assert!(driver
            .on_record(b"{\"id\":1,\"error\":{\"code\":-1,\"message\":\"no\"}}\n")
            .is_err());
        assert!(!driver.is_complete());
    }

    #[test]
    fn long_running_prompt_is_open_ready_before_completion() {
        let mut driver =
            StructuredAdapterDriver::new(AdapterDialect::KimiAcp, Some("long task"), None, &cwd())
                .unwrap();
        driver.start().unwrap();
        let mut session = driver.on_record(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"protocolVersion\":1,\"agentCapabilities\":{\"loadSession\":false}}}\n").unwrap();
        let _ = session.remove(0);
        let prompt = driver
            .on_record(
                b"{\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"sessionId\":\"native_long\"}}\n",
            )
            .unwrap();
        assert_eq!(prompt.len(), 1);
        assert!(driver.is_open_ready());
        assert!(
            !driver.is_complete(),
            "prompt completion is deliberately not an open prerequisite"
        );
    }

    fn cwd() -> String {
        std::env::current_dir()
            .unwrap()
            .to_string_lossy()
            .into_owned()
    }
}
