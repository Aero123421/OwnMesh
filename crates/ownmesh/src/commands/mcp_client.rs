//! Hardened authenticated client for the configured Streamable HTTP MCP endpoint.

use crate::auth::{load_access_token, open_secret_store, resolve_issuer, SessionPaths};
use ownmesh_domain::ErrorCode;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde_json::Value;
use std::time::{Duration, Instant};

pub(crate) const MAX_MCP_MESSAGE_BYTES: usize = 256 * 1024;
const MCP_PROTOCOL_VERSION: &str = "2025-03-26";
const MCP_SESSION_ID: HeaderName = HeaderName::from_static("mcp-session-id");
const MCP_PROTOCOL_VERSION_HEADER: HeaderName = HeaderName::from_static("mcp-protocol-version");

#[derive(Debug)]
pub(crate) struct McpClientError {
    pub(crate) code: ErrorCode,
    pub(crate) message: String,
    pub(crate) hint: Option<&'static str>,
}

impl McpClientError {
    pub(crate) fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
        }
    }

    fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = Some(hint);
        self
    }
}

/// Authenticated client whose endpoint is derived only from the configured,
/// credential-bound issuer. Tokens and arbitrary endpoint overrides are never
/// exposed by this API.
pub(crate) struct McpHttpClient {
    http: reqwest::Client,
    session_paths: SessionPaths,
    issuer: String,
    endpoint: String,
    access_token: String,
    session_id: Option<HeaderValue>,
}

impl McpHttpClient {
    /// Load the existing login from the OS keychain and bind `/mcp` to that
    /// login's configured issuer.
    pub(crate) async fn from_configured_auth() -> Result<Self, McpClientError> {
        let session_paths = SessionPaths::discover()
            .map_err(|err| McpClientError::new(ErrorCode::Config, format!("path error: {err}")))?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|err| {
                McpClientError::new(ErrorCode::Internal, format!("http client error: {err}"))
            })?;
        let (access_token, issuer) = load_bound_access(&session_paths, &http).await?;
        let endpoint = format!("{issuer}/mcp");
        Ok(Self {
            http,
            session_paths,
            issuer,
            endpoint,
            access_token,
            session_id: None,
        })
    }

    /// Forward one JSON-RPC message. Notifications return `None` and therefore
    /// produce no stdio response. A 401 refreshes credentials and retries once.
    pub(crate) async fn send_json_rpc(
        &mut self,
        request: &Value,
    ) -> Result<Option<Value>, McpClientError> {
        let request_id = validate_request(request)?;
        let payload = serde_json::to_vec(request).map_err(|err| {
            McpClientError::new(
                ErrorCode::InvalidArgument,
                format!("cannot encode JSON-RPC request: {err}"),
            )
        })?;
        if payload.len() > MAX_MCP_MESSAGE_BYTES {
            return Err(message_too_large("request"));
        }

        let mut response = self.send_once(&payload).await?;
        if response.status() == reqwest::StatusCode::UNAUTHORIZED {
            self.reload_access_token().await?;
            response = self.send_once(&payload).await?;
        }
        self.handle_response(response, request_id.as_ref()).await
    }

    /// Invoke a tool using the same public MCP contract used by remote clients.
    pub(crate) async fn call_tool(
        &mut self,
        request_id: Value,
        name: &str,
        arguments: Value,
    ) -> Result<Value, McpClientError> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": { "name": name, "arguments": arguments },
        });
        self.send_json_rpc(&request).await?.ok_or_else(|| {
            McpClientError::new(
                ErrorCode::BadEnvelope,
                "control-plane omitted the tools/call response",
            )
        })
    }

    /// Invoke one MCP tool and decode OwnMesh's standard JSON tool payload.
    pub(crate) async fn call_tool_value(
        &mut self,
        request_id: Value,
        name: &str,
        arguments: Value,
    ) -> Result<Value, McpClientError> {
        let response = self.call_tool(request_id, name, arguments).await?;
        if let Some(error) = response.get("error") {
            let rpc_code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            return Err(McpClientError::new(
                match rpc_code {
                    -32602 => ErrorCode::InvalidArgument,
                    -32004 => ErrorCode::Authorization,
                    -32009 => ErrorCode::Conflict,
                    _ => ErrorCode::Internal,
                },
                format!(
                    "MCP tool {name} was rejected: {}",
                    response_error_message(&response)
                ),
            ));
        }
        extract_tool_value(&response).map_err(|message| {
            McpClientError::new(
                ErrorCode::BadEnvelope,
                format!("invalid control-plane tool response: {message}"),
            )
        })
    }

    /// Invoke a public device operation and poll its authoritative operation
    /// record until it is terminal or needs explicit human approval.
    pub(crate) async fn call_tool_until_terminal(
        &mut self,
        name: &str,
        arguments: Value,
        device_id: &str,
        max_wait: Duration,
    ) -> Result<Value, McpClientError> {
        let mut value = self
            .call_tool_value(serde_json::json!(1), name, arguments)
            .await?;
        let operation_id = value
            .get("operation_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let started = Instant::now();
        let mut request_id = 2_u64;

        loop {
            let status = value.get("status").and_then(Value::as_str).ok_or_else(|| {
                McpClientError::new(
                    ErrorCode::BadEnvelope,
                    "control-plane operation response omitted status",
                )
            })?;
            if matches!(
                status,
                "completed"
                    | "failed"
                    | "denied"
                    | "cancelled"
                    | "device_offline"
                    | "tombstone"
                    | "approval_required"
            ) {
                return Ok(value);
            }
            if !matches!(status, "pending" | "running" | "cancel_requested") {
                return Err(McpClientError::new(
                    ErrorCode::BadEnvelope,
                    format!("control-plane returned unknown operation status {status}"),
                ));
            }
            let operation_id = operation_id.as_deref().ok_or_else(|| {
                McpClientError::new(
                    ErrorCode::BadEnvelope,
                    "pending operation response omitted operation_id",
                )
            })?;
            if started.elapsed() >= max_wait {
                return Err(McpClientError::new(
                    ErrorCode::Timeout,
                    format!(
                        "operation {operation_id} did not finish within {} seconds",
                        max_wait.as_secs()
                    ),
                ));
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
            value = self
                .call_tool_value(
                    serde_json::json!(request_id),
                    "ownmesh_get_operation",
                    serde_json::json!({
                        "operation_id": operation_id,
                        "device_id": device_id,
                    }),
                )
                .await?;
            if value.get("operation_id").and_then(Value::as_str) != Some(operation_id) {
                return Err(McpClientError::new(
                    ErrorCode::BadEnvelope,
                    "polled operation id does not match the requested operation",
                ));
            }
            request_id = request_id.saturating_add(1);
        }
    }

    async fn send_once(&self, payload: &[u8]) -> Result<reqwest::Response, McpClientError> {
        self.http
            .post(&self.endpoint)
            .headers(request_headers(self.session_id.as_ref()))
            .bearer_auth(&self.access_token)
            .body(payload.to_vec())
            .send()
            .await
            .map_err(|err| {
                McpClientError::new(
                    ErrorCode::DeviceOffline,
                    format!("control-plane request failed: {err}"),
                )
            })
    }

    async fn reload_access_token(&mut self) -> Result<(), McpClientError> {
        let (access_token, issuer) = load_bound_access(&self.session_paths, &self.http).await?;
        if issuer != self.issuer {
            return Err(McpClientError::new(
                ErrorCode::Config,
                "configured issuer changed while the MCP session was active; restart after logging in to that instance",
            ));
        }
        self.access_token = access_token;
        Ok(())
    }

    async fn handle_response(
        &mut self,
        response: reqwest::Response,
        request_id: Option<&Value>,
    ) -> Result<Option<Value>, McpClientError> {
        let status = response.status();
        if status.is_redirection() {
            return Err(McpClientError::new(
                ErrorCode::DeviceOffline,
                format!("control-plane returned {status}; redirects are refused"),
            ));
        }
        let response_session_id = response.headers().get(&MCP_SESSION_ID).cloned();
        let (content_type, bytes) = read_response_limited(response).await?;

        if !status.is_success() {
            let detail = if bytes.is_empty() {
                "request rejected".to_owned()
            } else {
                let value = decode_json(content_type.as_deref(), &bytes)?;
                response_error_message(&value).to_owned()
            };
            return Err(McpClientError::new(
                error_code_for_http(status),
                format!("control-plane request failed ({status}): {detail}"),
            ));
        }

        if let Some(value) = response_session_id {
            capture_session_id(&mut self.session_id, value)?;
        }

        let Some(expected_id) = request_id else {
            if bytes.is_empty() && matches!(status.as_u16(), 202 | 204) {
                return Ok(None);
            }
            return Err(McpClientError::new(
                ErrorCode::BadEnvelope,
                "control-plane returned a response body for a JSON-RPC notification",
            ));
        };

        if bytes.is_empty() {
            return Err(McpClientError::new(
                ErrorCode::BadEnvelope,
                "control-plane returned an empty JSON-RPC response",
            ));
        }
        let value = decode_json(content_type.as_deref(), &bytes)?;
        validate_response(&value, expected_id)?;
        Ok(Some(value))
    }
}

async fn load_bound_access(
    session_paths: &SessionPaths,
    http: &reqwest::Client,
) -> Result<(String, String), McpClientError> {
    // Resolve and compare before refreshing: `load_access_token` persists
    // rotated credentials and the default instance, so doing this afterwards
    // could accidentally erase evidence of an active-instance mismatch.
    let prior_session = session_paths.load_session().map_err(|err| {
        McpClientError::new(ErrorCode::Authentication, err.to_string())
            .with_hint("run `ownmesh login` first")
    })?;
    if prior_session.issuer.trim().is_empty() {
        return Err(McpClientError::new(
            ErrorCode::Authentication,
            "not logged in (missing auth session)",
        )
        .with_hint("run `ownmesh login` first"));
    }
    let credential_issuer = ownmesh_config::validate_control_plane_base_url(&prior_session.issuer)
        .map_err(|err| McpClientError::new(ErrorCode::Config, err.to_string()))?;
    let configured_issuer = resolve_issuer(&prior_session)
        .map_err(|err| McpClientError::new(ErrorCode::Config, err.to_string()))?;
    if configured_issuer != credential_issuer {
        return Err(McpClientError::new(
            ErrorCode::Config,
            "configured issuer does not match the signed-in session; log in to the active instance before connecting",
        ));
    }

    let store = open_secret_store(&session_paths.paths).map_err(|err| {
        McpClientError::new(ErrorCode::Internal, format!("keychain error: {err}"))
    })?;
    let (access_token, session) = load_access_token(session_paths, &store, http)
        .await
        .map_err(|err| {
            McpClientError::new(ErrorCode::Authentication, err.to_string())
                .with_hint("run `ownmesh login` first")
        })?;
    let refreshed_issuer = ownmesh_config::validate_control_plane_base_url(&session.issuer)
        .map_err(|err| McpClientError::new(ErrorCode::Config, err.to_string()))?;
    if refreshed_issuer != credential_issuer {
        return Err(McpClientError::new(
            ErrorCode::Config,
            "credential issuer changed during refresh; refusing the MCP connection",
        ));
    }
    Ok((access_token, credential_issuer))
}

fn validate_request(request: &Value) -> Result<Option<Value>, McpClientError> {
    let object = request.as_object().ok_or_else(|| {
        McpClientError::new(
            ErrorCode::InvalidArgument,
            "JSON-RPC input must be one object per line",
        )
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(McpClientError::new(
            ErrorCode::InvalidArgument,
            "JSON-RPC input must declare jsonrpc=2.0",
        ));
    }
    if object
        .get("method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(McpClientError::new(
            ErrorCode::InvalidArgument,
            "JSON-RPC input must contain a non-empty method",
        ));
    }
    match object.get("id") {
        None | Some(Value::Null) => Ok(None),
        Some(id @ (Value::String(_) | Value::Number(_))) => Ok(Some(id.clone())),
        Some(_) => Err(McpClientError::new(
            ErrorCode::InvalidArgument,
            "JSON-RPC id must be a string, number, null, or omitted",
        )),
    }
}

fn validate_response(response: &Value, expected_id: &Value) -> Result<(), McpClientError> {
    let object = response.as_object().ok_or_else(|| {
        McpClientError::new(
            ErrorCode::BadEnvelope,
            "JSON-RPC response must be an object",
        )
    })?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(McpClientError::new(
            ErrorCode::BadEnvelope,
            "JSON-RPC response must declare jsonrpc=2.0",
        ));
    }
    if object.get("id") != Some(expected_id) {
        return Err(McpClientError::new(
            ErrorCode::BadEnvelope,
            "JSON-RPC response id does not match the request",
        ));
    }
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    if has_result == has_error {
        return Err(McpClientError::new(
            ErrorCode::BadEnvelope,
            "JSON-RPC response must contain exactly one of result or error",
        ));
    }
    Ok(())
}

fn request_headers(session_id: Option<&HeaderValue>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(
        MCP_PROTOCOL_VERSION_HEADER,
        HeaderValue::from_static(MCP_PROTOCOL_VERSION),
    );
    if let Some(session_id) = session_id {
        headers.insert(MCP_SESSION_ID, session_id.clone());
    }
    headers
}

fn capture_session_id(
    current: &mut Option<HeaderValue>,
    value: HeaderValue,
) -> Result<(), McpClientError> {
    if value.is_empty() || value.as_bytes().len() > 256 {
        return Err(McpClientError::new(
            ErrorCode::BadEnvelope,
            "control-plane returned an invalid MCP session id",
        ));
    }
    *current = Some(value);
    Ok(())
}

async fn read_response_limited(
    mut response: reqwest::Response,
) -> Result<(Option<String>, Vec<u8>), McpClientError> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    if response
        .content_length()
        .is_some_and(|len| len > MAX_MCP_MESSAGE_BYTES as u64)
    {
        return Err(message_too_large("response"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|err| {
        McpClientError::new(
            ErrorCode::DeviceOffline,
            format!("failed to read control-plane response: {err}"),
        )
    })? {
        if bytes.len().saturating_add(chunk.len()) > MAX_MCP_MESSAGE_BYTES {
            return Err(message_too_large("response"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((content_type, bytes))
}

fn decode_json(content_type: Option<&str>, bytes: &[u8]) -> Result<Value, McpClientError> {
    if bytes.len() > MAX_MCP_MESSAGE_BYTES {
        return Err(message_too_large("response"));
    }
    let is_json = content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(McpClientError::new(
            ErrorCode::BadEnvelope,
            "control-plane response content type is not application/json",
        ));
    }
    serde_json::from_slice(bytes).map_err(|err| {
        McpClientError::new(
            ErrorCode::BadEnvelope,
            format!("control-plane response is not valid JSON: {err}"),
        )
    })
}

fn message_too_large(direction: &str) -> McpClientError {
    McpClientError::new(
        ErrorCode::BadEnvelope,
        format!("MCP {direction} exceeds the {MAX_MCP_MESSAGE_BYTES}-byte limit"),
    )
}

fn response_error_message(value: &Value) -> &str {
    value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .or_else(|| value.get("error").and_then(Value::as_str))
        .unwrap_or("request rejected")
}

/// Decode the standard MCP `tools/call` text content used by OwnMesh tools.
pub(crate) fn extract_tool_value(body: &Value) -> Result<Value, &'static str> {
    let result = body.get("result").ok_or("missing result")?;
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .ok_or("missing tool content")?;
    let text = content
        .first()
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .ok_or("missing tool JSON")?;
    serde_json::from_str(text).map_err(|_| "malformed tool JSON")
}

fn error_code_for_http(status: reqwest::StatusCode) -> ErrorCode {
    match status.as_u16() {
        400 | 422 => ErrorCode::InvalidArgument,
        401 => ErrorCode::Authentication,
        403 => ErrorCode::Authorization,
        408 | 504 => ErrorCode::Timeout,
        409 => ErrorCode::Conflict,
        _ if status.is_server_error() => ErrorCode::DeviceOffline,
        _ => ErrorCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_header_is_carried_to_subsequent_requests() {
        let mut session = None;
        capture_session_id(&mut session, HeaderValue::from_static("mcp_test_session"))
            .expect("valid session id");
        let headers = request_headers(session.as_ref());
        assert_eq!(
            headers.get(&MCP_SESSION_ID),
            Some(&HeaderValue::from_static("mcp_test_session"))
        );
    }

    #[test]
    fn notification_has_no_expected_response_id() {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {},
        });
        assert_eq!(
            validate_request(&notification).expect("valid notification"),
            None
        );
    }

    #[test]
    fn tool_payload_decoder_rejects_nonstandard_content() {
        let valid = serde_json::json!({
            "result": { "content": [{ "type": "text", "text": "{\"status\":\"completed\"}" }] }
        });
        assert_eq!(extract_tool_value(&valid).unwrap()["status"], "completed");
        assert_eq!(
            extract_tool_value(&serde_json::json!({"result": {}})),
            Err("missing tool content")
        );
    }
}
