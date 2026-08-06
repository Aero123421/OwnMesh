//! Local IPC client with timeout, cancellation, and reconnect.

use crate::endpoint::Endpoint;
use crate::error::{IpcError, IpcResult};
use crate::frame::{read_frame, write_frame};
use crate::rpc::{
    methods, DaemonStatus, HelloParams, HelloResult, RpcRequest, RpcResponse, JSONRPC_VERSION,
};
use crate::transport::{connect, ClientConnection};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Client identity presented during `ipc.hello`.
///
/// `client_name` is an untrusted label only. The server assigns the real principal
/// from OS peer credentials (and optional server-issued client credential).
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// Process label (`ownmesh`, `ownmesh-tui`, …) — untrusted display hint.
    pub client_name: String,
    /// Optional semantic version.
    pub client_version: Option<String>,
}

impl ClientIdentity {
    /// Build identity from package metadata.
    #[must_use]
    pub fn new(client_name: impl Into<String>, client_version: impl Into<String>) -> Self {
        Self {
            client_name: client_name.into(),
            client_version: Some(client_version.into()),
        }
    }
}

/// Reconnect / timeout policy.
#[derive(Debug, Clone)]
pub struct ClientOptions {
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// Maximum reconnect attempts after daemon restart.
    pub max_reconnect_attempts: u32,
    /// Base backoff between reconnect attempts.
    pub reconnect_base_delay: Duration,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(5),
            max_reconnect_attempts: 10,
            reconnect_base_delay: Duration::from_millis(100),
        }
    }
}

/// High-level IPC client.
pub struct IpcClient {
    endpoint: Endpoint,
    runtime_dir: PathBuf,
    identity: ClientIdentity,
    options: ClientOptions,
    /// Optional server-issued per-client credential (non-shared).
    client_credential: Option<String>,
    /// When set, deliberately send a shared token (negative tests only).
    legacy_shared_token: Option<String>,
    conn: Mutex<Option<ClientConnection>>,
}

impl IpcClient {
    /// Create a client targeting `endpoint`.
    ///
    /// Authentication uses OS peer credentials on the server; no shared token file
    /// is read. `runtime_dir` is retained for path symmetry / future credential files.
    #[must_use]
    pub fn new(
        endpoint: Endpoint,
        runtime_dir: impl Into<PathBuf>,
        identity: ClientIdentity,
        options: ClientOptions,
    ) -> Self {
        Self {
            endpoint,
            runtime_dir: runtime_dir.into(),
            identity,
            options,
            client_credential: None,
            legacy_shared_token: None,
            conn: Mutex::new(None),
        }
    }

    /// Attach a server-issued per-client credential (non-shared).
    #[must_use]
    pub fn with_client_credential(mut self, credential: impl Into<String>) -> Self {
        self.client_credential = Some(credential.into());
        self
    }

    /// Deliberately present a legacy shared token (negative / attack tests only).
    #[must_use]
    pub fn with_legacy_shared_token(mut self, token: impl Into<String>) -> Self {
        self.legacy_shared_token = Some(token.into());
        self
    }

    /// Backward-compatible alias for attack tests that previously overrode the shared token.
    #[must_use]
    pub fn with_token(self, token: impl Into<String>) -> Self {
        self.with_legacy_shared_token(token)
    }

    /// Endpoint currently targeted.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Runtime directory (legacy token path / future credential material).
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// Ensure a live authenticated connection, reconnecting if needed.
    async fn ensure_connected(&self) -> IpcResult<()> {
        let mut guard = self.conn.lock().await;
        if guard.is_some() {
            return Ok(());
        }
        let mut last_err = IpcError::Disconnected("not connected".into());
        for attempt in 0..=self.options.max_reconnect_attempts {
            match self.dial_and_hello().await {
                Ok(conn) => {
                    *guard = Some(conn);
                    return Ok(());
                }
                Err(err) => {
                    last_err = err;
                    if attempt == self.options.max_reconnect_attempts {
                        break;
                    }
                    let delay = self
                        .options
                        .reconnect_base_delay
                        .saturating_mul(attempt.saturating_add(1));
                    tokio::time::sleep(delay).await;
                }
            }
        }
        Err(last_err)
    }

    async fn dial_and_hello(&self) -> IpcResult<ClientConnection> {
        let mut conn = connect(&self.endpoint).await?;
        let hello = RpcRequest::new(
            methods::HELLO,
            Some(json!(HelloParams {
                token: self.legacy_shared_token.clone().unwrap_or_default(),
                client_name: self.identity.client_name.clone(),
                client_version: self.identity.client_version.clone(),
                client_credential: self.client_credential.clone(),
            })),
        );
        write_frame(&mut conn, &hello.to_bytes()?).await?;
        let resp_bytes = read_frame(&mut conn).await?;
        let resp = RpcResponse::from_bytes(&resp_bytes)?;
        let value = match resp.into_result() {
            Ok(v) => v,
            Err(IpcError::Remote { code, message })
                if code == crate::rpc::app_error::UNAUTHORIZED =>
            {
                return Err(IpcError::Unauthorized(message));
            }
            Err(IpcError::Remote { code, message })
                if code == crate::rpc::app_error::TOKEN_REVOKED =>
            {
                return Err(IpcError::Remote { code, message });
            }
            Err(err) => return Err(err),
        };
        let hello_result: HelloResult = serde_json::from_value(value)?;
        if !hello_result.authenticated {
            return Err(IpcError::Unauthorized(
                "server did not authenticate client".into(),
            ));
        }
        Ok(conn)
    }

    /// Drop the cached connection (forces reconnect on next call).
    pub async fn disconnect(&self) {
        let mut guard = self.conn.lock().await;
        *guard = None;
    }

    /// Call a JSON-RPC method with params.
    ///
    /// # Errors
    ///
    /// Returns transport, timeout, cancellation, or remote errors.
    pub async fn call(&self, method: &str, params: Option<Value>) -> IpcResult<Value> {
        self.call_cancellable(method, params, None).await
    }

    /// Call with an optional external cancellation flag.
    ///
    /// When `cancel` becomes `true`, the in-flight call fails with
    /// [`IpcError::Cancelled`].
    pub async fn call_cancellable(
        &self,
        method: &str,
        params: Option<Value>,
        cancel: Option<&tokio::sync::watch::Receiver<bool>>,
    ) -> IpcResult<Value> {
        let mut attempts = 0_u32;
        loop {
            attempts = attempts.saturating_add(1);
            self.ensure_connected().await?;
            let result = self.call_once(method, params.clone(), cancel).await;
            match result {
                Ok(value) => return Ok(value),
                Err(IpcError::Disconnected(_)) | Err(IpcError::Io(_))
                    if attempts <= self.options.max_reconnect_attempts =>
                {
                    self.disconnect().await;
                    let delay = self.options.reconnect_base_delay.saturating_mul(attempts);
                    tokio::time::sleep(delay).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn call_once(
        &self,
        method: &str,
        params: Option<Value>,
        cancel: Option<&tokio::sync::watch::Receiver<bool>>,
    ) -> IpcResult<Value> {
        let request = RpcRequest {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id: crate::rpc::RequestId::fresh(),
            method: method.to_owned(),
            params,
        };
        let payload = request.to_bytes()?;

        let call_future = async {
            let mut guard = self.conn.lock().await;
            let conn = guard
                .as_mut()
                .ok_or_else(|| IpcError::Disconnected("connection lost".into()))?;
            write_frame(conn, &payload).await?;
            let resp_bytes = read_frame(conn).await?;
            let resp = RpcResponse::from_bytes(&resp_bytes)?;
            if resp.id != request.id {
                return Err(IpcError::Protocol(format!(
                    "response id mismatch: expected {}, got {}",
                    request.id, resp.id
                )));
            }
            resp.into_result()
        };

        if let Some(cancel_rx) = cancel {
            let mut cancel_rx = cancel_rx.clone();
            tokio::select! {
                biased;
                () = async {
                    loop {
                        if *cancel_rx.borrow() {
                            break;
                        }
                        if cancel_rx.changed().await.is_err() {
                            break;
                        }
                    }
                } => {
                    self.disconnect().await;
                    Err(IpcError::Cancelled)
                }
                result = timeout(self.options.request_timeout, call_future) => {
                    match result {
                        Ok(inner) => inner,
                        Err(_) => {
                            self.disconnect().await;
                            Err(IpcError::Timeout)
                        }
                    }
                }
            }
        } else {
            match timeout(self.options.request_timeout, call_future).await {
                Ok(inner) => inner,
                Err(_) => {
                    self.disconnect().await;
                    Err(IpcError::Timeout)
                }
            }
        }
    }

    /// Fetch daemon status.
    ///
    /// # Errors
    ///
    /// Returns IPC errors from [`Self::call`].
    pub async fn status(&self) -> IpcResult<DaemonStatus> {
        let value = self.call(methods::STATUS, None).await?;
        Ok(serde_json::from_value(value)?)
    }

    /// Lightweight ping after reconnect.
    ///
    /// # Errors
    ///
    /// Returns IPC errors from [`Self::call`].
    pub async fn ping(&self) -> IpcResult<()> {
        let value = self.call(methods::PING, None).await?;
        if value.get("pong").and_then(Value::as_bool) == Some(true) {
            Ok(())
        } else {
            Err(IpcError::Protocol("unexpected ping response".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthGate;
    use crate::endpoint::{Endpoint, IpcBus};
    use crate::server::{reject_unknown_handler, IpcServer, ServerConfig};
    use std::sync::Arc;
    use tempfile::tempdir;

    async fn start_test_server(
        runtime: &Path,
    ) -> (Arc<IpcServer>, Endpoint, tokio::task::JoinHandle<()>) {
        let endpoint = Endpoint::default_for(runtime, IpcBus::Daemon);
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(
                endpoint.clone(),
                AuthGate::local_user(),
                "ownmeshd-test",
                "0.1.0-test",
            ),
            reject_unknown_handler(),
        ));
        let serve = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        (server, endpoint, handle)
    }

    #[tokio::test]
    async fn cli_status_over_ipc() {
        let dir = tempdir().unwrap();
        let (server, endpoint, handle) = start_test_server(dir.path()).await;

        let client = IpcClient::new(
            endpoint,
            dir.path(),
            ClientIdentity::new("ownmesh", "0.1.0"),
            ClientOptions::default(),
        );
        let status = client.status().await.expect("status");
        assert_eq!(status.version, "0.1.0-test");
        assert_eq!(status.state, "running");
        assert!(status.pid > 0);

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn tui_status_over_ipc() {
        let dir = tempdir().unwrap();
        let (server, endpoint, handle) = start_test_server(dir.path()).await;

        let client = IpcClient::new(
            endpoint,
            dir.path(),
            ClientIdentity::new("ownmesh-tui", "0.1.0"),
            ClientOptions::default(),
        );
        let status = client.status().await.expect("tui status");
        assert_eq!(status.state, "running");

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn shared_token_is_rejected() {
        let dir = tempdir().unwrap();
        let (server, endpoint, handle) = start_test_server(dir.path()).await;

        let client = IpcClient::new(
            endpoint,
            dir.path(),
            ClientIdentity::new("evil-process", "0.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        )
        .with_token("definitely-not-valid-shared-token");

        let err = client.status().await.expect_err("must reject");
        assert!(
            matches!(
                err,
                IpcError::Unauthorized(_) | IpcError::Remote { .. } | IpcError::Disconnected(_)
            ),
            "unexpected error: {err:?}"
        );

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn reconnect_after_disconnect() {
        let dir = tempdir().unwrap();
        let (server, endpoint, handle) = start_test_server(dir.path()).await;
        let client = IpcClient::new(
            endpoint,
            dir.path(),
            ClientIdentity::new("ownmesh", "0.1.0"),
            ClientOptions::default(),
        );
        client.ping().await.unwrap();
        client.disconnect().await;
        client.ping().await.unwrap();
        server.request_shutdown();
        let _ = handle.await;
    }
}
