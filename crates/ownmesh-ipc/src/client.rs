//! Local IPC client with timeout, cancellation, and reconnect.

use crate::auth::read_token_file;
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
#[derive(Debug, Clone)]
pub struct ClientIdentity {
    /// Process label (`ownmesh`, `ownmesh-tui`, …).
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
    /// Explicit token override (tests). When `None`, read from runtime dir.
    token_override: Option<String>,
    conn: Mutex<Option<ClientConnection>>,
}

impl IpcClient {
    /// Create a client targeting `endpoint`, reading the auth token from `runtime_dir`.
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
            token_override: None,
            conn: Mutex::new(None),
        }
    }

    /// Override the auth token (used by negative tests).
    #[must_use]
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token_override = Some(token.into());
        self
    }

    /// Endpoint currently targeted.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Runtime directory used for token discovery.
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
        let token = match &self.token_override {
            Some(t) => t.clone(),
            None => read_token_file(&self.runtime_dir)?,
        };
        let hello = RpcRequest::new(
            methods::HELLO,
            Some(json!(HelloParams {
                token,
                client_name: self.identity.client_name.clone(),
                client_version: self.identity.client_version.clone(),
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
            let result = self
                .call_once(method, params.clone(), cancel)
                .await;
            match result {
                Ok(value) => return Ok(value),
                Err(IpcError::Disconnected(_)) | Err(IpcError::Io(_))
                    if attempts <= self.options.max_reconnect_attempts =>
                {
                    self.disconnect().await;
                    let delay = self
                        .options
                        .reconnect_base_delay
                        .saturating_mul(attempts);
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
    use crate::auth::{generate_token, write_token_file, AuthGate};
    use crate::endpoint::{Endpoint, IpcBus};
    use crate::server::{reject_unknown_handler, IpcServer, ServerConfig};
    use std::sync::Arc;
    use tempfile::tempdir;

    async fn start_test_server(
        runtime: &Path,
    ) -> (Arc<IpcServer>, Endpoint, String, tokio::task::JoinHandle<()>) {
        let token = generate_token();
        write_token_file(runtime, &token).unwrap();
        let endpoint = Endpoint::default_for(runtime, IpcBus::Daemon);
        let server = Arc::new(IpcServer::new(
            ServerConfig {
                endpoint: endpoint.clone(),
                auth: AuthGate::new(token.clone()),
                server_name: "ownmeshd-test".into(),
                server_version: "0.1.0-test".into(),
            },
            reject_unknown_handler(),
        ));
        let serve = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve.serve().await;
        });
        // Give the listener a moment to bind.
        tokio::time::sleep(Duration::from_millis(50)).await;
        (server, endpoint, token, handle)
    }

    #[tokio::test]
    async fn cli_status_over_ipc() {
        let dir = tempdir().unwrap();
        let (server, endpoint, _token, handle) = start_test_server(dir.path()).await;

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
        let (server, endpoint, _token, handle) = start_test_server(dir.path()).await;

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
    async fn unauthorized_token_is_rejected() {
        let dir = tempdir().unwrap();
        let (server, endpoint, _token, handle) = start_test_server(dir.path()).await;

        let client = IpcClient::new(
            endpoint,
            dir.path(),
            ClientIdentity::new("evil-process", "0.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        )
        .with_token("definitely-not-the-real-token");

        let err = client.status().await.expect_err("must reject");
        assert!(
            matches!(err, IpcError::Unauthorized(_) | IpcError::Remote { .. } | IpcError::Disconnected(_)),
            "unexpected error: {err:?}"
        );
        assert!(
            err.code() == "ipc_unauthorized"
                || err.code() == "ipc_remote"
                || err.code() == "ipc_disconnected",
            "code={}",
            err.code()
        );

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn reconnect_after_disconnect() {
        let dir = tempdir().unwrap();
        let (server, endpoint, _token, handle) = start_test_server(dir.path()).await;
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
