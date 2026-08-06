//! Local IPC server loop (daemon side).

use crate::auth::AuthGate;
use crate::client::ClientIdentity;
use crate::endpoint::Endpoint;
use crate::error::{IpcError, IpcResult};
use crate::frame::{read_frame, write_frame};
use crate::rpc::{
    app_error, methods, DaemonStatus, HelloParams, HelloResult, RpcRequest, RpcResponse,
};
use crate::transport::{LocalListener, ServerConnection};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tokio::sync::watch;

/// Handler callback type used by the server for application methods.
///
/// The third argument is the authenticated client identity bound at `ipc.hello`
/// (never a self-reported principal inside method params).
pub type MethodHandler = Arc<
    dyn Fn(
            String,
            Option<Value>,
            ClientIdentity,
        ) -> Pin<Box<dyn Future<Output = IpcResult<Value>> + Send>>
        + Send
        + Sync,
>;

/// Shared revoked-client set checked on hello and every subsequent dispatch.
pub type RevokedClients = Arc<RwLock<HashSet<String>>>;

/// Configuration for [`IpcServer`].
#[derive(Clone)]
pub struct ServerConfig {
    /// Endpoint to bind.
    pub endpoint: Endpoint,
    /// Authentication gate.
    pub auth: AuthGate,
    /// Server package name reported in hello.
    pub server_name: String,
    /// Server package version reported in hello / status.
    pub server_version: String,
    /// Client names rejected at hello and on later dispatches.
    pub revoked_clients: RevokedClients,
}

impl ServerConfig {
    /// Build config with an empty revocation set.
    #[must_use]
    pub fn new(
        endpoint: Endpoint,
        auth: AuthGate,
        server_name: impl Into<String>,
        server_version: impl Into<String>,
    ) -> Self {
        Self {
            endpoint,
            auth,
            server_name: server_name.into(),
            server_version: server_version.into(),
            revoked_clients: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Attach a shared revoked-client set (typically owned by the daemon runtime).
    #[must_use]
    pub fn with_revoked_clients(mut self, revoked: RevokedClients) -> Self {
        self.revoked_clients = revoked;
        self
    }
}

/// Running IPC server handle.
pub struct IpcServer {
    cfg: ServerConfig,
    started_at: Instant,
    handler: MethodHandler,
    shutdown_tx: watch::Sender<bool>,
    shutdown_rx: watch::Receiver<bool>,
}

impl IpcServer {
    /// Construct a server (does not bind yet).
    #[must_use]
    pub fn new(cfg: ServerConfig, handler: MethodHandler) -> Self {
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        Self {
            cfg,
            started_at: Instant::now(),
            handler,
            shutdown_tx,
            shutdown_rx,
        }
    }

    /// Signal the accept loop to stop.
    pub fn request_shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    /// Borrow server config.
    #[must_use]
    pub fn config(&self) -> &ServerConfig {
        &self.cfg
    }

    /// Build the current status snapshot.
    #[must_use]
    pub fn status_snapshot(&self) -> DaemonStatus {
        DaemonStatus {
            version: self.cfg.server_version.clone(),
            pid: std::process::id(),
            state: "running".into(),
            endpoint: self.cfg.endpoint.display(),
            uptime_secs: self.started_at.elapsed().as_secs(),
        }
    }

    /// Bind and serve until shutdown is requested.
    ///
    /// # Errors
    ///
    /// Returns bind failures. Per-connection errors are logged and swallowed.
    pub async fn serve(self: Arc<Self>) -> IpcResult<()> {
        let listener = LocalListener::bind(self.cfg.endpoint.clone()).await?;
        tracing::info!(endpoint = %listener.endpoint().display(), "ipc server listening");

        let mut shutdown_rx = self.shutdown_rx.clone();
        loop {
            tokio::select! {
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        break;
                    }
                }
                accepted = listener.accept() => {
                    match accepted {
                        Ok(conn) => {
                            let server = Arc::clone(&self);
                            tokio::spawn(async move {
                                if let Err(err) = server.handle_connection(conn).await {
                                    tracing::warn!(error = %err, code = err.code(), "ipc connection closed with error");
                                }
                            });
                        }
                        Err(err) => {
                            if *self.shutdown_rx.borrow() {
                                break;
                            }
                            tracing::warn!(error = %err, "ipc accept failed");
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_connection(self: Arc<Self>, mut conn: ServerConnection) -> IpcResult<()> {
        let mut client: Option<ClientIdentity> = None;

        loop {
            let frame = match read_frame(&mut conn).await {
                Ok(f) => f,
                Err(IpcError::Disconnected(_)) => return Ok(()),
                Err(err) => return Err(err),
            };
            let req = match RpcRequest::from_bytes(&frame) {
                Ok(r) => r,
                Err(err) => {
                    let resp = RpcResponse::failure(
                        crate::rpc::RequestId::String("null".into()),
                        app_error::INVALID_PARAMS,
                        err.to_string(),
                    );
                    write_frame(&mut conn, &resp.to_bytes()?).await?;
                    continue;
                }
            };

            let response = self.dispatch(req, &mut client).await;
            write_frame(&mut conn, &response.to_bytes()?).await?;
        }
    }

    async fn dispatch(&self, req: RpcRequest, client: &mut Option<ClientIdentity>) -> RpcResponse {
        let id = req.id.clone();

        if req.method == methods::HELLO {
            // The authenticated identity is immutable for the lifetime of a
            // connection. A second hello must not be usable to switch principals
            // after ACL checks or revocation have bound the first identity.
            if let Some(identity) = client.as_ref() {
                return RpcResponse::failure(
                    id,
                    app_error::UNAUTHORIZED,
                    format!(
                        "ipc identity already bound to {}; reconnect to authenticate a new client",
                        identity.client_name
                    ),
                );
            }
            return match self.handle_hello(req) {
                Ok((result, identity)) => {
                    *client = Some(identity);
                    match serde_json::to_value(result) {
                        Ok(v) => RpcResponse::success(id, v),
                        Err(err) => RpcResponse::failure(id, app_error::INTERNAL, err.to_string()),
                    }
                }
                Err(IpcError::Remote { code, message }) => RpcResponse::failure(id, code, message),
                Err(err) if err.code() == "ipc_unauthorized" => {
                    RpcResponse::failure(id, app_error::UNAUTHORIZED, err.to_string())
                }
                Err(err) => RpcResponse::failure(id, app_error::UNAUTHORIZED, err.to_string()),
            };
        }

        let Some(identity) = client.clone() else {
            return RpcResponse::failure(
                id,
                app_error::UNAUTHORIZED,
                "ipc hello required before other methods",
            );
        };

        if self.is_revoked(&identity.client_name) {
            return RpcResponse::failure(
                id,
                app_error::TOKEN_REVOKED,
                format!("client {} is revoked", identity.client_name),
            );
        }

        if req.method == methods::PING {
            return RpcResponse::success(id, json!({"pong": true}));
        }

        if req.method == methods::STATUS {
            return match serde_json::to_value(self.status_snapshot()) {
                Ok(v) => RpcResponse::success(id, v),
                Err(err) => RpcResponse::failure(id, app_error::INTERNAL, err.to_string()),
            };
        }

        let handler = Arc::clone(&self.handler);
        let method = req.method.clone();
        let params = req.params.clone();
        match handler(method, params, identity).await {
            Ok(value) => RpcResponse::success(id, value),
            Err(IpcError::Remote { code, message }) => RpcResponse::failure(id, code, message),
            Err(err) if err.code() == "ipc_unauthorized" => {
                RpcResponse::failure(id, app_error::UNAUTHORIZED, err.to_string())
            }
            Err(err) => RpcResponse::failure(id, app_error::INTERNAL, err.to_string()),
        }
    }

    fn handle_hello(&self, req: RpcRequest) -> IpcResult<(HelloResult, ClientIdentity)> {
        let params: HelloParams = match req.params {
            Some(value) => serde_json::from_value(value)
                .map_err(|err| IpcError::Protocol(format!("invalid hello params: {err}")))?,
            None => {
                return Err(IpcError::Protocol("hello params required".into()));
            }
        };
        let peer = crate::auth::PeerCredential {
            token: params.token,
            client_name: params.client_name.clone(),
            os_user_id: None,
            pid: Some(std::process::id()),
        };
        self.cfg.auth.verify(&peer)?;
        if self.is_revoked(&params.client_name) {
            return Err(IpcError::Remote {
                code: app_error::TOKEN_REVOKED,
                message: format!("client {} is revoked", params.client_name),
            });
        }
        let identity = ClientIdentity {
            client_name: params.client_name,
            client_version: params.client_version,
        };
        Ok((
            HelloResult {
                server_name: self.cfg.server_name.clone(),
                server_version: self.cfg.server_version.clone(),
                authenticated: true,
            },
            identity,
        ))
    }

    fn is_revoked(&self, client_name: &str) -> bool {
        self.cfg
            .revoked_clients
            .read()
            .map(|g| g.contains(client_name))
            // Revocation state failure is authorization failure, never allow.
            .unwrap_or(true)
    }
}

/// Default handler that rejects unknown methods.
#[must_use]
pub fn reject_unknown_handler() -> MethodHandler {
    Arc::new(|method, _params, _client| {
        Box::pin(async move {
            Err(IpcError::Remote {
                code: app_error::METHOD_NOT_FOUND,
                message: format!("method not found: {method}"),
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{generate_token, write_token_file};
    use crate::client::{ClientOptions, IpcClient};
    use crate::endpoint::IpcBus;
    use crate::rpc::methods as m;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn second_hello_cannot_switch_bound_identity() {
        let token = generate_token();
        let endpoint = Endpoint::NamedPipe("test-only".into());
        let server = IpcServer::new(
            ServerConfig::new(endpoint, AuthGate::new(token.clone()), "test", "0.0.1"),
            reject_unknown_handler(),
        );
        let mut identity = None;

        let first = RpcRequest::new(
            methods::HELLO,
            Some(json!(HelloParams {
                token: token.clone(),
                client_name: "agent-a".into(),
                client_version: None,
            })),
        );
        let response = server.dispatch(first, &mut identity).await;
        assert!(response.error.is_none(), "{response:?}");
        assert_eq!(
            identity.as_ref().map(|i| i.client_name.as_str()),
            Some("agent-a")
        );

        let switch = RpcRequest::new(
            methods::HELLO,
            Some(json!(HelloParams {
                token,
                client_name: "agent-b".into(),
                client_version: None,
            })),
        );
        let response = server.dispatch(switch, &mut identity).await;
        assert_eq!(
            response.error.as_ref().map(|e| e.code),
            Some(app_error::UNAUTHORIZED)
        );
        assert_eq!(
            identity.as_ref().map(|i| i.client_name.as_str()),
            Some("agent-a"),
            "second hello must not mutate the bound identity"
        );
    }

    #[tokio::test]
    async fn revoked_client_rejected_on_hello_and_dispatch() {
        let dir = tempdir().unwrap();
        let token = generate_token();
        write_token_file(dir.path(), &token).unwrap();
        let revoked: RevokedClients = Arc::new(RwLock::new(HashSet::new()));
        let endpoint = Endpoint::default_for(dir.path(), IpcBus::Daemon);
        let handler: MethodHandler = Arc::new(|_m, _p, client| {
            Box::pin(async move { Ok(json!({ "client": client.client_name })) })
        });
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(endpoint.clone(), AuthGate::new(token), "test", "0.0.1")
                .with_revoked_clients(Arc::clone(&revoked)),
            handler,
        ));
        let serve = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = IpcClient::new(
            endpoint.clone(),
            dir.path(),
            ClientIdentity::new("agent-a", "1.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        );
        let ok = client
            .call("echo.who", None)
            .await
            .expect("pre-revoke call");
        assert_eq!(ok["client"], "agent-a");

        revoked.write().unwrap().insert("agent-a".into());

        let denied = client
            .call("echo.who", None)
            .await
            .expect_err("post-revoke dispatch");
        match denied {
            IpcError::Remote { code, .. } => assert_eq!(code, app_error::TOKEN_REVOKED),
            other => panic!("unexpected {other:?}"),
        }

        client.disconnect().await;
        let hello_denied = client
            .call(m::STATUS, None)
            .await
            .expect_err("revoked hello");
        match hello_denied {
            IpcError::Remote { code, .. } => assert_eq!(code, app_error::TOKEN_REVOKED),
            IpcError::Unauthorized(_) => {}
            other => panic!("unexpected {other:?}"),
        }

        server.request_shutdown();
        let _ = handle.await;
    }
}
