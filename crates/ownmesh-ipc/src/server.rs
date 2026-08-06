//! Local IPC server loop (daemon side).

use crate::auth::{AuthGate, PeerCredential};
use crate::endpoint::Endpoint;
use crate::error::{IpcError, IpcResult};
use crate::frame::{read_frame, write_frame};
use crate::rpc::{
    app_error, methods, DaemonStatus, HelloParams, HelloResult, RpcRequest, RpcResponse,
};
use crate::transport::{LocalListener, ServerConnection};
use serde_json::{json, Value};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::watch;

/// Handler callback type used by the server for application methods.
pub type MethodHandler = Arc<
    dyn Fn(String, Option<Value>) -> Pin<Box<dyn Future<Output = IpcResult<Value>> + Send>>
        + Send
        + Sync,
>;

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
        let listener = LocalListener::bind(self.cfg.endpoint.clone())?;
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
        let mut authenticated = false;

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

            let response = self.dispatch(req, &mut authenticated).await;
            write_frame(&mut conn, &response.to_bytes()?).await?;
        }
    }

    async fn dispatch(&self, req: RpcRequest, authenticated: &mut bool) -> RpcResponse {
        let id = req.id.clone();

        if req.method == methods::HELLO {
            return match self.handle_hello(req) {
                Ok(result) => {
                    *authenticated = true;
                    match serde_json::to_value(result) {
                        Ok(v) => RpcResponse::success(id, v),
                        Err(err) => RpcResponse::failure(id, app_error::INTERNAL, err.to_string()),
                    }
                }
                Err(err) => RpcResponse::failure(id, app_error::UNAUTHORIZED, err.to_string()),
            };
        }

        if !*authenticated {
            return RpcResponse::failure(
                id,
                app_error::UNAUTHORIZED,
                "ipc hello required before other methods",
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
        match handler(method, params).await {
            Ok(value) => RpcResponse::success(id, value),
            Err(IpcError::Remote { code, message }) => RpcResponse::failure(id, code, message),
            Err(err) if err.code() == "ipc_unauthorized" => {
                RpcResponse::failure(id, app_error::UNAUTHORIZED, err.to_string())
            }
            Err(err) => RpcResponse::failure(id, app_error::INTERNAL, err.to_string()),
        }
    }

    fn handle_hello(&self, req: RpcRequest) -> IpcResult<HelloResult> {
        let params: HelloParams = match req.params {
            Some(value) => serde_json::from_value(value)
                .map_err(|err| IpcError::Protocol(format!("invalid hello params: {err}")))?,
            None => {
                return Err(IpcError::Protocol("hello params required".into()));
            }
        };
        let peer = PeerCredential {
            token: params.token,
            client_name: params.client_name,
            os_user_id: None,
            pid: Some(std::process::id()),
        };
        self.cfg.auth.verify(&peer)?;
        Ok(HelloResult {
            server_name: self.cfg.server_name.clone(),
            server_version: self.cfg.server_version.clone(),
            authenticated: true,
        })
    }
}

/// Default handler that rejects unknown methods.
#[must_use]
pub fn reject_unknown_handler() -> MethodHandler {
    Arc::new(|method, _params| {
        Box::pin(async move {
            Err(IpcError::Remote {
                code: app_error::METHOD_NOT_FOUND,
                message: format!("method not found: {method}"),
            })
        })
    })
}
