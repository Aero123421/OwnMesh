//! Local IPC server loop (daemon side).

use crate::auth::{
    canonicalize_principal_key, AuthGate, AuthResolution, OsPeerIdentity, PeerCredential,
};
use crate::client::ClientIdentity;
use crate::endpoint::Endpoint;
use crate::error::{IpcError, IpcResult};
use crate::frame::{read_frame, write_frame};
use crate::registry::{canonical_client_id, managed_principal, MANAGEMENT_CLIENT_ID};
use crate::rpc::{
    app_error, methods, CredentialClientParams, CredentialProvisionParams, CredentialSecretResult,
    DaemonStatus, HelloParams, HelloResult, RpcRequest, RpcResponse,
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

/// Shared revoked-principal set checked on hello and every subsequent dispatch.
///
/// Keys are **mapped principal keys** (from OS peer / server-managed credentials),
/// never raw self-reported HELLO names.
pub type RevokedClients = Arc<RwLock<HashSet<String>>>;

#[derive(Clone)]
struct BoundClient {
    identity: ClientIdentity,
    auth: AuthResolution,
}

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
    /// Principal keys rejected at hello and on later dispatches.
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

    /// Attach a shared revoked-principal set (typically owned by the daemon runtime).
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

    /// Issue a server-managed per-client credential bound to the daemon OS user.
    ///
    /// This narrow daemon-local helper accepts only a client id. The principal is
    /// always derived as `client:<canonical client_id>`; callers cannot select it
    /// or open/mutate durable registry state directly.
    pub fn issue_client_credential(&self, client_id: impl Into<String>) -> IpcResult<String> {
        let client_id = validate_requested_client_id(&client_id.into())?;
        self.cfg
            .auth
            .issue_client_credential(client_id, self.cfg.auth.own_user_id())
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
        // Read one bounded frame before capturing identity. Windows named-pipe
        // impersonation is connection-bound to the last message read; Unix peer
        // credentials were already captured at accept. No frame contents are trusted yet.
        let first_frame = match read_frame(&mut conn).await {
            Ok(frame) => frame,
            Err(IpcError::Disconnected(_)) => return Ok(()),
            Err(err) => return Err(err),
        };
        // Capture OS peer once; never trust later self-reported identity fields.
        let os_peer = conn.peer_identity()?;
        if let Err(err) = self.cfg.auth.verify_os_peer(&os_peer) {
            tracing::warn!(error = %err, "rejecting connection: OS peer not permitted");
            return Err(err);
        }

        let mut client: Option<BoundClient> = None;
        let mut pending_frame = Some(first_frame);

        loop {
            let frame = if let Some(frame) = pending_frame.take() {
                frame
            } else {
                match read_frame(&mut conn).await {
                    Ok(f) => f,
                    Err(IpcError::Disconnected(_)) => return Ok(()),
                    Err(err) => return Err(err),
                }
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

            let response = self.dispatch(req, &mut client, &os_peer).await;
            write_frame(&mut conn, &response.to_bytes()?).await?;
        }
    }

    async fn dispatch(
        &self,
        req: RpcRequest,
        client: &mut Option<BoundClient>,
        os_peer: &OsPeerIdentity,
    ) -> RpcResponse {
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
                        identity.identity.client_name
                    ),
                );
            }
            return match self.handle_hello(req, os_peer) {
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

        // Revocation is always checked against the mapped principal key.
        if self.is_revoked(&identity.auth.principal_key) {
            return RpcResponse::failure(
                id,
                app_error::TOKEN_REVOKED,
                format!("principal {} is revoked", identity.auth.principal_key),
            );
        }

        // Registry-backed gates restrict uncredentialed same-uid peers to ping/status.
        // Default local_user()/for_user() gates leave this as a no-op.
        if let Err(err) = self.cfg.auth.authorize_method(&req.method, &identity.auth) {
            return match err {
                IpcError::Unauthorized(message) => {
                    RpcResponse::failure(id, app_error::UNAUTHORIZED, message)
                }
                other => RpcResponse::failure(id, app_error::INTERNAL, other.to_string()),
            };
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

        if credential_lifecycle_method(&req.method) {
            return match self.handle_credential_lifecycle(&req.method, req.params, os_peer) {
                Ok(value) => RpcResponse::success(id, value),
                Err(IpcError::Protocol(message) | IpcError::Codec(message)) => {
                    RpcResponse::failure(id, app_error::INVALID_PARAMS, message)
                }
                // Authentication already succeeded in authorize_method. Registry
                // Unauthorized here means invalid lifecycle state (duplicate/missing).
                Err(IpcError::Unauthorized(message)) => {
                    RpcResponse::failure(id, app_error::CONFLICT, message)
                }
                Err(IpcError::Remote { code, message }) => RpcResponse::failure(id, code, message),
                Err(err) => RpcResponse::failure(id, app_error::INTERNAL, err.to_string()),
            };
        }

        let handler = Arc::clone(&self.handler);
        let method = req.method.clone();
        let params = req.params.clone();
        match handler(method, params, identity.identity).await {
            Ok(value) => RpcResponse::success(id, value),
            Err(IpcError::Remote { code, message }) => RpcResponse::failure(id, code, message),
            Err(err) if err.code() == "ipc_unauthorized" => {
                RpcResponse::failure(id, app_error::UNAUTHORIZED, err.to_string())
            }
            Err(err) => RpcResponse::failure(id, app_error::INTERNAL, err.to_string()),
        }
    }

    fn handle_credential_lifecycle(
        &self,
        method: &str,
        params: Option<Value>,
        os_peer: &OsPeerIdentity,
    ) -> IpcResult<Value> {
        match method {
            methods::CREDENTIAL_PROVISION => {
                let params: CredentialProvisionParams = parse_required_params(params)?;
                let client_id = validate_requested_client_id(&params.client_id)?;
                let principal = managed_principal_for_client_id(&client_id);
                let credential = self
                    .cfg
                    .auth
                    .provision_client_credential(&client_id, &os_peer.user_id)?;
                serde_json::to_value(CredentialSecretResult {
                    client_id,
                    principal,
                    credential,
                })
                .map_err(|err| IpcError::Protocol(err.to_string()))
            }
            methods::CREDENTIAL_ROTATE => {
                let params: CredentialClientParams = parse_required_params(params)?;
                let client_id = validate_requested_client_id(&params.client_id)?;
                let principal = managed_principal_for_client_id(&client_id);
                let credential = self.cfg.auth.rotate_client_credential(&client_id)?;
                serde_json::to_value(CredentialSecretResult {
                    client_id,
                    principal,
                    credential,
                })
                .map_err(|err| IpcError::Protocol(err.to_string()))
            }
            methods::CREDENTIAL_REVOKE => {
                let params: CredentialClientParams = parse_required_params(params)?;
                let client_id = validate_requested_client_id(&params.client_id)?;
                self.cfg.auth.revoke_client_credential(&client_id)?;
                Ok(json!({ "ok": true, "client_id": client_id }))
            }
            _ => Err(IpcError::Protocol(format!(
                "not a credential lifecycle method: {method}"
            ))),
        }
    }

    fn handle_hello(
        &self,
        req: RpcRequest,
        os_peer: &OsPeerIdentity,
    ) -> IpcResult<(HelloResult, BoundClient)> {
        let params: HelloParams = match req.params {
            Some(value) => serde_json::from_value(value)
                .map_err(|err| IpcError::Protocol(format!("invalid hello params: {err}")))?,
            None => {
                return Err(IpcError::Protocol("hello params required".into()));
            }
        };

        // Self-reported client_name is intentionally NOT used for principal mapping.
        // Only OS peer + registry/in-memory credential yield a registered principal.
        // The optional owner claim is carried only to make its untrusted status explicit.
        let presented = PeerCredential {
            token: params.token,
            client_name: params.client_name,
            owner: params.owner,
            os_user_id: Some(os_peer.user_id.clone()),
            pid: Some(os_peer.pid),
            client_credential: params.client_credential,
        };

        let auth = self.cfg.auth.resolve_auth(os_peer, &presented)?;
        let principal = auth.principal_key.clone();

        if self.is_revoked(&principal) {
            return Err(IpcError::Remote {
                code: app_error::TOKEN_REVOKED,
                message: format!("principal {principal} is revoked"),
            });
        }

        // Only the server-assigned principal reaches application handlers;
        // credential metadata remains private to dispatch authorization.
        let identity = ClientIdentity {
            client_name: principal.clone(),
            client_version: params.client_version,
        };
        let bound = BoundClient {
            identity,
            auth: auth.clone(),
        };
        Ok((
            HelloResult {
                server_name: self.cfg.server_name.clone(),
                server_version: self.cfg.server_version.clone(),
                authenticated: true,
                principal: Some(principal),
                credentialed: auth.credentialed,
            },
            bound,
        ))
    }

    fn is_revoked(&self, principal_key: &str) -> bool {
        let principal_key = canonicalize_principal_key(principal_key);
        if principal_key.is_empty() {
            return true;
        }
        self.cfg
            .revoked_clients
            .read()
            .map(|guard| {
                guard
                    .iter()
                    .any(|stored| canonicalize_principal_key(stored) == principal_key)
            })
            // Revocation state failure is authorization failure, never allow.
            .unwrap_or(true)
    }
}

fn credential_lifecycle_method(method: &str) -> bool {
    matches!(
        method,
        methods::CREDENTIAL_PROVISION | methods::CREDENTIAL_ROTATE | methods::CREDENTIAL_REVOKE
    )
}

fn parse_required_params<T: serde::de::DeserializeOwned>(params: Option<Value>) -> IpcResult<T> {
    let value = params.ok_or_else(|| IpcError::Protocol("method params are required".into()))?;
    serde_json::from_value(value)
        .map_err(|err| IpcError::Protocol(format!("invalid params: {err}")))
}

fn validate_requested_client_id(raw: &str) -> IpcResult<String> {
    let client_id = canonical_client_id(raw)?;
    if client_id == MANAGEMENT_CLIENT_ID {
        return Err(IpcError::Protocol(
            "client_id is reserved for fixed daemon management".into(),
        ));
    }
    Ok(client_id)
}

fn managed_principal_for_client_id(client_id: &str) -> String {
    managed_principal(client_id)
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
    use crate::client::{ClientOptions, IpcClient};
    use crate::endpoint::IpcBus;
    use crate::rpc::methods as m;
    use std::time::Duration;
    use tempfile::tempdir;

    #[tokio::test]
    async fn second_hello_cannot_switch_bound_identity() {
        use crate::frame::{read_frame, write_frame};
        use crate::rpc::{HelloParams, RpcRequest, RpcResponse};
        use crate::transport::connect;

        let dir = tempdir().unwrap();
        let endpoint = Endpoint::default_for(dir.path(), IpcBus::Daemon);
        let auth = AuthGate::local_user();
        let cred_a = auth
            .issue_client_credential("agent-a", auth.own_user_id())
            .unwrap();
        let cred_b = auth
            .issue_client_credential("agent-b", auth.own_user_id())
            .unwrap();
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(endpoint.clone(), auth, "test", "0.0.1"),
            reject_unknown_handler(),
        ));
        let serve = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Attack path: raw second HELLO on the same connection must not rebind.
        let mut conn = connect(&endpoint).await.expect("connect");
        let hello_a = RpcRequest::new(
            m::HELLO,
            Some(json!(HelloParams {
                token: String::new(),
                client_name: "label-a".into(),
                owner: Some("spoofed-owner-a".into()),
                client_version: Some("1.0.0".into()),
                client_credential: Some(cred_a),
            })),
        );
        write_frame(&mut conn, &hello_a.to_bytes().unwrap())
            .await
            .unwrap();
        let first = RpcResponse::from_bytes(&read_frame(&mut conn).await.unwrap()).unwrap();
        let first_val = first.into_result().expect("first hello ok");
        assert_eq!(first_val["principal"], "client:agent-a");

        let hello_b = RpcRequest::new(
            m::HELLO,
            Some(json!(HelloParams {
                token: String::new(),
                client_name: "label-b-as-admin".into(),
                owner: Some("spoofed-owner-b".into()),
                client_version: Some("9.9.9".into()),
                client_credential: Some(cred_b.clone()),
            })),
        );
        write_frame(&mut conn, &hello_b.to_bytes().unwrap())
            .await
            .unwrap();
        let second = RpcResponse::from_bytes(&read_frame(&mut conn).await.unwrap()).unwrap();
        match second.into_result() {
            Err(IpcError::Remote { code, message }) => {
                assert_eq!(code, app_error::UNAUTHORIZED);
                assert!(
                    message.to_ascii_lowercase().contains("already bound"),
                    "{message}"
                );
            }
            other => panic!("second hello must fail closed, got {other:?}"),
        }

        // Bound identity remains agent-a for subsequent methods on this conn.
        let ping_req = RpcRequest::new(m::PING, None);
        write_frame(&mut conn, &ping_req.to_bytes().unwrap())
            .await
            .unwrap();
        let ping_resp = RpcResponse::from_bytes(&read_frame(&mut conn).await.unwrap()).unwrap();
        ping_resp
            .into_result()
            .expect("ping under original principal");

        // A fresh connection may authenticate as agent-b.
        let client_b = IpcClient::new(
            server.config().endpoint.clone(),
            dir.path(),
            ClientIdentity::new("label-b", "1.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        )
        .with_client_credential(cred_b);
        client_b.ping().await.expect("other principal on new conn");

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn self_reported_name_does_not_become_principal() {
        let dir = tempdir().unwrap();
        let endpoint = Endpoint::default_for(dir.path(), IpcBus::Daemon);
        let handler: MethodHandler = Arc::new(|_m, _p, client| {
            Box::pin(async move { Ok(json!({ "principal": client.client_name })) })
        });
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(endpoint.clone(), AuthGate::local_user(), "test", "0.0.1"),
            handler,
        ));
        let serve = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = IpcClient::new(
            endpoint,
            dir.path(),
            ClientIdentity::new("i-am-root", "1.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        );
        let got = client.call("echo.who", None).await.expect("call");
        let principal = got["principal"].as_str().unwrap();
        assert_ne!(principal, "i-am-root");
        assert!(
            principal.starts_with("user:"),
            "expected OS-derived principal, got {principal}"
        );

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn revoked_principal_rejected_on_hello_and_dispatch() {
        let dir = tempdir().unwrap();
        let revoked: RevokedClients = Arc::new(RwLock::new(HashSet::new()));
        let endpoint = Endpoint::default_for(dir.path(), IpcBus::Daemon);
        let auth = AuthGate::local_user();
        let cred = auth
            .issue_client_credential("agent-a", auth.own_user_id())
            .unwrap();
        let handler: MethodHandler = Arc::new(|_m, _p, client| {
            Box::pin(async move { Ok(json!({ "client": client.client_name })) })
        });
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(endpoint.clone(), auth, "test", "0.0.1")
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
            ClientIdentity::new("ignored-label", "1.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        )
        .with_client_credential(cred.clone());
        let ok = client
            .call("echo.who", None)
            .await
            .expect("pre-revoke call");
        assert_eq!(ok["client"], "client:agent-a");

        revoked.write().unwrap().insert("client:agent-a".into());

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

        // Alias bypass: reconnect with a different self-reported name + same credential.
        let alias = IpcClient::new(
            endpoint,
            dir.path(),
            ClientIdentity::new("totally-different-alias", "9.9.9"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        )
        .with_client_credential(cred);
        let alias_denied = alias.status().await.expect_err("alias must stay revoked");
        match alias_denied {
            IpcError::Remote { code, .. } => assert_eq!(code, app_error::TOKEN_REVOKED),
            IpcError::Unauthorized(_) => {}
            other => panic!("unexpected {other:?}"),
        }

        server.request_shutdown();
        let _ = handle.await;
    }
}
