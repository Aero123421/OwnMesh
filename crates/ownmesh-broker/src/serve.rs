//! Broker accept loop and elevated execution.

use crate::now_unix;
use crate::peer::{
    assert_endpoint_peer_verifiable, loopback_tcp_peer_unverifiable_error,
    named_pipe_peer_unverifiable_error,
};
use ownmesh_broker_client::{
    verify_request, BrokerEndpoint, BrokerRequest, BrokerResponse, BrokerSecret, ElevatedCommand,
    ReplayCache,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;

/// Runtime broker state.
pub struct BrokerState {
    pub secret: BrokerSecret,
    pub replay: ReplayCache,
    pub allowed_callers: Vec<String>,
}

/// Serve configuration.
#[derive(Debug, Clone)]
pub struct BrokerServeConfig {
    pub endpoint: BrokerEndpoint,
    pub secret_file: PathBuf,
    pub allow_callers: Vec<String>,
    /// Optional path to write the bound TCP address (tests).
    pub addr_file: Option<PathBuf>,
}

/// Reject any non-loopback TCP bind (networkless design).
pub fn enforce_bind_is_networkless(addr: SocketAddr) -> Result<(), String> {
    if !addr.ip().is_loopback() {
        return Err(format!(
            "broker must bind to loopback only (networkless design); refused {addr}"
        ));
    }
    Ok(())
}

/// Load or create the shared secret file.
pub fn load_or_create_secret(path: &Path) -> Result<BrokerSecret, String> {
    if path.exists() {
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        if bytes.len() < 32 {
            return Err("secret file too short".into());
        }
        Ok(BrokerSecret::from_bytes(bytes))
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let secret = BrokerSecret::generate();
        std::fs::write(path, secret.as_bytes()).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(secret)
    }
}

/// Verify + authorize + run structured elevated command.
pub fn execute_verified(
    secret: &BrokerSecret,
    replay: &mut ReplayCache,
    allowed: &[String],
    req: &BrokerRequest,
    now: i64,
) -> Result<BrokerResponse, String> {
    verify_request(secret, req, now).map_err(|e| e.to_string())?;
    replay.check_and_insert(req).map_err(|e| e.to_string())?;
    if !allowed.iter().any(|a| a == &req.caller_principal) {
        return Ok(BrokerResponse {
            request_id: req.request_id.clone(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some("unauthorized caller".into()),
        });
    }
    // Structured elevated execution only — never pass through a raw shell string.
    Ok(run_elevated_command(req))
}

fn run_elevated_command(req: &BrokerRequest) -> BrokerResponse {
    run_elevated(&req.request_id, &req.command)
}

fn run_elevated(request_id: &str, command: &ElevatedCommand) -> BrokerResponse {
    let mut cmd = Command::new(&command.program);
    cmd.args(&command.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &command.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &command.env {
        cmd.env(k, v);
    }
    // On Windows, Job Object management is best-effort via process group later;
    // kill_on_drop is handled by the OS when broker exits.
    match cmd.output() {
        Ok(out) => BrokerResponse {
            request_id: request_id.to_string(),
            ok: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            error: None,
        },
        Err(e) => BrokerResponse {
            request_id: request_id.to_string(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(e.to_string()),
        },
    }
}

/// Run the broker accept loop until cancelled / error.
///
/// Production start is fail-closed unless the endpoint supports OS peer
/// credential verification (Unix domain socket + SO_PEERCRED). Loopback TCP and
/// Named Pipe are refused with an explicit error.
pub async fn run_broker(cfg: BrokerServeConfig) -> Result<(), String> {
    // Peer-cred gate before bind / secret side effects that imply a live broker.
    assert_endpoint_peer_verifiable(&cfg.endpoint)?;

    match &cfg.endpoint {
        BrokerEndpoint::LoopbackTcp(_) => {
            // Double-check: never bind an unverifiable privileged endpoint.
            Err(loopback_tcp_peer_unverifiable_error())
        }
        BrokerEndpoint::NamedPipe(_name) => {
            // Safe peer identity is not available without large/unsafe OS API surface.
            Err(named_pipe_peer_unverifiable_error())
        }
        #[cfg(unix)]
        BrokerEndpoint::UnixSocket(path) => run_unix_broker(path, &cfg).await,
        #[cfg(not(unix))]
        BrokerEndpoint::UnixSocket(path) => Err(format!(
            "unix socket {} not supported on this OS (fail-closed)",
            path.display()
        )),
    }
}

#[cfg(unix)]
async fn run_unix_broker(path: &Path, cfg: &BrokerServeConfig) -> Result<(), String> {
    use crate::peer::allowed_peer_uids_from_env;

    let secret = load_or_create_secret(&cfg.secret_file)?;
    let state = Arc::new(AsyncMutex::new(BrokerState {
        secret,
        replay: ReplayCache::new(),
        allowed_callers: cfg.allow_callers.clone(),
    }));

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
    let listener = tokio::net::UnixListener::bind(path)
        .await
        .map_err(|e| format!("unix bind: {e}"))?;
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    eprintln!(
        "ownmesh-broker listening on unix socket {} (mode 0600, SO_PEERCRED required)",
        path.display()
    );
    if let Some(af) = &cfg.addr_file {
        std::fs::write(af, path.display().to_string()).map_err(|e| e.to_string())?;
    }
    let allowed_uids = allowed_peer_uids_from_env();
    loop {
        let (sock, _addr) = listener.accept().await.map_err(|e| e.to_string())?;
        // Fail-closed: drop connections that fail peer-cred retrieval or uid check.
        match crate::peer::authorize_unix_peer(&sock, &allowed_uids) {
            Ok(check) => {
                if std::env::var_os("OWNMESH_BROKER_DEBUG").is_some() {
                    eprintln!(
                        "peer check ok method={} cred={:?}",
                        check.method, check.cred
                    );
                }
                let st = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_stream(sock, st).await {
                        eprintln!("unix conn error: {e}");
                    }
                });
            }
            Err(e) => {
                eprintln!("ownmesh-broker: rejecting peer (fail-closed): {e}");
                // sock dropped — connection not served
            }
        }
    }
}

/// Handle a TCP connection (public for tests of MAC/capability path only).
///
/// Production `run_broker` refuses LoopbackTcp endpoints; this helper remains for
/// in-process unit tests that exercise request auth without OS peer credentials.
pub async fn handle_tcp_conn(
    sock: tokio::net::TcpStream,
    state: Arc<AsyncMutex<BrokerState>>,
) -> Result<(), String> {
    handle_stream(sock, state).await
}

async fn handle_stream<S>(mut sock: S, state: Arc<AsyncMutex<BrokerState>>) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(&mut sock);
    let mut lines = BufReader::new(reader).lines();
    let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    let req: BrokerRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = BrokerResponse {
                request_id: "unknown".into(),
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(format!("malformed request: {e}")),
            };
            write_resp(&mut writer, &resp).await?;
            return Ok(());
        }
    };
    let now = now_unix();
    let resp = {
        let mut st = state.lock().await;
        // Capability is mandatory on every request.
        if req.capability.is_none() {
            BrokerResponse {
                request_id: req.request_id.clone(),
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some("capability token required".into()),
            }
        } else {
            let allowed = st.allowed_callers.clone();
            let secret_bytes = st.secret.as_bytes().to_vec();
            let secret = BrokerSecret::from_bytes(secret_bytes);
            match execute_verified(&secret, &mut st.replay, &allowed, &req, now) {
                Ok(r) => r,
                Err(e) => BrokerResponse {
                    request_id: req.request_id.clone(),
                    ok: false,
                    exit_code: None,
                    stdout: String::new(),
                    stderr: String::new(),
                    error: Some(e),
                },
            }
        }
    };
    write_resp(&mut writer, &resp).await
}

async fn write_resp<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &BrokerResponse,
) -> Result<(), String> {
    let mut out = serde_json::to_string(resp).map_err(|e| e.to_string())?;
    out.push('\n');
    writer
        .write_all(out.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}
