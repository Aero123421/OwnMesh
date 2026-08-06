//! Broker accept loop and elevated execution.

use crate::now_unix;
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
    /// When true, requests must carry a valid capability token.
    pub require_capability: bool,
}

/// Serve configuration.
#[derive(Debug, Clone)]
pub struct BrokerServeConfig {
    pub endpoint: BrokerEndpoint,
    pub secret_file: PathBuf,
    pub allow_callers: Vec<String>,
    pub require_capability: bool,
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
pub async fn run_broker(cfg: BrokerServeConfig) -> Result<(), String> {
    let secret = load_or_create_secret(&cfg.secret_file)?;
    let state = Arc::new(AsyncMutex::new(BrokerState {
        secret,
        replay: ReplayCache::new(),
        allowed_callers: cfg.allow_callers.clone(),
        require_capability: cfg.require_capability,
    }));
    let addr_file = cfg.addr_file.as_deref();

    match &cfg.endpoint {
        BrokerEndpoint::LoopbackTcp(addr) => serve_loopback(*addr, addr_file, state).await,
        #[cfg(windows)]
        BrokerEndpoint::NamedPipe(name) => serve_named_pipe(name, addr_file, state).await,
        #[cfg(not(windows))]
        BrokerEndpoint::NamedPipe(name) => {
            Err(format!("named pipe {name} not supported on this OS"))
        }
        #[cfg(unix)]
        BrokerEndpoint::UnixSocket(path) => serve_unix_socket(path, addr_file, state).await,
        #[cfg(not(unix))]
        BrokerEndpoint::UnixSocket(path) => Err(format!(
            "unix socket {} not supported on this OS",
            path.display()
        )),
    }
}

async fn serve_loopback(
    addr: SocketAddr,
    addr_file: Option<&Path>,
    state: Arc<AsyncMutex<BrokerState>>,
) -> Result<(), String> {
    enforce_bind_is_networkless(addr)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("bind failed: {e}"))?;
    let local = listener
        .local_addr()
        .map_err(|e| format!("local_addr: {e}"))?;
    enforce_bind_is_networkless(local)?;
    if let Some(path) = addr_file {
        std::fs::write(path, local.to_string()).map_err(|e| e.to_string())?;
    }
    eprintln!("ownmesh-broker listening on {local} (loopback TCP fallback)");
    loop {
        let (sock, peer) = listener.accept().await.map_err(|e| e.to_string())?;
        if !peer.ip().is_loopback() {
            // Drop non-loopback peers — networkless enforcement.
            continue;
        }
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_conn(sock, st).await {
                eprintln!("conn error: {e}");
            }
        });
    }
}

#[cfg(windows)]
async fn serve_named_pipe(
    name: &str,
    addr_file: Option<&Path>,
    state: Arc<AsyncMutex<BrokerState>>,
) -> Result<(), String> {
    // Named pipes are OS-local IPC. Default SD grants creator owner / admins /
    // LocalSystem full control (Microsoft Named Pipe Security docs). Production
    // service install tightens ACL to the registered user + ownmeshd.
    use tokio::net::windows::named_pipe::ServerOptions;
    eprintln!("ownmesh-broker listening on named pipe {name}");
    if let Some(path) = addr_file {
        std::fs::write(path, name).map_err(|e| e.to_string())?;
    }
    let mut server = ServerOptions::new()
        .first_pipe_instance(true)
        .create(name)
        .map_err(|e| format!("CreateNamedPipe failed: {e}"))?;
    loop {
        server
            .connect()
            .await
            .map_err(|e| format!("pipe connect: {e}"))?;
        let connected = server;
        // Prepare next instance before handling.
        server = ServerOptions::new()
            .create(name)
            .map_err(|e| format!("CreateNamedPipe next: {e}"))?;
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_stream(connected, st).await {
                eprintln!("pipe conn error: {e}");
            }
        });
    }
}

#[cfg(unix)]
async fn serve_unix_socket(
    path: &Path,
    addr_file: Option<&Path>,
    state: Arc<AsyncMutex<BrokerState>>,
) -> Result<(), String> {
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
        "ownmesh-broker listening on unix socket {} (mode 0600)",
        path.display()
    );
    if let Some(addr_file) = addr_file {
        std::fs::write(addr_file, path.display().to_string()).map_err(|e| e.to_string())?;
    }
    loop {
        let (sock, _addr) = listener.accept().await.map_err(|e| e.to_string())?;
        // Local unix peer probe (mode 0600 + MAC; SO_PEERCRED documented in peer.rs).
        match crate::peer::check_unix_peer(&sock) {
            Ok(check) => {
                if std::env::var_os("OWNMESH_BROKER_DEBUG").is_some() {
                    eprintln!("peer check method={}", check.method);
                }
            }
            Err(e) => eprintln!("peer check warning: {e}"),
        }
        let st = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(e) = handle_stream(sock, st).await {
                eprintln!("unix conn error: {e}");
            }
        });
    }
}

/// Handle a TCP connection (public for tests).
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
        if st.require_capability && req.capability.is_none() {
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
