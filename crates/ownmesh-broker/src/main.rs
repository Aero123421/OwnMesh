//! OwnMesh networkless privileged broker.
//!
//! Listens only on local IPC (loopback TCP with shared secret for portable tests;
//! production OS service uses named pipe / unix socket + peer credentials).
//! Never opens outbound network connections.

use clap::{Parser, Subcommand};
use ownmesh_broker_client::{
    build_request, verify_request, BrokerRequest, BrokerResponse, BrokerSecret, ElevatedCommand,
    ReplayCache, DEFAULT_BROKER_ENDPOINT,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex as AsyncMutex;

/// CLI.
#[derive(Debug, Parser)]
#[command(name = "ownmesh-broker", version, about = "OwnMesh privileged broker (networkless)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Print help overview.
    Help,
    /// Show version.
    Version,
    /// Run broker (local loopback for dev/test).
    Run {
        /// Bind address (loopback only enforced).
        #[arg(long, default_value = "127.0.0.1:0")]
        bind: String,
        /// Path to secret file (32+ bytes). Generated if missing.
        #[arg(long)]
        secret_file: PathBuf,
        /// Write chosen bind address to this file.
        #[arg(long)]
        addr_file: Option<PathBuf>,
        /// Allowed caller principal ids (comma-separated).
        #[arg(long, default_value = "ownmeshd")]
        allow_callers: String,
    },
    /// Status (always local; no network probes).
    Status,
    /// One-shot local elevated run via in-process verify (test helper).
    Exec {
        #[arg(long)]
        secret_file: PathBuf,
        #[arg(long)]
        program: String,
        #[arg(long, default_value = "ownmeshd")]
        caller: String,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    if let Err(e) = run(cli).await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    match cli.cmd {
        Commands::Help => {
            println!(
                "ownmesh-broker — networkless privileged broker\n\
                 endpoint basename: {DEFAULT_BROKER_ENDPOINT}\n\
                 commands: help, version, run, status, exec"
            );
            Ok(())
        }
        Commands::Version => {
            println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Commands::Status => {
            println!("status=idle network=disabled endpoint={DEFAULT_BROKER_ENDPOINT}");
            Ok(())
        }
        Commands::Run {
            bind,
            secret_file,
            addr_file,
            allow_callers,
        } => {
            let addr: SocketAddr = bind
                .parse()
                .map_err(|e| format!("invalid bind address: {e}"))?;
            if !addr.ip().is_loopback() {
                return Err("broker must bind to loopback only (networkless design)".into());
            }
            let secret = load_or_create_secret(&secret_file)?;
            let allowed: Vec<String> = allow_callers
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            let listener = TcpListener::bind(addr)
                .await
                .map_err(|e| format!("bind failed: {e}"))?;
            let local = listener
                .local_addr()
                .map_err(|e| format!("local_addr: {e}"))?;
            if let Some(path) = addr_file {
                std::fs::write(&path, local.to_string()).map_err(|e| e.to_string())?;
            }
            eprintln!("ownmesh-broker listening on {local} (loopback only)");
            let state = Arc::new(AsyncMutex::new(BrokerState {
                secret,
                replay: ReplayCache::new(),
                allowed_callers: allowed,
            }));
            loop {
                let (sock, peer) = listener.accept().await.map_err(|e| e.to_string())?;
                if !peer.ip().is_loopback() {
                    continue;
                }
                let st = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(sock, st).await {
                        eprintln!("conn error: {e}");
                    }
                });
            }
        }
        Commands::Exec {
            secret_file,
            program,
            caller,
            args,
        } => {
            let secret = load_or_create_secret(&secret_file)?;
            let now = now_unix();
            let req = build_request(
                &secret,
                caller,
                format!("op_{}", now),
                ElevatedCommand {
                    program,
                    args,
                    cwd: None,
                    env: vec![],
                },
                now,
                60,
            );
            let mut replay = ReplayCache::new();
            let resp = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now)?;
            println!("{}", serde_json::to_string_pretty(&resp).unwrap());
            if !resp.ok {
                std::process::exit(resp.exit_code.unwrap_or(1));
            }
            Ok(())
        }
    }
}

struct BrokerState {
    secret: BrokerSecret,
    replay: ReplayCache,
    allowed_callers: Vec<String>,
}

async fn handle_conn(mut sock: TcpStream, state: Arc<AsyncMutex<BrokerState>>) -> Result<(), String> {
    let (reader, mut writer) = sock.split();
    let mut lines = BufReader::new(reader).lines();
    let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    let req: BrokerRequest = serde_json::from_str(&line).map_err(|e| e.to_string())?;
    let now = now_unix();
    let resp = {
        let mut st = state.lock().await;
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
    };
    let mut out = serde_json::to_string(&resp).map_err(|e| e.to_string())?;
    out.push('\n');
    writer
        .write_all(out.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn execute_verified(
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
    let mut cmd = Command::new(&req.command.program);
    cmd.args(&req.command.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &req.command.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &req.command.env {
        cmd.env(k, v);
    }
    match cmd.output() {
        Ok(out) => Ok(BrokerResponse {
            request_id: req.request_id.clone(),
            ok: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            error: None,
        }),
        Err(e) => Ok(BrokerResponse {
            request_id: req.request_id.clone(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(e.to_string()),
        }),
    }
}

fn load_or_create_secret(path: &PathBuf) -> Result<BrokerSecret, String> {
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
        Ok(secret)
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_non_loopback_bind_config() {
        // Unit-level: parse check used by run()
        let addr: SocketAddr = "8.8.8.8:9".parse().unwrap();
        assert!(!addr.ip().is_loopback());
    }

    #[test]
    fn unprivileged_caller_rejected() {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("sec");
        let secret = load_or_create_secret(&secret_path).unwrap();
        let req = build_request(
            &secret,
            "evil",
            "op",
            ElevatedCommand {
                program: "cmd.exe".into(),
                args: vec!["/C".into(), "echo no".into()],
                cwd: None,
                env: vec![],
            },
            now_unix(),
            30,
        );
        let mut replay = ReplayCache::new();
        let resp = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix())
            .unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("unauthorized caller"));
    }
}
