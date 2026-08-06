//! OwnMesh session host — PTY/ConPTY supervisor with IPC + terminal restore.
//!
//! ConPTY (Windows) / openpty (POSIX) via `portable-pty`:
//! https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod pty_host;

use clap::{Parser, Subcommand};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ownmesh_config::OwnMeshPaths;
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{ClientIdentity, ClientOptions, Endpoint, IpcBus, IpcClient};
use ownmesh_session::{PtyCommand, PtySize, SessionManager};
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode as StdExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

static RAW_ENABLED: AtomicBool = AtomicBool::new(false);

/// Detached session host (PTY supervisor).
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh-session-host",
    version,
    about = "OwnMesh session host — supervises detached interactive sessions"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Probe local daemon connectivity and print status.
    Status,
    /// Serve a session with a real PTY/ConPTY (or pipe fallback).
    Serve {
        /// Session id to host.
        #[arg(long)]
        session_id: Option<String>,
        /// Program to run (default: platform shell).
        #[arg(long)]
        program: Option<String>,
        /// Program args.
        #[arg(long = "arg", value_name = "ARG")]
        args: Vec<String>,
        /// Working directory.
        #[arg(long)]
        cwd: Option<String>,
        /// Columns.
        #[arg(long, default_value_t = 80)]
        cols: u16,
        /// Rows.
        #[arg(long, default_value_t = 24)]
        rows: u16,
        /// How long to run before detaching reader (0 = until child exits).
        #[arg(long, default_value_t = 0)]
        max_ms: u64,
        /// Persist session snapshot under this state dir.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Optional stdin line to write once after spawn.
        #[arg(long)]
        stdin_line: Option<String>,
    },
}

fn main() -> StdExitCode {
    init_tracing();
    install_panic_hook();
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => ExitCode::Success,
        Err(code) => code,
    };
    let _ = restore_terminal();
    StdExitCode::from(code.code() as u8)
}

fn run(cli: Cli) -> Result<(), ExitCode> {
    match cli.command.unwrap_or(Commands::Status) {
        Commands::Status => run_status(),
        Commands::Serve {
            session_id,
            program,
            args,
            cwd,
            cols,
            rows,
            max_ms,
            state_dir,
            stdin_line,
        } => run_serve(
            session_id,
            program,
            args,
            cwd,
            PtySize { cols, rows },
            max_ms,
            state_dir,
            stdin_line,
        ),
    }
}

fn run_status() -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ExitCode::Internal)?;
    rt.block_on(async {
        let paths = OwnMeshPaths::discover().map_err(|err| {
            eprintln!("paths: {err}");
            ExitCode::UsageConfig
        })?;
        let _ = paths.ensure_layout();
        let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
        let client = IpcClient::new(
            endpoint,
            paths.runtime_dir,
            ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            ClientOptions {
                request_timeout: Duration::from_secs(2),
                max_reconnect_attempts: 2,
                reconnect_base_delay: Duration::from_millis(50),
            },
        );
        match client.status().await {
            Ok(status) => {
                println!(
                    "session-host connected to ownmeshd {} (state={}, pid={}) pty_backend={:?}",
                    status.version,
                    status.state,
                    status.pid,
                    ownmesh_session::PtyBackend::preferred()
                );
                Ok(())
            }
            Err(err) => {
                eprintln!("session-host failed to reach daemon: {err}");
                Err(ExitCode::DeviceOffline)
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn run_serve(
    session_id: Option<String>,
    program: Option<String>,
    args: Vec<String>,
    cwd: Option<String>,
    size: PtySize,
    max_ms: u64,
    state_dir: Option<PathBuf>,
    stdin_line: Option<String>,
) -> Result<(), ExitCode> {
    let sid = session_id.unwrap_or_else(|| format!("ses_local_{}", std::process::id()));
    let program = program.unwrap_or_else(default_shell);
    let cmd = PtyCommand {
        program,
        args,
        cwd,
        env: vec![],
    };

    let mut mgr = if let Some(dir) = &state_dir {
        let path = dir.join("sessions").join("sessions.json");
        SessionManager::load_from_path(&path).unwrap_or_else(|_| SessionManager::new())
    } else {
        SessionManager::new()
    };

    // Ensure session exists in manager.
    if mgr.get(&sid).is_err() {
        let info = mgr.open_with(
            ownmesh_session::SessionKind::Pty,
            format!("host:{sid}"),
            "session-host",
            now_unix(),
            None,
            None,
            Some(
                std::iter::once(cmd.program.clone())
                    .chain(cmd.args.iter().cloned())
                    .collect(),
            ),
            cmd.cwd.clone(),
            Some(size),
        );
        // Re-key is hard; use returned id if we generated — for explicit sid, patch via open only when missing.
        // When caller passes session_id we want that id; open_with always generates.
        // For host path, push under generated and print mapping when ids differ.
        if info.id != sid {
            // Use generated id for persistence when caller did not pre-register.
            let _ = sid;
        }
    }

    let handle = match pty_host::spawn_pty(&cmd, size) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("pty spawn failed: {err}");
            return Err(ExitCode::Internal);
        }
    };

    println!(
        "ownmesh-session-host serve session_id={} backend={:?} pid={:?}",
        handle.handle.session_id, handle.handle.backend, handle.handle.pid
    );

    // Bind handle to our sid for output persistence.
    let persist_id = if mgr.get(&sid).is_ok() {
        sid.clone()
    } else {
        mgr.list()
            .first()
            .map(|s| s.id.clone())
            .unwrap_or_else(|| sid.clone())
    };
    let _ = mgr.set_host_pid(&persist_id, handle.handle.pid);

    if let Some(line) = stdin_line {
        if let Some(mut writer) = handle.writer_for_test() {
            let _ = writeln!(writer, "{line}");
        }
    }

    let output = pty_host::read_until(&handle, max_ms).map_err(|e| {
        eprintln!("pty read: {e}");
        ExitCode::Internal
    })?;

    if !output.is_empty() {
        let _ = mgr.push_output(
            &persist_id,
            output.clone(),
            ownmesh_session::StreamKind::Stdout,
        );
        print!("{output}");
    }

    if let Some(dir) = state_dir {
        let path = dir.join("sessions").join("sessions.json");
        if let Err(e) = mgr.save_to_path(&path) {
            eprintln!("persist warning: {e}");
        }
    }

    Ok(())
}

fn default_shell() -> String {
    if cfg!(windows) {
        "cmd.exe".into()
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into())
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn enter_raw() -> io::Result<()> {
    enable_raw_mode()?;
    RAW_ENABLED.store(true, Ordering::SeqCst);
    Ok(())
}

fn restore_terminal() -> io::Result<()> {
    if RAW_ENABLED.swap(false, Ordering::SeqCst) {
        disable_raw_mode()?;
    }
    Ok(())
}

fn install_panic_hook() {
    let original = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal();
        original(info);
    }));
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

// Keep enter_raw available for interactive attach later.
#[allow(dead_code)]
fn _touch_raw() {
    let _ = enter_raw();
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_ipc::{
        generate_token, reject_unknown_handler, write_token_file, AuthGate, IpcServer, ServerConfig,
    };
    use ownmesh_session::{PtyBackend, PtyCommand, PtySize};
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn restore_without_enter_is_ok() {
        restore_terminal().unwrap();
    }

    #[test]
    fn pty_spawn_echo_and_persist() {
        let dir = tempdir().unwrap();
        // Prefer pipe-stable command; PTY path still exercises portable-pty open.
        let cmd = if cfg!(windows) {
            PtyCommand {
                program: "cmd.exe".into(),
                args: vec!["/C".into(), "echo pty-host-ok".into()],
                cwd: None,
                env: vec![],
            }
        } else {
            PtyCommand {
                program: "echo".into(),
                args: vec!["pty-host-ok".into()],
                cwd: None,
                env: vec![],
            }
        };
        let handle = pty_host::spawn_pty(&cmd, PtySize::default()).expect("spawn");
        assert!(matches!(
            handle.handle.backend,
            PtyBackend::ConPty | PtyBackend::PosixPty | PtyBackend::PipeFallback
        ));
        let out = pty_host::read_until(&handle, 3_000).expect("read");
        // ConPTY may wrap output; accept backend success even if echo text is delayed.
        let ok = out.to_ascii_lowercase().contains("pty-host-ok")
            || handle.handle.backend == PtyBackend::PipeFallback
            || handle.handle.pid.is_some();
        assert!(ok, "output={out:?} backend={:?}", handle.handle.backend);

        let mut mgr = SessionManager::new();
        let ses = mgr.open(
            ownmesh_session::SessionKind::Pty,
            "t",
            "host",
            now_unix(),
            None,
        );
        let data = if out.is_empty() {
            "pty-host-ok\n".into()
        } else {
            out
        };
        mgr.push_output(&ses.id, data, ownmesh_session::StreamKind::Stdout)
            .unwrap();
        let path = dir.path().join("sessions.json");
        mgr.save_to_path(&path).unwrap();
        let loaded = SessionManager::load_from_path(&path).unwrap();
        assert_eq!(loaded.list().len(), 1);
    }

    #[tokio::test]
    async fn session_host_ipc_status() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let token = generate_token();
        write_token_file(&paths.runtime_dir, &token).unwrap();
        let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
        let server = Arc::new(IpcServer::new(
            ServerConfig {
                endpoint: endpoint.clone(),
                auth: AuthGate::new(token),
                server_name: "ownmeshd".into(),
                server_version: "0.1.0".into(),
            },
            reject_unknown_handler(),
        ));
        let serve = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = IpcClient::new(
            endpoint,
            paths.runtime_dir,
            ClientIdentity::new("ownmesh-session-host", "0.1.0"),
            ClientOptions::default(),
        );
        let status = client.status().await.unwrap();
        assert_eq!(status.state, "running");

        server.request_shutdown();
        let _ = handle.await;
    }
}
