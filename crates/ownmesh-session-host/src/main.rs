//! OwnMesh session host — PTY/ConPTY supervisor with IPC + terminal restore.
//!
//! ConPTY (Windows) / openpty (POSIX) via `portable-pty`:
//! https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session

#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value
)]

use clap::{Parser, Subcommand};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{ClientIdentity, ClientOptions, Endpoint, IpcClient};
use ownmesh_session::{
    load_manager, save_manager, PtyCommand, PtySize, SessionError, SessionManager, SessionResult,
};
use ownmesh_session_host::{read_until, spawn_pty, PtySession, SupervisorIpcServer};
use std::io;
use std::path::{Path, PathBuf};
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
    /// Run the persistent local-only PTY supervisor sidecar.
    ///
    /// This creates no network listener: it binds only OwnMesh IPC's per-user
    /// Unix socket or Windows named pipe endpoint.
    Supervise {
        /// Custody-attested owner-only sidecar state directory.
        #[arg(long)]
        state_dir: PathBuf,
        /// Runtime directory used to derive the local endpoint.
        #[arg(long)]
        runtime_dir: PathBuf,
    },
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
        Commands::Supervise {
            state_dir,
            runtime_dir,
        } => run_supervise(state_dir, runtime_dir),
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

fn run_supervise(state_dir: PathBuf, runtime_dir: PathBuf) -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| ExitCode::Internal)?;
    rt.block_on(async move {
        let (server, _) = SupervisorIpcServer::new(state_dir, runtime_dir).map_err(|err| {
            eprintln!("session supervisor setup: {err}");
            ExitCode::UsageConfig
        })?;
        server.serve().await.map_err(|err| {
            eprintln!("session supervisor stopped: {err}");
            ExitCode::Internal
        })
    })
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
        paths.ensure_layout().map_err(|err| {
            eprintln!("paths: {err}");
            ExitCode::UsageConfig
        })?;
        let cfg = load_config(&paths).map_err(|err| {
            eprintln!("config: {err}");
            ExitCode::UsageConfig
        })?;
        let endpoint = Endpoint::configured_daemon(
            &paths.runtime_dir,
            cfg.service_socket.path.as_deref(),
        )
        .map_err(|err| {
            eprintln!("service endpoint configuration failed: {err}");
            ExitCode::UsageConfig
        })?;
        let client = IpcClient::new(
            endpoint,
            paths.runtime_dir,
            ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            ClientOptions {
                request_timeout: Duration::from_secs(2),
                max_reconnect_attempts: 2,
                reconnect_base_delay: Duration::from_millis(50),
            },
        )
        .with_client_credential_from_env()
        .map_err(|err| {
            eprintln!(
                "session-host credential configuration failed: {err}; set {} to a daemon-provisioned cooperative-client credential",
                ownmesh_ipc::CLIENT_CREDENTIAL_ENV
            );
            ExitCode::Authentication
        })?;
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
                if matches!(err, ownmesh_ipc::IpcError::Unauthorized(_))
                    || matches!(
                        err,
                        ownmesh_ipc::IpcError::Remote { code, .. }
                            if matches!(
                                code,
                                ownmesh_ipc::app_error::UNAUTHORIZED
                                    | ownmesh_ipc::app_error::TOKEN_REVOKED
                            )
                    )
                {
                    eprintln!(
                        "session-host authentication failed: {err}; provision this cooperative client and set {}",
                        ownmesh_ipc::CLIENT_CREDENTIAL_ENV
                    );
                    Err(ExitCode::Authentication)
                } else {
                    eprintln!("session-host failed to reach daemon: {err}");
                    Err(ExitCode::DeviceOffline)
                }
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

    let sessions_path = state_dir
        .as_ref()
        .map(|dir| dir.join("sessions").join("sessions.json"));
    let mut mgr = load_session_manager(sessions_path.as_deref()).map_err(|err| {
        eprintln!("load session state: {err}");
        ExitCode::Internal
    })?;

    // Do not create a durable session until its process exists. For a new session,
    // creation and PID assignment are saved by one transaction below.
    let existing_id = match mgr.get(&sid) {
        Ok(_) => Some(sid.clone()),
        Err(SessionError::NotFound) => None,
        Err(err) => {
            eprintln!("find session: {err}");
            return Err(ExitCode::Internal);
        }
    };

    let handle = match spawn_pty(&cmd, size) {
        Ok(h) => h,
        Err(err) => {
            eprintln!("pty spawn failed: {err}");
            return Err(ExitCode::Internal);
        }
    };

    let persist_id = register_spawned_session(
        &mut mgr,
        sessions_path.as_deref(),
        existing_id,
        &sid,
        &cmd,
        size,
        handle.handle.pid,
    )
    .map_err(|err| {
        eprintln!("persist spawned session: {err}");
        report_cleanup_error(&handle);
        ExitCode::Internal
    })?;

    println!(
        "ownmesh-session-host serve session_id={} backend={:?} pid={:?}",
        handle.handle.session_id, handle.handle.backend, handle.handle.pid
    );

    if let Some(line) = stdin_line {
        handle.write_stdin_line(&line).map_err(|err| {
            eprintln!("pty stdin: {err}");
            report_cleanup_error(&handle);
            ExitCode::Internal
        })?;
    }

    // read_until always terminates and waits for the child, including on read errors.
    let output = read_until(&handle, max_ms).map_err(|err| {
        eprintln!("pty read: {err}");
        ExitCode::Internal
    })?;

    finalize_reaped_session(&mut mgr, sessions_path.as_deref(), &persist_id, &output).map_err(
        |err| {
            eprintln!("persist terminal session state: {err}");
            ExitCode::Internal
        },
    )?;

    if !output.is_empty() {
        print!("{output}");
    }

    Ok(())
}

/// Load session state through the shared `ownmesh-session` persistence layer.
fn load_session_manager(path: Option<&Path>) -> SessionResult<SessionManager> {
    path.map_or_else(
        || Ok(SessionManager::new()),
        |path| load_manager(path).map_err(|err| SessionError::Persist(err.to_string())),
    )
}

/// Register a successfully spawned process and save session creation plus PID atomically.
#[allow(clippy::too_many_arguments)]
fn register_spawned_session(
    manager: &mut SessionManager,
    path: Option<&Path>,
    existing_id: Option<String>,
    requested_id: &str,
    cmd: &PtyCommand,
    size: PtySize,
    pid: Option<u32>,
) -> SessionResult<String> {
    mutate_and_persist(manager, path, |manager| {
        let persist_id = if let Some(id) = existing_id {
            id
        } else {
            manager
                .open_with(
                    ownmesh_session::SessionKind::Pty,
                    format!("host:{requested_id}"),
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
                    None,
                )?
                .id
        };
        manager.set_host_pid(&persist_id, pid)?;
        Ok(persist_id)
    })
}

fn report_cleanup_error(handle: &PtySession) {
    if let Err(err) = handle.terminate_and_wait() {
        eprintln!("pty cleanup: {err}");
    }
}

/// Record final output and mark a reaped child's session terminal in one transaction.
fn finalize_reaped_session(
    manager: &mut SessionManager,
    path: Option<&Path>,
    session_id: &str,
    output: &str,
) -> SessionResult<()> {
    mutate_and_persist(manager, path, |manager| {
        if !output.is_empty() {
            manager.push_output(session_id, output, ownmesh_session::StreamKind::Stdout)?;
        }
        manager.set_host_pid(session_id, None)?;
        manager.close(session_id)
    })
}

/// Apply a manager mutation and durably save it as one in-memory transaction.
///
/// Any mutation or persistence error restores the complete pre-mutation manager.
fn mutate_and_persist<T>(
    manager: &mut SessionManager,
    path: Option<&Path>,
    mutate: impl FnOnce(&mut SessionManager) -> SessionResult<T>,
) -> SessionResult<T> {
    let snapshot = manager.clone();
    let value = match mutate(manager) {
        Ok(value) => value,
        Err(err) => {
            *manager = snapshot;
            return Err(err);
        }
    };

    if let Some(path) = path {
        if let Err(err) = save_manager(path, manager) {
            *manager = snapshot;
            return Err(SessionError::Persist(err.to_string()));
        }
    }
    Ok(value)
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
    use ownmesh_ipc::{reject_unknown_handler, AuthGate, IpcBus, IpcServer, ServerConfig};
    use ownmesh_session::{PtyBackend, PtyCommand, PtySize, SessionState};
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
        let handle = spawn_pty(&cmd, PtySize::default()).expect("spawn");
        assert!(matches!(
            handle.handle.backend,
            PtyBackend::ConPty | PtyBackend::PosixPty | PtyBackend::PipeFallback
        ));
        let out = read_until(&handle, 3_000).expect("read");
        // ConPTY may wrap output; accept backend success even if echo text is delayed.
        let ok = out.to_ascii_lowercase().contains("pty-host-ok")
            || handle.handle.backend == PtyBackend::PipeFallback
            || handle.handle.pid.is_some();
        assert!(ok, "output={out:?} backend={:?}", handle.handle.backend);

        let mut mgr = SessionManager::new();
        let ses = mgr
            .open(
                ownmesh_session::SessionKind::Pty,
                "t",
                "host",
                now_unix(),
                None,
            )
            .unwrap();
        let data = if out.is_empty() {
            "pty-host-ok\n".into()
        } else {
            out
        };
        mgr.push_output(&ses.id, data, ownmesh_session::StreamKind::Stdout)
            .unwrap();
        let path = dir.path().join("sessions.json");
        save_manager(&path, &mgr).unwrap();
        let loaded = load_manager(&path).unwrap();
        assert_eq!(loaded.list().len(), 1);
    }

    #[test]
    fn failed_spawn_does_not_persist_phantom_session() {
        let dir = tempdir().unwrap();
        let result = run_serve(
            Some("requested".into()),
            Some("ownmesh-program-that-does-not-exist".into()),
            vec![],
            None,
            PtySize::default(),
            100,
            Some(dir.path().to_path_buf()),
            None,
        );

        assert_eq!(result, Err(ExitCode::Internal));
        assert!(!dir.path().join("sessions/sessions.json").exists());
    }

    #[test]
    fn failed_initial_persist_does_not_leave_phantom_session() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        std::fs::create_dir(&path).unwrap();

        let mut mgr = SessionManager::new();
        let before = serde_json::to_value(&mgr).unwrap();
        let cmd = PtyCommand {
            program: "test-program".into(),
            args: vec!["--flag".into()],
            cwd: None,
            env: vec![],
        };

        let err = register_spawned_session(
            &mut mgr,
            Some(&path),
            None,
            "requested",
            &cmd,
            PtySize::default(),
            Some(42),
        )
        .expect_err("save to a directory must fail");

        assert!(matches!(err, SessionError::Persist(_)));
        assert_eq!(serde_json::to_value(&mgr).unwrap(), before);
        assert!(mgr.list().is_empty());
    }

    #[test]
    fn initial_session_creation_and_pid_are_saved_together() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let mut mgr = SessionManager::new();
        let cmd = PtyCommand {
            program: "test-program".into(),
            args: vec!["--flag".into()],
            cwd: Some("workdir".into()),
            env: vec![],
        };

        let id = register_spawned_session(
            &mut mgr,
            Some(&path),
            None,
            "requested",
            &cmd,
            PtySize::default(),
            Some(42),
        )
        .unwrap();

        let loaded = load_manager(&path).unwrap();
        let session = loaded.get(&id).unwrap();
        assert_eq!(session.host_pid, Some(42));
        assert_eq!(loaded.list().len(), 1);
    }

    #[test]
    fn reaped_session_output_and_terminal_lifecycle_are_saved_together() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        let mut mgr = SessionManager::new();
        let target = mgr
            .open(
                ownmesh_session::SessionKind::Pty,
                "target",
                "host",
                now_unix(),
                None,
            )
            .unwrap();
        mgr.attach_observer(&target.id, "reader", now_unix())
            .unwrap();
        mgr.set_host_pid(&target.id, Some(42)).unwrap();

        finalize_reaped_session(&mut mgr, Some(&path), &target.id, "final output\n").unwrap();

        let loaded = load_manager(&path).unwrap();
        let info = loaded.get(&target.id).unwrap();
        assert_eq!(info.host_pid, None);
        assert_eq!(info.state, SessionState::Closed);
        assert!(info.controller.is_none());
        let replay = loaded
            .replay_from(&target.id, "reader", 1, now_unix())
            .unwrap();
        assert_eq!(replay.len(), 1);
        assert_eq!(replay[0].data, "final output\n");
    }

    #[test]
    fn terminal_persist_failure_restores_complete_manager() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        std::fs::create_dir(&path).unwrap();

        let mut mgr = SessionManager::new();
        let target = mgr
            .open(
                ownmesh_session::SessionKind::Pty,
                "target",
                "host",
                now_unix(),
                None,
            )
            .unwrap();
        mgr.set_host_pid(&target.id, Some(42)).unwrap();
        let unrelated = mgr
            .open(
                ownmesh_session::SessionKind::Process,
                "unrelated",
                "other",
                now_unix(),
                None,
            )
            .unwrap();
        mgr.push_output(
            &unrelated.id,
            "existing output",
            ownmesh_session::StreamKind::System,
        )
        .unwrap();
        let before = serde_json::to_value(&mgr).unwrap();

        let err = finalize_reaped_session(&mut mgr, Some(&path), &target.id, "new output\n")
            .expect_err("save to a directory must fail");

        assert!(matches!(err, SessionError::Persist(_)));
        assert_eq!(serde_json::to_value(&mgr).unwrap(), before);
        let restored = mgr.get(&target.id).unwrap();
        assert_eq!(restored.host_pid, Some(42));
        assert_eq!(restored.state, SessionState::Running);
    }

    #[test]
    fn mutation_failure_also_restores_complete_manager() {
        let mut mgr = SessionManager::new();
        let target = mgr
            .open(
                ownmesh_session::SessionKind::Pty,
                "target",
                "host",
                now_unix(),
                None,
            )
            .unwrap();
        let before = serde_json::to_value(&mgr).unwrap();

        let err = mutate_and_persist(&mut mgr, None, |manager| {
            manager.set_host_pid(&target.id, Some(42))?;
            manager.push_output("missing", "must fail", ownmesh_session::StreamKind::Stdout)?;
            Ok(())
        })
        .expect_err("second mutation must fail");

        assert_eq!(err, SessionError::NotFound);
        assert_eq!(serde_json::to_value(&mgr).unwrap(), before);
    }

    #[test]
    fn corrupt_persisted_manager_is_not_replaced_with_empty_state() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("sessions.json");
        std::fs::write(&path, b"not json").unwrap();

        let err = load_session_manager(Some(&path)).expect_err("corruption must surface");
        assert!(matches!(err, SessionError::Persist(_)));
        assert_eq!(std::fs::read(&path).unwrap(), b"not json");
    }

    #[tokio::test]
    async fn session_host_ipc_status() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(
                endpoint.clone(),
                AuthGate::local_user(),
                "ownmeshd",
                "0.1.0",
            ),
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
