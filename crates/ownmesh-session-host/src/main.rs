//! OwnMesh session host — PTY supervisor skeleton with IPC client + terminal restore.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

use clap::{Parser, Subcommand};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ownmesh_config::OwnMeshPaths;
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{ClientIdentity, ClientOptions, Endpoint, IpcBus, IpcClient};
use std::io;
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
    /// Serve a session (skeleton — PTY arrives in chapter 9).
    Serve {
        /// Session id to host.
        #[arg(long)]
        session_id: Option<String>,
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
        Commands::Serve { session_id } => run_serve(session_id),
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
                    "session-host connected to ownmeshd {} (state={}, pid={})",
                    status.version, status.state, status.pid
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

fn run_serve(session_id: Option<String>) -> Result<(), ExitCode> {
    // Enter/leave raw mode to prove restore path; full PTY is chapter 9.
    if let Err(err) = enter_raw() {
        eprintln!("raw mode unavailable: {err}");
        return Err(ExitCode::Internal);
    }
    let _ = restore_terminal();
    println!(
        "ownmesh-session-host serve skeleton (session_id={:?}) — PTY arrives in chapter 9",
        session_id.unwrap_or_else(|| "unset".into())
    );
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_ipc::{
        generate_token, reject_unknown_handler, write_token_file, AuthGate, IpcServer, ServerConfig,
    };
    use std::sync::Arc;
    use tempfile::tempdir;

    #[test]
    fn restore_without_enter_is_ok() {
        restore_terminal().unwrap();
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
