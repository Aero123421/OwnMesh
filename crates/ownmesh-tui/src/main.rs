//! OwnMesh TUI entrypoint — skeleton with IPC status + guaranteed terminal restore.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod i18n;
mod terminal;

use clap::Parser;
use ownmesh_config::OwnMeshPaths;
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{ClientIdentity, ClientOptions, DaemonStatus, Endpoint, IpcBus, IpcClient};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use std::process::ExitCode as StdExitCode;
use std::time::Duration;
use terminal::{create_ratatui, TerminalGuard};

/// OwnMesh terminal UI.
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh-tui",
    version,
    about = "OwnMesh TUI — approvals, sessions, and status"
)]
struct Cli {
    /// Fetch status via IPC and print once (no interactive UI).
    #[arg(long)]
    pub status: bool,

    /// Skip alternate-screen UI even without --status.
    #[arg(long)]
    pub once: bool,
}

fn main() -> StdExitCode {
    init_tracing();
    let cli = Cli::parse();
    let code = match run(cli) {
        Ok(()) => ExitCode::Success,
        Err(code) => code,
    };
    StdExitCode::from(code.code() as u8)
}

fn run(cli: Cli) -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|_| ExitCode::Internal)?;

    let status = rt.block_on(fetch_status());

    if cli.status || cli.once {
        match status {
            Ok(s) => {
                println!(
                    "ownmeshd {version} state={state} pid={pid} endpoint={endpoint}",
                    version = s.version,
                    state = s.state,
                    pid = s.pid,
                    endpoint = s.endpoint
                );
                Ok(())
            }
            Err(err) => {
                eprintln!("TUI failed to reach daemon: {err}");
                Err(ExitCode::DeviceOffline)
            }
        }
    } else {
        run_interactive(status.ok())
    }
}

async fn fetch_status() -> Result<DaemonStatus, ownmesh_ipc::IpcError> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        ownmesh_ipc::IpcError::Protocol(format!("paths: {err}"))
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
    client.status().await
}

fn run_interactive(status: Option<DaemonStatus>) -> Result<(), ExitCode> {
    let mut guard = TerminalGuard::enter().map_err(|err| {
        eprintln!("failed to enter raw terminal mode: {err}");
        ExitCode::Internal
    })?;

    let result = (|| -> Result<(), ExitCode> {
        let mut terminal = create_ratatui().map_err(|_| ExitCode::Internal)?;
        terminal
            .draw(|frame| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([Constraint::Length(3), Constraint::Min(3), Constraint::Length(2)])
                    .split(frame.area());

                let title = Paragraph::new(Line::from(vec![
                    Span::styled(
                        " OwnMesh ",
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("TUI skeleton"),
                ]))
                .block(Block::default().borders(Borders::ALL).title("header"));
                frame.render_widget(title, chunks[0]);

                let body = match &status {
                    Some(s) => format!(
                        "Connected to ownmeshd {}\nstate={} pid={} uptime={}s\nendpoint={}",
                        s.version, s.state, s.pid, s.uptime_secs, s.endpoint
                    ),
                    None => {
                        "Daemon offline.\nStart `ownmeshd run` then relaunch the TUI.".into()
                    }
                };
                let body = Paragraph::new(body)
                    .block(Block::default().borders(Borders::ALL).title("status"));
                frame.render_widget(body, chunks[1]);

                let footer = Paragraph::new("q quit · skeleton UI (chapter 13 expands this)")
                    .block(Block::default().borders(Borders::ALL));
                frame.render_widget(footer, chunks[2]);
            })
            .map_err(|_| ExitCode::Internal)?;

        // Brief display then exit (full event loop arrives with rich TUI chapter).
        std::thread::sleep(Duration::from_millis(50));
        Ok(())
    })();

    let _ = guard.restore();
    result
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
    use terminal::restore_terminal;

    #[tokio::test]
    async fn tui_client_fetches_daemon_status() {
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
            ClientIdentity::new("ownmesh-tui", "0.1.0"),
            ClientOptions::default(),
        );
        let status = client.status().await.unwrap();
        assert_eq!(status.state, "running");

        server.request_shutdown();
        let _ = handle.await;
    }

    #[test]
    fn panic_hook_restores_without_enter() {
        // Calling restore must never panic even if the terminal was not entered.
        restore_terminal().unwrap();
    }
}
