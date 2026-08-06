//! OwnMesh TUI — rich multi-screen UI with i18n, wizard, and Ctrl+K palette.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::field_reassign_with_default,
    clippy::match_same_arms,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::unnested_or_patterns,
    clippy::unnecessary_wraps,
    clippy::unused_self
)]

mod app;
mod i18n;
mod palette;
mod terminal;
mod theme;
mod ui;
mod width;
mod wizard;

use app::{App, Overlay, Screen};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use i18n::Lang;
use ownmesh_config::OwnMeshPaths;
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{
    methods, ClientIdentity, ClientOptions, DaemonStatus, Endpoint, IpcBus, IpcClient,
};
use palette::filter_commands;
use serde_json::json;
use std::process::ExitCode as StdExitCode;
use std::time::Duration;
use terminal::{create_ratatui, TerminalGuard};
use wizard::WizardStep;

/// OwnMesh terminal UI.
#[derive(Debug, Parser)]
#[command(
    name = "ownmesh-tui",
    version,
    about = "OwnMesh TUI — approvals, sessions, setup wizard, and status"
)]
struct Cli {
    /// Fetch status via IPC and print once (no interactive UI).
    #[arg(long)]
    pub status: bool,

    /// Skip alternate-screen UI even without --status.
    #[arg(long)]
    pub once: bool,

    /// Force language (`en-US`, `ja-JP`, `zh-Hans`, `ru-RU`).
    #[arg(long)]
    pub lang: Option<String>,

    /// Open setup wizard immediately.
    #[arg(long)]
    pub wizard: bool,

    /// Run translation completeness check and exit (CI helper).
    #[arg(long)]
    pub check_i18n: bool,
}

fn main() -> StdExitCode {
    init_tracing();
    let cli = Cli::parse();

    if cli.check_i18n {
        let issues = i18n::completeness_report();
        if issues.is_empty() {
            println!(
                "i18n completeness: OK ({} keys × 4 locales)",
                i18n::Msg::ALL.len()
            );
            return StdExitCode::from(ExitCode::Success.code() as u8);
        }
        eprintln!("i18n completeness FAILED:");
        for i in issues {
            eprintln!("  - {i}");
        }
        return StdExitCode::from(ExitCode::UsageConfig.code() as u8);
    }

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
        let paths = OwnMeshPaths::discover().map_err(|err| {
            eprintln!("paths: {err}");
            ExitCode::UsageConfig
        })?;
        let _ = paths.ensure_layout();
        let mut app = App::new(paths, status.ok());
        if let Some(lang) = &cli.lang {
            app.lang = Lang::parse(lang);
        }
        if cli.wizard {
            app.overlay = Overlay::Wizard;
        }
        // Best-effort refresh of approvals / sessions while runtime is live.
        if app.daemon.is_some() {
            if let Ok(v) = rt.block_on(ipc_call(methods::APPROVAL_LIST, None)) {
                app.set_approvals_from_json(&v);
            }
            if let Ok(v) = rt.block_on(ipc_call("session.list", None)) {
                app.set_sessions_from_json(&v);
            }
        }
        run_interactive(app, &rt)
    }
}

async fn fetch_status() -> Result<DaemonStatus, ownmesh_ipc::IpcError> {
    let paths = OwnMeshPaths::discover()
        .map_err(|err| ownmesh_ipc::IpcError::Protocol(format!("paths: {err}")))?;
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

async fn ipc_call(
    method: &str,
    params: Option<serde_json::Value>,
) -> Result<serde_json::Value, ownmesh_ipc::IpcError> {
    let paths = OwnMeshPaths::discover()
        .map_err(|err| ownmesh_ipc::IpcError::Protocol(format!("paths: {err}")))?;
    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let client = IpcClient::new(
        endpoint,
        paths.runtime_dir,
        ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        ClientOptions {
            request_timeout: Duration::from_secs(2),
            max_reconnect_attempts: 1,
            reconnect_base_delay: Duration::from_millis(20),
        },
    );
    client.call(method, params).await
}

fn run_interactive(mut app: App, rt: &tokio::runtime::Runtime) -> Result<(), ExitCode> {
    let mut guard = TerminalGuard::enter().map_err(|err| {
        eprintln!("failed to enter raw terminal mode: {err}");
        ExitCode::Internal
    })?;

    let result = (|| -> Result<(), ExitCode> {
        let mut terminal = create_ratatui().map_err(|_| ExitCode::Internal)?;
        while !app.should_quit {
            terminal
                .draw(|frame| ui::draw(frame, &app))
                .map_err(|_| ExitCode::Internal)?;

            if !event::poll(Duration::from_millis(200)).unwrap_or(false) {
                continue;
            }
            let Ok(ev) = event::read() else {
                continue;
            };
            match ev {
                Event::Key(key)
                    if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat =>
                {
                    handle_key(&mut app, key, rt);
                }
                Event::Mouse(me) => {
                    // Optional mouse: click left nav regions is best-effort via scroll.
                    use crossterm::event::{MouseButton, MouseEventKind};
                    if matches!(
                        me.kind,
                        MouseEventKind::Down(MouseButton::Left)
                            | MouseEventKind::ScrollDown
                            | MouseEventKind::ScrollUp
                    ) {
                        // Ignore coordinate mapping; scroll cycles list cursor.
                        if matches!(me.kind, MouseEventKind::ScrollDown) {
                            app.list_cursor = app.list_cursor.saturating_add(1);
                        } else if matches!(me.kind, MouseEventKind::ScrollUp) {
                            app.list_cursor = app.list_cursor.saturating_sub(1);
                        }
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
        Ok(())
    })();

    let _ = guard.restore();
    result
}

fn handle_key(app: &mut App, key: KeyEvent, rt: &tokio::runtime::Runtime) {
    // Global: Ctrl+K palette
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('k') {
        app.open_palette();
        return;
    }

    if app.palette.open {
        handle_palette_key(app, key);
        return;
    }

    if app.overlay == Overlay::Wizard {
        handle_wizard_key(app, key);
        return;
    }

    if app.overlay == Overlay::Help {
        if matches!(
            key.code,
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::F(1)
        ) {
            app.overlay = Overlay::None;
        }
        return;
    }

    match key.code {
        KeyCode::Char('q' | 'Q') => app.should_quit = true,
        KeyCode::F(1) | KeyCode::Char('?') => app.overlay = Overlay::Help,
        KeyCode::Tab | KeyCode::Right | KeyCode::Char('l')
            if !key.modifiers.contains(KeyModifiers::CONTROL) =>
        {
            // 'l' also used in settings — only cycle screens outside settings letter binds.
            if app.screen == Screen::Settings && key.code == KeyCode::Char('l') {
                app.cycle_settings_lang();
            } else {
                app.next_screen();
            }
        }
        KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') => app.prev_screen(),
        KeyCode::Char('1') => app.screen = Screen::Dashboard,
        KeyCode::Char('2') => app.screen = Screen::Devices,
        KeyCode::Char('3') => app.screen = Screen::Workspaces,
        KeyCode::Char('4') => app.screen = Screen::Sessions,
        KeyCode::Char('5') => app.screen = Screen::Profiles,
        KeyCode::Char('6') => app.screen = Screen::Approvals,
        KeyCode::Char('7') => app.screen = Screen::Transfers,
        KeyCode::Char('8') => app.screen = Screen::Activity,
        KeyCode::Char('9') => app.screen = Screen::Diagnostics,
        KeyCode::Char('0') => app.screen = Screen::Settings,
        KeyCode::Char('w') => {
            app.overlay = Overlay::Wizard;
            app.wizard.step = WizardStep::Welcome;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.screen == Screen::Approvals {
                app.approval_cursor = app.approval_cursor.saturating_sub(1);
            } else {
                app.list_cursor = app.list_cursor.saturating_sub(1);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.screen == Screen::Approvals {
                if !app.approvals.is_empty() {
                    app.approval_cursor = (app.approval_cursor + 1).min(app.approvals.len() - 1);
                }
            } else {
                app.list_cursor = app.list_cursor.saturating_add(1);
            }
        }
        KeyCode::Char('a') if app.screen == Screen::Approvals => {
            approve_selected(app, rt, true);
        }
        KeyCode::Char('d') if app.screen == Screen::Approvals => {
            approve_selected(app, rt, false);
        }
        KeyCode::Char('r') if app.screen == Screen::Approvals => {
            refresh_approvals(app, rt);
        }
        KeyCode::Char('p') if app.screen == Screen::Settings => {
            app.cycle_settings_preset();
        }
        KeyCode::Enter if app.screen == Screen::Settings => {
            if let Err(e) = app.apply_settings() {
                app.status_line = e;
            }
        }
        _ => {}
    }
}

fn handle_palette_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => app.palette.close(),
        KeyCode::Enter => app.run_selected_palette(),
        KeyCode::Up => {
            let n = filter_commands(app.lang, &app.palette.query).len();
            app.palette.move_cursor(-1, n);
        }
        KeyCode::Down => {
            let n = filter_commands(app.lang, &app.palette.query).len();
            app.palette.move_cursor(1, n);
        }
        KeyCode::Backspace => {
            app.palette.query.pop();
            app.palette.cursor = 0;
        }
        KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.palette.query.push(c);
            app.palette.cursor = 0;
        }
        _ => {}
    }
}

fn handle_wizard_key(app: &mut App, key: KeyEvent) {
    match key.code {
        KeyCode::Esc => {
            if app.wizard.step == WizardStep::Done || app.wizard.step == WizardStep::Welcome {
                app.overlay = Overlay::None;
            } else {
                app.wizard.step = app.wizard.step.back();
            }
        }
        KeyCode::Backspace => {
            app.wizard.step = app.wizard.step.back();
        }
        KeyCode::Up => match app.wizard.step {
            WizardStep::Language => app.wizard.cycle_lang(-1),
            WizardStep::Preset => app.wizard.cycle_preset(-1),
            _ => {}
        },
        KeyCode::Down => match app.wizard.step {
            WizardStep::Language => app.wizard.cycle_lang(1),
            WizardStep::Preset => app.wizard.cycle_preset(1),
            _ => {}
        },
        KeyCode::Enter => match app.wizard.step {
            WizardStep::Welcome | WizardStep::Language | WizardStep::Preset => {
                if app.wizard.step == WizardStep::Language {
                    app.lang = app.wizard.lang;
                }
                app.wizard.step = app.wizard.step.next();
            }
            WizardStep::Confirm => match app.wizard.save(&app.paths) {
                Ok(()) => {
                    app.lang = app.wizard.lang;
                    app.policy_preset = app.wizard.selected_preset();
                    app.status_line = i18n::t(app.lang, i18n::Msg::WizardSaveOk).to_owned();
                }
                Err(e) => {
                    app.wizard.error = Some(e);
                }
            },
            WizardStep::Done => {
                app.overlay = Overlay::None;
            }
        },
        _ => {}
    }
}

fn refresh_approvals(app: &mut App, rt: &tokio::runtime::Runtime) {
    match rt.block_on(ipc_call(methods::APPROVAL_LIST, None)) {
        Ok(v) => {
            app.set_approvals_from_json(&v);
            app.status_line = format!("approvals: {}", app.approvals.len());
        }
        Err(e) => {
            app.status_line = format!("refresh failed: {e}");
        }
    }
}

fn approve_selected(app: &mut App, rt: &tokio::runtime::Runtime, approve: bool) {
    let Some(item) = app.approvals.get(app.approval_cursor) else {
        app.status_line = i18n::t(app.lang, i18n::Msg::ApprovalsEmpty).to_owned();
        return;
    };
    if item.state != "pending" {
        app.status_line = format!("already {}", item.state);
        return;
    }
    let method = if approve {
        methods::APPROVAL_APPROVE
    } else {
        methods::APPROVAL_DENY
    };
    let id = item.id.clone();
    match rt.block_on(ipc_call(method, Some(json!({ "id": id })))) {
        Ok(_) => {
            refresh_approvals(app, rt);
            app.status_line = if approve {
                i18n::t(app.lang, i18n::Msg::ApprovalsApprove).to_owned()
            } else {
                i18n::t(app.lang, i18n::Msg::ApprovalsDeny).to_owned()
            };
        }
        Err(e) => app.status_line = format!("ipc: {e}"),
    }
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
    use ownmesh_policy::{
        full_access_has_no_hidden_restrictive_rules, preset_document, AccessPreset,
    };
    use std::sync::Arc;
    use tempfile::tempdir;
    use terminal::restore_terminal;
    use wizard::apply_setup;

    #[tokio::test]
    async fn tui_client_fetches_daemon_status() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let token = generate_token();
        write_token_file(&paths.runtime_dir, &token).unwrap();
        let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(endpoint.clone(), AuthGate::new(token), "ownmeshd", "0.1.0"),
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
        restore_terminal().unwrap();
    }

    #[test]
    fn wizard_e2e_all_presets_persist() {
        for (preset, wire) in [
            (AccessPreset::Recommended, "recommended"),
            (AccessPreset::WorkspaceOnly, "workspace_only"),
            (AccessPreset::FullUserAccess, "full_user_access"),
            (AccessPreset::FullAccess, "full_access"),
        ] {
            let dir = tempdir().unwrap();
            let paths = OwnMeshPaths::for_base(dir.path());
            apply_setup(&paths, Lang::EnUs, preset).unwrap();
            let pol = ownmesh_config::load_policy(&paths).unwrap();
            assert_eq!(pol.preset.as_deref(), Some(wire));
            let cfg = ownmesh_config::load_config(&paths).unwrap();
            assert_eq!(cfg.lang, "en-US");
            if preset == AccessPreset::FullAccess {
                assert!(full_access_has_no_hidden_restrictive_rules(
                    &preset_document(AccessPreset::FullAccess)
                ));
            }
        }
    }

    #[test]
    fn i18n_cli_completeness_clean() {
        assert!(i18n::completeness_report().is_empty());
    }
}
