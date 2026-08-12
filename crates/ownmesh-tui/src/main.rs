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

use app::{App, ApprovalDecision, Overlay, PendingApproval, Screen};
use clap::Parser;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use i18n::Lang;
use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{methods, ClientIdentity, ClientOptions, DaemonStatus, Endpoint, IpcClient};
use palette::filter_commands;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode as StdExitCode, Stdio};
use std::time::{Duration, Instant};
use terminal::{create_ratatui, TerminalGuard};
use wizard::{apply_setup_request, SetupRequest, WizardStep};

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
    ///
    /// Resolution order is `--lang`, then `OWNMESH_LANG`, then `config.lang`.
    #[arg(long, env = "OWNMESH_LANG")]
    pub lang: Option<String>,

    /// Open setup wizard immediately.
    #[arg(long)]
    pub wizard: bool,

    /// Run translation completeness check and exit (CI helper).
    #[arg(long)]
    pub check_i18n: bool,
}

const APPROVAL_CLI_TIMEOUT: Duration = Duration::from_secs(6 * 60 + 30);
const APPROVAL_CHILD_POLL: Duration = Duration::from_millis(200);
const SETUP_AGENT_WAIT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupCliOutcome {
    Complete,
    AgentUnavailable,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalCliOutcome {
    Applied,
    Failed,
    TimedOut,
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
    if let Err(err) = &status {
        if ipc_unauthorized(err) {
            eprintln!("{}", actionable_ipc_error(err));
        }
    }

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
                if ipc_unauthorized(&err) {
                    Err(ExitCode::Authentication)
                } else {
                    eprintln!("TUI failed to reach daemon: {err}");
                    Err(ExitCode::DeviceOffline)
                }
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
        if cli.wizard || app.readiness.needs_onboarding() {
            app.open_setup_wizard();
        }
        // Best-effort refresh of approvals / sessions while runtime is live.
        if app.daemon.is_some() {
            match rt.block_on(ipc_call(methods::APPROVAL_LIST, None)) {
                Ok(v) => app.set_approvals_from_json(&v),
                Err(err) => app.status_line = actionable_ipc_error(&err),
            }
            match rt.block_on(ipc_call("session.list", None)) {
                Ok(v) => app.set_sessions_from_json(&v),
                Err(err) => app.status_line = actionable_ipc_error(&err),
            }
        }
        run_interactive(app, &rt)
    }
}

fn daemon_endpoint(paths: &OwnMeshPaths) -> Result<Endpoint, ownmesh_ipc::IpcError> {
    let cfg = load_config(paths)
        .map_err(|err| ownmesh_ipc::IpcError::Protocol(format!("config: {err}")))?;
    Endpoint::configured_daemon(&paths.runtime_dir, cfg.service_socket.path.as_deref())
}

async fn fetch_status() -> Result<DaemonStatus, ownmesh_ipc::IpcError> {
    let paths = OwnMeshPaths::discover()
        .map_err(|err| ownmesh_ipc::IpcError::Protocol(format!("paths: {err}")))?;
    let _ = paths.ensure_layout();
    let endpoint = daemon_endpoint(&paths)?;
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
    .with_client_credential_from_env()?;
    client.status().await
}

async fn ipc_call(
    method: &str,
    params: Option<serde_json::Value>,
) -> Result<serde_json::Value, ownmesh_ipc::IpcError> {
    let paths = OwnMeshPaths::discover()
        .map_err(|err| ownmesh_ipc::IpcError::Protocol(format!("paths: {err}")))?;
    let endpoint = daemon_endpoint(&paths)?;
    let client = IpcClient::new(
        endpoint,
        paths.runtime_dir,
        ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        ClientOptions {
            request_timeout: Duration::from_secs(2),
            max_reconnect_attempts: 1,
            reconnect_base_delay: Duration::from_millis(20),
        },
    )
    .with_client_credential_from_env()?;
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
                Event::Paste(text) if app.overlay == Overlay::Wizard => {
                    append_wizard_server_text(&mut app, &text);
                }
                _ => {}
            }

            if let Some(request) = app.take_pending_setup() {
                terminal
                    .draw(|frame| ui::draw(frame, &app))
                    .map_err(|_| ExitCode::Internal)?;
                drop(terminal);
                guard.restore().map_err(|_| ExitCode::Internal)?;
                let outcome = run_setup_cli(&request);

                guard = TerminalGuard::enter().map_err(|err| {
                    eprintln!("failed to restore raw terminal mode: {err}");
                    ExitCode::Internal
                })?;
                terminal = create_ratatui().map_err(|_| ExitCode::Internal)?;
                terminal.clear().map_err(|_| ExitCode::Internal)?;
                drain_pending_events();

                let daemon = wait_for_daemon(rt, SETUP_AGENT_WAIT);
                app.refresh_local_state(daemon);
                app.overlay = Overlay::Wizard;
                app.wizard.step = WizardStep::Done;
                app.wizard.saved = outcome != SetupCliOutcome::Failed;
                app.wizard.error = match outcome {
                    SetupCliOutcome::Complete if app.readiness.agent_running => None,
                    SetupCliOutcome::Complete | SetupCliOutcome::AgentUnavailable => Some(
                        local_setup_message(
                            app.lang,
                            "Account and device are ready. Agent could not start; choose Repair Agent after fixing service permissions.",
                            "アカウントとPC登録は完了しました。Agentを開始できません。権限を確認後「Agentを修復」を実行してください。",
                        )
                        .to_owned(),
                    ),
                    SetupCliOutcome::Failed => Some(
                        local_setup_message(
                            app.lang,
                            "Setup stopped before completion. Review the message above and try again.",
                            "セットアップは完了しませんでした。直前の表示を確認して、もう一度実行してください。",
                        )
                        .to_owned(),
                    ),
                };
                continue;
            }

            let Some(pending) = app.take_pending_approval() else {
                continue;
            };

            // The sibling CLI owns the browser/passkey wait. Leave raw mode and
            // the alternate screen first so its bounded, human-facing output is
            // readable (including the URL fallback on headless systems).
            terminal
                .draw(|frame| ui::draw(frame, &app))
                .map_err(|_| ExitCode::Internal)?;
            drop(terminal);
            guard.restore().map_err(|_| ExitCode::Internal)?;
            let outcome = run_approval_cli(&pending, APPROVAL_CLI_TIMEOUT);

            guard = TerminalGuard::enter().map_err(|err| {
                eprintln!("failed to restore raw terminal mode: {err}");
                ExitCode::Internal
            })?;
            terminal = create_ratatui().map_err(|_| ExitCode::Internal)?;
            terminal.clear().map_err(|_| ExitCode::Internal)?;
            drain_pending_events();

            let refreshed = refresh_approvals(&mut app, rt);
            if refreshed {
                app.status_line = match outcome {
                    ApprovalCliOutcome::Applied => {
                        i18n::t(app.lang, i18n::Msg::ApprovalsApplied).to_owned()
                    }
                    ApprovalCliOutcome::Failed => {
                        i18n::t(app.lang, i18n::Msg::ApprovalsFailed).to_owned()
                    }
                    ApprovalCliOutcome::TimedOut => {
                        i18n::t(app.lang, i18n::Msg::ApprovalsTimedOut).to_owned()
                    }
                };
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

    if app.overlay == Overlay::Connector {
        if matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q')) {
            app.overlay = Overlay::None;
        }
        return;
    }

    match key.code {
        KeyCode::Char('q' | 'Q') => app.should_quit = true,
        KeyCode::F(1) | KeyCode::Char('?') => app.overlay = Overlay::Help,
        KeyCode::Char('/' | ':') => app.open_palette(),
        KeyCode::Esc if app.screen != Screen::Dashboard => {
            app.screen = Screen::Dashboard;
            app.list_cursor = 0;
        }
        KeyCode::Tab if app.screen == Screen::Dashboard => app.move_overview_action(1),
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
            app.open_setup_wizard();
        }
        KeyCode::Up | KeyCode::Char('k') => {
            if app.screen == Screen::Approvals {
                app.approval_cursor = app.approval_cursor.saturating_sub(1);
            } else if app.screen == Screen::Dashboard {
                app.move_overview_action(-1);
            } else {
                app.list_cursor = app.list_cursor.saturating_sub(1);
            }
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if app.screen == Screen::Approvals {
                if !app.approvals.is_empty() {
                    app.approval_cursor = (app.approval_cursor + 1).min(app.approvals.len() - 1);
                }
            } else if app.screen == Screen::Dashboard {
                app.move_overview_action(1);
            } else {
                app.list_cursor = app.list_cursor.saturating_add(1);
            }
        }
        KeyCode::Enter if app.screen == Screen::Dashboard => app.run_overview_action(),
        KeyCode::Char('a') if app.screen == Screen::Approvals => {
            app.queue_selected_approval(ApprovalDecision::Approve);
        }
        KeyCode::Char('d') if app.screen == Screen::Approvals => {
            app.queue_selected_approval(ApprovalDecision::Deny);
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
        KeyCode::Backspace if app.wizard.step == WizardStep::Server => {
            app.wizard.control_plane_url.pop();
            app.wizard.error = None;
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
            WizardStep::Server => {
                match ownmesh_config::validate_control_plane_base_url(
                    app.wizard.control_plane_url.trim(),
                ) {
                    Ok(url) => {
                        app.wizard.control_plane_url = url;
                        app.wizard.error = None;
                        app.wizard.step = app.wizard.step.next();
                    }
                    Err(error) => {
                        app.wizard.error = Some(format!("control-plane URL: {error}"));
                    }
                }
            }
            WizardStep::Confirm => {
                if let Err(error) = app.queue_wizard_setup() {
                    app.wizard.error = Some(error);
                }
            }
            WizardStep::Done => {
                app.overlay = Overlay::None;
            }
        },
        KeyCode::Char(c)
            if app.wizard.step == WizardStep::Server
                && !key.modifiers.contains(KeyModifiers::CONTROL)
                && app.wizard.control_plane_url.len() < 2048 =>
        {
            app.wizard.control_plane_url.push(c);
            app.wizard.error = None;
        }
        _ => {}
    }
}

fn append_wizard_server_text(app: &mut App, text: &str) {
    if app.wizard.step != WizardStep::Server {
        return;
    }
    for ch in text.chars().filter(|ch| !ch.is_control()) {
        if app.wizard.control_plane_url.len() + ch.len_utf8() > 2048 {
            break;
        }
        app.wizard.control_plane_url.push(ch);
    }
    app.wizard.error = None;
}

fn refresh_approvals(app: &mut App, rt: &tokio::runtime::Runtime) -> bool {
    match rt.block_on(ipc_call(methods::APPROVAL_LIST, None)) {
        Ok(v) => {
            app.set_approvals_from_json(&v);
            app.status_line = format!("approvals: {}", app.approvals.len());
            true
        }
        Err(e) => {
            app.status_line = actionable_ipc_error(&e);
            false
        }
    }
}

fn run_setup_cli(request: &SetupRequest) -> SetupCliOutcome {
    let Ok(current) = std::env::current_exe() else {
        return SetupCliOutcome::Failed;
    };
    let ownmesh = sibling_ownmesh_path(&current);
    if !ownmesh.is_file() {
        eprintln!("OwnMesh CLI was not found beside ownmesh-tui.");
        return SetupCliOutcome::Failed;
    }

    if request.configure {
        let Ok(paths) = OwnMeshPaths::discover() else {
            return SetupCliOutcome::Failed;
        };
        if let Err(error) = apply_setup_request(&paths, request) {
            eprintln!("OwnMesh setup: {error}");
            return SetupCliOutcome::Failed;
        }
    }
    println!("\nOwnMesh setup — follow the URL + code prompt if sign-in is required.\n");
    if request.login
        && !run_ownmesh_step(
            &ownmesh,
            vec![OsString::from("login"), OsString::from("--device")],
        )
    {
        return SetupCliOutcome::Failed;
    }
    if request.enroll
        && !run_ownmesh_step(
            &ownmesh,
            vec![OsString::from("device"), OsString::from("enroll")],
        )
    {
        return SetupCliOutcome::Failed;
    }
    if request.install_agent {
        let installed = run_ownmesh_step(
            &ownmesh,
            vec![OsString::from("service"), OsString::from("install")],
        );
        let started = installed
            && run_ownmesh_step(
                &ownmesh,
                vec![OsString::from("service"), OsString::from("start")],
            );
        if !started {
            return SetupCliOutcome::AgentUnavailable;
        }
    }
    SetupCliOutcome::Complete
}

fn run_ownmesh_step(executable: &Path, args: Vec<OsString>) -> bool {
    Command::new(executable)
        .args(args)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .is_ok_and(|status| status.success())
}

fn wait_for_daemon(rt: &tokio::runtime::Runtime, timeout: Duration) -> Option<DaemonStatus> {
    let started = Instant::now();
    loop {
        if let Ok(status) = rt.block_on(fetch_status()) {
            return Some(status);
        }
        if started.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn local_setup_message(lang: Lang, en: &'static str, ja: &'static str) -> &'static str {
    if lang == Lang::JaJp {
        ja
    } else {
        en
    }
}

fn run_approval_cli(pending: &PendingApproval, timeout: Duration) -> ApprovalCliOutcome {
    let Ok(current) = std::env::current_exe() else {
        return ApprovalCliOutcome::Failed;
    };
    let ownmesh = sibling_ownmesh_path(&current);
    if !ownmesh.is_file() {
        return ApprovalCliOutcome::Failed;
    }

    let Ok(mut child) = Command::new(ownmesh)
        .args(approval_cli_args(pending))
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    else {
        return ApprovalCliOutcome::Failed;
    };

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    ApprovalCliOutcome::Applied
                } else {
                    ApprovalCliOutcome::Failed
                };
            }
            Ok(None) if started.elapsed() < timeout => {
                std::thread::sleep(APPROVAL_CHILD_POLL);
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return ApprovalCliOutcome::TimedOut;
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return ApprovalCliOutcome::Failed;
            }
        }
    }
}

fn sibling_ownmesh_path(current_exe: &Path) -> PathBuf {
    current_exe.with_file_name(format!("ownmesh{}", std::env::consts::EXE_SUFFIX))
}

fn approval_cli_args(pending: &PendingApproval) -> Vec<OsString> {
    vec![
        OsString::from("approval"),
        OsString::from(pending.decision.cli_verb()),
        // Prevent an untrusted approval id beginning with '-' from becoming a
        // CLI option. Idempotency is generated by the sibling CLI when omitted.
        OsString::from("--"),
        OsString::from(&pending.id),
    ]
}

fn drain_pending_events() {
    for _ in 0..64 {
        if !event::poll(Duration::ZERO).unwrap_or(false) {
            break;
        }
        let _ = event::read();
    }
}

fn ipc_unauthorized(err: &ownmesh_ipc::IpcError) -> bool {
    matches!(err, ownmesh_ipc::IpcError::Unauthorized(_))
        || matches!(
            err,
            ownmesh_ipc::IpcError::Remote { code, .. }
                if matches!(
                    *code,
                    ownmesh_ipc::app_error::UNAUTHORIZED
                        | ownmesh_ipc::app_error::TOKEN_REVOKED
                )
        )
        || matches!(
            err,
            ownmesh_ipc::IpcError::Protocol(message)
                if message.contains(ownmesh_ipc::CLIENT_CREDENTIAL_ENV)
        )
}

fn actionable_ipc_error(err: &ownmesh_ipc::IpcError) -> String {
    if ipc_unauthorized(err) {
        format!(
            "authentication failed: {err}; provision ownmesh-tui and set {}",
            ownmesh_ipc::CLIENT_CREDENTIAL_ENV
        )
    } else {
        format!("ipc: {err}")
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
    use ownmesh_ipc::{reject_unknown_handler, AuthGate, IpcBus, IpcServer, ServerConfig};
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

    #[test]
    fn approval_cli_delegation_uses_exact_positional_id_and_auto_idempotency() {
        let pending = PendingApproval {
            id: "--idempotency-key=attacker-value".into(),
            decision: ApprovalDecision::Approve,
        };
        assert_eq!(
            approval_cli_args(&pending),
            vec![
                OsString::from("approval"),
                OsString::from("approve"),
                OsString::from("--"),
                OsString::from("--idempotency-key=attacker-value"),
            ]
        );
    }

    #[test]
    fn approval_palette_queues_the_selected_pending_request() {
        let dir = tempdir().unwrap();
        let mut app = App::new(OwnMeshPaths::for_base(dir.path()), None);
        app.set_approvals_from_json(&serde_json::json!({
            "approvals": [
                { "id": "approval-1", "state": "pending", "capability": "fs.read" },
                { "id": "approval-2", "state": "pending", "capability": "fs.write" }
            ]
        }));
        app.approval_cursor = 1;

        app.dispatch_palette(palette::PaletteAction::DenySelected);

        assert_eq!(
            app.take_pending_approval(),
            Some(PendingApproval {
                id: "approval-2".into(),
                decision: ApprovalDecision::Deny,
            })
        );
        assert_eq!(app.screen, Screen::Approvals);
    }

    #[test]
    fn decided_approval_is_never_queued_for_delegation() {
        let dir = tempdir().unwrap();
        let mut app = App::new(OwnMeshPaths::for_base(dir.path()), None);
        app.set_approvals_from_json(&serde_json::json!({
            "approvals": [
                { "id": "approval-1", "state": "approved", "capability": "fs.read" }
            ]
        }));

        app.queue_selected_approval(ApprovalDecision::Approve);

        assert_eq!(app.take_pending_approval(), None);
        assert_eq!(
            app.status_line,
            i18n::t(app.lang, i18n::Msg::ApprovalsAlreadyDecided)
        );
    }
}
