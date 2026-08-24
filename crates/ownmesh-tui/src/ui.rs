//! Ratatui rendering for all screens, wizard, palette, and 80x24 layout.

use crate::app::{App, Overlay, OverviewAction, Screen};
use crate::i18n::{t, Lang, Msg};
use crate::palette::filter_commands;
use crate::theme::{ascii_fallback, ColorMode};
#[cfg(test)]
use crate::width::display_width;
use crate::width::truncate_to_width;
use crate::wizard::{WizardStep, WIZARD_PRESETS};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use ownmesh_policy::AccessPreset;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use std::sync::LazyLock;

/// Minimum comfortable layout from the checklist.
pub const MIN_COLS: u16 = 80;
pub const MIN_ROWS: u16 = 24;

const LOGO_WIDTH: usize = 74;
const LOGO_PIXEL_HEIGHT: usize = 12;
static LOGO_RGB: LazyLock<Vec<u8>> = LazyLock::new(|| {
    BASE64_STANDARD
        .decode(include_str!("../assets/ownmesh-wordmark.rgb.b64").trim())
        .expect("embedded OwnMesh wordmark must be valid base64")
});

/// Draw the full TUI frame.
pub fn draw(frame: &mut Frame<'_>, app: &App) {
    let area = frame.area();
    let narrow = area.width < MIN_COLS || area.height < MIN_ROWS;
    let brand_height = if narrow { 3 } else { 8 };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(brand_height),
            Constraint::Min(8),
            Constraint::Length(3),
            Constraint::Length(2),
        ])
        .split(area);

    draw_brand(frame, app, chunks[0], narrow);
    if app.screen == Screen::Dashboard {
        draw_dashboard(frame, app, chunks[1]);
    } else {
        draw_body(frame, app, centered_width(chunks[1], 96), narrow);
    }
    draw_command_bar(frame, app, chunks[2]);
    draw_footer(frame, app, chunks[3]);

    match app.overlay {
        Overlay::Help => draw_help_modal(frame, app),
        Overlay::Wizard => draw_wizard(frame, app),
        Overlay::Connector => draw_connector_modal(frame, app),
        Overlay::None => {}
    }
    if app.palette.open {
        draw_palette(frame, app);
    }
}

fn draw_brand(frame: &mut Frame<'_>, app: &App, area: Rect, narrow: bool) {
    let state = if app.readiness.needs_onboarding() {
        localized(
            app.lang,
            "setup required",
            "セットアップが必要",
            "需要设置",
            "требуется настройка",
        )
    } else if app.readiness.ready() {
        localized(
            app.lang,
            "this device ready",
            "このPCは準備完了",
            "此设备已就绪",
            "устройство готово",
        )
    } else {
        localized(
            app.lang,
            "agent needs attention",
            "Agentの確認が必要",
            "代理需要处理",
            "агент требует внимания",
        )
    };
    let raster_logo = matches!(app.theme.mode, ColorMode::TrueColor | ColorMode::Ansi256);
    if narrow || area.width < 106 || ascii_fallback() || !raster_logo {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled("OwnMesh", app.theme.title)),
                Line::from(Span::styled(state, app.theme.muted)),
            ])
            .alignment(Alignment::Center),
            area,
        );
        return;
    }

    let screen = if app.screen == Screen::Dashboard {
        String::new()
    } else {
        format!(
            "  |  {}",
            t(app.lang, app.screen.title_msg()).to_ascii_lowercase()
        )
    };
    let total_width = area.width.min(110);
    let group = Rect {
        x: area.x + area.width.saturating_sub(total_width) / 2,
        y: area.y,
        width: total_width,
        height: area.height,
    };
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(76), Constraint::Min(24)])
        .split(group);
    frame.render_widget(
        Paragraph::new(logo_lines(app.theme.mode)),
        Rect {
            y: area.y + 1,
            height: 6,
            ..columns[0]
        },
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("│  ", app.theme.muted),
            Span::styled(
                "▪",
                if app.readiness.ready() {
                    app.theme.ok
                } else {
                    app.theme.warn
                },
            ),
            Span::styled(format!("  {state}{screen}"), app.theme.muted),
        ])),
        Rect {
            x: columns[1].x,
            y: area.y + 3,
            width: columns[1].width,
            height: 1,
        },
    );
}

fn logo_lines(mode: ColorMode) -> Vec<Line<'static>> {
    (0..LOGO_PIXEL_HEIGHT / 2)
        .map(|row| {
            let spans = (0..LOGO_WIDTH)
                .map(|column| {
                    let top = logo_pixel(column, row * 2);
                    let bottom = logo_pixel(column, row * 2 + 1);
                    if logo_luma(top) < 24 && logo_luma(bottom) < 24 {
                        Span::raw(" ")
                    } else {
                        Span::styled(
                            "▀",
                            Style::default()
                                .fg(logo_color(mode, top))
                                .bg(logo_color(mode, bottom)),
                        )
                    }
                })
                .collect::<Vec<_>>();
            Line::from(spans)
        })
        .collect()
}

fn logo_pixel(x: usize, y: usize) -> [u8; 3] {
    let offset = (y * LOGO_WIDTH + x) * 3;
    [LOGO_RGB[offset], LOGO_RGB[offset + 1], LOGO_RGB[offset + 2]]
}

fn logo_luma([red, green, blue]: [u8; 3]) -> u8 {
    let weighted = u16::from(red) * 54 + u16::from(green) * 183 + u16::from(blue) * 19;
    (weighted / 256) as u8
}

fn logo_color(mode: ColorMode, rgb @ [red, green, blue]: [u8; 3]) -> Color {
    match mode {
        ColorMode::TrueColor => Color::Rgb(red, green, blue),
        ColorMode::Ansi256 => {
            let luma = logo_luma(rgb);
            if luma < 24 {
                Color::Black
            } else {
                Color::Indexed(232 + ((u16::from(luma) * 23 / 255) as u8))
            }
        }
        ColorMode::Ansi16 | ColorMode::NoColor | ColorMode::HighContrast => Color::Reset,
    }
}

fn draw_footer(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let agent = if app.readiness.ready() {
        localized(
            app.lang,
            "agent running",
            "Agent実行中",
            "代理运行中",
            "агент запущен",
        )
    } else if app.readiness.agent_running {
        localized(
            app.lang,
            "agent running · autostart missing",
            "Agent実行中 · 自動起動未設定",
            "代理运行中 · 未设置自启动",
            "агент запущен · автозапуск не настроен",
        )
    } else {
        localized(
            app.lang,
            "agent unavailable",
            "Agent未接続",
            "代理不可用",
            "агент недоступен",
        )
    };
    let server = if app.readiness.server_url.is_some() {
        localized(
            app.lang,
            "server configured",
            "サーバー設定済み",
            "服务器已配置",
            "сервер настроен",
        )
    } else {
        localized(
            app.lang,
            "server not configured",
            "サーバー未設定",
            "服务器未配置",
            "сервер не настроен",
        )
    };
    let text = format!(
        "{agent}    |    {server}    |    v{}",
        env!("CARGO_PKG_VERSION")
    );
    let block = Block::default()
        .borders(Borders::TOP)
        .border_set(app.border_set())
        .border_style(app.theme.border);
    frame.render_widget(
        Paragraph::new(truncate_to_width(
            &text,
            area.width.saturating_sub(2) as usize,
        ))
        .style(app.theme.muted)
        .alignment(Alignment::Center)
        .block(block),
        area,
    );
}

fn draw_command_bar(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let text = if app.status_line.is_empty() {
        localized(
            app.lang,
            "↑/↓ select · Enter open · Ctrl+K commands · ? help · Ctrl+C exit",
            "↑/↓ 選択 · Enter 開く · Ctrl+K コマンド · ? ヘルプ · Ctrl+C 終了",
            "↑/↓ 选择 · Enter 打开 · Ctrl+K 命令 · ? 帮助 · Ctrl+C 退出",
            "↑/↓ выбор · Enter открыть · Ctrl+K команды · ? помощь · Ctrl+C выход",
        )
        .to_owned()
    } else {
        app.status_line.clone()
    };
    let area = centered_width(area, 110);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(app.border_set())
        .border_style(app.theme.border);
    frame.render_widget(
        Paragraph::new(truncate_to_width(
            &text,
            area.width.saturating_sub(2) as usize,
        ))
        .style(app.theme.muted)
        .block(block),
        area,
    );
}

fn centered_width(area: Rect, max_width: u16) -> Rect {
    let width = area.width.min(max_width.max(20));
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y,
        width,
        height: area.height,
    }
}

fn draw_body(frame: &mut Frame<'_>, app: &App, area: Rect, narrow: bool) {
    let title = t(app.lang, app.screen.title_msg());
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(app.border_set())
        .border_style(app.theme.border)
        .title(title)
        .title_style(app.theme.accent);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if narrow {
        let note = t(app.lang, Msg::LayoutNarrow);
        frame.render_widget(
            Paragraph::new(note).style(app.theme.warn),
            Rect {
                x: inner.x,
                y: inner.y,
                width: inner.width,
                height: 1,
            },
        );
    }

    let body = if narrow && inner.height > 1 {
        Rect {
            x: inner.x,
            y: inner.y + 1,
            width: inner.width,
            height: inner.height.saturating_sub(1),
        }
    } else {
        inner
    };

    match app.screen {
        Screen::Dashboard => unreachable!("dashboard is rendered before the framed body"),
        Screen::Devices => draw_devices(frame, app, body),
        Screen::Workspaces => draw_workspaces(frame, app, body),
        Screen::Sessions => draw_list_screen(
            frame,
            app,
            body,
            if app.sessions.is_empty() {
                vec![t(app.lang, Msg::SessionsEmpty).to_owned()]
            } else {
                app.sessions.clone()
            },
            t(app.lang, Msg::SessionsHint),
        ),
        Screen::Profiles => draw_list_screen(
            frame,
            app,
            body,
            app.profile_lines(),
            t(app.lang, Msg::ProfilesHint),
        ),
        Screen::Approvals => draw_approvals(frame, app, body),
        Screen::Transfers => draw_list_screen(
            frame,
            app,
            body,
            app.transfer_lines(),
            t(app.lang, Msg::TransfersHint),
        ),
        Screen::Activity => draw_list_screen(
            frame,
            app,
            body,
            if app.activity.is_empty() {
                vec![t(app.lang, Msg::ActivityEmpty).to_owned()]
            } else {
                app.activity.clone()
            },
            t(app.lang, Msg::ActivityHint),
        ),
        Screen::Diagnostics => draw_diagnostics(frame, app, body),
        Screen::Settings => draw_settings(frame, app, body),
    }
}

fn draw_dashboard(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let content = centered_width(area, 78);
    let actions = app.overview_actions();
    let action_height = u16::try_from(actions.len()).unwrap_or(6).min(6);
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(5),
            Constraint::Length(1),
            Constraint::Length(action_height),
            Constraint::Min(0),
        ])
        .split(content);

    let heading = if app.readiness.ready() {
        localized(
            app.lang,
            "This machine is ready",
            "このPCは準備完了です",
            "此设备已准备就绪",
            "Это устройство готово",
        )
    } else if app.readiness.needs_onboarding() {
        localized(
            app.lang,
            "Finish setup",
            "セットアップを完了してください",
            "完成设置",
            "Завершите настройку",
        )
    } else {
        localized(
            app.lang,
            "Agent needs attention",
            "Agentの修復が必要です",
            "代理需要处理",
            "Агент требует внимания",
        )
    };
    frame.render_widget(
        Paragraph::new(heading).style(app.theme.title.add_modifier(Modifier::BOLD)),
        sections[0],
    );

    let server_ok = app.readiness.server_url.is_some();
    let rows = vec![
        readiness_line(
            app,
            localized(app.lang, "Server", "サーバー", "服务器", "Сервер"),
            server_ok,
            localized(app.lang, "configured", "設定済み", "已配置", "настроен"),
            localized(
                app.lang,
                "not configured",
                "未設定",
                "未配置",
                "не настроен",
            ),
        ),
        readiness_line(
            app,
            localized(app.lang, "Account", "アカウント", "账户", "Аккаунт"),
            app.readiness.account_present,
            localized(
                app.lang,
                "login recorded",
                "ログイン記録あり",
                "已记录登录",
                "вход сохранён",
            ),
            localized(
                app.lang,
                "sign-in required",
                "ログインが必要",
                "需要登录",
                "требуется вход",
            ),
        ),
        readiness_line(
            app,
            localized(
                app.lang,
                "This device",
                "このPC",
                "此设备",
                "Это устройство",
            ),
            app.readiness.device_id.is_some(),
            localized(
                app.lang,
                "enrolled",
                "登録済み",
                "已注册",
                "зарегистрировано",
            ),
            localized(
                app.lang,
                "not enrolled",
                "未登録",
                "未注册",
                "не зарегистрировано",
            ),
        ),
        readiness_line(
            app,
            "Agent",
            app.readiness.agent_running && app.readiness.service_installed,
            localized(app.lang, "running", "実行中", "运行中", "запущен"),
            if app.readiness.agent_running {
                localized(
                    app.lang,
                    "autostart not installed",
                    "自動起動が未設定",
                    "未安装自启动",
                    "автозапуск не установлен",
                )
            } else if app.readiness.service_installed {
                localized(
                    app.lang,
                    "not reachable",
                    "応答なし",
                    "无法连接",
                    "не отвечает",
                )
            } else {
                localized(
                    app.lang,
                    "not installed",
                    "未設定",
                    "未安装",
                    "не установлен",
                )
            },
        ),
    ];
    frame.render_widget(Paragraph::new(rows), sections[1]);

    let action_items = actions
        .iter()
        .enumerate()
        .map(|(index, action)| {
            let (label, description) = overview_action_copy(app.lang, *action);
            let mark = if index == app.overview_action_cursor {
                ">"
            } else {
                " "
            };
            let text = format!("{mark}  {label:<20} {description}");
            let style = if index == app.overview_action_cursor {
                app.theme.selection
            } else {
                app.theme.body
            };
            ListItem::new(truncate_to_width(
                &text,
                sections[3].width.saturating_sub(1) as usize,
            ))
            .style(style)
        })
        .collect::<Vec<_>>();
    frame.render_widget(List::new(action_items), sections[3]);
}

fn readiness_line(
    app: &App,
    label: &str,
    ok: bool,
    ok_text: &str,
    missing_text: &str,
) -> Line<'static> {
    let marker = if ok { "[ok]" } else { "[--]" };
    let value = if ok { ok_text } else { missing_text };
    Line::from(vec![
        Span::styled(
            format!("{marker:<6}"),
            if ok { app.theme.ok } else { app.theme.warn },
        ),
        Span::styled(format!("{label:<14}"), app.theme.body),
        Span::styled(
            value.to_owned(),
            if ok { app.theme.body } else { app.theme.warn },
        ),
    ])
}

fn overview_action_copy(lang: Lang, action: OverviewAction) -> (&'static str, &'static str) {
    match action {
        OverviewAction::SetupRepair => (
            localized(
                lang,
                "Finish setup",
                "セットアップ",
                "完成设置",
                "Завершить настройку",
            ),
            localized(
                lang,
                "Configure, sign in, and enroll",
                "設定・ログイン・PC登録",
                "配置、登录并注册",
                "Настроить, войти и зарегистрировать",
            ),
        ),
        OverviewAction::RepairAgent => (
            localized(
                lang,
                "Repair Agent",
                "Agentを修復",
                "修复代理",
                "Исправить агент",
            ),
            localized(
                lang,
                "Install and start this device",
                "自動起動を設定して開始",
                "安装并启动此设备",
                "Установить и запустить",
            ),
        ),
        OverviewAction::Connector => (
            localized(
                lang,
                "ChatGPT connector",
                "ChatGPTコネクタ",
                "ChatGPT 连接器",
                "Коннектор ChatGPT",
            ),
            localized(
                lang,
                "Show MCP URL and instructions",
                "MCP URLと手順を表示",
                "显示 MCP URL 和说明",
                "Показать MCP URL и инструкции",
            ),
        ),
        OverviewAction::Reauthenticate => (
            localized(
                lang,
                "Re-authenticate",
                "再認証",
                "重新认证",
                "Войти заново",
            ),
            localized(
                lang,
                "Refresh the account login",
                "アカウントのログインを更新",
                "刷新账户登录",
                "Обновить вход в аккаунт",
            ),
        ),
        OverviewAction::Devices => (
            localized(lang, "Devices", "デバイス", "设备", "Устройства"),
            localized(
                lang,
                "Registered computers",
                "登録済みのPC",
                "已注册的电脑",
                "Зарегистрированные компьютеры",
            ),
        ),
        OverviewAction::Workspace => (
            localized(
                lang,
                "Workspaces",
                "ワークスペース",
                "工作区",
                "Рабочие области",
            ),
            localized(
                lang,
                "Allowed folders",
                "操作を許可したフォルダ",
                "允许的文件夹",
                "Разрешённые папки",
            ),
        ),
        OverviewAction::Doctor => (
            localized(lang, "Diagnostics", "診断", "诊断", "Диагностика"),
            localized(
                lang,
                "Local system checks",
                "ローカル状態を確認",
                "本地系统检查",
                "Локальные проверки",
            ),
        ),
    }
}

fn draw_devices(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let mut lines = vec![
        Line::from(Span::styled(t(app.lang, Msg::DevicesLocal), app.theme.body)),
        Line::from(match &app.daemon {
            Some(s) => format!("  endpoint={} state={}", s.endpoint, s.state),
            None => format!("  {}", t(app.lang, Msg::DaemonOffline)),
        }),
        Line::from(""),
        Line::from(Span::styled(
            t(app.lang, Msg::DevicesInventory),
            app.theme.body,
        )),
    ];
    let snapshot = app.device_inventory.loaded_snapshot().cloned();
    match &app.device_inventory {
        crate::control_plane::DeviceInventory::NotConfigured => {
            lines.push(Line::from(t(app.lang, Msg::DevicesNotConfigured)));
        }
        crate::control_plane::DeviceInventory::AuthRequired => {
            lines.push(Line::from(t(app.lang, Msg::DevicesAuthRequired)));
        }
        crate::control_plane::DeviceInventory::Empty => {
            lines.push(Line::from(t(app.lang, Msg::DevicesEmpty)));
        }
        crate::control_plane::DeviceInventory::Loaded { devices, truncated } => {
            for device in devices {
                lines.push(Line::from(crate::control_plane::format_device_row(
                    device,
                    app.readiness.device_id.as_deref(),
                )));
            }
            if *truncated {
                lines.push(Line::from(Span::styled(
                    t(app.lang, Msg::DevicesTruncated),
                    app.theme.muted,
                )));
            }
        }
        crate::control_plane::DeviceInventory::Unreachable { message, .. } => {
            lines.push(Line::from(format!(
                "{} {}",
                t(app.lang, Msg::DevicesUnreachable),
                message
            )));
            if let Some(crate::control_plane::DeviceInventory::Loaded { devices, truncated }) =
                snapshot.as_ref()
            {
                for device in devices {
                    lines.push(Line::from(crate::control_plane::format_device_row(
                        device,
                        app.readiness.device_id.as_deref(),
                    )));
                }
                if *truncated {
                    lines.push(Line::from(Span::styled(
                        t(app.lang, Msg::DevicesTruncated),
                        app.theme.muted,
                    )));
                }
            }
        }
        crate::control_plane::DeviceInventory::Idle => {
            lines.push(Line::from(t(app.lang, Msg::DevicesHint)));
        }
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        t(app.lang, Msg::DevicesHintRefresh),
        app.theme.muted,
    )));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn draw_workspaces(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let root = app.paths.state_dir.join("workspace");
    let lines = vec![
        Line::from(format!(
            "{}: {}",
            t(app.lang, Msg::WorkspacesRoot),
            root.display()
        )),
        Line::from(""),
        Line::from(Span::styled(
            t(app.lang, Msg::WorkspacesHint),
            app.theme.muted,
        )),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

/// Render `items` with the shared cursor kept in range and scrolled into
/// view. A stateful widget recomputes the viewport offset each frame so the
/// selected row is always visible (issue #135).
fn render_list_with_cursor(
    frame: &mut Frame<'_>,
    items: Vec<ListItem<'_>>,
    selected: usize,
    area: Rect,
) {
    let mut state = ListState::default();
    if let Some(last) = items.len().checked_sub(1) {
        state.select(Some(selected.min(last)));
    }
    frame.render_stateful_widget(List::new(items), area, &mut state);
}

fn draw_list_screen(frame: &mut Frame<'_>, app: &App, area: Rect, items: Vec<String>, hint: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(area);
    // Highlight and viewport follow one pre-clamped selection so they can
    // never disagree (#135).
    let selected = items
        .len()
        .checked_sub(1)
        .map_or(0, |last| app.list_cursor.min(last));
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let style = if i == selected {
                app.theme.selection
            } else {
                app.theme.body
            };
            let text = truncate_to_width(s, chunks[0].width.saturating_sub(1) as usize);
            ListItem::new(text).style(style)
        })
        .collect();
    render_list_with_cursor(frame, list_items, selected, chunks[0]);
    frame.render_widget(
        Paragraph::new(hint)
            .style(app.theme.muted)
            .wrap(Wrap { trim: true }),
        chunks[1],
    );
}

fn draw_approvals(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(area);

    if app.approvals.is_empty() {
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(t(app.lang, Msg::ApprovalsEmpty)),
                Line::from(Span::styled(t(app.lang, Msg::OfflineData), app.theme.muted)),
            ]),
            chunks[0],
        );
    } else {
        let selected = app
            .approval_cursor
            .min(app.approvals.len().saturating_sub(1));
        let items: Vec<ListItem> = app
            .approvals
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let mark = if i == selected { ">" } else { " " };
                let line = format!(
                    "{mark} [{}] {} · {} — {}",
                    a.state, a.id, a.capability, a.reason
                );
                let style = if i == selected {
                    app.theme.selection
                } else if a.state == "pending" {
                    app.theme.warn
                } else {
                    app.theme.body
                };
                ListItem::new(truncate_to_width(
                    &line,
                    chunks[0].width.saturating_sub(1) as usize,
                ))
                .style(style)
            })
            .collect();
        render_list_with_cursor(frame, items, selected, chunks[0]);
    }
    frame.render_widget(
        Paragraph::new(t(app.lang, Msg::ApprovalsHint)).style(app.theme.muted),
        chunks[1],
    );
}

fn draw_diagnostics(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let mut lines = vec![Line::from(Span::styled(
        t(app.lang, Msg::DiagDoctor),
        app.theme.accent.add_modifier(Modifier::BOLD),
    ))];
    for c in &app.doctor.checks {
        let st = match c.status {
            ownmesh_diagnostics::CheckStatus::Pass => ("PASS", app.theme.ok),
            ownmesh_diagnostics::CheckStatus::Warn => ("WARN", app.theme.warn),
            ownmesh_diagnostics::CheckStatus::Fail => ("FAIL", app.theme.err),
        };
        lines.push(Line::from(vec![
            Span::styled(format!("[{}] ", st.0), st.1),
            Span::raw(format!("{} — {}", c.id, c.message)),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        t(app.lang, Msg::DiagHint),
        app.theme.muted,
    )));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn draw_settings(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let lines = vec![
        Line::from(format!(
            "{}: {}",
            t(app.lang, Msg::SettingsLang),
            app.lang.bcp47()
        )),
        Line::from(format!(
            "{}: {}",
            t(app.lang, Msg::SettingsPreset),
            app.preset_label()
        )),
        Line::from(format!(
            "{}: {:?}",
            t(app.lang, Msg::SettingsColor),
            app.theme.mode
        )),
        Line::from(""),
        Line::from(Span::styled(
            t(app.lang, Msg::SettingsHint),
            app.theme.muted,
        )),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn centered(area: Rect, w_pct: u16, h_pct: u16) -> Rect {
    let w = area.width.saturating_mul(w_pct) / 100;
    let h = area.height.saturating_mul(h_pct) / 100;
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    Rect {
        x,
        y,
        width: w.max(20).min(area.width),
        height: h.max(8).min(area.height),
    }
}

fn centered_fixed(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width).max(20);
    let height = height.min(area.height).max(8);
    Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 2,
        width,
        height,
    }
}

fn localized(
    lang: Lang,
    en: &'static str,
    ja: &'static str,
    zh: &'static str,
    ru: &'static str,
) -> &'static str {
    match lang {
        Lang::EnUs => en,
        Lang::JaJp => ja,
        Lang::ZhHans => zh,
        Lang::RuRu => ru,
    }
}

fn draw_help_modal(frame: &mut Frame<'_>, app: &App) {
    let area = centered(frame.area(), 70, 50);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(app.border_set())
        .border_style(app.theme.accent)
        .title(t(app.lang, Msg::HelpTitle));
    let p = Paragraph::new(t(app.lang, Msg::HelpBody))
        .wrap(Wrap { trim: true })
        .style(app.theme.body)
        .block(block);
    frame.render_widget(p, area);
}

fn draw_connector_modal(frame: &mut Frame<'_>, app: &App) {
    // Linux gains a linger-disclosure line (#143); keep the modal tall enough.
    let height = if cfg!(target_os = "linux") { 18 } else { 16 };
    let area = centered_fixed(frame.area(), 76, height);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(app.border_set())
        .border_style(app.theme.accent)
        .title(localized(
            app.lang,
            " ChatGPT connector ",
            " ChatGPTコネクタ ",
            " ChatGPT 连接器 ",
            " Коннектор ChatGPT ",
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let connector_url = app.readiness.connector_url();
    let url = connector_url.as_deref().unwrap_or(localized(
        app.lang,
        "Finish setup first",
        "先にセットアップを完了してください",
        "请先完成设置",
        "Сначала завершите настройку",
    ));
    let linger_note: Option<Line<'_>> = if cfg!(target_os = "linux") {
        Some(Line::from(Span::styled(
            localized(
                app.lang,
                "Linux: the agent stops at logout unless you enable lingering \
                 (loginctl enable-linger $USER).",
                "Linux: ログアウトでエージェントが停止します。常時オンにするには自分で \
                 lingeringを有効化してください (loginctl enable-linger $USER)。",
                "Linux：注销后代理会停止；如需保持在线，请自行启用 lingering \
                 (loginctl enable-linger $USER)。",
                "Linux: агент останавливается при выходе из системы; для постоянной работы \
                 включите lingering (loginctl enable-linger $USER).",
            ),
            app.theme.muted,
        )))
    } else {
        None
    };
    let mut lines = vec![
        Line::from(localized(
            app.lang,
            "Add OwnMesh in ChatGPT. This is separate from enrolling this PC.",
            "ChatGPT側にOwnMeshを追加します。このPCの登録とは別の設定です。",
            "在 ChatGPT 中添加 OwnMesh；这与注册此设备不同。",
            "Добавьте OwnMesh в ChatGPT; это не регистрация устройства.",
        )),
        Line::from(""),
        Line::from(Span::styled("MCP URL", app.theme.muted)),
        Line::from(Span::styled(url.to_owned(), app.theme.accent)),
        Line::from(""),
        Line::from(localized(
            app.lang,
            "1. ChatGPT Settings → Connectors → Add custom connector",
            "1. ChatGPTの 設定 → コネクタ → カスタムコネクタを追加",
            "1. ChatGPT 设置 → 连接器 → 添加自定义连接器",
            "1. ChatGPT Настройки → Коннекторы → Добавить",
        )),
        Line::from(localized(
            app.lang,
            "2. Paste the MCP URL, choose OAuth, and sign in when prompted.",
            "2. MCP URLを貼り、OAuthを選択。表示された画面でログインします。",
            "2. 粘贴 MCP URL，选择 OAuth，然后登录。",
            "2. Вставьте MCP URL, выберите OAuth и войдите.",
        )),
        Line::from(""),
    ];
    if let Some(note) = linger_note {
        lines.push(note);
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        localized(
            app.lang,
            "Esc / Enter  close",
            "Esc / Enter  閉じる",
            "Esc / Enter  关闭",
            "Esc / Enter  закрыть",
        ),
        app.theme.muted,
    )));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn draw_wizard(frame: &mut Frame<'_>, app: &App) {
    let wz = &app.wizard;
    let height = match wz.step {
        WizardStep::Welcome => 13,
        WizardStep::Server => 14,
        WizardStep::Language => 15,
        WizardStep::Preset => 20,
        WizardStep::Confirm => 19,
        WizardStep::Done => 14,
    };
    let area = centered_fixed(frame.area(), 82, height);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(app.border_set())
        .border_style(app.theme.title)
        .title(t(wz.lang, Msg::WizardTitle));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    match wz.step {
        WizardStep::Welcome => {
            lines.push(Line::from(Span::styled(
                localized(
                    wz.lang,
                    "Set up this machine for OwnMesh",
                    "このPCでOwnMeshを使えるようにします",
                    "为此设备设置 OwnMesh",
                    "Настройка OwnMesh на этом устройстве",
                ),
                app.theme.accent,
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(localized(
                wz.lang,
                "Choose a server and access policy. OwnMesh then signs in, enrolls",
                "サーバーとアクセス範囲を選びます。その後、ログイン・PC登録・",
                "选择服务器和访问策略，然后登录、注册并启动代理。",
                "Выберите сервер и политику; затем вход, регистрация и запуск агента.",
            )));
            lines.push(Line::from(localized(
                wz.lang,
                "this device, and starts the local Agent when needed.",
                "Agentの起動まで必要な処理を順番に行います。",
                "",
                "",
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "[Enter] {} · [Esc] {}",
                t(wz.lang, Msg::Next),
                t(wz.lang, Msg::Cancel)
            )));
        }
        WizardStep::Server => {
            lines.push(Line::from(Span::styled(
                localized(
                    wz.lang,
                    "OwnMesh server",
                    "OwnMeshサーバー",
                    "OwnMesh 服务器",
                    "Сервер OwnMesh",
                ),
                app.theme.accent,
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                truncate_to_width(
                    &format!("> {}", wz.control_plane_url),
                    inner.width.saturating_sub(2) as usize,
                ),
                app.theme.selection,
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                localized(
                    wz.lang,
                    "Paste the HTTPS URL from your deployment. Changing it requires a new sign-in.",
                    "デプロイしたHTTPS URLを入力します。変更時は再ログインが必要です。",
                    "粘贴部署的 HTTPS URL。更改后需要重新登录。",
                    "Вставьте HTTPS URL. При смене сервера потребуется новый вход.",
                ),
                app.theme.muted,
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(localized(
                wz.lang,
                "Type or paste · Enter next · Esc back",
                "入力/貼り付け · Enter 次へ · Esc 戻る",
                "输入或粘贴 · Enter 下一步 · Esc 返回",
                "Введите или вставьте · Enter далее · Esc назад",
            )));
        }
        WizardStep::Language => {
            lines.push(Line::from(Span::styled(
                t(wz.lang, Msg::WizardLangStep),
                app.theme.accent,
            )));
            for (i, lang) in Lang::ALL.iter().enumerate() {
                let mark = if i == wz.lang_idx { ">" } else { " " };
                lines.push(Line::from(format!("{mark} {}", lang.bcp47())));
            }
            lines.push(Line::from(""));
            lines.push(Line::from("↑/↓ select · Enter next · Esc back"));
        }
        WizardStep::Preset => {
            lines.push(Line::from(Span::styled(
                t(wz.lang, Msg::WizardPresetStep),
                app.theme.accent,
            )));
            if wz.original_preset == AccessPreset::Custom && !wz.preset_changed {
                lines.push(Line::from(localized(
                    wz.lang,
                    "> Custom (preserved; choose below only to replace it)",
                    "> カスタム（保持。変更する場合だけ下から選択）",
                    "> 自定义（保留；仅在需要替换时选择下方项目）",
                    "> Своя политика (сохранена; ниже — только для замены)",
                )));
            }
            for (i, preset) in WIZARD_PRESETS.iter().enumerate() {
                let mark = if (wz.preset_changed || wz.original_preset != AccessPreset::Custom)
                    && i == wz.preset_idx
                {
                    ">"
                } else {
                    " "
                };
                let (name, desc) = preset_msgs(*preset);
                lines.push(Line::from(format!("{mark} {}", t(wz.lang, name))));
                lines.push(Line::from(Span::styled(
                    format!("    {}", t(wz.lang, desc)),
                    app.theme.muted,
                )));
            }
        }
        WizardStep::Confirm => {
            lines.push(Line::from(Span::styled(
                t(wz.lang, Msg::WizardConfirmStep),
                app.theme.accent,
            )));
            lines.push(Line::from(format!(
                "{}: {}",
                localized(wz.lang, "Server", "サーバー", "服务器", "Сервер"),
                wz.control_plane_url
            )));
            lines.push(Line::from(format!(
                "{}: {}",
                t(wz.lang, Msg::SettingsLang),
                wz.lang.bcp47()
            )));
            let preset_label = if wz.selected_preset() == AccessPreset::Custom {
                localized(
                    wz.lang,
                    "Custom (preserved)",
                    "カスタム（保持）",
                    "自定义（保留）",
                    "Своя политика (сохранена)",
                )
            } else {
                let (name, _) = preset_msgs(wz.selected_preset());
                t(wz.lang, name)
            };
            lines.push(Line::from(format!(
                "{}: {}",
                t(wz.lang, Msg::SettingsPreset),
                preset_label
            )));
            if wz.selected_preset() == AccessPreset::FullAccess {
                lines.push(Line::from(Span::styled(
                    t(wz.lang, Msg::WizardFullAccessNote),
                    app.theme.warn,
                )));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                localized(
                    wz.lang,
                    "Next: sign in (URL + code), enroll this device, install/start Agent as needed.",
                    "次に、URL＋コードでログインし、PC登録とAgentの設定・起動を行います。",
                    "接下来按需登录、注册此设备并安装/启动代理。",
                    "Далее: вход, регистрация устройства и установка/запуск агента.",
                ),
                app.theme.muted,
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "[Enter] {} · [Backspace] {}",
                t(wz.lang, Msg::Finish),
                t(wz.lang, Msg::Back)
            )));
        }
        WizardStep::Done => {
            lines.push(Line::from(Span::styled(
                t(wz.lang, Msg::WizardDone),
                if wz.error.is_some() {
                    app.theme.warn
                } else {
                    app.theme.ok
                },
            )));
            lines.push(Line::from(t(wz.lang, Msg::WizardSaveOk)));
            if let Some(err) = &wz.error {
                lines.push(Line::from(Span::styled(err.as_str(), app.theme.warn)));
            }
            lines.push(Line::from(""));
            lines.push(Line::from("[Enter/Esc] close"));
        }
    }
    if let Some(err) = &wz.error {
        if wz.step != WizardStep::Done {
            lines.push(Line::from(Span::styled(err.as_str(), app.theme.err)));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn preset_msgs(preset: AccessPreset) -> (Msg, Msg) {
    match preset {
        AccessPreset::WorkspaceOnly => (
            Msg::WizardPresetWorkspaceOnly,
            Msg::WizardPresetWorkspaceOnlyDesc,
        ),
        AccessPreset::Recommended => (
            Msg::WizardPresetRecommended,
            Msg::WizardPresetRecommendedDesc,
        ),
        AccessPreset::FullUserAccess => (Msg::WizardPresetFullUser, Msg::WizardPresetFullUserDesc),
        AccessPreset::FullAccess => (Msg::WizardPresetFullAccess, Msg::WizardPresetFullAccessDesc),
        AccessPreset::Custom => (Msg::SettingsPreset, Msg::SettingsHint),
    }
}

fn draw_palette(frame: &mut Frame<'_>, app: &App) {
    let items = filter_commands(app.lang, &app.palette.query);
    let item_rows = u16::try_from(items.len().min(12)).unwrap_or(12);
    let area = centered_fixed(frame.area(), 76, item_rows.saturating_add(4));
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(app.border_set())
        .border_style(app.theme.accent)
        .title(t(app.lang, Msg::PaletteTitle));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);

    frame.render_widget(
        Paragraph::new(format!("> {}", app.palette.query)).style(app.theme.body),
        chunks[0],
    );

    let selected = items
        .len()
        .checked_sub(1)
        .map_or(0, |last| app.palette.cursor.min(last));
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == selected {
                app.theme.selection
            } else {
                app.theme.body
            };
            ListItem::new(truncate_to_width(
                t(app.lang, c.label_msg),
                chunks[1].width.saturating_sub(1) as usize,
            ))
            .style(style)
        })
        .collect();
    render_list_with_cursor(frame, list_items, selected, chunks[1]);
    frame.render_widget(
        Paragraph::new(t(app.lang, Msg::PaletteHint)).style(app.theme.muted),
        chunks[2],
    );
}

/// Render app into a string snapshot (for tests).
#[cfg(test)]
#[must_use]
pub fn render_snapshot(app: &App, width: u16, height: u16) -> String {
    let mut terminal = ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, height))
        .expect("test backend");
    terminal.draw(|f| draw(f, app)).expect("draw");
    buffer_to_string(terminal.backend().buffer())
}

/// Convert a ratatui buffer to a plain multiline string.
#[cfg(test)]
#[must_use]
pub fn buffer_to_string(buf: &ratatui::buffer::Buffer) -> String {
    let area = buf.area;
    let mut out = String::new();
    for y in 0..area.height {
        let mut x = 0u16;
        while x < area.width {
            let cell = &buf[(x, y)];
            let sym = cell.symbol();
            out.push_str(sym);
            let w = display_width(sym).max(1) as u16;
            x = x.saturating_add(w);
        }
        out.push('\n');
    }
    out
}

/// Assert snapshot fits width without obvious raw overflow markers.
#[cfg(test)]
#[must_use]
pub fn line_display_widths(snapshot: &str) -> Vec<usize> {
    snapshot.lines().map(display_width).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{ColorMode, Theme};
    use ownmesh_config::OwnMeshPaths;
    use tempfile::tempdir;

    fn test_app(lang: Lang) -> App {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let mut app = App::new(paths, None);
        app.lang = lang;
        app.overlay = Overlay::None;
        app.theme = Theme::new(ColorMode::NoColor);
        app
    }

    #[test]
    fn layout_80x24_all_screens() {
        for screen in Screen::ALL {
            let mut app = test_app(Lang::EnUs);
            app.screen = *screen;
            let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
            let widths = line_display_widths(&snap);
            assert_eq!(widths.len(), MIN_ROWS as usize, "screen={screen:?}");
            for (i, w) in widths.iter().enumerate() {
                assert!(
                    *w <= MIN_COLS as usize,
                    "screen={screen:?} line {i} width {w} > {MIN_COLS}\n{snap}"
                );
            }
            assert!(
                snap.contains("OwnMesh") || snap.to_lowercase().contains("ownmesh"),
                "missing title on {screen:?}"
            );
        }
    }

    #[test]
    fn cjk_width_snapshot_ja_zh() {
        for lang in [Lang::JaJp, Lang::ZhHans] {
            let mut app = test_app(lang);
            app.screen = Screen::Devices;
            let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
            for (i, w) in line_display_widths(&snap).iter().enumerate() {
                assert!(
                    *w <= MIN_COLS as usize,
                    "{lang:?} line {i} overflow {w}\n{snap}"
                );
            }
            // The selected screen title remains legible in the quiet shell.
            let nav = t(lang, Msg::NavDevices);
            assert!(
                snap.contains(nav) || snap.contains(truncate_to_width(nav, 4).as_str()),
                "nav missing for {lang:?}: {snap}"
            );
        }
    }

    #[test]
    fn russian_overflow_snapshot() {
        let mut app = test_app(Lang::RuRu);
        // Long-copy screens exercise wrapping/truncation.
        for screen in [
            Screen::Transfers,
            Screen::Approvals,
            Screen::Settings,
            Screen::Diagnostics,
        ] {
            app.screen = screen;
            let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
            for (i, w) in line_display_widths(&snap).iter().enumerate() {
                assert!(
                    *w <= MIN_COLS as usize,
                    "ru screen={screen:?} line {i} width {w}\n{snap}"
                );
            }
        }
        // Footer Russian is long — must truncate, not blow width.
        app.screen = Screen::Dashboard;
        let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
        let footer = snap.lines().last().unwrap_or("");
        assert!(display_width(footer) <= MIN_COLS as usize);
    }

    #[test]
    fn transfers_snapshot_is_facts_only() {
        let mut app = test_app(Lang::EnUs);
        app.screen = Screen::Transfers;
        let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS).to_ascii_lowercase();
        assert!(snap.contains("local"));
        assert!(snap.contains("relay"));
        assert!(
            !snap.contains("lan discovery enabled")
                && !snap.contains("start lan transfer")
                && !snap.contains("p2p ready"),
            "must not promise LAN UI: {snap}"
        );
    }

    #[test]
    fn palette_and_wizard_render() {
        let mut app = test_app(Lang::EnUs);
        app.palette.open();
        let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
        assert!(
            snap.to_ascii_lowercase().contains("command")
                || snap.contains("palette")
                || snap.contains("Dashboard")
                || snap.contains("Go to")
        );

        app.palette.close();
        app.overlay = Overlay::Wizard;
        let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
        assert!(
            snap.to_ascii_lowercase().contains("setup")
                || snap.contains("Wizard")
                || snap.contains("Configure")
        );
    }

    #[test]
    fn long_sessions_list_scrolls_selection_into_view() {
        let mut app = test_app(Lang::EnUs);
        app.screen = Screen::Sessions;
        app.set_sessions_from_json(&serde_json::json!({
            "sessions": (0..40)
                .map(|i| serde_json::json!({ "id": format!("s{i:02}"), "state": "active" }))
                .collect::<Vec<_>>()
        }));
        for _ in 0..39 {
            app.move_list_cursor(1);
        }
        assert_eq!(app.list_cursor, 39);
        let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
        assert!(
            snap.contains("s39"),
            "selected row must scroll into view:\n{snap}"
        );
        assert!(
            !snap.contains("s00"),
            "rows above the viewport must be scrolled away:\n{snap}"
        );

        // Moving back up brings the top rows into view again.
        for _ in 0..39 {
            app.move_list_cursor(-1);
        }
        assert_eq!(app.list_cursor, 0);
        let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
        assert!(snap.contains("s00"), "first row visible again:\n{snap}");
        assert!(!snap.contains("s39"), "bottom row scrolled away:\n{snap}");
    }

    #[test]
    fn long_approval_queue_scrolls_selection_into_view() {
        let mut app = test_app(Lang::EnUs);
        app.screen = Screen::Approvals;
        app.set_approvals_from_json(&serde_json::json!({
            "approvals": (0..30)
                .map(|i| {
                    serde_json::json!({
                        "id": format!("ap-{i:02}"),
                        "capability": "fs.read",
                        "state": "pending",
                        "reason": "check"
                    })
                })
                .collect::<Vec<_>>()
        }));
        app.approval_cursor = 29;
        let snap = render_snapshot(&app, MIN_COLS, MIN_ROWS);
        assert!(
            snap.contains("ap-29"),
            "selected approval must scroll into view:\n{snap}"
        );
        assert!(
            !snap.contains("ap-00"),
            "approvals above the viewport must be scrolled away:\n{snap}"
        );
    }

    #[test]
    fn overview_renders_selected_linux_console_structure() {
        let app = test_app(Lang::EnUs);
        let snapshot = render_snapshot(&app, 120, 32).to_ascii_lowercase();
        for expected in [
            "setup required",
            "finish setup",
            "server",
            "account",
            "this device",
            "agent",
            "ctrl+k commands",
            "server not configured",
        ] {
            assert!(
                snapshot.contains(expected),
                "missing {expected}:\n{snapshot}"
            );
        }
        assert!(!snapshot.contains("/connect"));
        assert!(!snapshot.contains("control plane connected"));
    }

    #[test]
    fn connector_modal_names_the_separate_chatgpt_step() {
        let mut app = test_app(Lang::EnUs);
        app.readiness.server_url = Some("https://mesh.example".into());
        app.overlay = Overlay::Connector;
        let snapshot = render_snapshot(&app, 120, 32).to_ascii_lowercase();
        assert!(snapshot.contains("https://mesh.example/mcp"));
        assert!(snapshot.contains("separate from enrolling this pc"));
    }

    #[test]
    fn devices_inventory_renders_multi_device_and_keeps_error_snapshot() {
        let mut app = test_app(Lang::EnUs);
        app.screen = Screen::Devices;
        app.readiness.device_id = Some("dev_local".into());
        app.replace_device_inventory(crate::control_plane::DeviceInventory::Loaded {
            devices: vec![
                crate::control_plane::InventoryDevice {
                    id: "dev_local".into(),
                    name: Some("This PC".into()),
                    enrollment_status: Some("active".into()),
                    connection_status: Some("connected".into()),
                    agent_version: Some("1.2.11".into()),
                    last_seen_at: Some("2026-08-14T00:00:00Z".into()),
                },
                crate::control_plane::InventoryDevice {
                    id: "dev_other".into(),
                    name: Some("Studio".into()),
                    enrollment_status: Some("active".into()),
                    connection_status: Some("offline".into()),
                    agent_version: Some("1.2.10".into()),
                    last_seen_at: Some("2026-08-13T00:00:00Z".into()),
                },
            ],
            truncated: false,
        });
        let snap = render_snapshot(&app, 120, 32);
        assert!(snap.contains("dev_local"));
        assert!(snap.contains("This PC"));
        assert!(snap.contains("dev_other"));
        assert!(snap.contains("Studio"));
        assert!(snap.contains("enroll=active"));
        assert!(snap.contains("route=offline"));
        assert!(snap.to_ascii_lowercase().contains("refresh"));
        assert!(!snap.contains("atk_"));
        assert!(!snap.to_ascii_lowercase().contains("bearer "));

        app.replace_device_inventory(crate::control_plane::DeviceInventory::Unreachable {
            message: "[REDACTED line containing bearer]".into(),
            previous: Some(Box::new(crate::control_plane::DeviceInventory::Loaded {
                devices: vec![crate::control_plane::InventoryDevice {
                    id: "dev_local".into(),
                    name: Some("This PC".into()),
                    enrollment_status: Some("active".into()),
                    connection_status: Some("connected".into()),
                    agent_version: Some("1.2.11".into()),
                    last_seen_at: None,
                }],
                truncated: false,
            })),
        });
        let failed = render_snapshot(&app, 120, 32);
        assert!(failed.contains("This PC"));
        assert!(failed.contains("unreachable"));
        assert!(!failed.contains("atk_secret"));
    }

    #[test]
    fn devices_empty_and_auth_states_are_honest() {
        let mut app = test_app(Lang::EnUs);
        app.screen = Screen::Devices;
        app.replace_device_inventory(crate::control_plane::DeviceInventory::Empty);
        let empty = render_snapshot(&app, MIN_COLS, MIN_ROWS).to_ascii_lowercase();
        assert!(empty.contains("no enrolled devices"));
        app.replace_device_inventory(crate::control_plane::DeviceInventory::AuthRequired);
        let auth = render_snapshot(&app, MIN_COLS, MIN_ROWS).to_ascii_lowercase();
        assert!(auth.contains("authentication required"));
        app.replace_device_inventory(crate::control_plane::DeviceInventory::NotConfigured);
        let missing = render_snapshot(&app, MIN_COLS, MIN_ROWS).to_ascii_lowercase();
        assert!(missing.contains("not configured"));
    }
}
