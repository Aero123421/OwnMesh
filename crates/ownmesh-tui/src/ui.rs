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
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
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
        Overlay::None => {}
    }
    if app.palette.open {
        draw_palette(frame, app);
    }
}

fn draw_brand(frame: &mut Frame<'_>, app: &App, area: Rect, narrow: bool) {
    let state = if app.active_instance.is_none() {
        "setup required"
    } else if app.daemon.is_some() {
        "private mesh online"
    } else {
        "private mesh offline"
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
                if app.daemon.is_some() {
                    app.theme.ok
                } else {
                    app.theme.muted
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
    let device_count = usize::from(app.daemon.is_some());
    let plane = if app.active_instance.is_some() {
        "control plane connected"
    } else {
        "control plane not configured"
    };
    let text = format!(
        "{device_count} device{} online    |    {plane}    |    v{}",
        if device_count == 1 { "" } else { "s" },
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
        ">   Type a command…".to_owned()
    } else {
        format!(">   {}", app.status_line)
    };
    let area = centered_width(area, area.width.saturating_sub(8));
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
    let width = area.width.clamp(36, 64);
    let height = area.height.min(9);
    let menu = Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(height) / 3,
        width,
        height,
    };
    if height < 9 {
        let lines: Vec<Line> = OverviewAction::ALL
            .iter()
            .enumerate()
            .map(|(index, action)| {
                let marker = if index == app.overview_action_cursor {
                    "> "
                } else {
                    "  "
                };
                Line::from(Span::styled(
                    format!("{marker}{:<13} {}", action.command(), action.description()),
                    if index == app.overview_action_cursor {
                        app.theme.selection
                    } else {
                        app.theme.body
                    },
                ))
            })
            .collect();
        frame.render_widget(Paragraph::new(lines), menu);
        return;
    }

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(menu);
    for (index, action) in OverviewAction::ALL.iter().enumerate() {
        let selected = index == app.overview_action_cursor;
        let line = Line::from(vec![
            Span::styled(if selected { ">   " } else { "    " }, app.theme.body),
            Span::styled(format!("{:<15}", action.command()), app.theme.body),
            Span::styled(action.description(), app.theme.muted),
        ]);
        if selected {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_set(app.border_set())
                .border_style(app.theme.border);
            frame.render_widget(Paragraph::new(line).block(block), rows[index]);
        } else {
            frame.render_widget(Paragraph::new(line), rows[index]);
        }
    }
}

fn draw_devices(frame: &mut Frame<'_>, app: &App, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(t(app.lang, Msg::DevicesLocal), app.theme.body)),
        Line::from(match &app.daemon {
            Some(s) => format!("  endpoint={} state={}", s.endpoint, s.state),
            None => format!("  {}", t(app.lang, Msg::DaemonOffline)),
        }),
        Line::from(""),
        Line::from(Span::styled(t(app.lang, Msg::DevicesHint), app.theme.muted)),
    ];
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

fn draw_list_screen(frame: &mut Frame<'_>, app: &App, area: Rect, items: Vec<String>, hint: &str) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(2)])
        .split(area);
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let style = if i == app.list_cursor {
                app.theme.selection
            } else {
                app.theme.body
            };
            let text = truncate_to_width(s, chunks[0].width.saturating_sub(1) as usize);
            ListItem::new(text).style(style)
        })
        .collect();
    frame.render_widget(List::new(list_items), chunks[0]);
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
        let items: Vec<ListItem> = app
            .approvals
            .iter()
            .enumerate()
            .map(|(i, a)| {
                let mark = if i == app.approval_cursor { ">" } else { " " };
                let line = format!(
                    "{mark} [{}] {} · {} — {}",
                    a.state, a.id, a.capability, a.reason
                );
                let style = if i == app.approval_cursor {
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
        frame.render_widget(List::new(items), chunks[0]);
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

fn draw_wizard(frame: &mut Frame<'_>, app: &App) {
    let area = centered(frame.area(), 80, 70);
    frame.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_set(app.border_set())
        .border_style(app.theme.title)
        .title(t(app.lang, Msg::WizardTitle));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let wz = &app.wizard;
    let mut lines: Vec<Line> = Vec::new();
    match wz.step {
        WizardStep::Welcome => {
            lines.push(Line::from(t(wz.lang, Msg::WizardWelcome)));
            lines.push(Line::from(""));
            lines.push(Line::from(format!(
                "[Enter] {} · [Esc] {}",
                t(wz.lang, Msg::Next),
                t(wz.lang, Msg::Cancel)
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
            lines.push(Line::from("↑/↓ select · Enter next · Esc cancel"));
        }
        WizardStep::Preset => {
            lines.push(Line::from(Span::styled(
                t(wz.lang, Msg::WizardPresetStep),
                app.theme.accent,
            )));
            for (i, preset) in WIZARD_PRESETS.iter().enumerate() {
                let mark = if i == wz.preset_idx { ">" } else { " " };
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
                t(wz.lang, Msg::SettingsLang),
                wz.lang.bcp47()
            )));
            let (name, _) = preset_msgs(wz.selected_preset());
            lines.push(Line::from(format!(
                "{}: {}",
                t(wz.lang, Msg::SettingsPreset),
                t(wz.lang, name)
            )));
            if wz.selected_preset() == AccessPreset::FullAccess {
                lines.push(Line::from(Span::styled(
                    t(wz.lang, Msg::WizardFullAccessNote),
                    app.theme.ok,
                )));
            }
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
                app.theme.ok,
            )));
            lines.push(Line::from(t(wz.lang, Msg::WizardSaveOk)));
            if let Some(err) = &wz.error {
                lines.push(Line::from(Span::styled(err.as_str(), app.theme.err)));
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
    let area = centered(frame.area(), 70, 60);
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

    let items = filter_commands(app.lang, &app.palette.query);
    let list_items: Vec<ListItem> = items
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let style = if i == app.palette.cursor {
                app.theme.selection
            } else {
                app.theme.body
            };
            ListItem::new(t(app.lang, c.label_msg)).style(style)
        })
        .collect();
    frame.render_widget(List::new(list_items), chunks[1]);
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
    fn overview_renders_selected_linux_console_structure() {
        let app = test_app(Lang::EnUs);
        let snapshot = render_snapshot(&app, 120, 32).to_ascii_lowercase();
        for expected in [
            "setup required",
            "/connect",
            "/devices",
            "/workspace",
            "/doctor",
            "type a command",
            "control plane not configured",
        ] {
            assert!(
                snapshot.contains(expected),
                "missing {expected}:\n{snapshot}"
            );
        }
    }
}
