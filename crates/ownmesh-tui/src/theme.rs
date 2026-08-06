//! Obsidian-inspired theme with color-depth and accessibility fallbacks.

use ratatui::style::{Color, Modifier, Style};

/// Color depth / accessibility mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ColorMode {
    /// Prefer truecolor Obsidian palette.
    #[default]
    TrueColor,
    /// 256-color approximation.
    Ansi256,
    /// 16-color basic palette.
    Ansi16,
    /// No color (bold/dim only).
    NoColor,
    /// High contrast pairs.
    HighContrast,
}

impl ColorMode {
    /// Resolve from environment (`NO_COLOR`, `OWNMESH_COLOR`, `COLORTERM`).
    #[must_use]
    pub fn detect() -> Self {
        if std::env::var_os("NO_COLOR").is_some() {
            return Self::NoColor;
        }
        if let Ok(v) = std::env::var("OWNMESH_COLOR") {
            match v.to_ascii_lowercase().as_str() {
                "none" | "off" | "no" | "0" => return Self::NoColor,
                "16" => return Self::Ansi16,
                "256" => return Self::Ansi256,
                "high" | "hc" | "high-contrast" => return Self::HighContrast,
                "true" | "truecolor" | "24bit" => return Self::TrueColor,
                _ => {}
            }
        }
        if std::env::var("COLORTERM")
            .map(|v| v.eq_ignore_ascii_case("truecolor") || v.eq_ignore_ascii_case("24bit"))
            .unwrap_or(false)
        {
            return Self::TrueColor;
        }
        Self::Ansi256
    }
}

/// Whether reduced-motion is requested (`OWNMESH_REDUCED_MOTION` or `prefers-reduced-motion` proxy).
#[must_use]
#[allow(dead_code)]
pub fn reduced_motion() -> bool {
    matches!(
        std::env::var("OWNMESH_REDUCED_MOTION")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Whether ASCII-only borders/glyphs are forced.
#[must_use]
pub fn ascii_fallback() -> bool {
    matches!(
        std::env::var("OWNMESH_ASCII")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    ) || std::env::var_os("OWNMESH_NO_UNICODE").is_some()
}

/// Theme styles derived from [`ColorMode`].
#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub mode: ColorMode,
    pub title: Style,
    pub border: Style,
    pub nav_active: Style,
    pub nav_inactive: Style,
    pub body: Style,
    pub muted: Style,
    pub warn: Style,
    pub ok: Style,
    pub err: Style,
    pub accent: Style,
    pub selection: Style,
}

impl Theme {
    #[must_use]
    pub fn new(mode: ColorMode) -> Self {
        match mode {
            ColorMode::TrueColor => Self {
                mode,
                title: Style::default()
                    .fg(Color::Rgb(197, 164, 114))
                    .add_modifier(Modifier::BOLD),
                border: Style::default().fg(Color::Rgb(70, 70, 70)),
                nav_active: Style::default()
                    .fg(Color::Rgb(232, 232, 232))
                    .bg(Color::Rgb(42, 42, 42))
                    .add_modifier(Modifier::BOLD),
                nav_inactive: Style::default().fg(Color::Rgb(140, 140, 140)),
                body: Style::default().fg(Color::Rgb(220, 220, 220)),
                muted: Style::default().fg(Color::Rgb(120, 120, 120)),
                warn: Style::default().fg(Color::Rgb(210, 170, 80)),
                ok: Style::default().fg(Color::Rgb(120, 180, 120)),
                err: Style::default().fg(Color::Rgb(200, 100, 100)),
                accent: Style::default().fg(Color::Rgb(120, 160, 200)),
                selection: Style::default()
                    .fg(Color::Rgb(20, 20, 20))
                    .bg(Color::Rgb(197, 164, 114)),
            },
            ColorMode::Ansi256 => Self {
                mode,
                title: Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                border: Style::default().fg(Color::DarkGray),
                nav_active: Style::default()
                    .fg(Color::White)
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
                nav_inactive: Style::default().fg(Color::Gray),
                body: Style::default().fg(Color::White),
                muted: Style::default().fg(Color::DarkGray),
                warn: Style::default().fg(Color::Yellow),
                ok: Style::default().fg(Color::Green),
                err: Style::default().fg(Color::Red),
                accent: Style::default().fg(Color::Cyan),
                selection: Style::default().fg(Color::Black).bg(Color::Yellow),
            },
            ColorMode::Ansi16 => Self {
                mode,
                title: Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                border: Style::default().fg(Color::White),
                nav_active: Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
                nav_inactive: Style::default().fg(Color::White),
                body: Style::default().fg(Color::White),
                muted: Style::default().fg(Color::White),
                warn: Style::default().fg(Color::Yellow),
                ok: Style::default().fg(Color::Green),
                err: Style::default().fg(Color::Red),
                accent: Style::default().fg(Color::Cyan),
                selection: Style::default().fg(Color::Black).bg(Color::Cyan),
            },
            ColorMode::NoColor => Self {
                mode,
                title: Style::default().add_modifier(Modifier::BOLD),
                border: Style::default(),
                nav_active: Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED),
                nav_inactive: Style::default().add_modifier(Modifier::DIM),
                body: Style::default(),
                muted: Style::default().add_modifier(Modifier::DIM),
                warn: Style::default().add_modifier(Modifier::BOLD),
                ok: Style::default(),
                err: Style::default().add_modifier(Modifier::BOLD),
                accent: Style::default().add_modifier(Modifier::UNDERLINED),
                selection: Style::default().add_modifier(Modifier::REVERSED),
            },
            ColorMode::HighContrast => Self {
                mode,
                title: Style::default()
                    .fg(Color::White)
                    .bg(Color::Black)
                    .add_modifier(Modifier::BOLD),
                border: Style::default().fg(Color::White),
                nav_active: Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
                nav_inactive: Style::default().fg(Color::White),
                body: Style::default().fg(Color::White),
                muted: Style::default().fg(Color::Gray),
                warn: Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
                ok: Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                err: Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                accent: Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
                selection: Style::default().fg(Color::Black).bg(Color::White),
            },
        }
    }
}
