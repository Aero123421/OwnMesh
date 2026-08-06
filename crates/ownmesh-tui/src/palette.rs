//! Ctrl+K command palette.

use crate::app::Screen;
use crate::i18n::{t, Lang, Msg};

/// A palette entry.
#[derive(Debug, Clone)]
pub struct PaletteCommand {
    pub id: &'static str,
    pub label_msg: Msg,
    pub keywords: &'static str,
    pub action: PaletteAction,
}

/// Action dispatched when a command runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteAction {
    Goto(Screen),
    OpenWizard,
    OpenHelp,
    Quit,
    ApproveSelected,
    DenySelected,
}

/// Static command catalog.
pub fn all_commands() -> &'static [PaletteCommand] {
    &COMMANDS
}

const COMMANDS: [PaletteCommand; 15] = [
    PaletteCommand {
        id: "goto.dashboard",
        label_msg: Msg::CmdGotoDashboard,
        keywords: "home dashboard status",
        action: PaletteAction::Goto(Screen::Dashboard),
    },
    PaletteCommand {
        id: "goto.devices",
        label_msg: Msg::CmdGotoDevices,
        keywords: "device machines",
        action: PaletteAction::Goto(Screen::Devices),
    },
    PaletteCommand {
        id: "goto.workspaces",
        label_msg: Msg::CmdGotoWorkspaces,
        keywords: "workspace folder root",
        action: PaletteAction::Goto(Screen::Workspaces),
    },
    PaletteCommand {
        id: "goto.sessions",
        label_msg: Msg::CmdGotoSessions,
        keywords: "session pty shell",
        action: PaletteAction::Goto(Screen::Sessions),
    },
    PaletteCommand {
        id: "goto.profiles",
        label_msg: Msg::CmdGotoProfiles,
        keywords: "profile cli codex claude",
        action: PaletteAction::Goto(Screen::Profiles),
    },
    PaletteCommand {
        id: "goto.approvals",
        label_msg: Msg::CmdGotoApprovals,
        keywords: "approval queue ask permit",
        action: PaletteAction::Goto(Screen::Approvals),
    },
    PaletteCommand {
        id: "goto.transfers",
        label_msg: Msg::CmdGotoTransfers,
        keywords: "transfer file copy relay",
        action: PaletteAction::Goto(Screen::Transfers),
    },
    PaletteCommand {
        id: "goto.activity",
        label_msg: Msg::CmdGotoActivity,
        keywords: "activity audit log",
        action: PaletteAction::Goto(Screen::Activity),
    },
    PaletteCommand {
        id: "goto.diagnostics",
        label_msg: Msg::CmdGotoDiagnostics,
        keywords: "doctor diagnostics health",
        action: PaletteAction::Goto(Screen::Diagnostics),
    },
    PaletteCommand {
        id: "goto.settings",
        label_msg: Msg::CmdGotoSettings,
        keywords: "settings config language policy",
        action: PaletteAction::Goto(Screen::Settings),
    },
    PaletteCommand {
        id: "wizard",
        label_msg: Msg::CmdOpenWizard,
        keywords: "wizard setup onboarding",
        action: PaletteAction::OpenWizard,
    },
    PaletteCommand {
        id: "help",
        label_msg: Msg::CmdOpenHelp,
        keywords: "help f1",
        action: PaletteAction::OpenHelp,
    },
    PaletteCommand {
        id: "approve",
        label_msg: Msg::CmdApproveSelected,
        keywords: "approve allow yes",
        action: PaletteAction::ApproveSelected,
    },
    PaletteCommand {
        id: "deny",
        label_msg: Msg::CmdDenySelected,
        keywords: "deny reject no",
        action: PaletteAction::DenySelected,
    },
    PaletteCommand {
        id: "quit",
        label_msg: Msg::CmdQuit,
        keywords: "quit exit q",
        action: PaletteAction::Quit,
    },
];

/// Filter commands by query (case-insensitive substring on label + keywords + id).
#[must_use]
pub fn filter_commands(lang: Lang, query: &str) -> Vec<&'static PaletteCommand> {
    let q = query.trim().to_ascii_lowercase();
    all_commands()
        .iter()
        .filter(|c| {
            if q.is_empty() {
                return true;
            }
            let label = t(lang, c.label_msg).to_ascii_lowercase();
            label.contains(&q) || c.keywords.contains(q.as_str()) || c.id.contains(q.as_str())
        })
        .collect()
}

/// Mutable palette UI state.
#[derive(Debug, Clone, Default)]
pub struct PaletteState {
    pub open: bool,
    pub query: String,
    pub cursor: usize,
}

impl PaletteState {
    pub fn open(&mut self) {
        self.open = true;
        self.query.clear();
        self.cursor = 0;
    }

    pub fn close(&mut self) {
        self.open = false;
        self.query.clear();
        self.cursor = 0;
    }

    pub fn move_cursor(&mut self, delta: isize, len: usize) {
        if len == 0 {
            self.cursor = 0;
            return;
        }
        let n = len as isize;
        self.cursor = (self.cursor as isize + delta).rem_euclid(n) as usize;
    }
}
