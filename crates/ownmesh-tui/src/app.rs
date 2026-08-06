//! Application state, navigation, and pure helpers.

use crate::i18n::{t, Lang, Msg};
use crate::palette::{filter_commands, PaletteAction, PaletteState};
use crate::theme::{ascii_fallback, ColorMode, Theme};
use crate::wizard::{
    apply_setup, preset_from_wire, preset_wire_name, WizardState, WizardStep, WIZARD_PRESETS,
};
use ownmesh_config::{load_config, load_policy, OwnMeshPaths};
use ownmesh_diagnostics::{run_doctor, DoctorInput, DoctorReport};
use ownmesh_ipc::DaemonStatus;
use ownmesh_policy::AccessPreset;
use ownmesh_profiles::official_profiles;
use ownmesh_transfer::TransferConfig;
use serde_json::Value;

/// Primary navigation screens (§13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Screen {
    Dashboard,
    Devices,
    Workspaces,
    Sessions,
    Profiles,
    Approvals,
    Transfers,
    Activity,
    Diagnostics,
    Settings,
}

impl Screen {
    pub const ALL: &'static [Screen] = &[
        Self::Dashboard,
        Self::Devices,
        Self::Workspaces,
        Self::Sessions,
        Self::Profiles,
        Self::Approvals,
        Self::Transfers,
        Self::Activity,
        Self::Diagnostics,
        Self::Settings,
    ];

    #[must_use]
    pub fn title_msg(self) -> Msg {
        match self {
            Self::Dashboard => Msg::NavDashboard,
            Self::Devices => Msg::NavDevices,
            Self::Workspaces => Msg::NavWorkspaces,
            Self::Sessions => Msg::NavSessions,
            Self::Profiles => Msg::NavProfiles,
            Self::Approvals => Msg::NavApprovals,
            Self::Transfers => Msg::NavTransfers,
            Self::Activity => Msg::NavActivity,
            Self::Diagnostics => Msg::NavDiagnostics,
            Self::Settings => Msg::NavSettings,
        }
    }

    #[must_use]
    pub fn index(self) -> usize {
        Self::ALL.iter().position(|s| *s == self).unwrap_or(0)
    }

    #[must_use]
    pub fn from_index(i: usize) -> Self {
        Self::ALL.get(i).copied().unwrap_or(Self::Dashboard)
    }
}

/// One row in the approvals queue (TUI §7).
#[derive(Debug, Clone)]
pub struct ApprovalItem {
    pub id: String,
    pub capability: String,
    pub state: String,
    pub reason: String,
}

/// Overlay mode on top of a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlay {
    None,
    Help,
    Wizard,
}

/// Root application model.
#[derive(Debug)]
pub struct App {
    pub lang: Lang,
    pub theme: Theme,
    pub screen: Screen,
    pub overlay: Overlay,
    pub palette: PaletteState,
    pub wizard: WizardState,
    pub paths: OwnMeshPaths,
    pub daemon: Option<DaemonStatus>,
    pub approvals: Vec<ApprovalItem>,
    pub approval_cursor: usize,
    pub sessions: Vec<String>,
    pub activity: Vec<String>,
    pub doctor: DoctorReport,
    pub policy_preset: AccessPreset,
    pub status_line: String,
    pub should_quit: bool,
    pub list_cursor: usize,
}

impl App {
    /// Build app from paths + optional daemon status snapshot.
    #[must_use]
    pub fn new(paths: OwnMeshPaths, daemon: Option<DaemonStatus>) -> Self {
        let cfg = load_config(&paths).unwrap_or_default();
        let lang = Lang::parse(&cfg.lang);
        let pol = load_policy(&paths).unwrap_or_default();
        let policy_preset = preset_from_wire(pol.preset.as_deref().unwrap_or("recommended"));
        let doctor = run_doctor(&DoctorInput {
            config_readable: true,
            daemon_reachable: daemon.is_some(),
            identity_present: false,
            control_plane_url: cfg.active_instance.as_ref().and_then(|id| {
                cfg.instances
                    .iter()
                    .find(|i| &i.id == id)
                    .map(|i| i.base_url.clone())
            }),
            telemetry_enabled: cfg.telemetry.project
                || cfg.telemetry.crash_upload
                || cfg.telemetry.usage_analytics,
            relay_enabled: TransferConfig::default().relay_enabled,
        });

        let mut app = Self {
            lang,
            theme: Theme::new(ColorMode::detect()),
            screen: Screen::Dashboard,
            overlay: Overlay::None,
            palette: PaletteState::default(),
            wizard: WizardState {
                lang,
                lang_idx: Lang::ALL.iter().position(|l| *l == lang).unwrap_or(0),
                preset_idx: WIZARD_PRESETS
                    .iter()
                    .position(|p| *p == policy_preset)
                    .unwrap_or(1),
                ..WizardState::default()
            },
            paths,
            daemon,
            approvals: Vec::new(),
            approval_cursor: 0,
            sessions: Vec::new(),
            activity: Vec::new(),
            doctor,
            policy_preset,
            status_line: String::new(),
            should_quit: false,
            list_cursor: 0,
        };
        // First-run: open wizard when policy still default and no active instance.
        if cfg.active_instance.is_none() && !app.paths.policy_file().is_file() {
            app.overlay = Overlay::Wizard;
        }
        app
    }

    /// Replace approvals list from IPC JSON `{ "approvals": [ ... ] }`.
    pub fn set_approvals_from_json(&mut self, value: &Value) {
        self.approvals.clear();
        if let Some(arr) = value.get("approvals").and_then(|a| a.as_array()) {
            for a in arr {
                self.approvals.push(ApprovalItem {
                    id: a
                        .get("id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    capability: a
                        .get("capability")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                    state: a
                        .get("state")
                        .and_then(|v| v.as_str())
                        .unwrap_or("pending")
                        .to_owned(),
                    reason: a
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_owned(),
                });
            }
        }
        if self.approval_cursor >= self.approvals.len() {
            self.approval_cursor = self.approvals.len().saturating_sub(1);
        }
    }

    pub fn set_sessions_from_json(&mut self, value: &Value) {
        self.sessions.clear();
        let arr = value
            .get("sessions")
            .and_then(|a| a.as_array())
            .cloned()
            .unwrap_or_default();
        for s in arr {
            let id = s
                .get("id")
                .or_else(|| s.get("session_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("?");
            let state = s.get("state").and_then(|v| v.as_str()).unwrap_or("");
            self.sessions.push(format!("{id}  {state}"));
        }
    }

    #[must_use]
    pub fn nav_labels(&self) -> Vec<String> {
        Screen::ALL
            .iter()
            .map(|s| t(self.lang, s.title_msg()).to_owned())
            .collect()
    }

    pub fn next_screen(&mut self) {
        let i = (self.screen.index() + 1) % Screen::ALL.len();
        self.screen = Screen::from_index(i);
        self.list_cursor = 0;
    }

    pub fn prev_screen(&mut self) {
        let n = Screen::ALL.len();
        let i = (self.screen.index() + n - 1) % n;
        self.screen = Screen::from_index(i);
        self.list_cursor = 0;
    }

    pub fn open_palette(&mut self) {
        self.palette.open();
    }

    /// Handle a palette action.
    pub fn dispatch_palette(&mut self, action: PaletteAction) {
        match action {
            PaletteAction::Goto(screen) => {
                self.screen = screen;
                self.list_cursor = 0;
            }
            PaletteAction::OpenWizard => {
                self.overlay = Overlay::Wizard;
                self.wizard.step = WizardStep::Welcome;
                self.wizard.saved = false;
            }
            PaletteAction::OpenHelp => self.overlay = Overlay::Help,
            PaletteAction::Quit => self.should_quit = true,
            PaletteAction::ApproveSelected => {
                self.screen = Screen::Approvals;
                self.status_line = format!(
                    "{} — IPC approve when daemon online",
                    t(self.lang, Msg::ApprovalsApprove)
                );
            }
            PaletteAction::DenySelected => {
                self.screen = Screen::Approvals;
                self.status_line = format!(
                    "{} — IPC deny when daemon online",
                    t(self.lang, Msg::ApprovalsDeny)
                );
            }
        }
        self.palette.close();
    }

    pub fn run_selected_palette(&mut self) {
        let items = filter_commands(self.lang, &self.palette.query);
        if let Some(cmd) = items.get(self.palette.cursor) {
            self.dispatch_palette(cmd.action);
        }
    }

    /// Apply settings language + preset to disk.
    pub fn apply_settings(&mut self) -> Result<(), String> {
        apply_setup(&self.paths, self.lang, self.policy_preset)?;
        self.status_line = t(self.lang, Msg::WizardSaveOk).to_owned();
        Ok(())
    }

    pub fn cycle_settings_lang(&mut self) {
        let idx = Lang::ALL.iter().position(|l| *l == self.lang).unwrap_or(0);
        self.lang = Lang::ALL[(idx + 1) % Lang::ALL.len()];
    }

    pub fn cycle_settings_preset(&mut self) {
        let idx = WIZARD_PRESETS
            .iter()
            .position(|p| *p == self.policy_preset)
            .unwrap_or(0);
        self.policy_preset = WIZARD_PRESETS[(idx + 1) % WIZARD_PRESETS.len()];
    }

    #[must_use]
    pub fn profile_lines(&self) -> Vec<String> {
        official_profiles()
            .into_iter()
            .map(|p| format!("{} — {}", p.id, p.display_name))
            .collect()
    }

    #[must_use]
    pub fn transfer_lines(&self) -> Vec<String> {
        let cfg = TransferConfig::default();
        vec![
            t(self.lang, Msg::TransfersLocalPlan).to_owned(),
            t(self.lang, Msg::TransfersLocalCopy).to_owned(),
            format!(
                "{} (relay_enabled={})",
                t(self.lang, Msg::TransfersRelayOff),
                cfg.relay_enabled
            ),
            t(self.lang, Msg::TransfersRelayFailClosed).to_owned(),
            t(self.lang, Msg::TransfersNoLanPromise).to_owned(),
        ]
    }

    #[must_use]
    pub fn border_set(&self) -> ratatui::symbols::border::Set {
        if ascii_fallback() {
            ratatui::symbols::border::PLAIN
        } else {
            ratatui::symbols::border::ROUNDED
        }
    }

    #[must_use]
    pub fn preset_label(&self) -> String {
        let msg = match self.policy_preset {
            AccessPreset::WorkspaceOnly => Msg::WizardPresetWorkspaceOnly,
            AccessPreset::Recommended => Msg::WizardPresetRecommended,
            AccessPreset::FullUserAccess => Msg::WizardPresetFullUser,
            AccessPreset::FullAccess => Msg::WizardPresetFullAccess,
            AccessPreset::Custom => Msg::SettingsPreset,
        };
        format!(
            "{} ({})",
            t(self.lang, msg),
            preset_wire_name(self.policy_preset)
        )
    }
}
