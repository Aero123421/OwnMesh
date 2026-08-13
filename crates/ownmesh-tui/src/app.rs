//! Application state, navigation, and pure helpers.

use crate::i18n::{t, Lang, Msg};
use crate::palette::{filter_commands, PaletteAction, PaletteState};
use crate::theme::{ColorMode, Theme};
use crate::wizard::{
    apply_setup, preset_from_wire, preset_wire_name, SetupRequest, SetupStatus, WizardState,
    WIZARD_PRESETS,
};
use ownmesh_config::{load_config, load_policy, OwnMeshPaths};
use ownmesh_diagnostics::{
    run_doctor, BinaryObservation, ConfigObservation, ControlPlaneObservation,
    CredentialObservation, DaemonObservation, DoctorInput, DoctorReport, PrivacyPolicyObservation,
    ServiceObservation,
};
use ownmesh_ipc::DaemonStatus;
use ownmesh_policy::AccessPreset;
use ownmesh_profiles::official_profiles;
use serde_json::Value;
use std::fs;

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
    #[cfg(test)]
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

    /// Quiet, task-oriented navigation shown on the main screen. Advanced
    /// views remain available from the command palette.
    pub const PRIMARY: &'static [Screen] = &[
        Self::Dashboard,
        Self::Devices,
        Self::Workspaces,
        Self::Approvals,
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
    pub fn primary_index(self) -> usize {
        Self::PRIMARY.iter().position(|s| *s == self).unwrap_or(0)
    }

    #[must_use]
    pub fn from_primary_index(i: usize) -> Self {
        Self::PRIMARY.get(i).copied().unwrap_or(Self::Dashboard)
    }
}

/// First-use actions kept intentionally small on the overview.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverviewAction {
    SetupRepair,
    RepairAgent,
    Reauthenticate,
    Connector,
    Devices,
    Workspace,
    Doctor,
}

/// Honest local readiness markers. These are observations, not inferred live
/// network state: a configured server is never labelled "connected" here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub server_url: Option<String>,
    pub account_present: bool,
    pub device_id: Option<String>,
    pub service_installed: bool,
    pub agent_running: bool,
}

impl Readiness {
    #[must_use]
    pub fn needs_onboarding(&self) -> bool {
        self.server_url.is_none() || !self.account_present || self.device_id.is_none()
    }

    #[must_use]
    pub fn ready(&self) -> bool {
        !self.needs_onboarding() && self.service_installed && self.agent_running
    }

    #[must_use]
    pub fn connector_url(&self) -> Option<String> {
        self.server_url
            .as_deref()
            .map(|url| format!("{}/mcp", url.trim_end_matches('/')))
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

/// Browser-confirmed decision requested from the approvals screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalDecision {
    Approve,
    Deny,
}

impl ApprovalDecision {
    #[must_use]
    pub const fn cli_verb(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Deny => "deny",
        }
    }
}

/// Exact approval selected by the user before the TUI leaves the alternate screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingApproval {
    pub id: String,
    pub decision: ApprovalDecision,
}

/// Overlay mode on top of a screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overlay {
    None,
    Help,
    Wizard,
    Connector,
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
    pending_approval: Option<PendingApproval>,
    pub sessions: Vec<String>,
    pub activity: Vec<String>,
    pub doctor: DoctorReport,
    pub readiness: Readiness,
    pub policy_preset: AccessPreset,
    pub overview_action_cursor: usize,
    pub status_line: String,
    pub should_quit: bool,
    pub list_cursor: usize,
    pending_setup: Option<SetupRequest>,
    pending_reauthentication: bool,
}

impl App {
    /// Build app from paths + optional daemon status snapshot.
    #[must_use]
    pub fn new(paths: OwnMeshPaths, daemon: Option<DaemonStatus>) -> Self {
        let cfg = load_config(&paths).unwrap_or_default();
        let lang = Lang::parse(&cfg.lang);
        let pol = load_policy(&paths).unwrap_or_default();
        let policy_preset = preset_from_wire(pol.preset.as_deref().unwrap_or("recommended"));
        let active_instance = cfg.active_instance.as_ref().and_then(|id| {
            cfg.instances
                .iter()
                .find(|instance| &instance.id == id)
                .map(|instance| instance.base_url.clone())
        });
        let readiness = readiness_from_local(&paths, &cfg, daemon.as_ref());
        // Read-only local observations only: no network probes, no secret material.
        let doctor = run_doctor(&doctor_input_from_local(
            &paths,
            &cfg,
            &pol,
            daemon.as_ref(),
        ));

        Self {
            lang,
            theme: Theme::new(ColorMode::detect()),
            screen: Screen::Dashboard,
            overlay: Overlay::None,
            palette: PaletteState::default(),
            wizard: WizardState::from_existing(lang, policy_preset, active_instance.as_deref()),
            paths,
            daemon,
            approvals: Vec::new(),
            approval_cursor: 0,
            pending_approval: None,
            sessions: Vec::new(),
            activity: Vec::new(),
            doctor,
            readiness,
            policy_preset,
            overview_action_cursor: 0,
            status_line: String::new(),
            should_quit: false,
            list_cursor: 0,
            pending_setup: None,
            pending_reauthentication: false,
        }
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

    pub fn next_screen(&mut self) {
        let i = (self.screen.primary_index() + 1) % Screen::PRIMARY.len();
        self.screen = Screen::from_primary_index(i);
        self.list_cursor = 0;
    }

    pub fn prev_screen(&mut self) {
        let n = Screen::PRIMARY.len();
        let i = (self.screen.primary_index() + n - 1) % n;
        self.screen = Screen::from_primary_index(i);
        self.list_cursor = 0;
    }

    pub fn move_overview_action(&mut self, delta: isize) {
        let len = self.overview_actions().len() as isize;
        if len == 0 {
            self.overview_action_cursor = 0;
            return;
        }
        self.overview_action_cursor =
            (self.overview_action_cursor as isize + delta).rem_euclid(len) as usize;
    }

    #[must_use]
    pub fn overview_actions(&self) -> Vec<OverviewAction> {
        let mut actions = Vec::with_capacity(6);
        if self.readiness.needs_onboarding() {
            actions.push(OverviewAction::SetupRepair);
        } else if !self.readiness.agent_running || !self.readiness.service_installed {
            actions.push(OverviewAction::RepairAgent);
        } else {
            actions.push(OverviewAction::Connector);
        }
        if self.readiness.server_url.is_some() && !actions.contains(&OverviewAction::Connector) {
            actions.push(OverviewAction::Connector);
        }
        // Session metadata cannot prove that an OS-keychain item is still
        // readable. Keep an explicit recovery path visible whenever a recorded
        // login might otherwise make the setup wizard skip authentication.
        if self.readiness.server_url.is_some() && self.readiness.account_present {
            actions.push(OverviewAction::Reauthenticate);
        }
        actions.extend([
            OverviewAction::Devices,
            OverviewAction::Workspace,
            OverviewAction::Doctor,
        ]);
        actions
    }

    pub fn run_overview_action(&mut self) {
        match self
            .overview_actions()
            .get(self.overview_action_cursor)
            .copied()
            .unwrap_or(OverviewAction::SetupRepair)
        {
            OverviewAction::SetupRepair => self.open_setup_wizard(),
            OverviewAction::RepairAgent => {
                self.pending_setup = Some(SetupRequest {
                    control_plane_url: self.readiness.server_url.clone().unwrap_or_default(),
                    lang: self.lang,
                    preset: self.policy_preset,
                    configure: false,
                    update_policy: false,
                    login: false,
                    enroll: false,
                    install_agent: true,
                });
            }
            OverviewAction::Connector => self.overlay = Overlay::Connector,
            OverviewAction::Reauthenticate => self.pending_reauthentication = true,
            OverviewAction::Devices => self.screen = Screen::Devices,
            OverviewAction::Workspace => self.screen = Screen::Workspaces,
            OverviewAction::Doctor => self.screen = Screen::Diagnostics,
        }
    }

    pub fn open_setup_wizard(&mut self) {
        self.wizard = WizardState::from_existing(
            self.lang,
            self.policy_preset,
            self.readiness.server_url.as_deref(),
        );
        self.overlay = Overlay::Wizard;
    }

    pub fn queue_wizard_setup(&mut self) -> Result<(), String> {
        let request = self.wizard.build_request(
            self.readiness.server_url.as_deref(),
            SetupStatus {
                account_present: self.readiness.account_present,
                device_present: self.readiness.device_id.is_some(),
                agent_running: self.readiness.agent_running,
                service_installed: self.readiness.service_installed,
            },
        )?;
        self.pending_setup = Some(request);
        Ok(())
    }

    pub fn take_pending_setup(&mut self) -> Option<SetupRequest> {
        self.pending_setup.take()
    }

    pub fn take_pending_reauthentication(&mut self) -> bool {
        std::mem::take(&mut self.pending_reauthentication)
    }

    pub fn refresh_local_state(&mut self, daemon: Option<DaemonStatus>) {
        let refreshed = Self::new(self.paths.clone(), daemon);
        self.lang = refreshed.lang;
        self.daemon = refreshed.daemon;
        self.doctor = refreshed.doctor;
        self.readiness = refreshed.readiness;
        self.policy_preset = refreshed.policy_preset;
        self.wizard = refreshed.wizard;
        self.overview_action_cursor = self
            .overview_action_cursor
            .min(self.overview_actions().len().saturating_sub(1));
    }

    pub fn open_palette(&mut self) {
        self.palette.open();
    }

    /// Queue the selected pending item for the browser/passkey approval flow.
    pub fn queue_selected_approval(&mut self, decision: ApprovalDecision) {
        let Some(item) = self.approvals.get(self.approval_cursor) else {
            self.status_line = t(self.lang, Msg::ApprovalsEmpty).to_owned();
            return;
        };
        if item.state != "pending" {
            self.status_line = t(self.lang, Msg::ApprovalsAlreadyDecided).to_owned();
            return;
        }
        self.pending_approval = Some(PendingApproval {
            id: item.id.clone(),
            decision,
        });
        self.status_line = t(self.lang, Msg::ApprovalsBrowserFlow).to_owned();
    }

    pub fn take_pending_approval(&mut self) -> Option<PendingApproval> {
        self.pending_approval.take()
    }

    /// Handle a palette action.
    pub fn dispatch_palette(&mut self, action: PaletteAction) {
        match action {
            PaletteAction::Goto(screen) => {
                self.screen = screen;
                self.list_cursor = 0;
            }
            PaletteAction::OpenWizard => self.open_setup_wizard(),
            PaletteAction::OpenHelp => self.overlay = Overlay::Help,
            PaletteAction::Quit => self.should_quit = true,
            PaletteAction::ApproveSelected => {
                self.screen = Screen::Approvals;
                self.queue_selected_approval(ApprovalDecision::Approve);
            }
            PaletteAction::DenySelected => {
                self.screen = Screen::Approvals;
                self.queue_selected_approval(ApprovalDecision::Deny);
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
        vec![
            t(self.lang, Msg::TransfersLocalPlan).to_owned(),
            t(self.lang, Msg::TransfersLocalCopy).to_owned(),
            format!(
                "{} (relay_enabled={})",
                t(self.lang, Msg::TransfersRelayOff),
                false
            ),
            t(self.lang, Msg::TransfersRelayFailClosed).to_owned(),
            t(self.lang, Msg::TransfersNoLanPromise).to_owned(),
        ]
    }

    #[must_use]
    pub fn border_set(&self) -> ratatui::symbols::border::Set<'_> {
        ratatui::symbols::border::PLAIN
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

fn readiness_from_local(
    paths: &OwnMeshPaths,
    cfg: &ownmesh_config::OwnMeshConfig,
    daemon: Option<&DaemonStatus>,
) -> Readiness {
    let server_url = cfg.active_instance.as_ref().and_then(|id| {
        cfg.instances
            .iter()
            .find(|instance| &instance.id == id)
            .map(|instance| instance.base_url.trim().trim_end_matches('/').to_owned())
            .filter(|url| !url.is_empty())
    });
    let session = fs::read_to_string(paths.state_dir.join("auth_session.json"))
        .ok()
        .and_then(|raw| serde_json::from_str::<Value>(&raw).ok());
    let session_issuer = session
        .as_ref()
        .and_then(|value| value.get("issuer"))
        .and_then(Value::as_str)
        .map(str::trim)
        .map(|issuer| issuer.trim_end_matches('/'));
    let session_matches_server = match (server_url.as_deref(), session_issuer) {
        (Some(server), Some(issuer)) => server == issuer,
        _ => false,
    };
    let account_present = session_matches_server
        && session
            .as_ref()
            .and_then(|value| value.get("has_refresh_token"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
    let device_id = if session_matches_server {
        session
            .as_ref()
            .and_then(|value| value.get("device_id"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(ToOwned::to_owned)
    } else {
        None
    };
    let service_installed =
        fs::read_to_string(paths.state_dir.join("service").join("user-service.json"))
            .ok()
            .and_then(|raw| serde_json::from_str::<Value>(&raw).ok())
            .and_then(|value| value.get("installed").and_then(Value::as_bool))
            .unwrap_or(false);

    Readiness {
        server_url,
        account_present,
        device_id,
        service_installed,
        agent_running: daemon.is_some(),
    }
}

/// Build doctor input from local, already-loaded state.
///
/// Privacy contract: no network probes, no secret/token material, credentials
/// presence is left unknown (defaults) unless a non-secret session marker exists.
fn doctor_input_from_local(
    paths: &OwnMeshPaths,
    cfg: &ownmesh_config::OwnMeshConfig,
    pol: &ownmesh_config::PolicyFile,
    daemon: Option<&DaemonStatus>,
) -> DoctorInput {
    let config_path = paths.config_file();
    let config_present = config_path.exists();
    let config_readable = config_present && fs::read_to_string(&config_path).is_ok();

    let control_plane_url = cfg.active_instance.as_ref().and_then(|id| {
        cfg.instances
            .iter()
            .find(|i| &i.id == id)
            .map(|i| i.base_url.trim().trim_end_matches('/').to_string())
            .filter(|u| !u.is_empty())
    });

    let auth_session_present = paths.state_dir.join("auth_session.json").is_file();

    DoctorInput {
        binary: BinaryObservation {
            cli_version: env!("CARGO_PKG_VERSION").to_string(),
            cli_path: std::env::current_exe()
                .ok()
                .map(|p| p.display().to_string()),
            cli_on_path: false,
            daemon_path: None,
            daemon_on_path: false,
        },
        config: ConfigObservation {
            path: Some(config_path.display().to_string()),
            present: config_present,
            readable: config_readable,
            parse_ok: config_readable,
            validate_ok: config_readable && cfg.validate().is_ok(),
            permissions_ok: true,
            message: None,
        },
        // Presence flags only — never load keychain secrets from the TUI path.
        credentials: CredentialObservation {
            human_refresh_present: false,
            device_key_present: false,
            device_credential_present: false,
            auth_session_present,
            enrolled_device_id_present: false,
        },
        daemon: DaemonObservation {
            endpoint: None,
            reachable: daemon.is_some(),
            message: None,
        },
        // Network is opt-in; TUI never probes the control plane.
        control_plane: ControlPlaneObservation {
            configured: control_plane_url.is_some(),
            url: control_plane_url,
            probed: false,
            reachable: None,
            http_status: None,
            message: None,
        },
        privacy_policy: PrivacyPolicyObservation {
            policy_present: paths.policy_file().exists(),
            policy_preset: pol.preset.clone(),
            policy_valid: pol.validate().is_ok(),
            telemetry_project: cfg.telemetry.project,
            telemetry_crash_upload: cfg.telemetry.crash_upload,
            telemetry_usage_analytics: cfg.telemetry.usage_analytics,
            relay_enabled: false,
            update_mode: Some(cfg.update.mode.clone()),
            update_channel: Some(cfg.update.channel.clone()),
            update_network_off: cfg.update.mode == "off",
        },
        service: ServiceObservation::default(),
    }
}
