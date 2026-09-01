//! OwnMesh TUI i18n: en-US / ja-JP / zh-Hans / ru-RU.

use std::collections::BTreeMap;

/// Supported UI languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lang {
    EnUs,
    JaJp,
    ZhHans,
    RuRu,
}

impl Lang {
    pub const ALL: [Lang; 4] = [Self::EnUs, Self::JaJp, Self::ZhHans, Self::RuRu];

    #[must_use]
    pub fn parse(s: &str) -> Self {
        let n = s.trim().to_ascii_lowercase().replace('_', "-");
        match n.as_str() {
            "ja" | "ja-jp" | "jp" => Self::JaJp,
            "zh" | "zh-cn" | "zh-hans" | "zh-sg" => Self::ZhHans,
            "ru" | "ru-ru" => Self::RuRu,
            _ => Self::EnUs,
        }
    }

    #[must_use]
    pub fn bcp47(self) -> &'static str {
        match self {
            Self::EnUs => "en-US",
            Self::JaJp => "ja-JP",
            Self::ZhHans => "zh-Hans",
            Self::RuRu => "ru-RU",
        }
    }
}

/// Message keys used across the TUI. Completeness is verified per locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Msg {
    AppTitle,
    // Nav
    NavDashboard,
    NavDevices,
    NavWorkspaces,
    NavSessions,
    NavApprovals,
    NavTransfers,
    NavActivity,
    NavDiagnostics,
    NavSettings,
    // Common chrome
    FooterHint,
    PaletteTitle,
    PaletteHint,
    HelpTitle,
    HelpBody,
    DaemonOnline,
    DaemonOffline,
    EmptyList,
    Confirm,
    Cancel,
    Back,
    Next,
    Finish,
    Selected,
    // Dashboard
    DashTitle,
    DashWelcome,
    DashStatus,
    DashQuickActions,
    // Devices
    DevicesTitle,
    DevicesLocal,
    DevicesHint,
    DevicesInventory,
    DevicesHintRefresh,
    DevicesEmpty,
    DevicesNotConfigured,
    DevicesAuthRequired,
    DevicesUnreachable,
    DevicesTruncated,
    // Workspaces
    WorkspacesTitle,
    WorkspacesRoot,
    WorkspacesHint,
    // Sessions
    SessionsTitle,
    SessionsEmpty,
    SessionsHint,
    // Approvals
    ApprovalsTitle,
    ApprovalsEmpty,
    ApprovalsPending,
    ApprovalsApprove,
    ApprovalsDeny,
    ApprovalsHint,
    ApprovalsScopeOnce,
    ApprovalsAlreadyDecided,
    ApprovalsBrowserFlow,
    ApprovalsApplied,
    ApprovalsFailed,
    ApprovalsTimedOut,
    // Transfers
    TransfersTitle,
    TransfersLocalPlan,
    TransfersLocalCopy,
    TransfersRelayOff,
    TransfersRelayFailClosed,
    TransfersNoLanPromise,
    TransfersHint,
    // Activity
    ActivityTitle,
    ActivityEmpty,
    ActivityHint,
    // Diagnostics
    DiagTitle,
    DiagDoctor,
    DiagHint,
    // Settings
    SettingsTitle,
    SettingsLang,
    SettingsPreset,
    SettingsColor,
    SettingsHint,
    // Wizard
    WizardTitle,
    WizardWelcome,
    WizardLangStep,
    WizardPresetStep,
    WizardConfirmStep,
    WizardDone,
    WizardPresetRecommended,
    WizardPresetWorkspaceOnly,
    WizardPresetFullUser,
    WizardPresetFullAccess,
    WizardPresetRecommendedDesc,
    WizardPresetWorkspaceOnlyDesc,
    WizardPresetFullUserDesc,
    WizardPresetFullAccessDesc,
    WizardSaveOk,
    WizardFullAccessNote,
    // Palette commands
    CmdGotoDashboard,
    CmdGotoDevices,
    CmdGotoWorkspaces,
    CmdGotoSessions,
    CmdGotoApprovals,
    CmdGotoTransfers,
    CmdGotoActivity,
    CmdGotoDiagnostics,
    CmdGotoSettings,
    CmdOpenWizard,
    CmdOpenHelp,
    CmdQuit,
    CmdApproveSelected,
    CmdDenySelected,
    // Misc
    LayoutNarrow,
    PressEnter,
    OfflineData,
}

impl Msg {
    /// Stable catalog of every key (order used by completeness checks).
    pub const ALL: &'static [Msg] = &[
        Self::AppTitle,
        Self::NavDashboard,
        Self::NavDevices,
        Self::NavWorkspaces,
        Self::NavSessions,
        Self::NavApprovals,
        Self::NavTransfers,
        Self::NavActivity,
        Self::NavDiagnostics,
        Self::NavSettings,
        Self::FooterHint,
        Self::PaletteTitle,
        Self::PaletteHint,
        Self::HelpTitle,
        Self::HelpBody,
        Self::DaemonOnline,
        Self::DaemonOffline,
        Self::EmptyList,
        Self::Confirm,
        Self::Cancel,
        Self::Back,
        Self::Next,
        Self::Finish,
        Self::Selected,
        Self::DashTitle,
        Self::DashWelcome,
        Self::DashStatus,
        Self::DashQuickActions,
        Self::DevicesTitle,
        Self::DevicesLocal,
        Self::DevicesHint,
        Self::DevicesInventory,
        Self::DevicesHintRefresh,
        Self::DevicesEmpty,
        Self::DevicesNotConfigured,
        Self::DevicesAuthRequired,
        Self::DevicesUnreachable,
        Self::DevicesTruncated,
        Self::WorkspacesTitle,
        Self::WorkspacesRoot,
        Self::WorkspacesHint,
        Self::SessionsTitle,
        Self::SessionsEmpty,
        Self::SessionsHint,
        Self::ApprovalsTitle,
        Self::ApprovalsEmpty,
        Self::ApprovalsPending,
        Self::ApprovalsApprove,
        Self::ApprovalsDeny,
        Self::ApprovalsHint,
        Self::ApprovalsScopeOnce,
        Self::ApprovalsAlreadyDecided,
        Self::ApprovalsBrowserFlow,
        Self::ApprovalsApplied,
        Self::ApprovalsFailed,
        Self::ApprovalsTimedOut,
        Self::TransfersTitle,
        Self::TransfersLocalPlan,
        Self::TransfersLocalCopy,
        Self::TransfersRelayOff,
        Self::TransfersRelayFailClosed,
        Self::TransfersNoLanPromise,
        Self::TransfersHint,
        Self::ActivityTitle,
        Self::ActivityEmpty,
        Self::ActivityHint,
        Self::DiagTitle,
        Self::DiagDoctor,
        Self::DiagHint,
        Self::SettingsTitle,
        Self::SettingsLang,
        Self::SettingsPreset,
        Self::SettingsColor,
        Self::SettingsHint,
        Self::WizardTitle,
        Self::WizardWelcome,
        Self::WizardLangStep,
        Self::WizardPresetStep,
        Self::WizardConfirmStep,
        Self::WizardDone,
        Self::WizardPresetRecommended,
        Self::WizardPresetWorkspaceOnly,
        Self::WizardPresetFullUser,
        Self::WizardPresetFullAccess,
        Self::WizardPresetRecommendedDesc,
        Self::WizardPresetWorkspaceOnlyDesc,
        Self::WizardPresetFullUserDesc,
        Self::WizardPresetFullAccessDesc,
        Self::WizardSaveOk,
        Self::WizardFullAccessNote,
        Self::CmdGotoDashboard,
        Self::CmdGotoDevices,
        Self::CmdGotoWorkspaces,
        Self::CmdGotoSessions,
        Self::CmdGotoApprovals,
        Self::CmdGotoTransfers,
        Self::CmdGotoActivity,
        Self::CmdGotoDiagnostics,
        Self::CmdGotoSettings,
        Self::CmdOpenWizard,
        Self::CmdOpenHelp,
        Self::CmdQuit,
        Self::CmdApproveSelected,
        Self::CmdDenySelected,
        Self::LayoutNarrow,
        Self::PressEnter,
        Self::OfflineData,
    ];

    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::AppTitle => "app.title",
            Self::NavDashboard => "nav.dashboard",
            Self::NavDevices => "nav.devices",
            Self::NavWorkspaces => "nav.workspaces",
            Self::NavSessions => "nav.sessions",
            Self::NavApprovals => "nav.approvals",
            Self::NavTransfers => "nav.transfers",
            Self::NavActivity => "nav.activity",
            Self::NavDiagnostics => "nav.diagnostics",
            Self::NavSettings => "nav.settings",
            Self::FooterHint => "chrome.footer",
            Self::PaletteTitle => "palette.title",
            Self::PaletteHint => "palette.hint",
            Self::HelpTitle => "help.title",
            Self::HelpBody => "help.body",
            Self::DaemonOnline => "daemon.online",
            Self::DaemonOffline => "daemon.offline",
            Self::EmptyList => "common.empty",
            Self::Confirm => "common.confirm",
            Self::Cancel => "common.cancel",
            Self::Back => "common.back",
            Self::Next => "common.next",
            Self::Finish => "common.finish",
            Self::Selected => "common.selected",
            Self::DashTitle => "dash.title",
            Self::DashWelcome => "dash.welcome",
            Self::DashStatus => "dash.status",
            Self::DashQuickActions => "dash.quick",
            Self::DevicesTitle => "devices.title",
            Self::DevicesLocal => "devices.local",
            Self::DevicesHint => "devices.hint",
            Self::DevicesInventory => "devices.inventory",
            Self::DevicesHintRefresh => "devices.hint_refresh",
            Self::DevicesEmpty => "devices.empty",
            Self::DevicesNotConfigured => "devices.not_configured",
            Self::DevicesAuthRequired => "devices.auth_required",
            Self::DevicesUnreachable => "devices.unreachable",
            Self::DevicesTruncated => "devices.truncated",
            Self::WorkspacesTitle => "workspaces.title",
            Self::WorkspacesRoot => "workspaces.root",
            Self::WorkspacesHint => "workspaces.hint",
            Self::SessionsTitle => "sessions.title",
            Self::SessionsEmpty => "sessions.empty",
            Self::SessionsHint => "sessions.hint",
            Self::ApprovalsTitle => "approvals.title",
            Self::ApprovalsEmpty => "approvals.empty",
            Self::ApprovalsPending => "approvals.pending",
            Self::ApprovalsApprove => "approvals.approve",
            Self::ApprovalsDeny => "approvals.deny",
            Self::ApprovalsHint => "approvals.hint",
            Self::ApprovalsScopeOnce => "approvals.scope_once",
            Self::ApprovalsAlreadyDecided => "approvals.already_decided",
            Self::ApprovalsBrowserFlow => "approvals.browser_flow",
            Self::ApprovalsApplied => "approvals.applied",
            Self::ApprovalsFailed => "approvals.failed",
            Self::ApprovalsTimedOut => "approvals.timed_out",
            Self::TransfersTitle => "transfers.title",
            Self::TransfersLocalPlan => "transfers.local_plan",
            Self::TransfersLocalCopy => "transfers.local_copy",
            Self::TransfersRelayOff => "transfers.relay_off",
            Self::TransfersRelayFailClosed => "transfers.relay_fail_closed",
            Self::TransfersNoLanPromise => "transfers.no_lan_promise",
            Self::TransfersHint => "transfers.hint",
            Self::ActivityTitle => "activity.title",
            Self::ActivityEmpty => "activity.empty",
            Self::ActivityHint => "activity.hint",
            Self::DiagTitle => "diag.title",
            Self::DiagDoctor => "diag.doctor",
            Self::DiagHint => "diag.hint",
            Self::SettingsTitle => "settings.title",
            Self::SettingsLang => "settings.lang",
            Self::SettingsPreset => "settings.preset",
            Self::SettingsColor => "settings.color",
            Self::SettingsHint => "settings.hint",
            Self::WizardTitle => "wizard.title",
            Self::WizardWelcome => "wizard.welcome",
            Self::WizardLangStep => "wizard.lang_step",
            Self::WizardPresetStep => "wizard.preset_step",
            Self::WizardConfirmStep => "wizard.confirm_step",
            Self::WizardDone => "wizard.done",
            Self::WizardPresetRecommended => "wizard.preset.recommended",
            Self::WizardPresetWorkspaceOnly => "wizard.preset.workspace_only",
            Self::WizardPresetFullUser => "wizard.preset.full_user",
            Self::WizardPresetFullAccess => "wizard.preset.full_access",
            Self::WizardPresetRecommendedDesc => "wizard.preset.recommended.desc",
            Self::WizardPresetWorkspaceOnlyDesc => "wizard.preset.workspace_only.desc",
            Self::WizardPresetFullUserDesc => "wizard.preset.full_user.desc",
            Self::WizardPresetFullAccessDesc => "wizard.preset.full_access.desc",
            Self::WizardSaveOk => "wizard.save_ok",
            Self::WizardFullAccessNote => "wizard.full_access_note",
            Self::CmdGotoDashboard => "cmd.goto.dashboard",
            Self::CmdGotoDevices => "cmd.goto.devices",
            Self::CmdGotoWorkspaces => "cmd.goto.workspaces",
            Self::CmdGotoSessions => "cmd.goto.sessions",
            Self::CmdGotoApprovals => "cmd.goto.approvals",
            Self::CmdGotoTransfers => "cmd.goto.transfers",
            Self::CmdGotoActivity => "cmd.goto.activity",
            Self::CmdGotoDiagnostics => "cmd.goto.diagnostics",
            Self::CmdGotoSettings => "cmd.goto.settings",
            Self::CmdOpenWizard => "cmd.open.wizard",
            Self::CmdOpenHelp => "cmd.open.help",
            Self::CmdQuit => "cmd.quit",
            Self::CmdApproveSelected => "cmd.approve",
            Self::CmdDenySelected => "cmd.deny",
            Self::LayoutNarrow => "layout.narrow",
            Self::PressEnter => "common.press_enter",
            Self::OfflineData => "common.offline_data",
        }
    }
}

/// Translate a message key.
#[must_use]
pub fn t(lang: Lang, msg: Msg) -> &'static str {
    catalog(lang).get(&msg).copied().unwrap_or("[missing]")
}

/// Full catalog for a language.
#[must_use]
pub fn catalog(lang: Lang) -> BTreeMap<Msg, &'static str> {
    match lang {
        Lang::EnUs => en_us(),
        Lang::JaJp => ja_jp(),
        Lang::ZhHans => zh_hans(),
        Lang::RuRu => ru_ru(),
    }
}

/// Missing keys for `lang` (empty string or absent).
#[must_use]
#[allow(dead_code)]
pub fn missing_keys(lang: Lang) -> Vec<&'static str> {
    let cat = catalog(lang);
    Msg::ALL
        .iter()
        .filter_map(|m| match cat.get(m) {
            Some(s) if !s.trim().is_empty() && *s != "[missing]" => None,
            _ => Some(m.key()),
        })
        .collect()
}

/// Completeness report across all locales. Empty vec = OK.
#[must_use]
pub fn completeness_report() -> Vec<String> {
    let mut issues = Vec::new();
    let en_len = Msg::ALL.len();
    for lang in Lang::ALL {
        let cat = catalog(lang);
        if cat.len() != en_len {
            issues.push(format!(
                "{}: map size {} != expected {}",
                lang.bcp47(),
                cat.len(),
                en_len
            ));
        }
        for m in Msg::ALL {
            match cat.get(m) {
                Some(s) if !s.trim().is_empty() => {}
                Some(_) => issues.push(format!("{}: empty {}", lang.bcp47(), m.key())),
                None => issues.push(format!("{}: missing {}", lang.bcp47(), m.key())),
            }
        }
    }
    issues
}

fn insert(map: &mut BTreeMap<Msg, &'static str>, msg: Msg, value: &'static str) {
    map.insert(msg, value);
}

fn en_us() -> BTreeMap<Msg, &'static str> {
    let mut m = BTreeMap::new();
    insert(&mut m, Msg::AppTitle, "OwnMesh");
    insert(&mut m, Msg::NavDashboard, "Overview");
    insert(&mut m, Msg::NavDevices, "Devices");
    insert(&mut m, Msg::NavWorkspaces, "Workspaces");
    insert(&mut m, Msg::NavSessions, "Sessions");
    insert(&mut m, Msg::NavApprovals, "Approvals");
    insert(&mut m, Msg::NavTransfers, "Transfers");
    insert(&mut m, Msg::NavActivity, "Activity");
    insert(&mut m, Msg::NavDiagnostics, "Diagnostics");
    insert(&mut m, Msg::NavSettings, "Settings");
    insert(
        &mut m,
        Msg::FooterHint,
        "q quit · Ctrl+K palette · F1 help · Tab nav · ←/→ screens",
    );
    insert(&mut m, Msg::PaletteTitle, "Command palette");
    insert(
        &mut m,
        Msg::PaletteHint,
        "Type to filter · Enter run · Esc close",
    );
    insert(&mut m, Msg::HelpTitle, "Help");
    insert(
        &mut m,
        Msg::HelpBody,
        "Navigate with Tab/arrows. Ctrl+K opens commands. Setup wizard: Ctrl+K → Wizard. Approvals: a approve, d deny. q quits normally; Ctrl+C exits from any screen or overlay.",
    );
    insert(&mut m, Msg::DaemonOnline, "Daemon online");
    insert(&mut m, Msg::DaemonOffline, "Daemon offline");
    insert(&mut m, Msg::EmptyList, "(empty)");
    insert(&mut m, Msg::Confirm, "Confirm");
    insert(&mut m, Msg::Cancel, "Cancel");
    insert(&mut m, Msg::Back, "Back");
    insert(&mut m, Msg::Next, "Next");
    insert(&mut m, Msg::Finish, "Finish");
    insert(&mut m, Msg::Selected, "selected");
    insert(&mut m, Msg::DashTitle, "Dashboard");
    insert(
        &mut m,
        Msg::DashWelcome,
        "Welcome to OwnMesh. Review status, approvals, and policy from one place.",
    );
    insert(&mut m, Msg::DashStatus, "Status");
    insert(
        &mut m,
        Msg::DashQuickActions,
        "Quick: Ctrl+K · Wizard · Approvals · Settings",
    );
    insert(&mut m, Msg::DevicesTitle, "Devices");
    insert(&mut m, Msg::DevicesLocal, "This device (local daemon)");
    insert(
        &mut m,
        Msg::DevicesHint,
        "Press r to refresh the authenticated Control Plane device list. This screen never polls in the background.",
    );
    insert(&mut m, Msg::DevicesInventory, "Control Plane devices");
    insert(
        &mut m,
        Msg::DevicesHintRefresh,
        "r refresh devices (explicit network request)",
    );
    insert(
        &mut m,
        Msg::DevicesEmpty,
        "No enrolled devices were returned.",
    );
    insert(
        &mut m,
        Msg::DevicesNotConfigured,
        "Control Plane is not configured.",
    );
    insert(
        &mut m,
        Msg::DevicesAuthRequired,
        "Authentication required. Reauthenticate to list devices.",
    );
    insert(
        &mut m,
        Msg::DevicesUnreachable,
        "Control Plane is unreachable.",
    );
    insert(
        &mut m,
        Msg::DevicesTruncated,
        "Showing the first 64 devices.",
    );
    insert(&mut m, Msg::WorkspacesTitle, "Workspaces");
    insert(&mut m, Msg::WorkspacesRoot, "Daemon workspace root");
    insert(
        &mut m,
        Msg::WorkspacesHint,
        "workspace_root_enforcement is independent of access_preset. This screen shows the local workspace root; remote MCP waits for activation_state=active on list/show.",
    );
    insert(&mut m, Msg::SessionsTitle, "Sessions");
    insert(&mut m, Msg::SessionsEmpty, "No interactive sessions yet.");
    insert(
        &mut m,
        Msg::SessionsHint,
        "Open sessions via CLI (`ownmesh session`) or session-host. Claim/release stays on-device.",
    );
    insert(&mut m, Msg::ApprovalsTitle, "Approvals");
    insert(&mut m, Msg::ApprovalsEmpty, "No pending approvals.");
    insert(&mut m, Msg::ApprovalsPending, "Pending");
    insert(&mut m, Msg::ApprovalsApprove, "Approve");
    insert(&mut m, Msg::ApprovalsDeny, "Deny");
    insert(
        &mut m,
        Msg::ApprovalsHint,
        "a approve · d deny · r refresh · Enter details",
    );
    insert(&mut m, Msg::ApprovalsScopeOnce, "one-time");
    insert(
        &mut m,
        Msg::ApprovalsAlreadyDecided,
        "The selected request is no longer pending.",
    );
    insert(
        &mut m,
        Msg::ApprovalsBrowserFlow,
        "Complete the browser passkey check; waiting for the signed decision…",
    );
    insert(&mut m, Msg::ApprovalsApplied, "Approval decision applied.");
    insert(
        &mut m,
        Msg::ApprovalsFailed,
        "Approval was not applied; retry or use `ownmesh approval`.",
    );
    insert(
        &mut m,
        Msg::ApprovalsTimedOut,
        "Approval timed out; the request remains fail-closed.",
    );
    insert(&mut m, Msg::TransfersTitle, "Transfers");
    insert(
        &mut m,
        Msg::TransfersLocalPlan,
        "Local plan: same-machine path planning with size limit and SHA-256.",
    );
    insert(
        &mut m,
        Msg::TransfersLocalCopy,
        "Local copy: hash-verified file copy (LocalLoopback transport only).",
    );
    insert(
        &mut m,
        Msg::TransfersRelayOff,
        "Cloud relay default: OFF (never selected implicitly).",
    );
    insert(
        &mut m,
        Msg::TransfersRelayFailClosed,
        "No direct path + relay off → explicit failure (fail-closed).",
    );
    insert(
        &mut m,
        Msg::TransfersNoLanPromise,
        "LAN discovery / direct encrypted P2P is not shipped in this release.",
    );
    insert(
        &mut m,
        Msg::TransfersHint,
        "Facts only — UI mirrors ownmesh-transfer capabilities.",
    );
    insert(&mut m, Msg::ActivityTitle, "Activity / Audit");
    insert(&mut m, Msg::ActivityEmpty, "No local activity loaded.");
    insert(
        &mut m,
        Msg::ActivityHint,
        "Audit events stay on-device. Export only via explicit support bundle.",
    );
    insert(&mut m, Msg::DiagTitle, "Diagnostics");
    insert(&mut m, Msg::DiagDoctor, "Doctor checks");
    insert(
        &mut m,
        Msg::DiagHint,
        "Run `ownmesh doctor` for CLI details. Bundles are redacted before export.",
    );
    insert(&mut m, Msg::SettingsTitle, "Settings");
    insert(&mut m, Msg::SettingsLang, "Language");
    insert(&mut m, Msg::SettingsPreset, "Policy preset");
    insert(&mut m, Msg::SettingsColor, "Color mode");
    insert(
        &mut m,
        Msg::SettingsHint,
        "l cycle language · p cycle preset · Enter apply · w wizard",
    );
    insert(&mut m, Msg::WizardTitle, "Setup wizard");
    insert(
        &mut m,
        Msg::WizardWelcome,
        "Configure language and access preset. Policy is saved to policy.toml.",
    );
    insert(&mut m, Msg::WizardLangStep, "Step 1 — Language");
    insert(&mut m, Msg::WizardPresetStep, "Step 2 — Access preset");
    insert(&mut m, Msg::WizardConfirmStep, "Step 3 — Confirm & save");
    insert(&mut m, Msg::WizardDone, "Setup complete");
    insert(&mut m, Msg::WizardPresetRecommended, "Recommended");
    insert(&mut m, Msg::WizardPresetWorkspaceOnly, "Workspace Only");
    insert(&mut m, Msg::WizardPresetFullUser, "Full User Access");
    insert(&mut m, Msg::WizardPresetFullAccess, "Full Access");
    insert(
        &mut m,
        Msg::WizardPresetRecommendedDesc,
        "Balanced: ask on write/exec, allow reads.",
    );
    insert(
        &mut m,
        Msg::WizardPresetWorkspaceOnlyDesc,
        "Confine ops to workspace; deny elevated/raw shell.",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullUserDesc,
        "User-level allow; elevated operations still ask.",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullAccessDesc,
        "All allow. No hidden deny rules (conformance-tested).",
    );
    insert(
        &mut m,
        Msg::WizardSaveOk,
        "Saved language and policy preset.",
    );
    insert(
        &mut m,
        Msg::WizardFullAccessNote,
        "Full Access has zero deny/ask rules — nothing is silently blocked.",
    );
    insert(&mut m, Msg::CmdGotoDashboard, "Go to Dashboard");
    insert(&mut m, Msg::CmdGotoDevices, "Go to Devices");
    insert(&mut m, Msg::CmdGotoWorkspaces, "Go to Workspaces");
    insert(&mut m, Msg::CmdGotoSessions, "Go to Sessions");
    insert(&mut m, Msg::CmdGotoApprovals, "Go to Approvals");
    insert(&mut m, Msg::CmdGotoTransfers, "Go to Transfers");
    insert(&mut m, Msg::CmdGotoActivity, "Go to Activity");
    insert(&mut m, Msg::CmdGotoDiagnostics, "Go to Diagnostics");
    insert(&mut m, Msg::CmdGotoSettings, "Go to Settings");
    insert(&mut m, Msg::CmdOpenWizard, "Open setup wizard");
    insert(&mut m, Msg::CmdOpenHelp, "Open help");
    insert(&mut m, Msg::CmdQuit, "Quit");
    insert(&mut m, Msg::CmdApproveSelected, "Approve selected");
    insert(&mut m, Msg::CmdDenySelected, "Deny selected");
    insert(
        &mut m,
        Msg::LayoutNarrow,
        "Terminal is smaller than 80x24 — layout compressed.",
    );
    insert(&mut m, Msg::PressEnter, "Press Enter");
    insert(&mut m, Msg::OfflineData, "Showing local/offline data");
    debug_assert_eq!(m.len(), Msg::ALL.len());
    m
}

fn ja_jp() -> BTreeMap<Msg, &'static str> {
    let mut m = BTreeMap::new();
    insert(&mut m, Msg::AppTitle, "OwnMesh");
    insert(&mut m, Msg::NavDashboard, "概要");
    insert(&mut m, Msg::NavDevices, "デバイス");
    insert(&mut m, Msg::NavWorkspaces, "ワークスペース");
    insert(&mut m, Msg::NavSessions, "セッション");
    insert(&mut m, Msg::NavApprovals, "承認");
    insert(&mut m, Msg::NavTransfers, "転送");
    insert(&mut m, Msg::NavActivity, "アクティビティ");
    insert(&mut m, Msg::NavDiagnostics, "診断");
    insert(&mut m, Msg::NavSettings, "設定");
    insert(
        &mut m,
        Msg::FooterHint,
        "q 終了 · Ctrl+K パレット · F1 ヘルプ · Tab 移動 · ←/→ 画面",
    );
    insert(&mut m, Msg::PaletteTitle, "コマンドパレット");
    insert(
        &mut m,
        Msg::PaletteHint,
        "入力で絞り込み · Enter 実行 · Esc 閉じる",
    );
    insert(&mut m, Msg::HelpTitle, "ヘルプ");
    insert(
        &mut m,
        Msg::HelpBody,
        "Tab/矢印で移動。Ctrl+K でコマンド。セットアップ: Ctrl+K → ウィザード。承認: a 許可、d 拒否。通常終了は q。Ctrl+C はどの画面・オーバーレイからでも緊急終了します。",
    );
    insert(&mut m, Msg::DaemonOnline, "デーモン接続中");
    insert(&mut m, Msg::DaemonOffline, "デーモン未接続");
    insert(&mut m, Msg::EmptyList, "（空）");
    insert(&mut m, Msg::Confirm, "確認");
    insert(&mut m, Msg::Cancel, "キャンセル");
    insert(&mut m, Msg::Back, "戻る");
    insert(&mut m, Msg::Next, "次へ");
    insert(&mut m, Msg::Finish, "完了");
    insert(&mut m, Msg::Selected, "選択中");
    insert(&mut m, Msg::DashTitle, "ダッシュボード");
    insert(
        &mut m,
        Msg::DashWelcome,
        "OwnMesh へようこそ。状態・承認・ポリシーを一箇所で確認できます。",
    );
    insert(&mut m, Msg::DashStatus, "状態");
    insert(
        &mut m,
        Msg::DashQuickActions,
        "ショートカット: Ctrl+K · ウィザード · 承認 · 設定",
    );
    insert(&mut m, Msg::DevicesTitle, "デバイス");
    insert(
        &mut m,
        Msg::DevicesLocal,
        "このデバイス（ローカルデーモン）",
    );
    insert(
        &mut m,
        Msg::DevicesHint,
        "r で認証済みコントロールプレーンのデバイス一覧を更新します。この画面はバックグラウンドで問い合わせません。",
    );
    insert(
        &mut m,
        Msg::DevicesInventory,
        "コントロールプレーンのデバイス",
    );
    insert(
        &mut m,
        Msg::DevicesHintRefresh,
        "r デバイス更新（明示的なネットワーク要求）",
    );
    insert(
        &mut m,
        Msg::DevicesEmpty,
        "登録デバイスは返りませんでした。",
    );
    insert(
        &mut m,
        Msg::DevicesNotConfigured,
        "コントロールプレーンが未設定です。",
    );
    insert(
        &mut m,
        Msg::DevicesAuthRequired,
        "認証が必要です。再認証してデバイスを一覧します。",
    );
    insert(
        &mut m,
        Msg::DevicesUnreachable,
        "コントロールプレーンに到達できません。",
    );
    insert(
        &mut m,
        Msg::DevicesTruncated,
        "先頭64台までを表示しています。",
    );
    insert(&mut m, Msg::WorkspacesTitle, "ワークスペース");
    insert(&mut m, Msg::WorkspacesRoot, "デーモンのワークスペース根");
    insert(
        &mut m,
        Msg::WorkspacesHint,
        "workspace_root_enforcement は access_preset と独立です。この画面はローカルのワークスペース root です。リモート MCP は list/show の activation_state が active になるまで使えません。",
    );
    insert(&mut m, Msg::SessionsTitle, "セッション");
    insert(
        &mut m,
        Msg::SessionsEmpty,
        "対話セッションはまだありません。",
    );
    insert(
        &mut m,
        Msg::SessionsHint,
        "CLI または session-host で開始。claim/release は端末内で完結します。",
    );
    insert(&mut m, Msg::ApprovalsTitle, "承認キュー");
    insert(&mut m, Msg::ApprovalsEmpty, "保留中の承認はありません。");
    insert(&mut m, Msg::ApprovalsPending, "保留");
    insert(&mut m, Msg::ApprovalsApprove, "許可");
    insert(&mut m, Msg::ApprovalsDeny, "拒否");
    insert(
        &mut m,
        Msg::ApprovalsHint,
        "a 許可 · d 拒否 · r 更新 · Enter 詳細",
    );
    insert(&mut m, Msg::ApprovalsScopeOnce, "一回限り");
    insert(
        &mut m,
        Msg::ApprovalsAlreadyDecided,
        "選択したリクエストはすでに保留中ではありません。",
    );
    insert(
        &mut m,
        Msg::ApprovalsBrowserFlow,
        "ブラウザでパスキー確認を完了してください。署名済みの判定を待っています…",
    );
    insert(&mut m, Msg::ApprovalsApplied, "承認の判定を適用しました。");
    insert(
        &mut m,
        Msg::ApprovalsFailed,
        "承認を適用できませんでした。再試行するか `ownmesh approval` を使ってください。",
    );
    insert(
        &mut m,
        Msg::ApprovalsTimedOut,
        "承認がタイムアウトしました。リクエストは安全側（未承認）のままです。",
    );
    insert(&mut m, Msg::TransfersTitle, "転送");
    insert(
        &mut m,
        Msg::TransfersLocalPlan,
        "ローカル計画: 同一マシンのパス計画（サイズ上限と SHA-256）。",
    );
    insert(
        &mut m,
        Msg::TransfersLocalCopy,
        "ローカルコピー: ハッシュ検証付きコピー（LocalLoopback のみ）。",
    );
    insert(
        &mut m,
        Msg::TransfersRelayOff,
        "クラウド中継の既定: OFF（暗黙選択なし）。",
    );
    insert(
        &mut m,
        Msg::TransfersRelayFailClosed,
        "直接経路なし + 中継 OFF → 明示的失敗（フェイルクローズ）。",
    );
    insert(
        &mut m,
        Msg::TransfersNoLanPromise,
        "LAN 探索 / 直接暗号 P2P 転送はこのリリースに含まれません。",
    );
    insert(
        &mut m,
        Msg::TransfersHint,
        "事実のみ — ownmesh-transfer の実装範囲を表示。",
    );
    insert(&mut m, Msg::ActivityTitle, "アクティビティ / 監査");
    insert(&mut m, Msg::ActivityEmpty, "ローカルの活動は未読込です。");
    insert(
        &mut m,
        Msg::ActivityHint,
        "監査は端末内に留まります。エクスポートはサポートバンドル経由のみ。",
    );
    insert(&mut m, Msg::DiagTitle, "診断");
    insert(&mut m, Msg::DiagDoctor, "Doctor チェック");
    insert(
        &mut m,
        Msg::DiagHint,
        "詳細は `ownmesh doctor`。バンドルは書き出し前にマスクされます。",
    );
    insert(&mut m, Msg::SettingsTitle, "設定");
    insert(&mut m, Msg::SettingsLang, "言語");
    insert(&mut m, Msg::SettingsPreset, "ポリシープリセット");
    insert(&mut m, Msg::SettingsColor, "カラーモード");
    insert(
        &mut m,
        Msg::SettingsHint,
        "l 言語切替 · p プリセット切替 · Enter 適用 · w ウィザード",
    );
    insert(&mut m, Msg::WizardTitle, "セットアップウィザード");
    insert(
        &mut m,
        Msg::WizardWelcome,
        "言語とアクセスプリセットを設定します。ポリシーは policy.toml に保存されます。",
    );
    insert(&mut m, Msg::WizardLangStep, "手順 1 — 言語");
    insert(&mut m, Msg::WizardPresetStep, "手順 2 — アクセスプリセット");
    insert(&mut m, Msg::WizardConfirmStep, "手順 3 — 確認と保存");
    insert(&mut m, Msg::WizardDone, "セットアップ完了");
    insert(&mut m, Msg::WizardPresetRecommended, "推奨");
    insert(&mut m, Msg::WizardPresetWorkspaceOnly, "ワークスペースのみ");
    insert(&mut m, Msg::WizardPresetFullUser, "フルユーザー");
    insert(&mut m, Msg::WizardPresetFullAccess, "フルアクセス");
    insert(
        &mut m,
        Msg::WizardPresetRecommendedDesc,
        "バランス型: 書き込み/実行は確認、読み取りは許可。",
    );
    insert(
        &mut m,
        Msg::WizardPresetWorkspaceOnlyDesc,
        "操作をワークスペースに限定。昇格/生シェルは拒否。",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullUserDesc,
        "ユーザー権限は許可。昇格操作のみ確認。",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullAccessDesc,
        "すべて許可。隠れた deny なし（適合テスト済み）。",
    );
    insert(
        &mut m,
        Msg::WizardSaveOk,
        "言語とポリシープリセットを保存しました。",
    );
    insert(
        &mut m,
        Msg::WizardFullAccessNote,
        "フルアクセスは deny/ask ルールがゼロです。暗黙のブロックはありません。",
    );
    insert(&mut m, Msg::CmdGotoDashboard, "ダッシュボードへ");
    insert(&mut m, Msg::CmdGotoDevices, "デバイスへ");
    insert(&mut m, Msg::CmdGotoWorkspaces, "ワークスペースへ");
    insert(&mut m, Msg::CmdGotoSessions, "セッションへ");
    insert(&mut m, Msg::CmdGotoApprovals, "承認へ");
    insert(&mut m, Msg::CmdGotoTransfers, "転送へ");
    insert(&mut m, Msg::CmdGotoActivity, "アクティビティへ");
    insert(&mut m, Msg::CmdGotoDiagnostics, "診断へ");
    insert(&mut m, Msg::CmdGotoSettings, "設定へ");
    insert(&mut m, Msg::CmdOpenWizard, "セットアップウィザードを開く");
    insert(&mut m, Msg::CmdOpenHelp, "ヘルプを開く");
    insert(&mut m, Msg::CmdQuit, "終了");
    insert(&mut m, Msg::CmdApproveSelected, "選択を許可");
    insert(&mut m, Msg::CmdDenySelected, "選択を拒否");
    insert(
        &mut m,
        Msg::LayoutNarrow,
        "端末が 80x24 未満です — レイアウトを圧縮します。",
    );
    insert(&mut m, Msg::PressEnter, "Enter を押す");
    insert(&mut m, Msg::OfflineData, "ローカル/オフラインデータを表示");
    debug_assert_eq!(m.len(), Msg::ALL.len());
    m
}

fn zh_hans() -> BTreeMap<Msg, &'static str> {
    let mut m = BTreeMap::new();
    insert(&mut m, Msg::AppTitle, "OwnMesh");
    insert(&mut m, Msg::NavDashboard, "概览");
    insert(&mut m, Msg::NavDevices, "设备");
    insert(&mut m, Msg::NavWorkspaces, "工作区");
    insert(&mut m, Msg::NavSessions, "会话");
    insert(&mut m, Msg::NavApprovals, "审批");
    insert(&mut m, Msg::NavTransfers, "传输");
    insert(&mut m, Msg::NavActivity, "活动");
    insert(&mut m, Msg::NavDiagnostics, "诊断");
    insert(&mut m, Msg::NavSettings, "设置");
    insert(
        &mut m,
        Msg::FooterHint,
        "q 退出 · Ctrl+K 命令板 · F1 帮助 · Tab 导航 · ←/→ 页面",
    );
    insert(&mut m, Msg::PaletteTitle, "命令面板");
    insert(&mut m, Msg::PaletteHint, "输入过滤 · Enter 执行 · Esc 关闭");
    insert(&mut m, Msg::HelpTitle, "帮助");
    insert(
        &mut m,
        Msg::HelpBody,
        "用 Tab/方向键导航。Ctrl+K 打开命令。向导: Ctrl+K → 向导。审批: a 批准，d 拒绝。正常退出按 q；Ctrl+C 可从任何界面或浮层紧急退出。",
    );
    insert(&mut m, Msg::DaemonOnline, "守护进程在线");
    insert(&mut m, Msg::DaemonOffline, "守护进程离线");
    insert(&mut m, Msg::EmptyList, "（空）");
    insert(&mut m, Msg::Confirm, "确认");
    insert(&mut m, Msg::Cancel, "取消");
    insert(&mut m, Msg::Back, "返回");
    insert(&mut m, Msg::Next, "下一步");
    insert(&mut m, Msg::Finish, "完成");
    insert(&mut m, Msg::Selected, "已选");
    insert(&mut m, Msg::DashTitle, "仪表盘");
    insert(
        &mut m,
        Msg::DashWelcome,
        "欢迎使用 OwnMesh。在此查看状态、审批与策略。",
    );
    insert(&mut m, Msg::DashStatus, "状态");
    insert(
        &mut m,
        Msg::DashQuickActions,
        "快捷: Ctrl+K · 向导 · 审批 · 设置",
    );
    insert(&mut m, Msg::DevicesTitle, "设备");
    insert(&mut m, Msg::DevicesLocal, "本机（本地守护进程）");
    insert(
        &mut m,
        Msg::DevicesHint,
        "按 r 刷新已认证控制平面的设备列表。此屏幕不会在后台轮询。",
    );
    insert(&mut m, Msg::DevicesInventory, "控制平面设备");
    insert(
        &mut m,
        Msg::DevicesHintRefresh,
        "r 刷新设备（显式网络请求）",
    );
    insert(&mut m, Msg::DevicesEmpty, "未返回已注册设备。");
    insert(&mut m, Msg::DevicesNotConfigured, "尚未配置控制平面。");
    insert(
        &mut m,
        Msg::DevicesAuthRequired,
        "需要认证。请重新认证后再列出设备。",
    );
    insert(&mut m, Msg::DevicesUnreachable, "无法连接控制平面。");
    insert(&mut m, Msg::DevicesTruncated, "仅显示前 64 台设备。");
    insert(&mut m, Msg::WorkspacesTitle, "工作区");
    insert(&mut m, Msg::WorkspacesRoot, "守护进程工作区根目录");
    insert(
        &mut m,
        Msg::WorkspacesHint,
        "workspace_root_enforcement 独立于 access_preset。此屏幕显示本地工作区根路径；远程 MCP 需等到 list/show 的 activation_state 为 active。",
    );
    insert(&mut m, Msg::SessionsTitle, "会话");
    insert(&mut m, Msg::SessionsEmpty, "尚无交互会话。");
    insert(
        &mut m,
        Msg::SessionsHint,
        "通过 CLI 或 session-host 打开会话。claim/release 仅在本机。",
    );
    insert(&mut m, Msg::ApprovalsTitle, "审批队列");
    insert(&mut m, Msg::ApprovalsEmpty, "没有待处理审批。");
    insert(&mut m, Msg::ApprovalsPending, "待处理");
    insert(&mut m, Msg::ApprovalsApprove, "批准");
    insert(&mut m, Msg::ApprovalsDeny, "拒绝");
    insert(
        &mut m,
        Msg::ApprovalsHint,
        "a 批准 · d 拒绝 · r 刷新 · Enter 详情",
    );
    insert(&mut m, Msg::ApprovalsScopeOnce, "一次性");
    insert(
        &mut m,
        Msg::ApprovalsAlreadyDecided,
        "所选请求已不再处于待处理状态。",
    );
    insert(
        &mut m,
        Msg::ApprovalsBrowserFlow,
        "请在浏览器中完成通行密钥验证；正在等待签名决定…",
    );
    insert(&mut m, Msg::ApprovalsApplied, "已应用审批决定。");
    insert(
        &mut m,
        Msg::ApprovalsFailed,
        "未能应用审批；请重试或使用 `ownmesh approval`。",
    );
    insert(
        &mut m,
        Msg::ApprovalsTimedOut,
        "审批超时；请求保持安全拒绝状态。",
    );
    insert(&mut m, Msg::TransfersTitle, "传输");
    insert(
        &mut m,
        Msg::TransfersLocalPlan,
        "本地计划: 同机路径规划（大小限制与 SHA-256）。",
    );
    insert(
        &mut m,
        Msg::TransfersLocalCopy,
        "本地复制: 带哈希校验的复制（仅 LocalLoopback）。",
    );
    insert(
        &mut m,
        Msg::TransfersRelayOff,
        "云中继默认: 关闭（绝不会隐式选用）。",
    );
    insert(
        &mut m,
        Msg::TransfersRelayFailClosed,
        "无直连且中继关闭 → 明确失败（故障关闭）。",
    );
    insert(
        &mut m,
        Msg::TransfersNoLanPromise,
        "本版本不包含 LAN 发现 / 直接加密 P2P 传输。",
    );
    insert(
        &mut m,
        Msg::TransfersHint,
        "仅展示事实 — 与 ownmesh-transfer 能力一致。",
    );
    insert(&mut m, Msg::ActivityTitle, "活动 / 审计");
    insert(&mut m, Msg::ActivityEmpty, "尚未加载本地活动。");
    insert(
        &mut m,
        Msg::ActivityHint,
        "审计事件保留在本机。仅可通过支持包显式导出。",
    );
    insert(&mut m, Msg::DiagTitle, "诊断");
    insert(&mut m, Msg::DiagDoctor, "Doctor 检查");
    insert(
        &mut m,
        Msg::DiagHint,
        "CLI 详情见 `ownmesh doctor`。导出前会脱敏。",
    );
    insert(&mut m, Msg::SettingsTitle, "设置");
    insert(&mut m, Msg::SettingsLang, "语言");
    insert(&mut m, Msg::SettingsPreset, "策略预设");
    insert(&mut m, Msg::SettingsColor, "颜色模式");
    insert(
        &mut m,
        Msg::SettingsHint,
        "l 切换语言 · p 切换预设 · Enter 应用 · w 向导",
    );
    insert(&mut m, Msg::WizardTitle, "设置向导");
    insert(
        &mut m,
        Msg::WizardWelcome,
        "配置语言与访问预设。策略保存到 policy.toml。",
    );
    insert(&mut m, Msg::WizardLangStep, "步骤 1 — 语言");
    insert(&mut m, Msg::WizardPresetStep, "步骤 2 — 访问预设");
    insert(&mut m, Msg::WizardConfirmStep, "步骤 3 — 确认并保存");
    insert(&mut m, Msg::WizardDone, "设置完成");
    insert(&mut m, Msg::WizardPresetRecommended, "推荐");
    insert(&mut m, Msg::WizardPresetWorkspaceOnly, "仅工作区");
    insert(&mut m, Msg::WizardPresetFullUser, "完整用户访问");
    insert(&mut m, Msg::WizardPresetFullAccess, "完全访问");
    insert(
        &mut m,
        Msg::WizardPresetRecommendedDesc,
        "均衡: 写入/执行需确认，读取允许。",
    );
    insert(
        &mut m,
        Msg::WizardPresetWorkspaceOnlyDesc,
        "操作限于工作区；拒绝提权/原始 shell。",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullUserDesc,
        "用户级允许；提权操作仍需确认。",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullAccessDesc,
        "全部允许。无隐藏 deny（符合性测试）。",
    );
    insert(&mut m, Msg::WizardSaveOk, "已保存语言与策略预设。");
    insert(
        &mut m,
        Msg::WizardFullAccessNote,
        "完全访问没有任何 deny/ask 规则 — 不会被静默拦截。",
    );
    insert(&mut m, Msg::CmdGotoDashboard, "转到仪表盘");
    insert(&mut m, Msg::CmdGotoDevices, "转到设备");
    insert(&mut m, Msg::CmdGotoWorkspaces, "转到工作区");
    insert(&mut m, Msg::CmdGotoSessions, "转到会话");
    insert(&mut m, Msg::CmdGotoApprovals, "转到审批");
    insert(&mut m, Msg::CmdGotoTransfers, "转到传输");
    insert(&mut m, Msg::CmdGotoActivity, "转到活动");
    insert(&mut m, Msg::CmdGotoDiagnostics, "转到诊断");
    insert(&mut m, Msg::CmdGotoSettings, "转到设置");
    insert(&mut m, Msg::CmdOpenWizard, "打开设置向导");
    insert(&mut m, Msg::CmdOpenHelp, "打开帮助");
    insert(&mut m, Msg::CmdQuit, "退出");
    insert(&mut m, Msg::CmdApproveSelected, "批准所选");
    insert(&mut m, Msg::CmdDenySelected, "拒绝所选");
    insert(&mut m, Msg::LayoutNarrow, "终端小于 80x24 — 使用压缩布局。");
    insert(&mut m, Msg::PressEnter, "按 Enter");
    insert(&mut m, Msg::OfflineData, "显示本地/离线数据");
    debug_assert_eq!(m.len(), Msg::ALL.len());
    m
}

fn ru_ru() -> BTreeMap<Msg, &'static str> {
    let mut m = BTreeMap::new();
    insert(&mut m, Msg::AppTitle, "OwnMesh");
    insert(&mut m, Msg::NavDashboard, "Обзор");
    insert(&mut m, Msg::NavDevices, "Устройства");
    insert(&mut m, Msg::NavWorkspaces, "Рабочие области");
    insert(&mut m, Msg::NavSessions, "Сессии");
    insert(&mut m, Msg::NavApprovals, "Одобрения");
    insert(&mut m, Msg::NavTransfers, "Передачи");
    insert(&mut m, Msg::NavActivity, "Активность");
    insert(&mut m, Msg::NavDiagnostics, "Диагностика");
    insert(&mut m, Msg::NavSettings, "Настройки");
    insert(
        &mut m,
        Msg::FooterHint,
        "q выход · Ctrl+K палитра · F1 справка · Tab навигация · ←/→ экраны",
    );
    insert(&mut m, Msg::PaletteTitle, "Палитра команд");
    insert(
        &mut m,
        Msg::PaletteHint,
        "Ввод — фильтр · Enter — выполнить · Esc — закрыть",
    );
    insert(&mut m, Msg::HelpTitle, "Справка");
    insert(
        &mut m,
        Msg::HelpBody,
        "Навигация Tab/стрелки. Ctrl+K — команды. Мастер: Ctrl+K → Wizard. Одобрения: a принять, d отклонить. Обычный выход — q; Ctrl+C завершает работу с любого экрана или панели.",
    );
    insert(&mut m, Msg::DaemonOnline, "Демон в сети");
    insert(&mut m, Msg::DaemonOffline, "Демон не в сети");
    insert(&mut m, Msg::EmptyList, "(пусто)");
    insert(&mut m, Msg::Confirm, "Подтвердить");
    insert(&mut m, Msg::Cancel, "Отмена");
    insert(&mut m, Msg::Back, "Назад");
    insert(&mut m, Msg::Next, "Далее");
    insert(&mut m, Msg::Finish, "Готово");
    insert(&mut m, Msg::Selected, "выбрано");
    insert(&mut m, Msg::DashTitle, "Панель управления");
    insert(
        &mut m,
        Msg::DashWelcome,
        "Добро пожаловать в OwnMesh. Статус, одобрения и политика — в одном месте.",
    );
    insert(&mut m, Msg::DashStatus, "Статус");
    insert(
        &mut m,
        Msg::DashQuickActions,
        "Быстро: Ctrl+K · Мастер · Одобрения · Настройки",
    );
    insert(&mut m, Msg::DevicesTitle, "Устройства");
    insert(
        &mut m,
        Msg::DevicesLocal,
        "Это устройство (локальный демон)",
    );
    insert(
        &mut m,
        Msg::DevicesHint,
        "Нажмите r, чтобы обновить список устройств Control Plane. Экран не опрашивает сеть в фоне.",
    );
    insert(&mut m, Msg::DevicesInventory, "Устройства Control Plane");
    insert(
        &mut m,
        Msg::DevicesHintRefresh,
        "r обновить устройства (явный сетевой запрос)",
    );
    insert(
        &mut m,
        Msg::DevicesEmpty,
        "Зарегистрированные устройства не возвращены.",
    );
    insert(
        &mut m,
        Msg::DevicesNotConfigured,
        "Control Plane не настроен.",
    );
    insert(
        &mut m,
        Msg::DevicesAuthRequired,
        "Требуется аутентификация. Повторно войдите, чтобы увидеть устройства.",
    );
    insert(&mut m, Msg::DevicesUnreachable, "Control Plane недоступен.");
    insert(
        &mut m,
        Msg::DevicesTruncated,
        "Показаны первые 64 устройства.",
    );
    insert(&mut m, Msg::WorkspacesTitle, "Рабочие области");
    insert(&mut m, Msg::WorkspacesRoot, "Корень рабочей области демона");
    insert(
        &mut m,
        Msg::WorkspacesHint,
        "workspace_root_enforcement не зависит от access_preset. Этот экран показывает локальный корень рабочей области; удалённый MCP ждёт activation_state=active в list/show.",
    );
    insert(&mut m, Msg::SessionsTitle, "Сессии");
    insert(&mut m, Msg::SessionsEmpty, "Интерактивных сессий пока нет.");
    insert(
        &mut m,
        Msg::SessionsHint,
        "Открывайте сессии через CLI или session-host. Claim/release остаётся на устройстве.",
    );
    insert(&mut m, Msg::ApprovalsTitle, "Очередь одобрений");
    insert(&mut m, Msg::ApprovalsEmpty, "Нет ожидающих одобрений.");
    insert(&mut m, Msg::ApprovalsPending, "Ожидает");
    insert(&mut m, Msg::ApprovalsApprove, "Одобрить");
    insert(&mut m, Msg::ApprovalsDeny, "Отклонить");
    insert(
        &mut m,
        Msg::ApprovalsHint,
        "a одобрить · d отклонить · r обновить · Enter подробности",
    );
    insert(&mut m, Msg::ApprovalsScopeOnce, "однократно");
    insert(
        &mut m,
        Msg::ApprovalsAlreadyDecided,
        "Выбранный запрос больше не ожидает решения.",
    );
    insert(
        &mut m,
        Msg::ApprovalsBrowserFlow,
        "Пройдите проверку passkey в браузере; ожидаем подписанное решение…",
    );
    insert(
        &mut m,
        Msg::ApprovalsApplied,
        "Решение по одобрению применено.",
    );
    insert(
        &mut m,
        Msg::ApprovalsFailed,
        "Одобрение не применено; повторите или используйте `ownmesh approval`.",
    );
    insert(
        &mut m,
        Msg::ApprovalsTimedOut,
        "Время ожидания истекло; запрос остаётся безопасно закрыт.",
    );
    insert(&mut m, Msg::TransfersTitle, "Передачи файлов");
    insert(
        &mut m,
        Msg::TransfersLocalPlan,
        "Локальный план: планирование пути на этой машине (лимит размера и SHA-256).",
    );
    insert(
        &mut m,
        Msg::TransfersLocalCopy,
        "Локальное копирование: проверка хеша (только LocalLoopback).",
    );
    insert(
        &mut m,
        Msg::TransfersRelayOff,
        "Облачный ретранслятор по умолчанию: ВЫКЛ (никогда не выбирается скрыто).",
    );
    insert(
        &mut m,
        Msg::TransfersRelayFailClosed,
        "Нет прямого пути + ретранслятор выкл → явный отказ (fail-closed).",
    );
    insert(
        &mut m,
        Msg::TransfersNoLanPromise,
        "LAN-обнаружение и прямая шифрованная P2P-передача в этом выпуске не поставляются.",
    );
    insert(
        &mut m,
        Msg::TransfersHint,
        "Только факты — UI отражает возможности ownmesh-transfer.",
    );
    insert(&mut m, Msg::ActivityTitle, "Активность / Аудит");
    insert(
        &mut m,
        Msg::ActivityEmpty,
        "Локальная активность не загружена.",
    );
    insert(
        &mut m,
        Msg::ActivityHint,
        "События аудита остаются на устройстве. Экспорт только через support bundle.",
    );
    insert(&mut m, Msg::DiagTitle, "Диагностика");
    insert(&mut m, Msg::DiagDoctor, "Проверки Doctor");
    insert(
        &mut m,
        Msg::DiagHint,
        "Подробности: `ownmesh doctor`. Пакеты редактируются перед экспортом.",
    );
    insert(&mut m, Msg::SettingsTitle, "Настройки");
    insert(&mut m, Msg::SettingsLang, "Язык");
    insert(&mut m, Msg::SettingsPreset, "Пресет политики");
    insert(&mut m, Msg::SettingsColor, "Цветовой режим");
    insert(
        &mut m,
        Msg::SettingsHint,
        "l язык · p пресет · Enter применить · w мастер",
    );
    insert(&mut m, Msg::WizardTitle, "Мастер настройки");
    insert(
        &mut m,
        Msg::WizardWelcome,
        "Настройте язык и пресет доступа. Политика сохраняется в policy.toml.",
    );
    insert(&mut m, Msg::WizardLangStep, "Шаг 1 — Язык");
    insert(&mut m, Msg::WizardPresetStep, "Шаг 2 — Пресет доступа");
    insert(
        &mut m,
        Msg::WizardConfirmStep,
        "Шаг 3 — Подтверждение и сохранение",
    );
    insert(&mut m, Msg::WizardDone, "Настройка завершена");
    insert(&mut m, Msg::WizardPresetRecommended, "Рекомендуемый");
    insert(
        &mut m,
        Msg::WizardPresetWorkspaceOnly,
        "Только рабочая область",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullUser,
        "Полный пользовательский доступ",
    );
    insert(&mut m, Msg::WizardPresetFullAccess, "Полный доступ");
    insert(
        &mut m,
        Msg::WizardPresetRecommendedDesc,
        "Баланс: спрашивать при записи/запуске, чтение разрешено.",
    );
    insert(
        &mut m,
        Msg::WizardPresetWorkspaceOnlyDesc,
        "Операции только в рабочей области; elevated/raw shell запрещены.",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullUserDesc,
        "Пользовательский уровень разрешён; elevated всё ещё спрашивает.",
    );
    insert(
        &mut m,
        Msg::WizardPresetFullAccessDesc,
        "Всё разрешено. Нет скрытых deny (проверено conformance-тестами).",
    );
    insert(
        &mut m,
        Msg::WizardSaveOk,
        "Язык и пресет политики сохранены.",
    );
    insert(
        &mut m,
        Msg::WizardFullAccessNote,
        "Полный доступ: ноль правил deny/ask — ничего не блокируется скрыто.",
    );
    insert(&mut m, Msg::CmdGotoDashboard, "Перейти на панель");
    insert(&mut m, Msg::CmdGotoDevices, "Перейти к устройствам");
    insert(&mut m, Msg::CmdGotoWorkspaces, "Перейти к рабочим областям");
    insert(&mut m, Msg::CmdGotoSessions, "Перейти к сессиям");
    insert(&mut m, Msg::CmdGotoApprovals, "Перейти к одобрениям");
    insert(&mut m, Msg::CmdGotoTransfers, "Перейти к передачам");
    insert(&mut m, Msg::CmdGotoActivity, "Перейти к активности");
    insert(&mut m, Msg::CmdGotoDiagnostics, "Перейти к диагностике");
    insert(&mut m, Msg::CmdGotoSettings, "Перейти к настройкам");
    insert(&mut m, Msg::CmdOpenWizard, "Открыть мастер настройки");
    insert(&mut m, Msg::CmdOpenHelp, "Открыть справку");
    insert(&mut m, Msg::CmdQuit, "Выход");
    insert(&mut m, Msg::CmdApproveSelected, "Одобрить выбранное");
    insert(&mut m, Msg::CmdDenySelected, "Отклонить выбранное");
    insert(
        &mut m,
        Msg::LayoutNarrow,
        "Терминал меньше 80x24 — сжатый макет.",
    );
    insert(&mut m, Msg::PressEnter, "Нажмите Enter");
    insert(&mut m, Msg::OfflineData, "Показаны локальные/офлайн-данные");
    debug_assert_eq!(m.len(), Msg::ALL.len());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translation_completeness_all_locales() {
        let issues = completeness_report();
        assert!(
            issues.is_empty(),
            "translation gaps:\n{}",
            issues.join("\n")
        );
    }

    #[test]
    fn lang_parse_aliases() {
        assert_eq!(Lang::parse("ja-JP"), Lang::JaJp);
        assert_eq!(Lang::parse("zh-Hans"), Lang::ZhHans);
        assert_eq!(Lang::parse("ru_RU"), Lang::RuRu);
        assert_eq!(Lang::parse("en"), Lang::EnUs);
    }

    #[test]
    fn transfers_copy_does_not_promise_lan() {
        for lang in Lang::ALL {
            let s = t(lang, Msg::TransfersNoLanPromise).to_ascii_lowercase();
            // Must state unavailability, not advertise LAN as ready.
            assert!(
                !s.contains("coming soon") && !s.contains("скоро") && !s.contains("即将"),
                "must not tease future LAN: {s}"
            );
            let plan = t(lang, Msg::TransfersLocalPlan);
            assert!(!plan.is_empty());
        }
    }
}
