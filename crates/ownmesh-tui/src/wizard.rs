//! Setup wizard state and the exact sibling-CLI request used to finish onboarding.

use crate::i18n::Lang;
use ownmesh_config::{
    load_config, load_policy, save_config, save_config_and_policy_transactional, save_policy,
    InstanceConfig, OwnMeshPaths, PolicyFile,
};
use ownmesh_policy::{full_access_has_no_hidden_restrictive_rules, preset_document, AccessPreset};

/// Wizard step index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Welcome = 0,
    Server = 1,
    Language = 2,
    Preset = 3,
    Confirm = 4,
    Done = 5,
}

impl WizardStep {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Welcome => Self::Server,
            Self::Server => Self::Language,
            Self::Language => Self::Preset,
            Self::Preset => Self::Confirm,
            Self::Confirm | Self::Done => Self::Done,
        }
    }

    #[must_use]
    pub fn back(self) -> Self {
        match self {
            Self::Welcome | Self::Server => Self::Welcome,
            Self::Language => Self::Server,
            Self::Preset => Self::Language,
            Self::Confirm => Self::Preset,
            Self::Done => Self::Confirm,
        }
    }
}

/// In-progress wizard selections.
#[derive(Debug, Clone)]
pub struct WizardState {
    pub step: WizardStep,
    pub control_plane_url: String,
    pub lang: Lang,
    pub original_lang: Lang,
    pub lang_idx: usize,
    pub preset_idx: usize,
    pub original_preset: AccessPreset,
    pub preset_changed: bool,
    pub saved: bool,
    pub error: Option<String>,
}

impl Default for WizardState {
    fn default() -> Self {
        Self {
            step: WizardStep::Welcome,
            control_plane_url: String::new(),
            lang: Lang::EnUs,
            original_lang: Lang::EnUs,
            lang_idx: 0,
            preset_idx: 1, // Recommended
            original_preset: AccessPreset::Recommended,
            preset_changed: false,
            saved: false,
            error: None,
        }
    }
}

/// One complete, exact setup/repair request handed to the sibling `ownmesh` CLI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupRequest {
    pub control_plane_url: String,
    pub lang: Lang,
    pub preset: AccessPreset,
    pub configure: bool,
    pub update_policy: bool,
    pub login: bool,
    pub enroll: bool,
    pub install_agent: bool,
}

/// Local state observed before deciding which setup steps are still needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetupStatus {
    pub account_present: bool,
    pub device_present: bool,
    pub agent_running: bool,
    pub service_installed: bool,
}

/// Built-in presets offered by the wizard (order matches UI).
pub const WIZARD_PRESETS: &[AccessPreset] = &[
    AccessPreset::WorkspaceOnly,
    AccessPreset::Recommended,
    AccessPreset::FullUserAccess,
    AccessPreset::FullAccess,
];

/// Wire names stored in `policy.toml`.
#[must_use]
pub fn preset_wire_name(preset: AccessPreset) -> &'static str {
    match preset {
        AccessPreset::WorkspaceOnly => "workspace_only",
        AccessPreset::Recommended => "recommended",
        AccessPreset::FullUserAccess => "full_user_access",
        AccessPreset::FullAccess => "full_access",
        AccessPreset::Custom => "custom",
    }
}

#[must_use]
pub fn preset_from_wire(name: &str) -> AccessPreset {
    match name.to_ascii_lowercase().replace('-', "_").as_str() {
        "workspace_only" => AccessPreset::WorkspaceOnly,
        "full_user_access" => AccessPreset::FullUserAccess,
        "full_access" => AccessPreset::FullAccess,
        "custom" => AccessPreset::Custom,
        _ => AccessPreset::Recommended,
    }
}

impl WizardState {
    #[must_use]
    pub fn from_existing(
        lang: Lang,
        preset: AccessPreset,
        control_plane_url: Option<&str>,
    ) -> Self {
        Self {
            control_plane_url: control_plane_url.unwrap_or_default().to_owned(),
            lang,
            original_lang: lang,
            lang_idx: Lang::ALL
                .iter()
                .position(|candidate| *candidate == lang)
                .unwrap_or(0),
            preset_idx: WIZARD_PRESETS
                .iter()
                .position(|candidate| *candidate == preset)
                .unwrap_or(1),
            original_preset: preset,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn selected_preset(&self) -> AccessPreset {
        if self.original_preset == AccessPreset::Custom && !self.preset_changed {
            return AccessPreset::Custom;
        }
        WIZARD_PRESETS
            .get(self.preset_idx)
            .copied()
            .unwrap_or(AccessPreset::Recommended)
    }

    pub fn cycle_lang(&mut self, delta: isize) {
        let n = Lang::ALL.len() as isize;
        let idx = (self.lang_idx as isize + delta).rem_euclid(n) as usize;
        self.lang_idx = idx;
        self.lang = Lang::ALL[idx];
    }

    pub fn cycle_preset(&mut self, delta: isize) {
        let n = WIZARD_PRESETS.len() as isize;
        self.preset_idx = (self.preset_idx as isize + delta).rem_euclid(n) as usize;
        self.preset_changed = true;
    }

    /// Validate and bind setup work to the currently observed local state.
    ///
    /// Changing the control plane deliberately forces a fresh login and device
    /// enrollment because both credentials are issuer-bound.
    pub fn build_request(
        &self,
        current_control_plane_url: Option<&str>,
        status: SetupStatus,
    ) -> Result<SetupRequest, String> {
        let control_plane_url =
            ownmesh_config::validate_control_plane_base_url(self.control_plane_url.trim())
                .map_err(|error| format!("control-plane URL: {error}"))?;
        let issuer_changed = current_control_plane_url
            .map(str::trim)
            .is_none_or(|current| current.trim_end_matches('/') != control_plane_url);
        let login = issuer_changed || !status.account_present;
        let enroll = login || !status.device_present;
        let update_policy = self.original_preset != self.selected_preset();
        let configure = issuer_changed || update_policy || self.original_lang != self.lang;

        Ok(SetupRequest {
            control_plane_url,
            lang: self.lang,
            preset: self.selected_preset(),
            configure,
            update_policy,
            login,
            enroll,
            install_agent: !status.agent_running || !status.service_installed,
        })
    }

    /// Persist language + policy preset under `paths`.
    ///
    /// # Errors
    ///
    /// Returns config IO / validation errors as strings.
    #[cfg(test)]
    pub fn save(&mut self, paths: &OwnMeshPaths) -> Result<(), String> {
        apply_setup(paths, self.lang, self.selected_preset())?;
        self.saved = true;
        self.error = None;
        self.step = WizardStep::Done;
        Ok(())
    }
}

/// Apply only the preferences selected in the TUI while preserving unrelated
/// instances, update settings, telemetry settings, service configuration, and
/// custom policy rules unless the user explicitly changes the preset.
pub fn apply_setup_request(paths: &OwnMeshPaths, request: &SetupRequest) -> Result<(), String> {
    if !request.configure {
        return Ok(());
    }
    if request.update_policy && request.preset == AccessPreset::Custom {
        return Err("choose a built-in preset before replacing a custom policy".into());
    }
    paths.ensure_layout().map_err(|error| error.to_string())?;
    let normalized = ownmesh_config::validate_control_plane_base_url(&request.control_plane_url)
        .map_err(|error| format!("control-plane URL: {error}"))?;
    let mut config = load_config(paths).map_err(|error| error.to_string())?;
    config.lang = request.lang.bcp47().to_owned();

    let matching_id = config
        .instances
        .iter()
        .find(|instance| instance.base_url.trim_end_matches('/') == normalized)
        .map(|instance| instance.id.clone());
    if let Some(id) = matching_id {
        config.active_instance = Some(id);
    } else if let Some(active) = config.active_instance.clone() {
        if let Some(instance) = config
            .instances
            .iter_mut()
            .find(|instance| instance.id == active)
        {
            instance.base_url.clone_from(&normalized);
        } else if let Some(instance) = config
            .instances
            .iter_mut()
            .find(|instance| instance.id == "default")
        {
            instance.base_url.clone_from(&normalized);
            config.active_instance = Some("default".into());
        } else {
            config.instances.push(InstanceConfig {
                id: "default".into(),
                base_url: normalized,
                display_name: None,
            });
            config.active_instance = Some("default".into());
        }
    } else if let Some(instance) = config
        .instances
        .iter_mut()
        .find(|instance| instance.id == "default")
    {
        instance.base_url = normalized;
        config.active_instance = Some("default".into());
    } else {
        config.instances.push(InstanceConfig {
            id: "default".into(),
            base_url: normalized,
            display_name: None,
        });
        config.active_instance = Some("default".into());
    }
    let mut policy = load_policy(paths).map_err(|error| error.to_string())?;
    if request.update_policy {
        policy.preset = Some(preset_wire_name(request.preset).into());
        policy.rules.clear();
    }
    config.validate().map_err(|error| error.to_string())?;
    policy.validate().map_err(|error| error.to_string())?;
    if request.preset == AccessPreset::FullAccess
        && !full_access_has_no_hidden_restrictive_rules(&preset_document(AccessPreset::FullAccess))
    {
        return Err("Full Access hidden deny detected — refusing to save".into());
    }
    save_config_and_policy_transactional(paths, &config, &policy)
        .map_err(|error| error.to_string())?;
    Ok(())
}

/// Apply setup choices: write `config.toml` lang and `policy.toml` preset.
///
/// Full Access is saved without introducing hidden deny rules (policy crate semantics unchanged).
///
/// # Errors
///
/// Propagates config load/save failures.
pub fn apply_setup(paths: &OwnMeshPaths, lang: Lang, preset: AccessPreset) -> Result<(), String> {
    paths.ensure_layout().map_err(|e| e.to_string())?;

    let mut cfg = load_config(paths).unwrap_or_default();
    cfg.lang = lang.bcp47().to_owned();
    cfg.validate().map_err(|e| e.to_string())?;
    save_config(paths, &cfg).map_err(|e| e.to_string())?;

    let policy = PolicyFile {
        schema_version: 1,
        preset: Some(preset_wire_name(preset).into()),
        delegate_remote_mcp: false,
        rules: Vec::new(),
    };
    policy.validate().map_err(|e| e.to_string())?;
    save_policy(paths, &policy).map_err(|e| e.to_string())?;

    // Conformance: Full Access must remain free of hidden restrictive rules.
    if preset == AccessPreset::FullAccess {
        let doc = preset_document(AccessPreset::FullAccess);
        if !full_access_has_no_hidden_restrictive_rules(&doc) {
            return Err("Full Access hidden deny detected — refusing to save".into());
        }
    }

    // Ensure round-trip load sees the preset.
    let loaded = load_policy(paths).map_err(|e| e.to_string())?;
    if loaded.preset.as_deref() != Some(preset_wire_name(preset)) {
        return Err(format!(
            "policy preset mismatch after save: {:?}",
            loaded.preset
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn wizard_saves_all_four_presets_to_config() {
        for preset in [
            AccessPreset::Recommended,
            AccessPreset::WorkspaceOnly,
            AccessPreset::FullUserAccess,
            AccessPreset::FullAccess,
        ] {
            let dir = tempdir().unwrap();
            let paths = OwnMeshPaths::for_base(dir.path());
            apply_setup(&paths, Lang::JaJp, preset).unwrap();

            let cfg = load_config(&paths).unwrap();
            assert_eq!(cfg.lang, "ja-JP");

            let pol = load_policy(&paths).unwrap();
            assert_eq!(pol.preset.as_deref(), Some(preset_wire_name(preset)));

            if preset == AccessPreset::FullAccess {
                let doc = preset_document(AccessPreset::FullAccess);
                assert!(
                    full_access_has_no_hidden_restrictive_rules(&doc),
                    "Full Access must not gain hidden deny"
                );
            }
        }
    }

    #[test]
    fn wizard_state_save_marks_done() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut wz = WizardState::default();
        wz.lang = Lang::RuRu;
        wz.lang_idx = 3;
        wz.preset_idx = 3; // Full Access
        wz.save(&paths).unwrap();
        assert!(wz.saved);
        assert_eq!(wz.step, WizardStep::Done);
        let pol = load_policy(&paths).unwrap();
        assert_eq!(pol.preset.as_deref(), Some("full_access"));
    }

    #[test]
    fn setup_request_reauthenticates_only_when_the_issuer_changes() {
        let mut wizard = WizardState::from_existing(
            Lang::JaJp,
            AccessPreset::FullUserAccess,
            Some("https://mesh.example.test"),
        );
        let repair = wizard
            .build_request(
                Some("https://mesh.example.test"),
                SetupStatus {
                    account_present: true,
                    device_present: true,
                    agent_running: false,
                    service_installed: false,
                },
            )
            .unwrap();
        assert!(!repair.login);
        assert!(!repair.enroll);
        assert!(repair.install_agent);

        wizard.control_plane_url = "https://other.example.test/".into();
        let moved = wizard
            .build_request(
                Some("https://mesh.example.test"),
                SetupStatus {
                    account_present: true,
                    device_present: true,
                    agent_running: true,
                    service_installed: true,
                },
            )
            .unwrap();
        assert!(moved.login);
        assert!(moved.enroll);
        assert!(!moved.install_agent);
        assert_eq!(moved.control_plane_url, "https://other.example.test");
    }

    #[test]
    fn returning_to_the_original_preset_does_not_replace_policy_rules() {
        let mut wizard = WizardState::from_existing(
            Lang::EnUs,
            AccessPreset::Recommended,
            Some("https://mesh.example.test"),
        );
        wizard.cycle_preset(1);
        wizard.cycle_preset(-1);
        let request = wizard
            .build_request(
                Some("https://mesh.example.test"),
                SetupStatus {
                    account_present: true,
                    device_present: true,
                    agent_running: true,
                    service_installed: true,
                },
            )
            .unwrap();
        assert_eq!(request.preset, AccessPreset::Recommended);
        assert!(!request.update_policy);
        assert!(!request.configure);
    }

    #[test]
    fn adding_a_server_does_not_replace_an_existing_policy() {
        let mut wizard = WizardState::from_existing(Lang::EnUs, AccessPreset::Recommended, None);
        wizard.control_plane_url = "https://mesh.example.test".into();
        let request = wizard
            .build_request(
                None,
                SetupStatus {
                    account_present: false,
                    device_present: false,
                    agent_running: false,
                    service_installed: false,
                },
            )
            .unwrap();
        assert!(request.configure);
        assert!(!request.update_policy);
        assert!(request.login);
        assert!(request.enroll);
    }

    #[test]
    fn authentication_repair_preserves_custom_configuration_and_policy() {
        use ownmesh_policy::{Decision, PolicyRule};

        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let mut config = load_config(&paths).unwrap();
        config.active_instance = Some("primary".into());
        config.instances = vec![
            InstanceConfig {
                id: "primary".into(),
                base_url: "https://mesh.example.test".into(),
                display_name: Some("Primary".into()),
            },
            InstanceConfig {
                id: "backup".into(),
                base_url: "https://backup.example.test".into(),
                display_name: None,
            },
        ];
        config.update.mode = "notify".into();
        config.update.channel = "beta".into();
        save_config(&paths, &config).unwrap();
        let policy = PolicyFile {
            schema_version: 1,
            preset: Some("custom".into()),
            delegate_remote_mcp: true,
            rules: vec![PolicyRule {
                id: "rule_keep_custom".into(),
                decision: Decision::Deny,
                priority: 10,
                capability: "command.*".into(),
                when_elevated: None,
                when_kind: None,
                path_prefix: None,
                program_equals: None,
                when_tag: None,
                description: None,
            }],
        };
        save_policy(&paths, &policy).unwrap();

        let wizard = WizardState::from_existing(
            Lang::EnUs,
            AccessPreset::Custom,
            Some("https://mesh.example.test"),
        );
        let request = wizard
            .build_request(
                Some("https://mesh.example.test"),
                SetupStatus {
                    account_present: false,
                    device_present: true,
                    agent_running: false,
                    service_installed: false,
                },
            )
            .unwrap();
        assert!(!request.configure);
        assert!(!request.update_policy);
        apply_setup_request(&paths, &request).unwrap();
        assert_eq!(load_config(&paths).unwrap(), config);
        assert_eq!(load_policy(&paths).unwrap(), policy);
    }
}
