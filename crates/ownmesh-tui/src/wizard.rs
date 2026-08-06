//! Setup wizard: language → access preset → save config/policy.

use crate::i18n::Lang;
use ownmesh_config::{
    load_config, load_policy, save_config, save_policy, OwnMeshPaths, PolicyFile,
};
use ownmesh_policy::{full_access_has_no_hidden_restrictive_rules, preset_document, AccessPreset};

/// Wizard step index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Welcome = 0,
    Language = 1,
    Preset = 2,
    Confirm = 3,
    Done = 4,
}

impl WizardStep {
    #[must_use]
    pub fn next(self) -> Self {
        match self {
            Self::Welcome => Self::Language,
            Self::Language => Self::Preset,
            Self::Preset => Self::Confirm,
            Self::Confirm | Self::Done => Self::Done,
        }
    }

    #[must_use]
    pub fn back(self) -> Self {
        match self {
            Self::Welcome | Self::Language => Self::Welcome,
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
    pub lang: Lang,
    pub lang_idx: usize,
    pub preset_idx: usize,
    pub saved: bool,
    pub error: Option<String>,
}

impl Default for WizardState {
    fn default() -> Self {
        Self {
            step: WizardStep::Welcome,
            lang: Lang::EnUs,
            lang_idx: 0,
            preset_idx: 1, // Recommended
            saved: false,
            error: None,
        }
    }
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
    pub fn selected_preset(&self) -> AccessPreset {
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
    }

    /// Persist language + policy preset under `paths`.
    ///
    /// # Errors
    ///
    /// Returns config IO / validation errors as strings.
    pub fn save(&mut self, paths: &OwnMeshPaths) -> Result<(), String> {
        apply_setup(paths, self.lang, self.selected_preset())?;
        self.saved = true;
        self.error = None;
        self.step = WizardStep::Done;
        Ok(())
    }
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
}
