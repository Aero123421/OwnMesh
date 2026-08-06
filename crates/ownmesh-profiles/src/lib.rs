//! OwnMesh official and custom CLI profile definitions.
//!
//! Official 9 profiles plus generic unknown-CLI execution path.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use thiserror::Error;

/// Stable crate name used by diagnostics and tests.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Crate version string from Cargo package metadata.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Profile errors.
#[derive(Debug, Error)]
pub enum ProfileError {
    #[error("unknown profile: {0}")]
    Unknown(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
}

pub type ProfileResult<T> = Result<T, ProfileError>;

/// How OwnMesh prefers to connect to a CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfacePreference {
    StructuredRpc,
    Jsonl,
    Acp,
    Http,
    Pty,
}

/// Official profile identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OfficialProfileId {
    CodexCli,
    ClaudeCode,
    KimiCode,
    OpenCode,
    PiCodingAgent,
    AntigravityCli,
    QwenCode,
    HermesAgent,
    QoderCli,
}

impl OfficialProfileId {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CodexCli => "codex-cli",
            Self::ClaudeCode => "claude-code",
            Self::KimiCode => "kimi-code",
            Self::OpenCode => "opencode",
            Self::PiCodingAgent => "pi-coding-agent",
            Self::AntigravityCli => "antigravity-cli",
            Self::QwenCode => "qwen-code",
            Self::HermesAgent => "hermes-agent",
            Self::QoderCli => "qoder-cli",
        }
    }

    #[must_use]
    pub fn all() -> &'static [OfficialProfileId] {
        &OFFICIAL_ALL
    }
}

const OFFICIAL_ALL: [OfficialProfileId; 9] = [
    OfficialProfileId::CodexCli,
    OfficialProfileId::ClaudeCode,
    OfficialProfileId::KimiCode,
    OfficialProfileId::OpenCode,
    OfficialProfileId::PiCodingAgent,
    OfficialProfileId::AntigravityCli,
    OfficialProfileId::QwenCode,
    OfficialProfileId::HermesAgent,
    OfficialProfileId::QoderCli,
];

/// Profile definition.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Profile {
    pub id: String,
    pub display_name: String,
    pub binaries: Vec<String>,
    pub interface_order: Vec<InterfacePreference>,
    #[serde(default)]
    pub version_args: Vec<String>,
    #[serde(default)]
    pub auth_status_args: Vec<String>,
    #[serde(default)]
    pub supports_native_resume: bool,
    #[serde(default)]
    pub official: bool,
}

/// Detection / status result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileStatus {
    pub id: String,
    pub detected: bool,
    pub binary_path: Option<String>,
    pub version: Option<String>,
    pub preferred_interface: Option<InterfacePreference>,
    pub notes: Vec<String>,
}

/// Build the nine official profiles.
#[must_use]
pub fn official_profiles() -> Vec<Profile> {
    vec![
        profile(
            OfficialProfileId::CodexCli,
            "OpenAI Codex CLI",
            &["codex"],
            &[InterfacePreference::StructuredRpc, InterfacePreference::Pty],
            true,
        ),
        profile(
            OfficialProfileId::ClaudeCode,
            "Claude Code",
            &["claude"],
            &[InterfacePreference::Acp, InterfacePreference::Pty],
            true,
        ),
        profile(
            OfficialProfileId::KimiCode,
            "Kimi Code",
            &["kimi"],
            &[InterfacePreference::Jsonl, InterfacePreference::Pty],
            false,
        ),
        profile(
            OfficialProfileId::OpenCode,
            "OpenCode",
            &["opencode"],
            &[InterfacePreference::Jsonl, InterfacePreference::Pty],
            false,
        ),
        profile(
            OfficialProfileId::PiCodingAgent,
            "Pi Coding Agent",
            &["pi"],
            &[InterfacePreference::Jsonl, InterfacePreference::Pty],
            true,
        ),
        profile(
            OfficialProfileId::AntigravityCli,
            "Antigravity CLI",
            &["agy"],
            &[InterfacePreference::Jsonl, InterfacePreference::Pty],
            false,
        ),
        profile(
            OfficialProfileId::QwenCode,
            "Qwen Code",
            &["qwen"],
            &[InterfacePreference::Jsonl, InterfacePreference::Pty],
            false,
        ),
        profile(
            OfficialProfileId::HermesAgent,
            "Hermes Agent",
            &["hermes"],
            &[InterfacePreference::Jsonl, InterfacePreference::Pty],
            false,
        ),
        profile(
            OfficialProfileId::QoderCli,
            "Qoder CLI",
            &["qoder"],
            &[InterfacePreference::Jsonl, InterfacePreference::Pty],
            false,
        ),
    ]
}

fn profile(
    id: OfficialProfileId,
    name: &str,
    bins: &[&str],
    iface: &[InterfacePreference],
    resume: bool,
) -> Profile {
    Profile {
        id: id.as_str().into(),
        display_name: name.into(),
        binaries: bins.iter().map(|s| (*s).to_string()).collect(),
        interface_order: iface.to_vec(),
        version_args: vec!["--version".into()],
        auth_status_args: vec![],
        supports_native_resume: resume,
        official: true,
    }
}

/// Registry of official + custom profiles.
#[derive(Debug, Default, Clone)]
pub struct ProfileRegistry {
    profiles: BTreeMap<String, Profile>,
}

impl ProfileRegistry {
    #[must_use]
    pub fn with_official() -> Self {
        let mut r = Self::default();
        for p in official_profiles() {
            r.profiles.insert(p.id.clone(), p);
        }
        r
    }

    pub fn insert(&mut self, profile: Profile) {
        self.profiles.insert(profile.id.clone(), profile);
    }

    pub fn get(&self, id: &str) -> ProfileResult<&Profile> {
        self.profiles
            .get(id)
            .ok_or_else(|| ProfileError::Unknown(id.to_string()))
    }

    pub fn list(&self) -> Vec<&Profile> {
        self.profiles.values().collect()
    }

    /// Detect binary on PATH and pick preferred interface.
    pub fn detect(&self, id: &str) -> ProfileResult<ProfileStatus> {
        let p = self.get(id)?;
        let mut notes = Vec::new();
        let mut binary_path = None;
        for b in &p.binaries {
            match which::which(b) {
                Ok(path) => {
                    binary_path = Some(path.to_string_lossy().into_owned());
                    break;
                }
                Err(_) => notes.push(format!("binary not on PATH: {b}")),
            }
        }
        let detected = binary_path.is_some();
        let preferred_interface = p.interface_order.first().copied();
        let version = if let Some(bin) = &binary_path {
            probe_version(bin, &p.version_args)
        } else {
            None
        };
        Ok(ProfileStatus {
            id: p.id.clone(),
            detected,
            binary_path,
            version,
            preferred_interface,
            notes,
        })
    }

    pub fn detect_all(&self) -> Vec<ProfileStatus> {
        self.profiles
            .keys()
            .filter_map(|id| self.detect(id).ok())
            .collect()
    }
}

fn probe_version(bin: &str, args: &[String]) -> Option<String> {
    let out = std::process::Command::new(bin)
        .args(args)
        .output()
        .ok()?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&out.stderr).into_owned();
    }
    let line = text.lines().next()?.trim().to_string();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

/// Generic launch plan for unknown CLI (no profile required).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenericLaunch {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub use_pty: bool,
}

/// Build generic launch — always available without registration.
#[must_use]
pub fn generic_launch(program: impl Into<String>, args: Vec<String>, use_pty: bool) -> GenericLaunch {
    GenericLaunch {
        program: program.into(),
        args,
        cwd: None,
        use_pty,
    }
}

/// Load optional custom profile TOML.
pub fn load_custom_profile_toml(raw: &str) -> ProfileResult<Profile> {
    let mut p: Profile = toml::from_str(raw).map_err(|e| ProfileError::Parse(e.to_string()))?;
    p.official = false;
    if p.id.trim().is_empty() {
        return Err(ProfileError::Parse("id required".into()));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nine_official_profiles() {
        let regs = ProfileRegistry::with_official();
        assert_eq!(regs.list().len(), 9);
        for id in OfficialProfileId::all() {
            assert!(regs.get(id.as_str()).is_ok());
        }
    }

    #[test]
    fn generic_without_profile() {
        let g = generic_launch("my-cli", vec!["--help".into()], true);
        assert_eq!(g.program, "my-cli");
        assert!(g.use_pty);
    }

    #[test]
    fn detect_self_platform_tool() {
        let mut reg = ProfileRegistry::with_official();
        // inject a profile for a binary that exists on Windows/Linux
        #[cfg(windows)]
        let bin = "cmd.exe";
        #[cfg(not(windows))]
        let bin = "sh";
        reg.insert(Profile {
            id: "test-shell".into(),
            display_name: "Test".into(),
            binaries: vec![bin.into()],
            interface_order: vec![InterfacePreference::Pty],
            version_args: vec![],
            auth_status_args: vec![],
            supports_native_resume: false,
            official: false,
        });
        let st = reg.detect("test-shell").unwrap();
        assert!(st.detected);
        assert!(st.binary_path.is_some());
    }

    #[test]
    fn custom_toml() {
        let raw = r#"
id = "my-cli"
display_name = "My CLI"
binaries = ["mycli"]
interface_order = ["pty"]
"#;
        let p = load_custom_profile_toml(raw).unwrap();
        assert_eq!(p.id, "my-cli");
        assert!(!p.official);
    }
}
