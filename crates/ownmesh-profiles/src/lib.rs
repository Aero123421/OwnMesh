//! `OwnMesh` official and custom CLI profile definitions.
//!
//! Official 9 profiles (`OWNMESH_SPECIFICATION.ja.md` §13) plus generic
//! unknown-CLI execution path. Fixture-based conformance tests live in
//! `tests` module and `fixtures/`.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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
    #[error("unsupported version: {0}")]
    UnsupportedVersion(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("parse: {0}")]
    Parse(String),
}

pub type ProfileResult<T> = Result<T, ProfileError>;

/// How `OwnMesh` prefers to connect to a CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfacePreference {
    /// Official Agent Client Protocol
    Acp,
    /// App Server / JSON-RPC (e.g. codex app-server)
    StructuredRpc,
    /// JSON / JSONL / stream-json non-interactive
    Jsonl,
    /// Headless HTTP API
    Http,
    /// PTY fallback (always last resort)
    Pty,
}

impl InterfacePreference {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Acp => "acp",
            Self::StructuredRpc => "structured_rpc",
            Self::Jsonl => "jsonl",
            Self::Http => "http",
            Self::Pty => "pty",
        }
    }
}

/// The child-process transport selected by an official adapter.
///
/// These values are deliberately narrower than a general network transport.
/// An adapter never creates an inbound listener; `LocalHttp` means that the
/// vendor's documented child server is contacted only by the local host.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterTransport {
    StdioJsonl,
    StdioJsonRpc,
    LocalHttp,
    Pty,
}

/// Vendor dialect carried over an [`AdapterTransport`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterDialect {
    CodexAppServer,
    ClaudeStreamJson,
    KimiAcp,
    OpenCodeServer,
    PiRpc,
    AgyStreamJson,
    QwenAcp,
    HermesAcp,
    QoderAcp,
}

impl AdapterDialect {
    /// Stable manifest binding string; never derive this from debug output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CodexAppServer => "codex_app_server",
            Self::ClaudeStreamJson => "claude_stream_json",
            Self::KimiAcp => "kimi_acp",
            Self::OpenCodeServer => "opencode_server",
            Self::PiRpc => "pi_rpc",
            Self::AgyStreamJson => "agy_stream_json",
            Self::QwenAcp => "qwen_acp",
            Self::HermesAcp => "hermes_acp",
            Self::QoderAcp => "qoder_acp",
        }
    }
}

/// Native-session continuation surface exposed by an adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum NativeResume {
    /// A native argv resume operation. `{{native_id}}` is a single argv item.
    Argv { args: Vec<String> },
    /// The native protocol negotiates load/resume support at runtime.
    Negotiated { method: String },
    /// The vendor documents no safe native resume operation for this adapter.
    Degraded,
}

/// Read-only profile authentication probe declaration.
///
/// An absent probe is intentional: OwnMesh reports `unknown` rather than
/// reading credential files or guessing a vendor CLI command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthProbe {
    pub args: Vec<String>,
    /// Successful process exit codes. Output is capped and redacted by the
    /// executor; it is never included in an audit record.
    pub success_exit_codes: Vec<i32>,
}

/// Explicit, source-backed contract for one official CLI adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterSpec {
    pub profile_id: String,
    pub transport: AdapterTransport,
    pub dialect: AdapterDialect,
    /// Start argv, excluding the executable.  Prompt/session placeholders are
    /// expanded only as one complete argument.
    pub start_args: Vec<String>,
    pub resume: NativeResume,
    pub auth_probe: Option<AuthProbe>,
    /// Structured mode permits event normalization and avoids a PTY.
    pub structured_events: bool,
    /// Profile safe capabilities; this is not a permission escalation surface.
    pub safe_capabilities: Vec<String>,
}

/// Return the nine explicit official adapter specifications.
///
/// The source links and the date on which each entry was verified are kept in
/// `docs/E6_ADAPTER_CONTRACTS.md`.  If that document does not establish a
/// resume surface, this function returns [`NativeResume::Degraded`] instead of
/// inventing one.
#[must_use]
pub fn official_adapter_specs() -> Vec<AdapterSpec> {
    use AdapterDialect::{
        AgyStreamJson, ClaudeStreamJson, CodexAppServer, HermesAcp, KimiAcp, OpenCodeServer, PiRpc,
        QoderAcp, QwenAcp,
    };
    use AdapterTransport::{StdioJsonRpc, StdioJsonl};

    vec![
        AdapterSpec {
            profile_id: "codex".into(),
            transport: StdioJsonRpc,
            dialect: CodexAppServer,
            start_args: vec!["app-server".into()],
            resume: NativeResume::Negotiated {
                method: "thread/resume".into(),
            },
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["thread_start".into(), "thread_resume".into()],
        },
        AdapterSpec {
            profile_id: "claude-code".into(),
            transport: StdioJsonl,
            dialect: ClaudeStreamJson,
            start_args: vec![
                "-p".into(),
                "{{prompt}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            resume: NativeResume::Argv {
                args: vec![
                    "-p".into(),
                    "{{prompt}}".into(),
                    "--resume".into(),
                    "{{native_id}}".into(),
                    "--output-format".into(),
                    "stream-json".into(),
                ],
            },
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["stream_events".into()],
        },
        AdapterSpec {
            profile_id: "kimi-code".into(),
            transport: StdioJsonRpc,
            dialect: KimiAcp,
            start_args: vec!["acp".into()],
            resume: NativeResume::Argv {
                args: vec!["acp".into(), "--session".into(), "{{native_id}}".into()],
            },
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["acp".into(), "stream_events".into()],
        },
        AdapterSpec {
            profile_id: "opencode".into(),
            transport: StdioJsonRpc,
            dialect: OpenCodeServer,
            start_args: vec!["acp".into()],
            resume: NativeResume::Negotiated {
                method: "session/load".into(),
            },
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["acp".into(), "stream_events".into()],
        },
        AdapterSpec {
            profile_id: "pi".into(),
            transport: StdioJsonl,
            dialect: PiRpc,
            start_args: vec!["--mode".into(), "rpc".into()],
            resume: NativeResume::Degraded,
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["strict_lf_jsonl".into()],
        },
        AdapterSpec {
            profile_id: "agy".into(),
            transport: StdioJsonl,
            dialect: AgyStreamJson,
            start_args: vec![
                "--print".into(),
                "{{prompt}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            resume: NativeResume::Degraded,
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["stream_events".into()],
        },
        AdapterSpec {
            profile_id: "qwen-code".into(),
            transport: StdioJsonRpc,
            dialect: QwenAcp,
            start_args: vec!["--acp".into()],
            resume: NativeResume::Negotiated {
                method: "session/load".into(),
            },
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["acp".into(), "stream_events".into()],
        },
        AdapterSpec {
            profile_id: "hermes-agent".into(),
            transport: StdioJsonRpc,
            dialect: HermesAcp,
            start_args: vec!["acp".into()],
            resume: NativeResume::Argv {
                args: vec!["acp".into(), "--resume".into(), "{{native_id}}".into()],
            },
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["acp".into(), "stream_events".into()],
        },
        AdapterSpec {
            profile_id: "qoder".into(),
            transport: StdioJsonRpc,
            dialect: QoderAcp,
            start_args: vec!["--acp".into()],
            resume: NativeResume::Negotiated {
                method: "session/load".into(),
            },
            auth_probe: None,
            structured_events: true,
            safe_capabilities: vec!["acp".into()],
        },
    ]
}

/// Retrieve an official adapter specification by stable profile ID or alias.
#[must_use]
pub fn official_adapter_spec(id: &str) -> Option<AdapterSpec> {
    let canonical = OfficialProfileId::parse(id)?.as_str();
    official_adapter_specs()
        .into_iter()
        .find(|spec| spec.profile_id == canonical)
}

/// Official profile identifiers — must match `OWNMESH_SPECIFICATION.ja.md` §13.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OfficialProfileId {
    /// `OpenAI` Codex CLI (`codex`)
    Codex,
    /// Claude Code (`claude`)
    ClaudeCode,
    /// Kimi Code (`kimi`)
    KimiCode,
    /// `OpenCode` (`opencode`)
    OpenCode,
    /// Pi Coding Agent (`pi`)
    Pi,
    /// Antigravity CLI (`agy`)
    Agy,
    /// Qwen Code (`qwen`)
    QwenCode,
    /// Hermes Agent (`hermes`)
    HermesAgent,
    /// Qoder CLI (`qodercli`)
    Qoder,
}

impl OfficialProfileId {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::ClaudeCode => "claude-code",
            Self::KimiCode => "kimi-code",
            Self::OpenCode => "opencode",
            Self::Pi => "pi",
            Self::Agy => "agy",
            Self::QwenCode => "qwen-code",
            Self::HermesAgent => "hermes-agent",
            Self::Qoder => "qoder",
        }
    }

    #[must_use]
    pub fn all() -> &'static [OfficialProfileId] {
        &OFFICIAL_ALL
    }

    /// Parse from stable ID string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        // Accept legacy aliases used in early scaffolding.
        match s {
            "codex" | "codex-cli" => Some(Self::Codex),
            "claude-code" => Some(Self::ClaudeCode),
            "kimi-code" => Some(Self::KimiCode),
            "opencode" => Some(Self::OpenCode),
            "pi" | "pi-coding-agent" => Some(Self::Pi),
            "agy" | "antigravity-cli" => Some(Self::Agy),
            "qwen-code" => Some(Self::QwenCode),
            "hermes-agent" => Some(Self::HermesAgent),
            "qoder" | "qoder-cli" => Some(Self::Qoder),
            _ => None,
        }
    }
}

const OFFICIAL_ALL: [OfficialProfileId; 9] = [
    OfficialProfileId::Codex,
    OfficialProfileId::ClaudeCode,
    OfficialProfileId::KimiCode,
    OfficialProfileId::OpenCode,
    OfficialProfileId::Pi,
    OfficialProfileId::Agy,
    OfficialProfileId::QwenCode,
    OfficialProfileId::HermesAgent,
    OfficialProfileId::Qoder,
];

/// Profile definition (runtime + TOML).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "fields mirror the stable profile TOML schema"
)]
pub struct Profile {
    pub id: String,
    pub display_name: String,
    /// Candidate executable names on PATH.
    #[serde(alias = "commands")]
    pub binaries: Vec<String>,
    pub interface_order: Vec<InterfacePreference>,
    #[serde(default = "default_version_args")]
    pub version_args: Vec<String>,
    #[serde(default)]
    pub version_regex: Option<String>,
    #[serde(default)]
    pub auth_status_args: Vec<String>,
    #[serde(default)]
    pub supports_native_resume: bool,
    #[serde(default)]
    pub supports_structured: bool,
    #[serde(default)]
    pub supports_acp: bool,
    /// Minimum supported version (semver-ish major.minor.patch prefix).
    #[serde(default)]
    pub min_version: Option<String>,
    /// Args template for non-interactive one-shot (may include `{{prompt}}`).
    #[serde(default)]
    pub non_interactive_args: Vec<String>,
    /// Args for structured/RPC start when preferred interface is available.
    #[serde(default)]
    pub structured_start_args: Vec<String>,
    /// Args for native resume (`{{native_id}}` placeholder).
    #[serde(default)]
    pub resume_args: Vec<String>,
    #[serde(default)]
    pub official: bool,
}

fn default_version_args() -> Vec<String> {
    vec!["--version".into()]
}

/// Detection / status result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileReadyState {
    NotInstalled,
    Installed,
    NeedsLogin,
    Authenticated,
    UnsupportedVersion,
    AdapterDegraded,
    Ready,
    Running,
}

/// Detection / status result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileStatus {
    pub id: String,
    pub detected: bool,
    pub binary_path: Option<String>,
    pub version: Option<String>,
    pub preferred_interface: Option<InterfacePreference>,
    pub state: ProfileReadyState,
    pub notes: Vec<String>,
}

/// Launch plan for a profile or generic CLI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchPlan {
    pub profile_id: Option<String>,
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub interface: InterfacePreference,
    pub use_pty: bool,
    pub env: BTreeMap<String, String>,
}

/// Build the nine official profiles (spec §13.4 adapter policy).
#[must_use]
#[allow(
    clippy::too_many_lines,
    reason = "the profile matrix is clearest as one declarative table"
)]
pub fn official_profiles() -> Vec<Profile> {
    vec![
        Profile {
            id: OfficialProfileId::Codex.as_str().into(),
            display_name: "OpenAI Codex CLI".into(),
            binaries: vec!["codex".into()],
            interface_order: vec![
                InterfacePreference::StructuredRpc,
                InterfacePreference::Jsonl,
                InterfacePreference::Pty,
            ],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            // App-server continuation is the negotiated `thread/resume` RPC,
            // not a guessed process argv invocation.
            supports_native_resume: true,
            supports_structured: true,
            supports_acp: false,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec!["exec".into(), "--json".into(), "{{prompt}}".into()],
            structured_start_args: vec!["app-server".into()],
            resume_args: vec![],
            official: true,
        },
        Profile {
            id: OfficialProfileId::ClaudeCode.as_str().into(),
            display_name: "Claude Code".into(),
            binaries: vec!["claude".into()],
            interface_order: vec![InterfacePreference::Jsonl, InterfacePreference::Pty],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: true,
            supports_structured: true,
            supports_acp: false,
            min_version: Some("1.0.0".into()),
            non_interactive_args: vec![
                "-p".into(),
                "{{prompt}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            structured_start_args: vec![
                "-p".into(),
                "{{prompt}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            // `-p` owns the follow-up prompt; without it a resumed process
            // would receive neither the requested turn nor stream-json flags.
            resume_args: vec![
                "-p".into(),
                "{{prompt}}".into(),
                "--resume".into(),
                "{{native_id}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            official: true,
        },
        Profile {
            id: OfficialProfileId::KimiCode.as_str().into(),
            display_name: "Kimi Code".into(),
            binaries: vec!["kimi".into()],
            interface_order: vec![
                InterfacePreference::Acp,
                InterfacePreference::Jsonl,
                InterfacePreference::Pty,
            ],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: true,
            supports_structured: true,
            supports_acp: true,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec![
                "--prompt".into(),
                "{{prompt}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            structured_start_args: vec!["acp".into()],
            resume_args: vec!["acp".into(), "--session".into(), "{{native_id}}".into()],
            official: true,
        },
        Profile {
            id: OfficialProfileId::OpenCode.as_str().into(),
            display_name: "OpenCode".into(),
            binaries: vec!["opencode".into()],
            interface_order: vec![
                InterfacePreference::Acp,
                InterfacePreference::Jsonl,
                InterfacePreference::Pty,
            ],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: true,
            supports_structured: true,
            supports_acp: true,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec!["run".into(), "{{prompt}}".into()],
            structured_start_args: vec!["acp".into()],
            resume_args: vec![],
            official: true,
        },
        Profile {
            id: OfficialProfileId::Pi.as_str().into(),
            display_name: "Pi Coding Agent".into(),
            binaries: vec!["pi".into()],
            interface_order: vec![InterfacePreference::Jsonl, InterfacePreference::Pty],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: false,
            supports_structured: true,
            supports_acp: false,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec!["--mode".into(), "rpc".into()],
            structured_start_args: vec!["--mode".into(), "rpc".into()],
            // The documented RPC integration is process-local; OwnMesh does
            // not invent an argv resume surface.
            resume_args: vec![],
            official: true,
        },
        Profile {
            id: OfficialProfileId::Agy.as_str().into(),
            display_name: "Antigravity CLI".into(),
            binaries: vec!["agy".into()],
            interface_order: vec![InterfacePreference::Jsonl, InterfacePreference::Pty],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: false,
            supports_structured: true,
            supports_acp: false,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec![
                "--print".into(),
                "{{prompt}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            structured_start_args: vec![
                "--print".into(),
                "{{prompt}}".into(),
                "--output-format".into(),
                "stream-json".into(),
            ],
            resume_args: vec![],
            official: true,
        },
        Profile {
            id: OfficialProfileId::QwenCode.as_str().into(),
            display_name: "Qwen Code".into(),
            binaries: vec!["qwen".into()],
            interface_order: vec![
                InterfacePreference::Acp,
                InterfacePreference::Jsonl,
                InterfacePreference::Pty,
            ],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: true,
            supports_structured: true,
            supports_acp: true,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec!["-p".into(), "{{prompt}}".into()],
            structured_start_args: vec!["--acp".into()],
            resume_args: vec![],
            official: true,
        },
        Profile {
            id: OfficialProfileId::HermesAgent.as_str().into(),
            display_name: "Hermes Agent".into(),
            binaries: vec!["hermes".into()],
            interface_order: vec![
                InterfacePreference::Acp,
                InterfacePreference::Jsonl,
                InterfacePreference::Pty,
            ],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: true,
            supports_structured: true,
            supports_acp: true,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec!["run".into(), "{{prompt}}".into()],
            structured_start_args: vec!["acp".into()],
            resume_args: vec!["acp".into(), "--resume".into(), "{{native_id}}".into()],
            official: true,
        },
        Profile {
            id: OfficialProfileId::Qoder.as_str().into(),
            display_name: "Qoder CLI".into(),
            // Spec §13.1: primary command is qodercli
            binaries: vec!["qodercli".into(), "qoder".into()],
            interface_order: vec![
                InterfacePreference::Acp,
                InterfacePreference::Jsonl,
                InterfacePreference::Pty,
            ],
            version_args: vec!["--version".into()],
            version_regex: Some(r"(\d+\.\d+\.\d+)".into()),
            auth_status_args: vec![],
            supports_native_resume: true,
            supports_structured: true,
            supports_acp: true,
            min_version: Some("0.1.0".into()),
            non_interactive_args: vec![],
            structured_start_args: vec!["--acp".into()],
            resume_args: vec![],
            official: true,
        },
    ]
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

    /// Retrieve a profile by its stable ID or a supported legacy alias.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Unknown`] when no matching profile is registered.
    pub fn get(&self, id: &str) -> ProfileResult<&Profile> {
        if let Some(p) = self.profiles.get(id) {
            return Ok(p);
        }
        // Legacy alias resolution
        if let Some(official) = OfficialProfileId::parse(id) {
            return self
                .profiles
                .get(official.as_str())
                .ok_or_else(|| ProfileError::Unknown(id.to_string()));
        }
        Err(ProfileError::Unknown(id.to_string()))
    }

    /// List registered profiles in stable ID order.
    #[must_use]
    pub fn list(&self) -> Vec<&Profile> {
        self.profiles.values().collect()
    }

    /// Select best interface given optional capability flags from version probe.
    #[must_use]
    pub fn select_interface(
        profile: &Profile,
        available: &[InterfacePreference],
    ) -> InterfacePreference {
        for pref in &profile.interface_order {
            if available.is_empty() || available.contains(pref) {
                return *pref;
            }
        }
        InterfacePreference::Pty
    }

    /// Detect a binary on `PATH` and pick its preferred interface.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Unknown`] when `id` is not registered.
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

        let state = if !detected {
            ProfileReadyState::NotInstalled
        } else if let (Some(min), Some(ver)) = (&p.min_version, &version) {
            if let Some(parsed) = parse_semver_prefix(ver) {
                if version_less(&parsed, min) {
                    notes.push(format!("version {ver} below minimum {min}"));
                    ProfileReadyState::UnsupportedVersion
                } else {
                    ProfileReadyState::Ready
                }
            } else {
                ProfileReadyState::Installed
            }
        } else {
            ProfileReadyState::Installed
        };

        Ok(ProfileStatus {
            id: p.id.clone(),
            detected,
            binary_path,
            version,
            preferred_interface,
            state,
            notes,
        })
    }

    /// Detect all registered profiles, omitting profiles that cannot be resolved.
    #[must_use]
    pub fn detect_all(&self) -> Vec<ProfileStatus> {
        self.profiles
            .keys()
            .filter_map(|id| self.detect(id).ok())
            .collect()
    }

    /// Build a launch plan for interactive or structured start.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is unknown, has no executable candidate,
    /// or its detected version is unsupported.
    pub fn launch_plan(
        &self,
        id: &str,
        prompt: Option<&str>,
        force_pty: bool,
    ) -> ProfileResult<LaunchPlan> {
        let p = self.get(id)?;
        let status = self.detect(id)?;
        let program = status
            .binary_path
            .clone()
            .or_else(|| p.binaries.first().cloned())
            .ok_or_else(|| ProfileError::Unknown(id.into()))?;

        if matches!(status.state, ProfileReadyState::UnsupportedVersion) {
            return Err(ProfileError::UnsupportedVersion(
                status.version.unwrap_or_else(|| "unknown".into()),
            ));
        }

        let interface = if force_pty {
            InterfacePreference::Pty
        } else {
            Self::select_interface(p, &p.interface_order)
        };

        let args = match interface {
            InterfacePreference::Pty => vec![],
            InterfacePreference::StructuredRpc
            | InterfacePreference::Acp
            | InterfacePreference::Http
            | InterfacePreference::Jsonl => {
                let template = if p.structured_start_args.is_empty() {
                    &p.non_interactive_args
                } else {
                    &p.structured_start_args
                };
                expand_template(template, prompt, None)
            }
        };

        Ok(LaunchPlan {
            profile_id: Some(p.id.clone()),
            program,
            args,
            cwd: None,
            interface,
            use_pty: interface == InterfacePreference::Pty || force_pty,
            env: BTreeMap::new(),
        })
    }

    /// Build a native resume plan when supported.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is unknown, has no executable candidate,
    /// or does not support native resume.
    pub fn resume_plan(&self, id: &str, native_id: &str) -> ProfileResult<LaunchPlan> {
        self.resume_plan_with_prompt(id, native_id, None)
    }

    /// Build an argv-native resume plan with the explicit follow-up prompt.
    ///
    /// This applies only to adapters whose documented continuation is a child
    /// argv surface. Negotiated JSON-RPC resumes are deliberately performed by
    /// the structured driver after capability negotiation.
    pub fn resume_plan_with_prompt(
        &self,
        id: &str,
        native_id: &str,
        prompt: Option<&str>,
    ) -> ProfileResult<LaunchPlan> {
        let p = self.get(id)?;
        if !p.supports_native_resume || p.resume_args.is_empty() {
            return Err(ProfileError::Parse(format!(
                "profile {id} does not support native resume"
            )));
        }
        let status = self.detect(id)?;
        let needs_prompt = p.resume_args.iter().any(|arg| arg.contains("{{prompt}}"));
        if needs_prompt && prompt.is_none_or(str::is_empty) {
            return Err(ProfileError::Parse(format!(
                "profile {id} native resume requires a non-empty follow-up prompt"
            )));
        }
        if prompt.is_some_and(|value| value.len() > 32 * 1024 || value.contains('\0')) {
            return Err(ProfileError::Parse(
                "native resume prompt exceeds bounded argv policy".into(),
            ));
        }
        if native_id.is_empty() || native_id.len() > 512 || native_id.chars().any(char::is_control)
        {
            return Err(ProfileError::Parse("invalid native resume id".into()));
        }
        let program = status
            .binary_path
            .or_else(|| p.binaries.first().cloned())
            .ok_or_else(|| ProfileError::Unknown(id.into()))?;
        Ok(LaunchPlan {
            profile_id: Some(p.id.clone()),
            program,
            args: expand_template(&p.resume_args, prompt, Some(native_id)),
            cwd: None,
            interface: InterfacePreference::StructuredRpc,
            use_pty: false,
            env: BTreeMap::new(),
        })
    }
}

fn expand_template(
    template: &[String],
    prompt: Option<&str>,
    native_id: Option<&str>,
) -> Vec<String> {
    template
        .iter()
        .map(|s| {
            let mut out = s.clone();
            if let Some(p) = prompt {
                out = out.replace("{{prompt}}", p);
            }
            if let Some(n) = native_id {
                out = out.replace("{{native_id}}", n);
            }
            out
        })
        .filter(|s| !s.contains("{{prompt}}") && !s.contains("{{native_id}}"))
        .collect()
}

fn probe_version(bin: &str, args: &[String]) -> Option<String> {
    let out = std::process::Command::new(bin).args(args).output().ok()?;
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

/// Extract `major.minor.patch` prefix from a version string.
#[must_use]
pub fn parse_semver_prefix(raw: &str) -> Option<String> {
    let re = regex_lite_semver(raw)?;
    Some(re)
}

fn regex_lite_semver(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() && !(bytes[i].is_ascii_digit()) {
        i += 1;
    }
    if i >= bytes.len() {
        return None;
    }
    let start = i;
    let mut dots = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_digit() {
            i += 1;
        } else if c == b'.' {
            dots += 1;
            if dots > 2 {
                break;
            }
            i += 1;
        } else {
            break;
        }
    }
    let s = raw.get(start..i)?.trim_matches('.').to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn version_less(a: &str, b: &str) -> bool {
    let pa = parse_parts(a);
    let pb = parse_parts(b);
    pa < pb
}

fn parse_parts(v: &str) -> (u64, u64, u64) {
    let mut it = v.split('.');
    let maj = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let pat = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (maj, min, pat)
}

/// Generic launch plan for unknown CLI (no profile required).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GenericLaunch {
    pub program: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub use_pty: bool,
}

/// Build generic command launch — always available without registration.
#[must_use]
pub fn generic_launch(
    program: impl Into<String>,
    args: Vec<String>,
    use_pty: bool,
) -> GenericLaunch {
    GenericLaunch {
        program: program.into(),
        args,
        cwd: None,
        use_pty,
    }
}

/// Build generic interactive session launch (PTY) without profile.
#[must_use]
pub fn generic_interactive_session(
    program: impl Into<String>,
    args: Vec<String>,
    cwd: Option<PathBuf>,
) -> LaunchPlan {
    LaunchPlan {
        profile_id: None,
        program: program.into(),
        args,
        cwd,
        interface: InterfacePreference::Pty,
        use_pty: true,
        env: BTreeMap::new(),
    }
}

/// Convert a generic launch into a [`LaunchPlan`].
#[must_use]
pub fn generic_to_plan(g: &GenericLaunch) -> LaunchPlan {
    LaunchPlan {
        profile_id: None,
        program: g.program.clone(),
        args: g.args.clone(),
        cwd: g.cwd.clone(),
        interface: if g.use_pty {
            InterfacePreference::Pty
        } else {
            InterfacePreference::Jsonl
        },
        use_pty: g.use_pty,
        env: BTreeMap::new(),
    }
}

/// Load optional custom profile TOML (spec §13.6 shape + extended fields).
///
/// # Errors
///
/// Returns [`ProfileError::Parse`] when the TOML is malformed or required profile
/// fields are missing.
pub fn load_custom_profile_toml(raw: &str) -> ProfileResult<Profile> {
    // Support both `binaries` and schema `commands`.
    #[derive(Deserialize)]
    struct Raw {
        id: String,
        display_name: String,
        #[serde(default)]
        binaries: Vec<String>,
        #[serde(default)]
        commands: Vec<String>,
        #[serde(default)]
        interface_order: Vec<InterfacePreference>,
        #[serde(default)]
        interactive: Option<bool>,
        #[serde(default)]
        detect: Option<DetectSection>,
        #[serde(default)]
        non_interactive: Option<NonInteractiveSection>,
        #[serde(default)]
        capabilities: Option<CapsSection>,
    }
    #[derive(Deserialize, Default)]
    struct DetectSection {
        #[serde(default)]
        version_args: Vec<String>,
        #[serde(default)]
        version_regex: Option<String>,
    }
    #[derive(Deserialize, Default)]
    struct NonInteractiveSection {
        #[serde(default)]
        args: Vec<String>,
    }
    #[derive(Deserialize, Default)]
    struct CapsSection {
        #[serde(default)]
        resume: bool,
        #[serde(default)]
        structured_output: bool,
        #[serde(default)]
        acp: bool,
    }

    // Try extended Profile first; fall back to schema-shaped TOML.
    if let Ok(mut p) = toml::from_str::<Profile>(raw) {
        p.official = false;
        if p.id.trim().is_empty() {
            return Err(ProfileError::Parse("id required".into()));
        }
        if p.binaries.is_empty() {
            return Err(ProfileError::Parse("binaries/commands required".into()));
        }
        if p.interface_order.is_empty() {
            p.interface_order = vec![InterfacePreference::Pty];
        }
        return Ok(p);
    }

    let r: Raw = toml::from_str(raw).map_err(|e| ProfileError::Parse(e.to_string()))?;
    if r.id.trim().is_empty() {
        return Err(ProfileError::Parse("id required".into()));
    }
    let mut binaries = r.binaries;
    if binaries.is_empty() {
        binaries = r.commands;
    }
    if binaries.is_empty() {
        return Err(ProfileError::Parse("commands required".into()));
    }
    let detect = r.detect.unwrap_or_default();
    let ni = r.non_interactive.unwrap_or_default();
    let caps = r.capabilities.unwrap_or_default();
    let mut interface_order = r.interface_order;
    if interface_order.is_empty() {
        interface_order = if r.interactive.unwrap_or(true) {
            vec![InterfacePreference::Pty]
        } else {
            vec![InterfacePreference::Jsonl, InterfacePreference::Pty]
        };
        if caps.acp {
            interface_order.insert(0, InterfacePreference::Acp);
        }
    }
    Ok(Profile {
        id: r.id,
        display_name: r.display_name,
        binaries,
        interface_order,
        version_args: if detect.version_args.is_empty() {
            default_version_args()
        } else {
            detect.version_args
        },
        version_regex: detect.version_regex,
        auth_status_args: vec![],
        supports_native_resume: caps.resume,
        supports_structured: caps.structured_output,
        supports_acp: caps.acp,
        min_version: None,
        non_interactive_args: ni.args,
        structured_start_args: vec![],
        resume_args: vec![],
        official: false,
    })
}

// ---------------------------------------------------------------------------
// Fixture-based conformance
// ---------------------------------------------------------------------------

/// On-disk / embedded fixture describing expected profile behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProfileFixture {
    pub id: String,
    pub display_name: String,
    pub binaries: Vec<String>,
    pub interface_order: Vec<InterfacePreference>,
    pub supports_native_resume: bool,
    pub supports_structured: bool,
    pub supports_acp: bool,
    pub min_version: Option<String>,
    /// Example version strings that must parse and be accepted.
    #[serde(default)]
    pub sample_versions_ok: Vec<String>,
    /// Example version strings that must be rejected as unsupported.
    #[serde(default)]
    pub sample_versions_bad: Vec<String>,
    /// Expected structured start argv head (first tokens).
    #[serde(default)]
    pub structured_start_prefix: Vec<String>,
    /// Expected non-interactive argv contains these tokens when prompt applied.
    #[serde(default)]
    pub non_interactive_contains: Vec<String>,
}

/// Build fixtures for all 9 official profiles (conformance matrix).
#[must_use]
pub fn official_fixtures() -> Vec<ProfileFixture> {
    official_profiles()
        .into_iter()
        .map(|p| ProfileFixture {
            id: p.id.clone(),
            display_name: p.display_name.clone(),
            binaries: p.binaries.clone(),
            interface_order: p.interface_order.clone(),
            supports_native_resume: p.supports_native_resume,
            supports_structured: p.supports_structured,
            supports_acp: p.supports_acp,
            min_version: p.min_version.clone(),
            sample_versions_ok: vec![
                format!(
                    "{} (test)",
                    p.min_version.clone().unwrap_or_else(|| "1.0.0".into())
                ),
                "v9.9.9-beta".into(),
            ],
            sample_versions_bad: p
                .min_version
                .as_ref()
                .map(|m| {
                    let parts = parse_parts(m);
                    if parts.0 > 0 {
                        vec!["0.0.1".into()]
                    } else {
                        vec![]
                    }
                })
                .unwrap_or_default(),
            structured_start_prefix: p.structured_start_args.iter().take(2).cloned().collect(),
            non_interactive_contains: p
                .non_interactive_args
                .iter()
                .filter(|a| !a.contains("{{"))
                .take(2)
                .cloned()
                .collect(),
        })
        .collect()
}

/// Run conformance checks for one profile against its fixture.
///
/// # Errors
///
/// Returns [`ProfileError::Parse`] when profile metadata, capabilities, version
/// handling, interface ordering, or launch behavior differs from the fixture.
#[allow(
    clippy::too_many_lines,
    reason = "the conformance checks form one linear audit sequence"
)]
pub fn conform_profile(profile: &Profile, fixture: &ProfileFixture) -> ProfileResult<Vec<String>> {
    let mut ok = Vec::new();
    if profile.id != fixture.id {
        return Err(ProfileError::Parse(format!(
            "id mismatch {} != {}",
            profile.id, fixture.id
        )));
    }
    if profile.binaries != fixture.binaries {
        return Err(ProfileError::Parse(format!(
            "{} binaries mismatch",
            profile.id
        )));
    }
    if profile.interface_order != fixture.interface_order {
        return Err(ProfileError::Parse(format!(
            "{} interface_order mismatch",
            profile.id
        )));
    }
    if profile.supports_native_resume != fixture.supports_native_resume
        || profile.supports_structured != fixture.supports_structured
        || profile.supports_acp != fixture.supports_acp
    {
        return Err(ProfileError::Parse(format!(
            "{} capability flags mismatch",
            profile.id
        )));
    }
    // PTY must be last in preference order (spec §13.3)
    if let Some(last) = profile.interface_order.last() {
        if *last != InterfacePreference::Pty {
            return Err(ProfileError::Parse(format!(
                "{} must list PTY as fallback last",
                profile.id
            )));
        }
    } else {
        return Err(ProfileError::Parse(format!(
            "{} empty interface_order",
            profile.id
        )));
    }
    ok.push("interface_order".into());

    // Version samples
    for v in &fixture.sample_versions_ok {
        let parsed = parse_semver_prefix(v).ok_or_else(|| {
            ProfileError::Parse(format!("{} failed to parse ok version {v}", profile.id))
        })?;
        if let Some(min) = &fixture.min_version {
            if version_less(&parsed, min) {
                return Err(ProfileError::Parse(format!(
                    "{} sample ok version {v} below min {min}",
                    profile.id
                )));
            }
        }
    }
    ok.push("version_parse_ok".into());

    for v in &fixture.sample_versions_bad {
        if let Some(parsed) = parse_semver_prefix(v) {
            if let Some(min) = &fixture.min_version {
                if !version_less(&parsed, min) {
                    return Err(ProfileError::Parse(format!(
                        "{} bad sample {v} not below min",
                        profile.id
                    )));
                }
            }
        }
    }
    ok.push("version_gate".into());

    // Structured start prefix
    if !fixture.structured_start_prefix.is_empty() {
        let head: Vec<_> = profile
            .structured_start_args
            .iter()
            .take(fixture.structured_start_prefix.len())
            .cloned()
            .collect();
        if head != fixture.structured_start_prefix {
            return Err(ProfileError::Parse(format!(
                "{} structured_start_prefix mismatch {:?} != {:?}",
                profile.id, head, fixture.structured_start_prefix
            )));
        }
        ok.push("structured_start".into());
    }

    // Preferred interface selection never skips to empty
    let selected = ProfileRegistry::select_interface(profile, &[]);
    if !profile.interface_order.contains(&selected) {
        return Err(ProfileError::Parse(format!(
            "{} select_interface out of order",
            profile.id
        )));
    }
    ok.push("best_interface".into());

    // Resume contract
    if profile.supports_native_resume {
        let negotiated = official_adapter_spec(&profile.id)
            .is_some_and(|spec| matches!(spec.resume, NativeResume::Negotiated { .. }));
        if profile.resume_args.is_empty() && !negotiated {
            return Err(ProfileError::Parse(format!(
                "{} claims resume but has empty resume_args",
                profile.id
            )));
        }
        ok.push("native_resume".into());
    }

    // ACP flag consistency
    if profile.supports_acp && !profile.interface_order.contains(&InterfacePreference::Acp) {
        return Err(ProfileError::Parse(format!(
            "{} supports_acp but Acp not in interface_order",
            profile.id
        )));
    }
    ok.push("acp_consistency".into());

    Ok(ok)
}

/// Load fixture JSON from a path (for optional external matrices).
///
/// # Errors
///
/// Returns an error when the file cannot be read or does not contain a valid
/// [`ProfileFixture`].
pub fn load_fixture_json(path: &Path) -> ProfileResult<ProfileFixture> {
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| ProfileError::Parse(e.to_string()))
}

/// Normalize adapter events into a common `OwnMesh` shape (minimal).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NormalizedEvent {
    pub kind: String,
    pub text: Option<String>,
    pub native_session_id: Option<String>,
    pub raw_type: String,
}

/// Maximum accepted adapter record length, excluding the trailing LF.
pub const MAX_ADAPTER_LINE_BYTES: usize = 64 * 1024;
/// Maximum normalized events returned in one replay page.
pub const MAX_ADAPTER_EVENTS_PER_PAGE: usize = 256;

/// A normalized adapter record with an absolute raw-byte cursor.
///
/// `cursor` points just after the record's terminating LF.  It therefore
/// remains meaningful when the caller appends more bytes to a local spool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterEventRecord {
    pub cursor: u64,
    pub event: Option<NormalizedEvent>,
    pub error: Option<String>,
}

/// Bounded result of parsing raw adapter output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdapterEventPage {
    /// Cursor supplied by the caller, usually the spool base offset.
    pub base_cursor: u64,
    /// Cursor to pass for the next page.  No bytes after it were consumed.
    pub next_cursor: u64,
    pub events: Vec<AdapterEventRecord>,
    /// More complete LF records remain after `next_cursor`.
    pub has_more: bool,
}

/// Parse one bounded page of LF-delimited adapter output.
///
/// This deliberately does not use `str::lines`: Pi's documented RPC mode
/// requires LF framing and generic line readers may also split Unicode line
/// separators inside a JSON payload.  An unterminated tail is left for a later
/// append and is never converted into a partial event.
#[must_use]
pub fn parse_adapter_event_page(raw: &[u8], base_cursor: u64) -> AdapterEventPage {
    let mut events = Vec::new();
    let mut consumed = 0_usize;
    let mut scan = 0_usize;

    while scan < raw.len() && events.len() < MAX_ADAPTER_EVENTS_PER_PAGE {
        let Some(relative_lf) = raw[scan..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let end = scan + relative_lf;
        let line = &raw[scan..end];
        let record_end = end + 1;
        let cursor = base_cursor.saturating_add(record_end as u64);
        let record = if line.len() > MAX_ADAPTER_LINE_BYTES {
            AdapterEventRecord {
                cursor,
                event: None,
                error: Some(format!(
                    "adapter record exceeds {MAX_ADAPTER_LINE_BYTES} byte limit"
                )),
            }
        } else {
            match std::str::from_utf8(line) {
                Ok(text) => match normalize_event_json(text.trim_end_matches('\r')) {
                    Some(event) => AdapterEventRecord {
                        cursor,
                        event: Some(event),
                        error: None,
                    },
                    None => AdapterEventRecord {
                        cursor,
                        event: None,
                        error: Some("malformed adapter JSON event".into()),
                    },
                },
                Err(_) => AdapterEventRecord {
                    cursor,
                    event: None,
                    error: Some("adapter record is not UTF-8 JSON".into()),
                },
            }
        };
        events.push(record);
        consumed = record_end;
        scan = record_end;
    }

    // Do not claim there is another record for a partial (no-LF) tail.  The
    // caller must append it before parsing again.
    let has_more = if events.len() == MAX_ADAPTER_EVENTS_PER_PAGE {
        raw[consumed..].contains(&b'\n')
    } else {
        false
    };
    AdapterEventPage {
        base_cursor,
        next_cursor: base_cursor.saturating_add(consumed as u64),
        events,
        has_more,
    }
}

/// Best-effort event normalization from JSONL adapter lines.
pub fn normalize_event_json(raw: &str) -> Option<NormalizedEvent> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let raw_type = if v.get("error").is_some() {
        "error".to_owned()
    } else {
        v.get("type")
            .or_else(|| v.get("event"))
            .and_then(|x| x.as_str())
            .unwrap_or("unknown")
            .to_string()
    };
    let kind = match raw_type.as_str() {
        "message" | "assistant" | "text" | "content" => "message",
        "tool_call" | "tool" | "function_call" => "tool_call",
        "error" | "failed" => "error",
        "session" | "session_started" => "session",
        "done" | "completed" | "result" => "completed",
        other => other,
    }
    .to_string();
    let text = v
        .get("text")
        .or_else(|| v.get("content"))
        .or_else(|| v.pointer("/message/content"))
        .or_else(|| v.pointer("/error/message"))
        .and_then(|x| {
            if x.is_string() {
                x.as_str().map(str::to_string)
            } else {
                Some(x.to_string())
            }
        });
    let native_session_id = v
        .get("session_id")
        .or_else(|| v.get("native_session_id"))
        .and_then(|x| x.as_str())
        .map(str::to_string);
    Some(NormalizedEvent {
        kind,
        text,
        native_session_id,
        raw_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nine_official_profiles() {
        let regs = ProfileRegistry::with_official();
        assert_eq!(regs.list().len(), 9);
        for id in OfficialProfileId::all() {
            assert!(regs.get(id.as_str()).is_ok(), "{}", id.as_str());
        }
        // Spec ids
        for id in [
            "codex",
            "claude-code",
            "kimi-code",
            "opencode",
            "pi",
            "agy",
            "qwen-code",
            "hermes-agent",
            "qoder",
        ] {
            assert_eq!(regs.get(id).unwrap().id, id);
        }
    }

    #[test]
    fn legacy_aliases_resolve() {
        let regs = ProfileRegistry::with_official();
        assert_eq!(regs.get("codex-cli").unwrap().id, "codex");
        assert_eq!(regs.get("pi-coding-agent").unwrap().id, "pi");
        assert_eq!(regs.get("antigravity-cli").unwrap().id, "agy");
        assert_eq!(regs.get("qoder-cli").unwrap().id, "qoder");
    }

    #[test]
    fn qoder_binary_is_qodercli() {
        let reg = ProfileRegistry::with_official();
        let p = reg.get("qoder").unwrap();
        assert_eq!(p.binaries[0], "qodercli");
    }

    #[test]
    fn generic_without_profile() {
        let g = generic_launch("my-cli", vec!["--help".into()], true);
        assert_eq!(g.program, "my-cli");
        assert!(g.use_pty);
        let plan = generic_to_plan(&g);
        assert!(plan.profile_id.is_none());
        assert!(plan.use_pty);
    }

    #[test]
    fn generic_interactive_session_no_profile() {
        let plan = generic_interactive_session("python", vec!["-i".into()], None);
        assert!(plan.profile_id.is_none());
        assert_eq!(plan.interface, InterfacePreference::Pty);
        assert!(plan.use_pty);
        assert_eq!(plan.program, "python");
    }

    #[test]
    fn detect_self_platform_tool() {
        let mut reg = ProfileRegistry::with_official();
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
            version_regex: None,
            auth_status_args: vec![],
            supports_native_resume: false,
            supports_structured: false,
            supports_acp: false,
            min_version: None,
            non_interactive_args: vec![],
            structured_start_args: vec![],
            resume_args: vec![],
            official: false,
        });
        let st = reg.detect("test-shell").unwrap();
        assert!(st.detected);
        assert!(st.binary_path.is_some());
    }

    #[test]
    fn custom_toml_schema_shape() {
        let raw = r#"
id = "my-cli"
display_name = "My CLI"
commands = ["mycli"]
interactive = true

[detect]
version_args = ["--version"]

[non_interactive]
args = ["--prompt", "{{prompt}}"]

[capabilities]
resume = false
structured_output = true
acp = false
"#;
        let p = load_custom_profile_toml(raw).unwrap();
        assert_eq!(p.id, "my-cli");
        assert!(!p.official);
        assert_eq!(p.binaries, vec!["mycli"]);
        assert!(p.supports_structured);
        assert!(p.non_interactive_args.contains(&"--prompt".into()));
    }

    #[test]
    fn all_nine_fixtures_conform() {
        let reg = ProfileRegistry::with_official();
        let fixtures = official_fixtures();
        assert_eq!(fixtures.len(), 9);
        for fx in &fixtures {
            let p = reg.get(&fx.id).expect(&fx.id);
            let checks = conform_profile(p, fx).unwrap_or_else(|e| panic!("{}: {e}", fx.id));
            assert!(
                checks.contains(&"interface_order".into()),
                "{} missing interface_order check",
                fx.id
            );
            assert!(
                checks.contains(&"best_interface".into()),
                "{} missing best_interface",
                fx.id
            );
        }
    }

    #[test]
    fn per_profile_conformance_matrix() {
        let reg = ProfileRegistry::with_official();
        for id in OfficialProfileId::all() {
            let p = reg.get(id.as_str()).unwrap();
            let fx = official_fixtures()
                .into_iter()
                .find(|f| f.id == p.id)
                .unwrap();
            conform_profile(p, &fx).unwrap();

            // Launch plan (binary may be missing — still builds argv against declared name)
            let plan = match reg.launch_plan(id.as_str(), Some("hello"), false) {
                Ok(plan) => plan,
                Err(ProfileError::UnsupportedVersion(_)) => continue,
                Err(e) => panic!("{} launch: {e}", id.as_str()),
            };
            assert_eq!(plan.profile_id.as_deref(), Some(id.as_str()));
            // force PTY fallback
            let pty = reg.launch_plan(id.as_str(), None, true).unwrap();
            assert!(pty.use_pty);
            assert_eq!(pty.interface, InterfacePreference::Pty);

            if matches!(
                official_adapter_spec(id.as_str()).unwrap().resume,
                NativeResume::Argv { .. }
            ) {
                let r = reg
                    .resume_plan_with_prompt(id.as_str(), "native_abc", Some("follow up"))
                    .unwrap();
                assert!(r.args.iter().any(|a| a.contains("native_abc")));
            }
        }
    }

    #[test]
    fn codex_prefers_app_server_rpc() {
        let reg = ProfileRegistry::with_official();
        let p = reg.get("codex").unwrap();
        assert_eq!(p.interface_order[0], InterfacePreference::StructuredRpc);
        assert_eq!(p.structured_start_args, vec!["app-server".to_string()]);
        assert!(p.supports_native_resume);
        assert!(matches!(
            official_adapter_spec("codex").unwrap().resume,
            NativeResume::Negotiated { ref method } if method == "thread/resume"
        ));
    }

    #[test]
    fn official_adapter_specs_are_explicit_and_complete() {
        let specs = official_adapter_specs();
        assert_eq!(specs.len(), 9);
        for id in OfficialProfileId::all() {
            let spec = official_adapter_spec(id.as_str()).expect("adapter spec");
            assert_eq!(spec.profile_id, id.as_str());
            assert!(spec.structured_events, "{}", spec.profile_id);
            assert!(
                !spec.safe_capabilities.is_empty(),
                "{} missing safe capabilities",
                spec.profile_id
            );
            assert!(spec.auth_probe.is_none(), "credentials must not be probed");
        }
        assert!(matches!(
            official_adapter_spec("agy").unwrap().resume,
            NativeResume::Degraded
        ));
        assert_eq!(
            official_adapter_spec("codex").unwrap().transport,
            AdapterTransport::StdioJsonRpc
        );
    }

    #[test]
    fn profile_launch_argv_matches_each_source_backed_adapter_start() {
        let reg = ProfileRegistry::with_official();
        for spec in official_adapter_specs() {
            let plan = reg
                .launch_plan(&spec.profile_id, Some("fixture prompt"), false)
                .unwrap_or_else(|err| panic!("{}: {err}", spec.profile_id));
            let expected: Vec<_> = spec
                .start_args
                .iter()
                .map(|arg| arg.replace("{{prompt}}", "fixture prompt"))
                .collect();
            assert_eq!(plan.args, expected, "{}", spec.profile_id);
            if let NativeResume::Argv { args } = spec.resume {
                let resume = reg
                    .resume_plan_with_prompt(
                        &spec.profile_id,
                        "native_fixture",
                        Some("fixture prompt"),
                    )
                    .unwrap();
                let expected_resume: Vec<_> = args
                    .iter()
                    .map(|arg| arg.replace("{{prompt}}", "fixture prompt"))
                    .map(|arg| arg.replace("{{native_id}}", "native_fixture"))
                    .collect();
                assert_eq!(resume.args, expected_resume, "{}", spec.profile_id);
            }
        }
    }

    #[test]
    fn bounded_adapter_parser_preserves_absolute_byte_cursors() {
        let raw = b"{\"type\":\"message\",\"text\":\"one\",\"session_id\":\"n1\"}\n{\"event\":\"tool_call\"}\n";
        let page = parse_adapter_event_page(raw, 40);
        assert_eq!(page.base_cursor, 40);
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.events[0].event.as_ref().unwrap().kind, "message");
        assert_eq!(
            page.events[0]
                .event
                .as_ref()
                .unwrap()
                .native_session_id
                .as_deref(),
            Some("n1")
        );
        assert_eq!(page.next_cursor, 40 + raw.len() as u64);
        assert!(!page.has_more);
    }

    #[test]
    fn malformed_and_oversize_records_are_visible_not_silent() {
        let mut raw = b"{not-json}\n".to_vec();
        raw.extend(std::iter::repeat_n(b'x', MAX_ADAPTER_LINE_BYTES + 1));
        raw.push(b'\n');
        let page = parse_adapter_event_page(&raw, 0);
        assert_eq!(page.events.len(), 2);
        assert_eq!(
            page.events[0].error.as_deref(),
            Some("malformed adapter JSON event")
        );
        assert!(page.events[1].error.as_deref().unwrap().contains("exceeds"));
    }

    #[test]
    fn post_open_json_rpc_errors_are_visible_structured_events() {
        let event =
            normalize_event_json(r#"{"id":3,"error":{"code":-32001,"message":"turn failed"}}"#)
                .expect("JSON-RPC error must not disappear from replay");
        assert_eq!(event.kind, "error");
        assert_eq!(event.text.as_deref(), Some("turn failed"));
    }

    #[test]
    fn parser_pages_without_rewinding_or_unicode_line_splitting() {
        let one = "{\"type\":\"message\",\"text\":\"a\u{2028}b\"}\n";
        let raw = one.as_bytes().repeat(MAX_ADAPTER_EVENTS_PER_PAGE + 1);
        let first = parse_adapter_event_page(&raw, 500);
        assert_eq!(first.events.len(), MAX_ADAPTER_EVENTS_PER_PAGE);
        assert!(first.has_more);
        let consumed = usize::try_from(first.next_cursor - first.base_cursor).unwrap();
        let second = parse_adapter_event_page(&raw[consumed..], first.next_cursor);
        assert_eq!(second.events.len(), 1);
        assert!(second.next_cursor > first.next_cursor);
        assert_eq!(
            second.events[0].event.as_ref().unwrap().text.as_deref(),
            Some("a\u{2028}b")
        );
    }

    #[test]
    fn claude_stream_json_and_resume() {
        let reg = ProfileRegistry::with_official();
        let p = reg.get("claude-code").unwrap();
        assert!(p.non_interactive_args.iter().any(|a| a == "stream-json"));
        assert!(p.supports_native_resume);
        assert!(reg.resume_plan("claude-code", "native").is_err());
        assert!(reg
            .resume_plan_with_prompt("claude-code", "native", Some("\0"))
            .is_err());
        assert!(reg
            .resume_plan_with_prompt("claude-code", "native", Some(&"x".repeat(32 * 1024 + 1)))
            .is_err());
    }

    #[test]
    fn normalize_events() {
        let e =
            normalize_event_json(r#"{"type":"message","text":"hi","session_id":"s1"}"#).unwrap();
        assert_eq!(e.kind, "message");
        assert_eq!(e.text.as_deref(), Some("hi"));
        assert_eq!(e.native_session_id.as_deref(), Some("s1"));
        let t = normalize_event_json(r#"{"event":"tool_call"}"#).unwrap();
        assert_eq!(t.kind, "tool_call");
    }

    #[test]
    fn parse_semver_prefix_samples() {
        assert_eq!(
            parse_semver_prefix("codex-cli 0.25.1").as_deref(),
            Some("0.25.1")
        );
        assert_eq!(parse_semver_prefix("v1.2.3-beta").as_deref(), Some("1.2.3"));
        assert!(version_less("0.9.0", "1.0.0"));
        assert!(!version_less("1.0.0", "0.9.9"));
    }

    #[test]
    fn fixture_json_roundtrip() {
        let fx = &official_fixtures()[0];
        let raw = serde_json::to_string_pretty(fx).unwrap();
        let back: ProfileFixture = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.id, fx.id);
    }
}
