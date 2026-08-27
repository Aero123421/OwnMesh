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
use std::process::Stdio;
use std::thread;
use std::time::Duration;
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
    #[error(
        "{0} is not installed or not resolvable; install it or add its bin dir to the daemon search dirs, then run `ownmesh doctor`"
    )]
    NotInstalled(String),
    #[error("profile launch dependency unavailable: {0}")]
    LaunchDependency(String),
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
                "--verbose".into(),
            ],
            resume: NativeResume::Argv {
                args: vec![
                    "-p".into(),
                    "{{prompt}}".into(),
                    "--resume".into(),
                    "{{native_id}}".into(),
                    "--output-format".into(),
                    "stream-json".into(),
                    "--verbose".into(),
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
            resume: NativeResume::Negotiated {
                method: "session/load".into(),
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
            resume: NativeResume::Negotiated {
                method: "session/load".into(),
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

/// Authentication evidence is separate from executable launchability.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileAuthState {
    Unknown,
    NeedsLogin,
    Authenticated,
}

/// Structured protocol evidence is never inferred from a parsed version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProfileProtocolState {
    Untested,
    Ready,
    Incompatible,
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
    /// True only when the exact detected program and any shebang interpreter
    /// can be launched with `child_path`.
    pub launchable: bool,
    pub authentication: ProfileAuthState,
    pub structured_protocol: ProfileProtocolState,
    pub notes: Vec<String>,
    /// Exact child PATH used for both probes and launch, omitted only when it
    /// cannot be represented safely on the current platform.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub child_path: Option<String>,
    /// Resolved shebang interpreter for wrapper-based CLIs (for example npm's
    /// `/usr/bin/env node`). This is launch evidence, never auth evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter_path: Option<String>,
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
                "--verbose".into(),
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
                "--verbose".into(),
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
            resume_args: vec![],
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
            resume_args: vec![],
            official: true,
        },
        Profile {
            id: OfficialProfileId::Qoder.as_str().into(),
            display_name: "Qoder CLI".into(),
            // Current documentation uses `qoder`; keep the historic
            // `qodercli` executable as a detection fallback.
            binaries: vec!["qoder".into(), "qodercli".into()],
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

    /// Detect a binary using the same deterministic search as process
    /// invocation (system PATH + user-local dirs, PATHEXT semantics on
    /// Windows) and pick its preferred interface.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Unknown`] when `id` is not registered.
    pub fn detect(&self, id: &str) -> ProfileResult<ProfileStatus> {
        self.detect_with_search_dirs(id, &executable_search_dirs())
    }

    /// Detect against an explicit search-directory list (tests / alternate
    /// PATHs). Shared with `ownmesh_exec` resolution so detection and launch
    /// never disagree about resolution semantics.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Unknown`] when `id` is not registered.
    pub fn detect_with_search_dirs(
        &self,
        id: &str,
        search_dirs: &[PathBuf],
    ) -> ProfileResult<ProfileStatus> {
        let p = self.get(id)?;
        let mut notes = Vec::new();
        let mut binary_path = None;
        for b in &p.binaries {
            // Launchable-file resolution (Unix exec bit verified): a
            // non-executable sibling can never be reported installed while
            // spawning it would fail (P1-D/P1-F).
            match ownmesh_exec::resolve_launchable_executable_in_dirs(
                b,
                search_dirs,
                None,
                cfg!(windows),
                std::env::var("PATHEXT").ok().as_deref(),
            ) {
                Some(path) => {
                    binary_path = Some(path.to_string_lossy().into_owned());
                    break;
                }
                None => notes.push(format!("binary not on PATH: {b}")),
            }
        }
        let detected = binary_path.is_some();
        let preferred_interface = p.interface_order.first().copied();
        let child_path = child_path(search_dirs);
        let interpreter_path = binary_path.as_deref().and_then(|bin| {
            match resolve_shebang_interpreter(Path::new(bin), search_dirs) {
                Ok(path) => path.map(|path| path.to_string_lossy().into_owned()),
                Err(reason) => {
                    notes.push(reason);
                    None
                }
            }
        });
        let launch_dependency_missing = notes
            .iter()
            .any(|note| note.starts_with("interpreter_not_found:"));
        if detected && child_path.is_none() {
            notes.push("child_path_unrepresentable: deterministic search PATH is invalid".into());
        }
        let version = if let (Some(bin), Some(path)) = (&binary_path, &child_path) {
            if launch_dependency_missing {
                None
            } else {
                probe_version(bin, &p.version_args, path)
            }
        } else {
            None
        };

        let state = if !detected {
            ProfileReadyState::NotInstalled
        } else if launch_dependency_missing || child_path.is_none() {
            ProfileReadyState::AdapterDegraded
        } else if let (Some(min), Some(ver)) = (&p.min_version, &version) {
            if let Some(parsed) = parse_semver_prefix(ver) {
                if version_less(&parsed, min) {
                    notes.push(format!("version {ver} below minimum {min}"));
                    ProfileReadyState::UnsupportedVersion
                } else {
                    // Binary/version/launch evidence is not authentication
                    // evidence. Without a documented read-only auth probe the
                    // most truthful state remains `installed`.
                    ProfileReadyState::Installed
                }
            } else {
                ProfileReadyState::Installed
            }
        } else {
            ProfileReadyState::Installed
        };
        let launchable = detected
            && !launch_dependency_missing
            && child_path.is_some()
            && !matches!(state, ProfileReadyState::UnsupportedVersion);
        if detected {
            notes.push("authentication_unknown: no documented read-only probe".into());
            notes.push("structured_protocol_untested: run an explicit session to verify".into());
        }

        Ok(ProfileStatus {
            id: p.id.clone(),
            detected,
            binary_path,
            version,
            preferred_interface,
            state,
            launchable,
            authentication: ProfileAuthState::Unknown,
            structured_protocol: ProfileProtocolState::Untested,
            notes,
            child_path,
            interpreter_path,
        })
    }

    /// Resolve a profile's binary against explicit search dirs WITHOUT
    /// spawning a version probe. Health/diagnostic surfaces must not run
    /// binaries as a side effect of observation, so this is the only
    /// discovery form they may use.
    ///
    /// # Errors
    ///
    /// Returns [`ProfileError::Unknown`] when `id` is not registered.
    pub fn resolve_binary_in_dirs(
        &self,
        id: &str,
        search_dirs: &[PathBuf],
    ) -> ProfileResult<Option<PathBuf>> {
        let p = self.get(id)?;
        for b in &p.binaries {
            if let Some(path) = ownmesh_exec::resolve_launchable_executable_in_dirs(
                b,
                search_dirs,
                None,
                cfg!(windows),
                std::env::var("PATHEXT").ok().as_deref(),
            ) {
                return Ok(Some(path));
            }
        }
        Ok(None)
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
        let dirs = executable_search_dirs();
        self.launch_plan_with_search_dirs(id, prompt, force_pty, &dirs)
    }

    /// [`launch_plan`] against an explicit search-directory list (tests /
    /// alternate PATHs). The resolved executable is the exact path detection
    /// proved, so launch never disagrees with detection.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is unknown, has no executable candidate,
    /// or its detected version is unsupported.
    pub fn launch_plan_with_search_dirs(
        &self,
        id: &str,
        prompt: Option<&str>,
        force_pty: bool,
        search_dirs: &[PathBuf],
    ) -> ProfileResult<LaunchPlan> {
        let p = self.get(id)?;
        let status = self.detect_with_search_dirs(id, search_dirs)?;
        // Never fall back to a bare unverified name: the exact resolved path
        // that detection proved executable is what launch must spawn.
        let program = status
            .binary_path
            .clone()
            .ok_or_else(|| ProfileError::NotInstalled(p.binaries.join(" / ")))?;

        if matches!(status.state, ProfileReadyState::UnsupportedVersion) {
            return Err(ProfileError::UnsupportedVersion(
                status.version.unwrap_or_else(|| "unknown".into()),
            ));
        }
        if matches!(status.state, ProfileReadyState::AdapterDegraded) {
            return Err(ProfileError::LaunchDependency(status.notes.join("; ")));
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

        let mut env = BTreeMap::new();
        if let Some(path) = status.child_path {
            env.insert("PATH".into(), path);
        }
        Ok(LaunchPlan {
            profile_id: Some(p.id.clone()),
            program,
            args,
            cwd: None,
            interface,
            use_pty: interface == InterfacePreference::Pty || force_pty,
            env,
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
        let dirs = executable_search_dirs();
        self.resume_plan_with_search_dirs(id, native_id, prompt, &dirs)
    }

    /// [`resume_plan_with_prompt`] against an explicit search-directory list.
    ///
    /// # Errors
    ///
    /// Returns an error when the profile is unknown, has no executable candidate,
    /// does not support native resume, or its native resume contract is unmet.
    pub fn resume_plan_with_search_dirs(
        &self,
        id: &str,
        native_id: &str,
        prompt: Option<&str>,
        search_dirs: &[PathBuf],
    ) -> ProfileResult<LaunchPlan> {
        let p = self.get(id)?;
        if !p.supports_native_resume || p.resume_args.is_empty() {
            return Err(ProfileError::Parse(format!(
                "profile {id} does not support native resume"
            )));
        }
        let status = self.detect_with_search_dirs(id, search_dirs)?;
        if matches!(status.state, ProfileReadyState::AdapterDegraded) {
            return Err(ProfileError::LaunchDependency(status.notes.join("; ")));
        }
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
            .ok_or_else(|| ProfileError::NotInstalled(p.binaries.join(" / ")))?;
        let mut env = BTreeMap::new();
        if let Some(path) = status.child_path {
            env.insert("PATH".into(), path);
        }
        Ok(LaunchPlan {
            profile_id: Some(p.id.clone()),
            program,
            args: expand_template(&p.resume_args, prompt, Some(native_id)),
            cwd: None,
            interface: InterfacePreference::StructuredRpc,
            use_pty: false,
            env,
        })
    }
}
/// System `PATH` plus deterministic user-local CLI dirs, mirroring
/// `ownmesh_exec::resolve_executable_invocation_path` exactly so detection
/// and launch never disagree about resolution semantics.
fn executable_search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    if !cfg!(windows) {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        dirs.extend(ownmesh_exec::user_cli_search_dirs(home.as_deref()));
    }
    dirs
}

fn child_path(search_dirs: &[PathBuf]) -> Option<String> {
    std::env::join_paths(search_dirs)
        .ok()
        .and_then(|value| value.into_string().ok())
}

/// Resolve the interpreter dependency of a Unix shebang wrapper without
/// invoking a shell or importing a login environment.
fn resolve_shebang_interpreter(
    program: &Path,
    search_dirs: &[PathBuf],
) -> Result<Option<PathBuf>, String> {
    #[cfg(windows)]
    {
        let _ = (program, search_dirs);
        Ok(None)
    }
    #[cfg(not(windows))]
    {
        use std::io::Read;

        let mut file = std::fs::File::open(program)
            .map_err(|_| "interpreter_not_found: wrapper could not be inspected".to_owned())?;
        let mut prefix = [0_u8; 4096];
        let count = file
            .read(&mut prefix)
            .map_err(|_| "interpreter_not_found: wrapper could not be inspected".to_owned())?;
        let first_line = prefix[..count]
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        let Some(shebang) = first_line.strip_prefix(b"#!") else {
            return Ok(None);
        };
        let shebang = std::str::from_utf8(shebang)
            .map_err(|_| "interpreter_not_found: shebang is not UTF-8".to_owned())?
            .trim();
        let mut words = shebang.split_ascii_whitespace();
        let interpreter = words
            .next()
            .ok_or_else(|| "interpreter_not_found: empty shebang".to_owned())?;
        let interpreter_path = PathBuf::from(interpreter);
        if interpreter_path
            .file_name()
            .is_some_and(|name| name == "env")
        {
            let mut command = words
                .next()
                .ok_or_else(|| "interpreter_not_found: env shebang omitted command".to_owned())?;
            if command == "-S" {
                command = words.next().ok_or_else(|| {
                    "interpreter_not_found: env -S shebang omitted command".to_owned()
                })?;
            } else if command.starts_with('-') {
                return Err(format!(
                    "interpreter_not_found: unsupported env shebang option {command}"
                ));
            }
            return ownmesh_exec::resolve_launchable_executable_in_dirs(
                command,
                search_dirs,
                None,
                false,
                None,
            )
            .map(Some)
            .ok_or_else(|| format!("interpreter_not_found: {command}"));
        }
        if interpreter_path.is_absolute() && ownmesh_exec::is_launchable_file(&interpreter_path) {
            Ok(Some(interpreter_path))
        } else {
            Err(format!("interpreter_not_found: {interpreter}"))
        }
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

const VERSION_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const VERSION_PROBE_STOP_GRACE: Duration = Duration::from_millis(500);
const VERSION_PROBE_OUTPUT_LIMIT: usize = 64 * 1024;

async fn stop_version_probe(child: &mut tokio::process::Child) {
    let _ = child.start_kill();
    let _ = tokio::time::timeout(VERSION_PROBE_STOP_GRACE, child.wait()).await;
}

async fn probe_version_bounded(bin: &str, args: &[String], child_path: &str) -> Option<String> {
    use tokio::io::AsyncReadExt;

    // P1-C: resolve through the shared executable resolver so Windows batch
    // shims (`name.cmd`/`name.bat`) are launched via the documented
    // `cmd.exe /e:ON /v:OFF /d /s /c call <script> <args>` form — CreateProcess
    // cannot exec batch files directly (Win32 error 193). Unresolved programs
    // fail the probe (reported not installed) instead of reaching the spawner
    // as a bare name that guesses differently.
    let resolved_argv = ownmesh_exec::resolve_spawn_argv(bin, args, None).ok()?;
    // A vendor CLI may perform network or credential discovery even for
    // `--version`. Profile discovery is a read-only convenience path and must
    // never hold the daemon request loop indefinitely. Async pipe reads cap
    // both memory and the producer: once the direct child exits, the deadline
    // expires, or the aggregate budget is full, dropping the read ends makes
    // inherited descendant writes fail instead of growing a temporary file.
    let mut command = tokio::process::Command::new(&resolved_argv[0]);
    command
        .args(&resolved_argv[1..])
        .env("PATH", child_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().ok()?;
    let mut stdout = child.stdout.take()?;
    let mut stderr = child.stderr.take()?;
    let deadline = tokio::time::Instant::now() + VERSION_PROBE_TIMEOUT;
    let mut stdout_done = false;
    let mut stderr_done = false;
    let mut stdout_output = Vec::new();
    let mut stderr_output = Vec::new();
    let mut stdout_chunk = [0_u8; 4096];
    let mut stderr_chunk = [0_u8; 4096];

    loop {
        if tokio::time::Instant::now() >= deadline {
            stop_version_probe(&mut child).await;
            return None;
        }
        let used = stdout_output.len() + stderr_output.len();
        if used >= VERSION_PROBE_OUTPUT_LIMIT {
            if child.try_wait().ok()?.is_none() {
                stop_version_probe(&mut child).await;
            }
            break;
        }

        let budget = VERSION_PROBE_OUTPUT_LIMIT - used;
        tokio::select! {
            biased;

            read = stdout.read(&mut stdout_chunk), if !stdout_done => {
                match read {
                    Ok(0) | Err(_) => stdout_done = true,
                    Ok(count) => stdout_output.extend_from_slice(&stdout_chunk[..count.min(budget)]),
                }
            }
            read = stderr.read(&mut stderr_chunk), if !stderr_done => {
                match read {
                    Ok(0) | Err(_) => stderr_done = true,
                    Ok(count) => stderr_output.extend_from_slice(&stderr_chunk[..count.min(budget)]),
                }
            }
            status = child.wait() => {
                status.ok()?;
                break;
            }
            () = tokio::time::sleep_until(deadline) => {
                stop_version_probe(&mut child).await;
                return None;
            }
        }
    }

    // Close both read ends before parsing so inherited writers cannot retain
    // any output resource after this bounded probe returns.
    drop(stdout);
    drop(stderr);
    let mut text = String::from_utf8_lossy(&stdout_output).into_owned();
    if text.trim().is_empty() {
        text = String::from_utf8_lossy(&stderr_output).into_owned();
    }
    let line = text.lines().next()?.trim().to_string();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

fn probe_version(bin: &str, args: &[String], child_path: &str) -> Option<String> {
    let bin = bin.to_owned();
    let args = args.to_vec();
    let child_path = child_path.to_owned();
    thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        runtime.block_on(probe_version_bounded(&bin, &args, &child_path))
    })
    .join()
    .ok()
    .flatten()
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    /// Stable reason when a vendor asks for a capability OwnMesh did not
    /// advertise. Never contains vendor payload text.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_reason: Option<String>,
}

/// Maximum accepted adapter record length, excluding the trailing LF.
pub const MAX_ADAPTER_LINE_BYTES: usize = 64 * 1024;
/// Maximum normalized events returned in one replay page.
pub const MAX_ADAPTER_EVENTS_PER_PAGE: usize = 256;
/// Maximum bytes copied from an adapter payload into a display event.
const MAX_NORMALIZED_EVENT_TEXT_BYTES: usize = 4 * 1024;
/// Maximum bytes copied from an adapter event name.
const MAX_NORMALIZED_EVENT_TYPE_BYTES: usize = 128;

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
    parse_adapter_event_page_inner(raw, base_cursor, None)
}

/// Parse one bounded page with the official vendor dialect selected by the
/// session's immutable profile metadata.
#[must_use]
pub fn parse_adapter_event_page_for_dialect(
    raw: &[u8],
    base_cursor: u64,
    dialect: AdapterDialect,
) -> AdapterEventPage {
    parse_adapter_event_page_inner(raw, base_cursor, Some(dialect))
}

fn parse_adapter_event_page_inner(
    raw: &[u8],
    base_cursor: u64,
    dialect: Option<AdapterDialect>,
) -> AdapterEventPage {
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
                Ok(text) => {
                    match classify_adapter_event_for_dialect(text.trim_end_matches('\r'), dialect) {
                        Ok(Some(event)) => AdapterEventRecord {
                            cursor,
                            event: Some(event),
                            error: None,
                        },
                        Ok(None) => {
                            // JSON-RPC handshakes, keepalives, and responses are
                            // protocol control records, not user-visible replay.
                            consumed = record_end;
                            scan = record_end;
                            continue;
                        }
                        Err(error) => AdapterEventRecord {
                            cursor,
                            event: None,
                            error: Some(error.into()),
                        },
                    }
                }
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
    classify_adapter_event(raw).ok().flatten()
}

fn classify_adapter_event_for_dialect(
    raw: &str,
    dialect: Option<AdapterDialect>,
) -> Result<Option<NormalizedEvent>, &'static str> {
    match dialect {
        Some(AdapterDialect::CodexAppServer) => classify_codex_event(raw),
        Some(AdapterDialect::ClaudeStreamJson) => classify_claude_event(raw),
        Some(AdapterDialect::PiRpc) => classify_pi_event(raw),
        Some(AdapterDialect::AgyStreamJson) => classify_agy_event(raw),
        Some(
            AdapterDialect::KimiAcp
            | AdapterDialect::OpenCodeServer
            | AdapterDialect::QwenAcp
            | AdapterDialect::HermesAcp
            | AdapterDialect::QoderAcp,
        ) => classify_acp_event(raw),
        None => classify_adapter_event(raw),
    }
}

fn parse_event_object(
    raw: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, &'static str> {
    serde_json::from_str::<serde_json::Value>(raw)
        .map_err(|_| "malformed adapter JSON event")?
        .as_object()
        .cloned()
        .ok_or("malformed adapter JSON event")
}

fn classify_codex_event(raw: &str) -> Result<Option<NormalizedEvent>, &'static str> {
    // Codex is JSON-RPC-like JSONL without the jsonrpc member. The shared
    // classifier delegates method notifications to the dedicated Codex map.
    classify_adapter_event(raw)
}

fn classify_acp_event(raw: &str) -> Result<Option<NormalizedEvent>, &'static str> {
    let object = parse_event_object(raw)?;
    if object.get("error").is_some() {
        return Ok(Some(normalized_event(
            "error",
            "json_rpc_error",
            bounded_json_string(object.get("error").and_then(|error| error.get("message"))),
            None,
        )));
    }
    let Some(method) = object.get("method").and_then(serde_json::Value::as_str) else {
        return if object.contains_key("id") {
            Ok(None)
        } else {
            Err("unrecognized ACP event")
        };
    };
    let params = object.get("params").and_then(serde_json::Value::as_object);
    let session_id = native_session_id(None, params);
    if method == "session/update" {
        let update = params
            .and_then(|params| params.get("update"))
            .and_then(serde_json::Value::as_object)
            .ok_or("ACP session/update omitted update")?;
        let update_type = update
            .get("sessionUpdate")
            .and_then(serde_json::Value::as_str)
            .ok_or("ACP session/update omitted sessionUpdate")?;
        let content_text = || {
            bounded_json_string(
                update
                    .get("content")
                    .and_then(|content| content.get("text")),
            )
        };
        let tool_id = || {
            update
                .get("toolCallId")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        let event = match update_type {
            "agent_message_chunk" => typed_event(
                "assistant_message_delta",
                update_type,
                content_text(),
                session_id,
                None,
                None,
                None,
            ),
            // Hidden reasoning is deliberately consumed as protocol control,
            // never copied into user-visible replay.
            "agent_thought_chunk" | "user_message_chunk" => return Ok(None),
            "tool_call" => typed_event(
                "tool_call",
                update_type,
                bounded_json_string(update.get("title")),
                session_id,
                tool_id(),
                bounded_json_string(update.get("status")),
                None,
            ),
            "tool_call_update" => {
                let status = bounded_json_string(update.get("status"));
                let kind = if matches!(status.as_deref(), Some("completed" | "failed")) {
                    "tool_result"
                } else {
                    "status"
                };
                typed_event(
                    kind,
                    update_type,
                    update
                        .get("content")
                        .and_then(first_content_text)
                        .or_else(|| bounded_json_string(update.get("title"))),
                    session_id,
                    tool_id(),
                    status,
                    None,
                )
            }
            "plan"
            | "current_mode_update"
            | "available_commands_update"
            | "config_option_update" => typed_event(
                "status",
                update_type,
                bounded_json_string(update.get("title")),
                session_id,
                None,
                None,
                None,
            ),
            "usage_update" => typed_event("usage", update_type, None, session_id, None, None, None),
            _ => return Err("unrecognized ACP session/update event"),
        };
        return Ok(Some(event));
    }
    if method == "session/request_permission" {
        let tool_call = params
            .and_then(|params| params.get("toolCall"))
            .and_then(serde_json::Value::as_object);
        return Ok(Some(typed_event(
            "permission_request",
            method,
            bounded_json_string(tool_call.and_then(|tool| tool.get("title"))),
            session_id,
            tool_call
                .and_then(|tool| tool.get("toolCallId"))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned),
            Some("waiting_approval".into()),
            None,
        )));
    }
    if method.starts_with("fs/") || method.starts_with("terminal/") {
        return Ok(Some(typed_event(
            "adapter_error",
            method,
            Some("adapter requested a client capability OwnMesh did not advertise".into()),
            session_id,
            None,
            Some("rejected".into()),
            Some("capability_not_advertised"),
        )));
    }
    if matches!(method, "ping" | "heartbeat" | "keepalive") {
        return Ok(None);
    }
    Err("unrecognized ACP JSON-RPC event")
}

fn classify_claude_event(raw: &str) -> Result<Option<NormalizedEvent>, &'static str> {
    let object = parse_event_object(raw)?;
    let raw_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or("Claude event omitted type")?;
    let session_id = object
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let event = match raw_type {
        "system" => typed_event(
            "session",
            raw_type,
            bounded_json_string(object.get("subtype")),
            session_id,
            None,
            Some("running".into()),
            None,
        ),
        "assistant" => {
            let content = object
                .get("message")
                .and_then(|message| message.get("content"));
            if let Some(tool) = content.and_then(first_tool_block) {
                typed_event(
                    "tool_call",
                    raw_type,
                    bounded_json_string(tool.get("name")),
                    session_id,
                    tool.get("id")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned),
                    Some("pending".into()),
                    None,
                )
            } else if let Some(text) = content.and_then(visible_content_text) {
                normalized_event("assistant_message", raw_type, Some(text), session_id)
            } else {
                return Ok(None);
            }
        }
        "user" => {
            let content = object
                .get("message")
                .and_then(|message| message.get("content"));
            let Some(tool) = content.and_then(first_tool_result_block) else {
                return Ok(None);
            };
            typed_event(
                "tool_result",
                raw_type,
                tool.get("content").and_then(visible_content_text),
                session_id,
                tool.get("tool_use_id")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                Some(
                    if tool.get("is_error").and_then(serde_json::Value::as_bool) == Some(true) {
                        "failed".into()
                    } else {
                        "completed".into()
                    },
                ),
                None,
            )
        }
        "result" => {
            let is_error = object
                .get("is_error")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false);
            typed_event(
                if is_error { "error" } else { "completed" },
                raw_type,
                bounded_json_string(object.get("result")),
                session_id,
                None,
                Some(if is_error { "failed" } else { "completed" }.into()),
                None,
            )
        }
        "stream_event" => {
            let event = object
                .get("event")
                .and_then(serde_json::Value::as_object)
                .ok_or("Claude stream_event omitted event")?;
            let delta = event.get("delta").and_then(serde_json::Value::as_object);
            if delta
                .and_then(|delta| delta.get("type"))
                .and_then(serde_json::Value::as_str)
                == Some("text_delta")
            {
                normalized_event(
                    "assistant_message_delta",
                    raw_type,
                    bounded_json_string(delta.and_then(|delta| delta.get("text"))),
                    session_id,
                )
            } else {
                return Ok(None);
            }
        }
        _ => return Err("unrecognized Claude stream-json event"),
    };
    Ok(Some(event))
}

fn classify_pi_event(raw: &str) -> Result<Option<NormalizedEvent>, &'static str> {
    let object = parse_event_object(raw)?;
    let raw_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or("Pi event omitted type")?;
    let event = match raw_type {
        "response" => {
            if object.get("success").and_then(serde_json::Value::as_bool) == Some(false) {
                normalized_event(
                    "error",
                    raw_type,
                    bounded_json_string(object.get("error")),
                    None,
                )
            } else {
                return Ok(None);
            }
        }
        "agent_start" | "turn_start" | "message_start" | "queue_update" | "compaction_start"
        | "compaction_end" | "auto_retry_start" | "auto_retry_end" => {
            normalized_event("status", raw_type, None, None)
        }
        "message_update" => {
            let update = object
                .get("assistantMessageEvent")
                .and_then(serde_json::Value::as_object)
                .ok_or("Pi message_update omitted assistantMessageEvent")?;
            match update.get("type").and_then(serde_json::Value::as_str) {
                Some("text_delta") => normalized_event(
                    "assistant_message_delta",
                    raw_type,
                    bounded_json_string(update.get("delta")),
                    None,
                ),
                Some("toolcall_start" | "toolcall_delta" | "toolcall_end") => typed_event(
                    "tool_call",
                    raw_type,
                    None,
                    None,
                    None,
                    Some("pending".into()),
                    None,
                ),
                // Thinking deltas are intentionally not public replay.
                Some("thinking_start" | "thinking_delta" | "thinking_end" | "start" | "done") => {
                    return Ok(None);
                }
                Some("error") => normalized_event("error", raw_type, None, None),
                _ => return Err("unrecognized Pi message_update event"),
            }
        }
        "message_end" | "turn_end" => {
            let text = object
                .get("message")
                .and_then(|message| message.get("content"))
                .and_then(visible_content_text);
            normalized_event("assistant_message", raw_type, text, None)
        }
        "tool_execution_start" => typed_event(
            "tool_call",
            raw_type,
            bounded_json_string(object.get("toolName")),
            None,
            bounded_json_string(object.get("toolCallId")),
            Some("in_progress".into()),
            None,
        ),
        "tool_execution_update" | "tool_execution_end" => typed_event(
            "tool_result",
            raw_type,
            object
                .get("partialResult")
                .or_else(|| object.get("result"))
                .and_then(|result| result.get("content"))
                .and_then(first_content_text),
            None,
            bounded_json_string(object.get("toolCallId")),
            Some(if raw_type.ends_with("end") {
                "completed".into()
            } else {
                "in_progress".into()
            }),
            None,
        ),
        "agent_end" => typed_event(
            "completed",
            raw_type,
            None,
            None,
            None,
            Some("completed".into()),
            None,
        ),
        "extension_error" => normalized_event(
            "error",
            raw_type,
            bounded_json_string(object.get("error")),
            None,
        ),
        _ => return Err("unrecognized Pi RPC event"),
    };
    Ok(Some(event))
}

fn classify_agy_event(raw: &str) -> Result<Option<NormalizedEvent>, &'static str> {
    let object = parse_event_object(raw)?;
    let raw_type = object
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or("Agy stream-json event omitted type")?;
    let session_id = bounded_json_string(object.get("session_id"));
    let event = match raw_type {
        "init" => normalized_event("session", raw_type, None, session_id),
        "message"
            if object.get("role").and_then(serde_json::Value::as_str) == Some("assistant") =>
        {
            normalized_event(
                if object.get("delta").and_then(serde_json::Value::as_bool) == Some(true) {
                    "assistant_message_delta"
                } else {
                    "assistant_message"
                },
                raw_type,
                bounded_json_string(object.get("content")),
                session_id,
            )
        }
        "message" => return Ok(None),
        "tool_use" => typed_event(
            "tool_call",
            raw_type,
            bounded_json_string(object.get("tool_name")),
            session_id,
            bounded_json_string(object.get("tool_id")),
            Some("pending".into()),
            None,
        ),
        "tool_result" => typed_event(
            "tool_result",
            raw_type,
            bounded_json_string(object.get("output").or_else(|| object.get("error"))),
            session_id,
            bounded_json_string(object.get("tool_id")),
            bounded_json_string(object.get("status")),
            None,
        ),
        "error" => normalized_event(
            "error",
            raw_type,
            bounded_json_string(object.get("message")),
            session_id,
        ),
        "result" => typed_event(
            "completed",
            raw_type,
            None,
            session_id,
            None,
            bounded_json_string(object.get("status")),
            None,
        ),
        _ => return Err("unrecognized Agy stream-json event"),
    };
    Ok(Some(event))
}

fn first_tool_block(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    value.as_array()?.iter().find_map(|block| {
        let object = block.as_object()?;
        (object.get("type").and_then(serde_json::Value::as_str) == Some("tool_use"))
            .then_some(object)
    })
}

fn first_tool_result_block(
    value: &serde_json::Value,
) -> Option<&serde_json::Map<String, serde_json::Value>> {
    value.as_array()?.iter().find_map(|block| {
        let object = block.as_object()?;
        (object.get("type").and_then(serde_json::Value::as_str) == Some("tool_result"))
            .then_some(object)
    })
}

fn visible_content_text(value: &serde_json::Value) -> Option<String> {
    if let Some(text) = value.as_str() {
        return Some(bounded_copy(text, MAX_NORMALIZED_EVENT_TEXT_BYTES));
    }
    let array = value.as_array()?;
    let mut text = String::new();
    for block in array {
        let Some(object) = block.as_object() else {
            continue;
        };
        if object.get("type").and_then(serde_json::Value::as_str) != Some("text") {
            continue;
        }
        if let Some(part) = object.get("text").and_then(serde_json::Value::as_str) {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(part);
            if text.len() >= MAX_NORMALIZED_EVENT_TEXT_BYTES {
                break;
            }
        }
    }
    (!text.is_empty()).then(|| bounded_copy(&text, MAX_NORMALIZED_EVENT_TEXT_BYTES))
}

fn first_content_text(value: &serde_json::Value) -> Option<String> {
    visible_content_text(value).or_else(|| {
        value
            .as_object()
            .and_then(|object| object.get("text"))
            .and_then(serde_json::Value::as_str)
            .map(|text| bounded_copy(text, MAX_NORMALIZED_EVENT_TEXT_BYTES))
    })
}

/// Classify one adapter record without exposing its raw JSON payload.
///
/// `Ok(None)` is reserved for protocol control traffic.  Invalid or unknown
/// records deliberately remain visible to the paging caller as a typed error.
fn classify_adapter_event(raw: &str) -> Result<Option<NormalizedEvent>, &'static str> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|_| "malformed adapter JSON event")?;
    let object = value.as_object().ok_or("malformed adapter JSON event")?;

    if object.get("error").is_some() {
        return Ok(Some(normalized_event(
            "error",
            "error",
            bounded_json_string(object.get("error").and_then(|error| error.get("message"))),
            native_session_id(Some(object), None),
        )));
    }

    if let Some(method) = object.get("method").and_then(serde_json::Value::as_str) {
        return classify_json_rpc_notification(method, object.get("params"));
    }

    // Headerless JSON-RPC still uses `id` for request responses.  These carry
    // startup/heartbeat protocol state and must not appear in normal replay.
    if object.contains_key("id") && object.contains_key("result") {
        return Ok(None);
    }

    classify_legacy_adapter_event(object)
}

fn classify_json_rpc_notification(
    method: &str,
    params: Option<&serde_json::Value>,
) -> Result<Option<NormalizedEvent>, &'static str> {
    if matches!(
        method,
        "initialized" | "notifications/initialized" | "ping" | "heartbeat" | "keepalive"
    ) {
        return Ok(None);
    }
    let params = params.and_then(serde_json::Value::as_object);
    let native_session_id = native_session_id(None, params);
    let event = match method {
        "configWarning" | "warning" => normalized_event(
            "status",
            method,
            bounded_json_string(
                params.and_then(|value| value.get("summary").or_else(|| value.get("message"))),
            ),
            native_session_id,
        ),
        "thread/started" | "thread/status/changed" | "remoteControl/status/changed" => {
            normalized_event(
                "session",
                method,
                bounded_json_string(params.and_then(|value| {
                    value
                        .get("status")
                        .or_else(|| value.get("thread").and_then(|thread| thread.get("status")))
                })),
                native_session_id,
            )
        }
        "turn/started" => normalized_event(
            "session",
            method,
            Some("turn started".into()),
            native_session_id,
        ),
        "turn/completed" => {
            let turn = params.and_then(|value| value.get("turn"));
            if turn
                .and_then(|value| value.pointer("/error/message"))
                .is_some()
            {
                normalized_event(
                    "error",
                    method,
                    bounded_json_string(turn.and_then(|value| value.pointer("/error/message"))),
                    native_session_id,
                )
            } else {
                normalized_event(
                    "completed",
                    method,
                    bounded_json_string(turn.and_then(|value| value.get("status"))),
                    native_session_id,
                )
            }
        }
        "item/agentMessage/delta" => normalized_event(
            "assistant_message_delta",
            method,
            Some(required_json_string(
                params.and_then(|value| value.get("delta")),
            )?),
            native_session_id,
        ),
        "item/reasoning/textDelta" | "item/reasoning/summaryTextDelta" => return Ok(None),
        "item/started" | "item/completed" => {
            let item = params.and_then(|value| value.get("item"));
            let item_type = required_json_string(item.and_then(|value| value.get("type")))?;
            if matches!(
                item_type.as_str(),
                "agentMessage" | "userMessage" | "reasoning"
            ) && method == "item/started"
            {
                return Ok(None);
            }
            if item_type == "agentMessage" {
                normalized_event(
                    "assistant_message",
                    method,
                    Some(required_json_string(
                        item.and_then(|value| value.get("text")),
                    )?),
                    native_session_id,
                )
            } else if matches!(item_type.as_str(), "userMessage" | "reasoning") {
                return Ok(None);
            } else {
                normalized_event(
                    if method == "item/completed" {
                        "tool_result"
                    } else {
                        "tool_call"
                    },
                    method,
                    Some(item_type),
                    native_session_id,
                )
            }
        }
        "item/commandExecution/outputDelta" => normalized_event(
            "tool_result",
            method,
            Some(required_json_string(
                params.and_then(|value| value.get("delta")),
            )?),
            native_session_id,
        ),
        "thread/tokenUsage/updated" | "turn/diff/updated" => normalized_event(
            if method == "thread/tokenUsage/updated" {
                "usage"
            } else {
                "status"
            },
            method,
            None,
            native_session_id,
        ),
        "error" => normalized_event(
            "error",
            method,
            bounded_json_string(
                params.and_then(|value| value.get("message").or_else(|| value.get("error"))),
            ),
            native_session_id,
        ),
        _ => return Err("unrecognized adapter JSON-RPC event"),
    };
    Ok(Some(event))
}

fn classify_legacy_adapter_event(
    object: &serde_json::Map<String, serde_json::Value>,
) -> Result<Option<NormalizedEvent>, &'static str> {
    let raw_type = object
        .get("type")
        .or_else(|| object.get("event"))
        .and_then(serde_json::Value::as_str)
        .ok_or("unrecognized adapter JSON event")?;
    let kind = match raw_type {
        "message" | "assistant" | "text" | "content" => "message",
        "tool_call" | "tool" | "function_call" => "tool_call",
        "error" | "failed" => "error",
        "session" | "session_started" => "session",
        "done" | "completed" | "result" => "completed",
        _ => return Err("unrecognized adapter JSON event"),
    };
    Ok(Some(normalized_event(
        kind,
        raw_type,
        bounded_json_string(
            object
                .get("text")
                .or_else(|| object.get("content"))
                .or_else(|| {
                    object
                        .get("message")
                        .and_then(|message| message.get("content"))
                }),
        ),
        native_session_id(Some(object), None),
    )))
}

fn normalized_event(
    kind: &str,
    raw_type: &str,
    text: Option<String>,
    native_session_id: Option<String>,
) -> NormalizedEvent {
    NormalizedEvent {
        kind: kind.into(),
        text,
        native_session_id,
        raw_type: bounded_copy(raw_type, MAX_NORMALIZED_EVENT_TYPE_BYTES),
        tool_call_id: None,
        status: None,
        capability_reason: None,
    }
}

fn typed_event(
    kind: &str,
    raw_type: &str,
    text: Option<String>,
    native_session_id: Option<String>,
    tool_call_id: Option<String>,
    status: Option<String>,
    capability_reason: Option<&str>,
) -> NormalizedEvent {
    let mut event = normalized_event(kind, raw_type, text, native_session_id);
    event.tool_call_id = tool_call_id.map(|value| bounded_copy(&value, 256));
    event.status = status.map(|value| bounded_copy(&value, 128));
    event.capability_reason = capability_reason.map(str::to_owned);
    event
}

fn required_json_string(value: Option<&serde_json::Value>) -> Result<String, &'static str> {
    bounded_json_string(value).ok_or("adapter event missing expected text")
}

fn bounded_json_string(value: Option<&serde_json::Value>) -> Option<String> {
    value
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded_copy(value, MAX_NORMALIZED_EVENT_TEXT_BYTES))
}

fn native_session_id(
    object: Option<&serde_json::Map<String, serde_json::Value>>,
    params: Option<&serde_json::Map<String, serde_json::Value>>,
) -> Option<String> {
    params
        .and_then(|params| {
            params
                .get("threadId")
                .or_else(|| params.get("session_id"))
                .or_else(|| params.get("native_session_id"))
                .or_else(|| params.get("thread").and_then(|thread| thread.get("id")))
        })
        .or_else(|| {
            object.and_then(|object| {
                object
                    .get("session_id")
                    .or_else(|| object.get("native_session_id"))
            })
        })
        .and_then(serde_json::Value::as_str)
        .map(|value| bounded_copy(value, MAX_NORMALIZED_EVENT_TYPE_BYTES))
}

fn bounded_copy(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.into();
    }
    let mut end = max_bytes.saturating_sub('…'.len_utf8());
    while !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}…", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::Instant;
    use tempfile::tempdir;

    #[test]
    #[ignore = "subprocess helper for the bounded version-probe test"]
    fn slow_version_probe_helper() {
        std::thread::sleep(Duration::from_secs(10));
        println!("late-version-output");
    }

    #[test]
    fn version_probe_is_bounded() {
        let exe = std::env::current_exe().unwrap();
        let args = vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "tests::slow_version_probe_helper".to_owned(),
            "--nocapture".to_owned(),
        ];
        let started = Instant::now();
        assert_eq!(
            probe_version(
                &exe.to_string_lossy(),
                &args,
                &std::env::var("PATH").unwrap_or_default(),
            ),
            None
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// P1-C: the version probe goes through the shared executable resolver, so
    /// a non-launchable file (Unix: no exec bit) fails the probe instead of
    /// reaching the spawner — and on Windows the same resolver rewrites
    /// `.cmd`/`.bat` shims to the documented `cmd.exe /c call` form. This
    /// proves detection and probing never disagree about resolution.
    #[test]
    fn version_probe_consults_shared_resolver() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("pi.cmd");
        std::fs::write(&shim, b"@echo off\r\n").unwrap();
        // Unix: without the exec bit the resolver refuses the file, so the
        // probe must fail closed (None) rather than spawn a bare name.
        #[cfg(unix)]
        {
            assert_eq!(
                probe_version(
                    &shim.to_string_lossy(),
                    &["--version".into()],
                    &std::env::var("PATH").unwrap_or_default(),
                ),
                None,
                "non-launchable probe target must fail closed"
            );
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shim).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shim, perms).unwrap();
        }
        // Windows: the shared resolver rewrites the .cmd shim to the pinned
        // System32 cmd.exe wrapper (pinned by ownmesh-exec unit tests); the
        // probe would spawn cmd.exe, not the batch file directly.
        #[cfg(windows)]
        {
            let argv = ownmesh_exec::resolve_spawn_argv(
                &shim.to_string_lossy(),
                &["--version".into()],
                None,
            )
            .expect("resolved");
            assert!(
                argv[0].to_ascii_lowercase().ends_with("system32\\cmd.exe"),
                "argv[0] must be the pinned System32 cmd.exe: {:?}",
                argv[0]
            );
            assert!(argv.contains(&"call".to_string()));
        }
    }

    #[test]
    #[ignore = "subprocess helper for the inherited version-probe output test"]
    #[allow(clippy::zombie_processes)] // The helper must exit while its descendant holds stdio.
    fn inherited_version_probe_output_helper() {
        const DESCENDANT_MARKER: &str = "OWNMESH_TEST_VERSION_PROBE_DESCENDANT";
        if std::env::var_os(DESCENDANT_MARKER).is_some() {
            use std::io::Write;

            let status_addr = std::env::var("OWNMESH_TEST_VERSION_PROBE_STATUS_ADDR").unwrap();
            let mut status = std::net::TcpStream::connect(status_addr).unwrap();
            status.write_all(b"started\n").unwrap();
            std::thread::sleep(Duration::from_millis(200));
            let mut output = std::io::stdout().lock();
            let chunk = [b'x'; 4096];
            let mut pipe_closed = false;
            for _ in 0..200 {
                if output.write_all(&chunk).is_err() || output.flush().is_err() {
                    pipe_closed = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            status
                .write_all(if pipe_closed { b"closed\n" } else { b"open\n" })
                .unwrap();
            return;
        }

        let exe = std::env::current_exe().unwrap();
        let descendant = Command::new(exe)
            .args([
                "--ignored",
                "--exact",
                "tests::inherited_version_probe_output_helper",
                "--quiet",
            ])
            .env(DESCENDANT_MARKER, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let pid_path = std::env::var_os("OWNMESH_TEST_VERSION_PROBE_PID_FILE").unwrap();
        std::fs::write(pid_path, descendant.id().to_string()).unwrap();
        println!("ownmesh-version 9.8.7");
    }

    fn terminate_version_probe_test_descendant(pid: &str) {
        #[cfg(windows)]
        let _ = Command::new("taskkill")
            .args(["/PID", pid, "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        #[cfg(unix)]
        let _ = Command::new("kill")
            .args(["-KILL", pid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    fn version_probe_test_descendant_is_alive(pid: &str) -> bool {
        #[cfg(windows)]
        {
            let filter = format!("PID eq {pid}");
            let Ok(output) = Command::new("tasklist")
                .args(["/FI", &filter, "/FO", "CSV", "/NH"])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .output()
            else {
                return true;
            };
            output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
        }
        #[cfg(unix)]
        {
            Command::new("kill")
                .args(["-0", pid])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
        }
    }

    #[test]
    fn version_probe_does_not_wait_for_inherited_output_handles() {
        use std::io::Read;

        const PID_FILE_ENV: &str = "OWNMESH_TEST_VERSION_PROBE_PID_FILE";
        const STATUS_ADDR_ENV: &str = "OWNMESH_TEST_VERSION_PROBE_STATUS_ADDR";
        let temp_dir = tempfile::tempdir().unwrap();
        let pid_file = temp_dir.path().join("descendant.pid");
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        std::env::set_var(PID_FILE_ENV, &pid_file);
        std::env::set_var(STATUS_ADDR_ENV, listener.local_addr().unwrap().to_string());
        let exe = std::env::current_exe().unwrap();
        let args = vec![
            "--ignored".to_owned(),
            "--exact".to_owned(),
            "tests::inherited_version_probe_output_helper".to_owned(),
            "--nocapture".to_owned(),
        ];
        let started = Instant::now();
        let _version = probe_version(
            &exe.to_string_lossy(),
            &args,
            &std::env::var("PATH").unwrap_or_default(),
        );
        std::env::remove_var(PID_FILE_ENV);
        std::env::remove_var(STATUS_ADDR_ENV);
        let pid = std::fs::read_to_string(&pid_file).unwrap();
        let accept_deadline = Instant::now() + Duration::from_secs(1);
        let mut status_stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break Some(stream),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= accept_deadline {
                        break None;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
                Err(error) => panic!("writer status accept failed: {error}"),
            }
        };
        let mut status = String::new();
        let terminated = match status_stream.as_mut() {
            // The direct helper recorded a successful spawn in `pid_file`.
            // On Unix libtest can hit SIGPIPE before entering the descendant
            // helper, so no status connection is itself the expected closure.
            None => !version_probe_test_descendant_is_alive(pid.trim()),
            Some(stream) => {
                // Linux may propagate the listener's nonblocking mode to
                // accepted sockets; restore blocking reads before the deadline.
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                match stream.read_to_string(&mut status) {
                    Ok(_) => {
                        status.is_empty() || status == "started\n" || status == "started\nclosed\n"
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::ConnectionReset
                                | std::io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        status.is_empty() || status == "started\n"
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        false
                    }
                    Err(error) => panic!("writer status read failed: {error}"),
                }
            }
        };
        if !terminated {
            terminate_version_probe_test_descendant(pid.trim());
        }
        assert!(
            terminated,
            "descendant output pipe remained writable: {status:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
    }

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
    fn qoder_prefers_current_name_and_keeps_legacy_binary() {
        let reg = ProfileRegistry::with_official();
        let p = reg.get("qoder").unwrap();
        assert_eq!(p.binaries, ["qoder", "qodercli"]);
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
        let (dir, dirs) = stub_profile_bins();
        let _ = &dir;
        for id in OfficialProfileId::all() {
            let p = reg.get(id.as_str()).unwrap();
            let fx = official_fixtures()
                .into_iter()
                .find(|f| f.id == p.id)
                .unwrap();
            conform_profile(p, &fx).unwrap();

            // Launch plan resolves against hermetic stub bins.
            let plan =
                match reg.launch_plan_with_search_dirs(id.as_str(), Some("hello"), false, &dirs) {
                    Ok(plan) => plan,
                    Err(ProfileError::UnsupportedVersion(_)) => continue,
                    Err(e) => panic!("{} launch: {e}", id.as_str()),
                };
            assert_eq!(plan.profile_id.as_deref(), Some(id.as_str()));
            // force PTY fallback
            let pty = reg
                .launch_plan_with_search_dirs(id.as_str(), None, true, &dirs)
                .unwrap();
            assert!(pty.use_pty);
            assert_eq!(pty.interface, InterfacePreference::Pty);

            if matches!(
                official_adapter_spec(id.as_str()).unwrap().resume,
                NativeResume::Argv { .. }
            ) {
                let r = reg
                    .resume_plan_with_search_dirs(
                        id.as_str(),
                        "native_abc",
                        Some("follow up"),
                        &dirs,
                    )
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
        let (dir, dirs) = stub_profile_bins();
        let _ = &dir;
        for spec in official_adapter_specs() {
            let plan = reg
                .launch_plan_with_search_dirs(
                    &spec.profile_id,
                    Some("fixture prompt"),
                    false,
                    &dirs,
                )
                .unwrap_or_else(|err| panic!("{}: {err}", spec.profile_id));
            let expected: Vec<_> = spec
                .start_args
                .iter()
                .map(|arg| arg.replace("{{prompt}}", "fixture prompt"))
                .collect();
            assert_eq!(plan.args, expected, "{}", spec.profile_id);
            if let NativeResume::Argv { args } = spec.resume {
                let resume = reg
                    .resume_plan_with_search_dirs(
                        &spec.profile_id,
                        "native_fixture",
                        Some("fixture prompt"),
                        &dirs,
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
    fn codex_json_rpc_fixture_normalizes_events_without_protocol_or_raw_payloads() {
        let raw = include_bytes!("../tests/fixtures/codex-0.149.1-app-server.jsonl");
        let page = parse_adapter_event_page(raw, 100);
        assert_eq!(page.events.len(), 8);
        assert_eq!(page.events[0].event.as_ref().unwrap().kind, "session");
        assert_eq!(
            page.events[1].event.as_ref().unwrap().text.as_deref(),
            Some("Hello from Codex")
        );
        assert_eq!(page.events[2].event.as_ref().unwrap().kind, "tool_call");
        assert_eq!(page.events[3].event.as_ref().unwrap().kind, "tool_result");
        assert_eq!(page.events[4].event.as_ref().unwrap().kind, "tool_result");
        assert_eq!(
            page.events[5].error.as_deref(),
            Some("unrecognized adapter JSON-RPC event")
        );
        assert_eq!(
            page.events[6].event.as_ref().unwrap().text.as_deref(),
            Some("after error")
        );
        assert_eq!(page.events[7].event.as_ref().unwrap().kind, "completed");
        assert!(
            !serde_json::to_string(&page)
                .unwrap()
                .contains("must-not-be-exposed"),
            "unknown JSON-RPC params must not be copied into replay"
        );
        assert_eq!(page.next_cursor, 100 + raw.len() as u64);
    }

    #[test]
    fn all_official_dialect_fixtures_normalize_bounded_public_events() {
        let fixtures: &[(AdapterDialect, &[u8], &[&str])] = &[
            (
                AdapterDialect::ClaudeStreamJson,
                include_bytes!("../tests/fixtures/claude-2.1.246-stream-json.jsonl"),
                &[
                    "session",
                    "assistant_message",
                    "tool_call",
                    "tool_result",
                    "completed",
                ],
            ),
            (
                AdapterDialect::KimiAcp,
                include_bytes!("../tests/fixtures/kimi-0.37-acp.jsonl"),
                &["assistant_message_delta", "usage"],
            ),
            (
                AdapterDialect::OpenCodeServer,
                include_bytes!("../tests/fixtures/opencode-1.18.23-acp.jsonl"),
                &[
                    "assistant_message_delta",
                    "tool_call",
                    "tool_result",
                    "usage",
                ],
            ),
            (
                AdapterDialect::PiRpc,
                include_bytes!("../tests/fixtures/pi-0.73.1-rpc.jsonl"),
                &[
                    "status",
                    "assistant_message_delta",
                    "tool_call",
                    "tool_result",
                    "completed",
                ],
            ),
            (
                AdapterDialect::AgyStreamJson,
                include_bytes!("../tests/fixtures/agy-2026-08-27-stream-json.jsonl"),
                &[
                    "session",
                    "assistant_message_delta",
                    "tool_call",
                    "tool_result",
                    "completed",
                ],
            ),
            (
                AdapterDialect::QwenAcp,
                include_bytes!("../tests/fixtures/qwen-acp-v1.jsonl"),
                &["assistant_message_delta", "permission_request"],
            ),
            (
                AdapterDialect::HermesAcp,
                include_bytes!("../tests/fixtures/hermes-acp-v1.jsonl"),
                &["assistant_message_delta", "permission_request"],
            ),
            (
                AdapterDialect::QoderAcp,
                include_bytes!("../tests/fixtures/qoder-acp-v1.jsonl"),
                &["assistant_message_delta", "adapter_error"],
            ),
        ];
        for (dialect, raw, expected) in fixtures {
            let page = parse_adapter_event_page_for_dialect(raw, 0, *dialect);
            let actual: Vec<_> = page
                .events
                .iter()
                .map(|record| {
                    record
                        .event
                        .as_ref()
                        .unwrap_or_else(|| panic!("{dialect:?}: {:?}", record.error))
                        .kind
                        .as_str()
                })
                .collect();
            assert_eq!(actual, *expected, "{dialect:?}");
            let public = serde_json::to_string(&page).unwrap();
            assert!(!public.contains("must-not-be-exposed"), "{dialect:?}");
            assert!(!public.contains("redacted"), "{dialect:?}");
        }
    }

    #[test]
    fn npm_wrapper_requires_and_exports_the_same_interpreter_path() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let codex = bin.join("codex");
        std::fs::write(&codex, b"#!/usr/bin/env node\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&codex).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&codex, perms).unwrap();
        }
        let reg = ProfileRegistry::with_official();
        let degraded = reg
            .detect_with_search_dirs("codex", std::slice::from_ref(&bin))
            .unwrap();
        if cfg!(unix) {
            assert_eq!(degraded.state, ProfileReadyState::AdapterDegraded);
            assert!(degraded
                .notes
                .iter()
                .any(|note| note == "interpreter_not_found: node"));
        }

        let node = bin.join("node");
        std::fs::write(&node, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&node).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&node, perms).unwrap();
            let status = reg
                .detect_with_search_dirs("codex", std::slice::from_ref(&bin))
                .unwrap();
            assert_eq!(
                status.interpreter_path.as_deref(),
                Some(node.to_string_lossy().as_ref())
            );
            let plan = reg
                .launch_plan_with_search_dirs(
                    "codex",
                    Some("hello"),
                    false,
                    std::slice::from_ref(&bin),
                )
                .unwrap();
            assert_eq!(plan.env.get("PATH"), status.child_path.as_ref());
        }
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

    /// Hermetic stub tree with an executable for every official profile so
    /// launch/conformance tests never depend on the CI host's installed CLIs.
    fn stub_profile_bins() -> (tempfile::TempDir, Vec<PathBuf>) {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let mut names: Vec<String> = Vec::new();
        for p in official_profiles() {
            for b in p.binaries {
                if !names.contains(&b) {
                    names.push(b);
                }
            }
        }
        for name in names {
            let path = bin.join(&name);
            std::fs::write(&path, b"#!/bin/sh\nexit 0\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).unwrap();
            }
        }
        let dirs = vec![bin];
        (dir, dirs)
    }

    /// User-local and NVM discovery (P1-D): fake `$HOME` trees must make
    /// official profiles resolvable without loading any shell startup file.
    #[cfg(not(windows))]
    #[test]
    fn detect_finds_user_local_and_nvm_clis_without_shell_sourcing() {
        let home = tempdir().unwrap();
        let local_bin = home.path().join(".local/bin");
        let nvm_bin = home.path().join(".nvm/versions/node/v24.19.0/bin");
        let cargo_bin = home.path().join(".cargo/bin");
        for dir in [&local_bin, &nvm_bin, &cargo_bin] {
            std::fs::create_dir_all(dir).unwrap();
        }
        for (name, dir) in [("codex", &local_bin), ("pi", &nvm_bin), ("agy", &cargo_bin)] {
            let path = dir.join(name);
            std::fs::write(&path, b"#!/bin/sh\n").unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).unwrap();
            }
        }
        let dirs = ownmesh_exec::user_cli_search_dirs(Some(home.path()));
        let reg = ProfileRegistry::with_official();
        for id in ["codex", "pi", "agy"] {
            let status = reg.detect_with_search_dirs(id, &dirs).unwrap();
            assert!(status.detected, "{id} must be detected: {status:?}");
            // A stub `--version` probe returns nothing, so the state is
            // `Installed` rather than `Ready`; detection itself is what
            // matters here.
            assert!(
                matches!(
                    status.state,
                    ProfileReadyState::Installed | ProfileReadyState::Ready
                ),
                "{id}: {status:?}"
            );
            assert!(
                status
                    .binary_path
                    .as_deref()
                    .unwrap()
                    .starts_with(&home.path().display().to_string()),
                "{id} must resolve inside the fake home: {status:?}"
            );
        }
        // Not installed stays NotInstalled with an actionable note.
        let missing = reg.detect_with_search_dirs("claude-code", &dirs).unwrap();
        assert_eq!(missing.state, ProfileReadyState::NotInstalled);
        assert!(!missing.detected);
        assert!(missing.notes.iter().any(|n| n.contains("not on PATH")));
    }

    /// Detection resolves the exact same invocable candidate that launch will
    /// spawn; a not-installed profile must never fall back to a bare name.
    #[test]
    fn launch_plan_refuses_unresolved_profiles_with_actionable_error() {
        let reg = ProfileRegistry::with_official();
        let empty: Vec<PathBuf> = Vec::new();
        let status = reg.detect_with_search_dirs("pi", &empty).unwrap();
        assert_eq!(status.state, ProfileReadyState::NotInstalled);

        let launch_err = reg
            .launch_plan_with_search_dirs("pi", None, false, &empty)
            .unwrap_err();
        match launch_err {
            ProfileError::NotInstalled(_) => {
                let msg = launch_err.to_string();
                assert!(
                    msg.contains("ownmesh doctor"),
                    "message must point at doctor: {msg}"
                );
            }
            other => panic!("expected NotInstalled, got {other:?}"),
        }
    }

    /// Windows npm-shim ordering (P1-C): detection must pick the `.cmd` shim
    /// over the extensionless POSIX sibling exactly like process resolution.
    #[test]
    fn detect_prefers_invocable_pathext_shim_on_windows() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pi"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("pi.cmd"), b"@echo off\r\n").unwrap();
        std::fs::write(dir.path().join("pi.ps1"), b"# powershell\n").unwrap();
        // Detection now verifies Unix executability (P1-D): a launchable
        // fixture needs its exec bit set on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dir.path().join("pi"))
                .unwrap()
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(dir.path().join("pi"), perms).unwrap();
        }
        let dirs = vec![dir.path().to_path_buf()];
        let reg = ProfileRegistry::with_official();
        let status = reg.detect_with_search_dirs("pi", &dirs).unwrap();
        // `resolve_launchable_executable_in_dirs` uses cfg!(windows) for
        // ordering, so on Unix this resolves the bare shim (Unix semantics).
        // The Windows ordering itself is pinned by ownmesh-exec unit tests;
        // here we prove detection and execution share the resolver.
        if cfg!(windows) {
            let expected = dir.path().join("pi.cmd").display().to_string();
            let actual = status.binary_path.as_deref().unwrap_or_default();
            assert!(
                actual.eq_ignore_ascii_case(&expected),
                "Windows paths and PATHEXT casing are case-insensitive: {actual:?} != {expected:?}"
            );
            assert!(status.detected);
        } else {
            let expected = dir.path().join("pi").display().to_string();
            assert_eq!(status.binary_path.as_deref(), Some(expected.as_str()));
        }
    }

    /// P1-D regression: a non-executable Unix candidate must never be reported
    /// installed (spawning it would fail with EACCES), and the no-probe
    /// resolver used by health surfaces agrees with detection.
    #[test]
    fn detection_skips_non_executable_candidates() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("pi");
        std::fs::write(&shim, b"#!/bin/sh\n").unwrap();
        let dirs = vec![dir.path().to_path_buf()];
        let reg = ProfileRegistry::with_official();
        // Non-executable (0644): detection must report NotInstalled even
        // though `is_file()` would be true.
        let status = reg.detect_with_search_dirs("pi", &dirs).unwrap();
        if cfg!(unix) {
            assert!(!status.detected, "{status:?}");
            assert_eq!(status.state, ProfileReadyState::NotInstalled);
            assert!(
                reg.resolve_binary_in_dirs("pi", &dirs).unwrap().is_none(),
                "no-probe resolver must agree"
            );
        }
        // After the exec bit is set, both detection forms find it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shim).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shim, perms).unwrap();
            let status = reg.detect_with_search_dirs("pi", &dirs).unwrap();
            assert!(status.detected, "{status:?}");
            assert!(reg.resolve_binary_in_dirs("pi", &dirs).unwrap().is_some());
        }
    }

    /// P1-F: the no-probe resolver never spawns version probes (health
    /// surfaces must not run binaries as an observation side effect).
    #[test]
    fn no_probe_resolver_does_not_run_version_probes() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("pi");
        std::fs::write(&shim, b"#!/bin/sh\necho 1.2.3\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shim).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shim, perms).unwrap();
        }
        let dirs = vec![dir.path().to_path_buf()];
        let reg = ProfileRegistry::with_official();
        let resolved = reg.resolve_binary_in_dirs("pi", &dirs).unwrap();
        // A probe would have parsed `1.2.3`; the no-probe form returns the
        // path only and never runs the child.
        assert!(resolved.is_some());
    }

    /// The profiles crate must never source shell startup files: source-level
    /// guard on production code (tests module stripped).
    #[test]
    fn profile_discovery_never_sources_shell_startup_files() {
        let src = include_str!("lib.rs");
        let prod = src.split("mod tests {").next().unwrap_or(src);
        // A real sourcing implementation would reference these file names
        // (typically quoted or as a path join); none may appear in production.
        for forbidden in [
            "\".bashrc\"",
            "\".zshrc\"",
            "\".bash_profile\"",
            "\"bash_login\"",
            "\".profile\"",
            "\".zprofile\"",
            "/.bashrc",
            "/.zshrc",
            "/.profile",
        ] {
            assert!(
                !prod.contains(forbidden),
                "profile discovery must not reference shell startup files: {forbidden}"
            );
        }
    }
}
