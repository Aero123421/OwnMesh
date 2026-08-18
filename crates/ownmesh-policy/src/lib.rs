//! `OwnMesh` allow / ask / deny policy evaluation and presets.
//!
//! Decision precedence: deny > ask > allow among matching rules; higher
//! priority wins within the same decision. Cloud + local synthesis is the
//! most restrictive combination. Full Access has no hidden hard denies.

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
use std::path::{Component, Path, PathBuf};
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

/// Policy errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("parse error: {0}")]
    Parse(String),
    #[error("invalid policy: {0}")]
    Invalid(String),
}

/// Result alias.
pub type PolicyResult<T> = Result<T, PolicyError>;

/// Final decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow = 0,
    Ask = 1,
    Deny = 2,
}

impl Decision {
    /// Most restrictive of two decisions.
    #[must_use]
    pub fn tighten(self, other: Self) -> Self {
        if self >= other {
            self
        } else {
            other
        }
    }
}

/// Named access presets from the specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessPreset {
    WorkspaceOnly,
    Recommended,
    FullUserAccess,
    FullAccess,
    Custom,
}

/// Server-captured executable identity used for approval-time pins and
/// pre-execution TOCTOU checks. Built only from daemon-side pins — never from
/// client-supplied digests. Not used to authorize reusable `command.run` grants
/// (those are never issued or matched).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableIdentityBinding {
    /// Canonical absolute path inspected when the pin was captured.
    pub path: String,
    /// Hex SHA-256 of full file contents at pin time.
    pub content_sha256: String,
    /// Byte length at pin time.
    pub len: u64,
    /// Platform file identity (Unix dev; Windows → None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<u64>,
    /// Platform file identity (Unix ino; Windows → None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    /// Policy classification recorded with the pin (`structured` / `raw_shell`).
    pub policy_kind: String,
}

impl ExecutableIdentityBinding {
    /// True when the binding carries the minimum fields required to pin identity.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        !self.path.trim().is_empty()
            && !self.content_sha256.trim().is_empty()
            && !self.policy_kind.trim().is_empty()
    }

    /// Exact match of path/digest/len/policy_kind and of any recorded device/inode.
    #[must_use]
    pub fn matches(&self, other: &Self) -> bool {
        if !self.is_bound() || !other.is_bound() {
            return false;
        }
        if self.path != other.path
            || self.content_sha256 != other.content_sha256
            || self.len != other.len
            || self.policy_kind != other.policy_kind
        {
            return false;
        }
        // When either side recorded device/inode, both must agree (fail closed on drift).
        if (self.device.is_some()
            || other.device.is_some()
            || self.inode.is_some()
            || other.inode.is_some())
            && (self.device != other.device || self.inode != other.inode)
        {
            return false;
        }
        true
    }
}

/// Machine classification tag for reading a credential-like location
/// (specification §7.4 `reads_sensitive_location`).
pub const TAG_READS_SENSITIVE_LOCATION: &str = "reads_sensitive_location";

/// Machine classification tag for writing a credential-like location
/// (specification §7.4 `writes_sensitive_location`).
pub const TAG_WRITES_SENSITIVE_LOCATION: &str = "writes_sensitive_location";

/// Facts about an operation used for matching (machine facts, not AI opinion).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OperationFacts {
    /// e.g. `command.run`, `filesystem.write`, `session.open`, `broker.elevated`
    pub capability: String,
    /// `structured | raw_shell | file | session | ...`
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub elevated: bool,
    #[serde(default)]
    pub workspace_relative: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Server-captured executable identity (structured `command.run` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_identity: Option<ExecutableIdentityBinding>,
    /// Registered device workspace the path is resolved against.
    ///
    /// `path` for filesystem capabilities is workspace-relative, so the same
    /// string denotes different files in different workspaces. Temporary grants
    /// record this alongside the path scope and refuse to match across
    /// workspaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    /// Canonical tool name for bounded-grant matching (`command_run`, `fs_write`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

/// Single policy rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRule {
    pub id: String,
    pub decision: Decision,
    /// Higher runs first within same decision class after global deny>ask>allow.
    #[serde(default)]
    pub priority: i32,
    /// Match capability exactly or `*` / prefix `command.*`.
    pub capability: String,
    #[serde(default)]
    pub when_elevated: Option<bool>,
    #[serde(default)]
    pub when_kind: Option<String>,
    #[serde(default)]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub program_equals: Option<String>,
    /// Match only when the server-computed facts carry this classification tag.
    ///
    /// Tags are machine facts derived by the daemon (specification §7.4
    /// operation classes such as `reads_sensitive_location`), never client or
    /// model assertions. A rule without a tag condition is unaffected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_tag: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
}

impl PolicyRule {
    fn matches(&self, facts: &OperationFacts) -> bool {
        if !capability_match(&self.capability, &facts.capability) {
            return false;
        }
        if let Some(e) = self.when_elevated {
            if e != facts.elevated {
                return false;
            }
        }
        if let Some(k) = &self.when_kind {
            if k != &facts.kind {
                return false;
            }
        }
        if let Some(tag) = &self.when_tag {
            if !facts.tags.iter().any(|candidate| candidate == tag) {
                return false;
            }
        }
        if let Some(prefix) = &self.path_prefix {
            match &facts.path {
                Some(p) if rule_path_prefix_matches(prefix, p) => {}
                _ => return false,
            }
        }
        if let Some(prog) = &self.program_equals {
            match &facts.program {
                Some(p) if p == prog => {}
                _ => return false,
            }
        }
        true
    }
}

/// Split a path scope into comparable native path components.
///
/// Separator semantics follow the host OS so a backslash remains an ordinary
/// filename byte on Unix and a separator on Windows. Root/prefix components are
/// preserved, preventing an absolute scope from matching a relative path.
/// Returns `None` for empty values or `..` traversal.
fn path_components(value: &str) -> Option<Vec<Component<'_>>> {
    // Whitespace is a real filename character. Trimming here would let a grant
    // approved for ` proj` be reused for the different path `proj`.
    if value.is_empty() {
        return None;
    }
    let mut out = Vec::new();
    for component in Path::new(value).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => return None,
            other => out.push(other),
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Match the documented textual prefix against the path the filesystem walk
/// will actually reach. Rules retain prefix compatibility (`.env` covers
/// `.env.production`), while an interior `..` is collapsed before matching so
/// it cannot escape an Allow prefix or dodge a Deny prefix.
fn rule_path_prefix_matches(prefix: &str, candidate: &str) -> bool {
    let has_parent = |value: &str| {
        Path::new(value)
            .components()
            .any(|part| part == Component::ParentDir)
    };
    if !has_parent(prefix) && !has_parent(candidate) {
        return candidate.starts_with(prefix);
    }

    let normalize = |value: &str| -> Option<String> {
        let path = Path::new(value);
        let mut normalized = PathBuf::new();
        for part in path.components() {
            match part {
                Component::CurDir => {}
                Component::ParentDir => {
                    if !normalized.pop() {
                        return None;
                    }
                }
                Component::RootDir | Component::Prefix(_) | Component::Normal(_) => {
                    normalized.push(part.as_os_str());
                }
            }
        }
        let mut rendered = normalized.to_string_lossy().into_owned();
        let trailing_separator =
            value.ends_with(std::path::MAIN_SEPARATOR) || cfg!(windows) && value.ends_with('/');
        if trailing_separator && !rendered.ends_with(std::path::MAIN_SEPARATOR) {
            rendered.push(std::path::MAIN_SEPARATOR);
        }
        Some(rendered)
    };

    let Some(prefix) = normalize(prefix) else {
        return false;
    };
    let Some(candidate) = normalize(candidate) else {
        return false;
    };
    candidate.starts_with(&prefix)
}

/// True when `candidate` is `scope` itself or a descendant of it.
///
/// Compares whole path components, never raw string prefixes: a scope of
/// `proj` must not capture `proj-secret`. Traversal (`..`) on either side fails
/// closed. This is the only containment rule temporary grants may use.
#[must_use]
pub fn path_scope_contains(scope: &str, candidate: &str) -> bool {
    let (Some(scope), Some(candidate)) = (path_components(scope), path_components(candidate))
    else {
        return false;
    };
    scope.len() <= candidate.len() && scope.iter().zip(&candidate).all(|(a, b)| a == b)
}

fn capability_match(pattern: &str, capability: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix(".*") {
        return capability == prefix || capability.starts_with(&format!("{prefix}."));
    }
    pattern == capability
}

/// A complete policy document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    pub preset: AccessPreset,
    #[serde(default)]
    pub rules: Vec<PolicyRule>,
    /// Optional human note.
    #[serde(default)]
    pub note: Option<String>,
}

/// Evaluation outcome with provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyVerdict {
    pub decision: Decision,
    pub matched_rule_id: Option<String>,
    pub reason: String,
}

/// Evaluate `facts` against a document. Default is Allow when no rule matches
/// (so Full Access empty-deny stays open). Callers that want default-deny
/// should add an explicit catch-all deny rule.
#[must_use]
pub fn evaluate(doc: &PolicyDocument, facts: &OperationFacts) -> PolicyVerdict {
    let mut matched: Vec<&PolicyRule> = doc.rules.iter().filter(|r| r.matches(facts)).collect();
    if matched.is_empty() {
        return PolicyVerdict {
            decision: Decision::Allow,
            matched_rule_id: None,
            reason: "no matching rule; default allow".into(),
        };
    }
    // Sort: decision severity desc, then priority desc.
    matched.sort_by(|a, b| {
        b.decision
            .cmp(&a.decision)
            .then_with(|| b.priority.cmp(&a.priority))
    });
    let top = matched[0];
    PolicyVerdict {
        decision: top.decision,
        matched_rule_id: Some(top.id.clone()),
        reason: top
            .description
            .clone()
            .unwrap_or_else(|| format!("matched rule {}", top.id)),
    }
}

/// Combine cloud and local policies: evaluate both, take the tighter decision.
///
/// Reference implementation of specification §7.2. **The shipped runtime does
/// not call this**: the control plane holds no policy document, so the device
/// evaluates one document and is the only policy authority
/// (ADR 0008). Its presence is not evidence that a cloud policy is fetched.
#[must_use]
pub fn evaluate_combined(
    cloud: &PolicyDocument,
    local: &PolicyDocument,
    facts: &OperationFacts,
) -> PolicyVerdict {
    let c = evaluate(cloud, facts);
    let l = evaluate(local, facts);
    let decision = c.decision.tighten(l.decision);
    let (matched_rule_id, reason) = if decision == c.decision && decision != l.decision {
        (c.matched_rule_id, format!("cloud: {}", c.reason))
    } else if decision == l.decision && decision != c.decision {
        (l.matched_rule_id, format!("local: {}", l.reason))
    } else if c.decision >= l.decision {
        (
            c.matched_rule_id,
            format!("combined cloud+local (cloud): {}", c.reason),
        )
    } else {
        (
            l.matched_rule_id,
            format!("combined cloud+local (local): {}", l.reason),
        )
    };
    PolicyVerdict {
        decision,
        matched_rule_id,
        reason,
    }
}

/// Ask before a restricted preset reads a credential-like file.
///
/// Specification §7.1 promises that Recommended confirms access to credentials.
/// Reads are otherwise allowed outright there, so without this rule a workspace
/// `.env` or private key would reach a connected model with no human in the
/// loop. The daemon supplies the tag from the resolved path; the rule never
/// fires on a client- or model-supplied claim.
///
/// This is an `Ask`, never a `Deny`: the user can still approve the read, and
/// the full-access presets do not carry this rule at all.
fn sensitive_read_ask_rule(id: &str) -> PolicyRule {
    PolicyRule {
        id: id.to_owned(),
        decision: Decision::Ask,
        priority: 60,
        capability: "filesystem.read".into(),
        when_elevated: None,
        when_kind: None,
        path_prefix: None,
        program_equals: None,
        when_tag: Some(TAG_READS_SENSITIVE_LOCATION.into()),
        description: Some("confirm reads of credential-like paths".into()),
    }
}

/// Built-in presets.
#[must_use]
// Keeping each complete preset together makes its security rules auditable.
#[allow(clippy::too_many_lines)]
pub fn preset_document(preset: AccessPreset) -> PolicyDocument {
    match preset {
        AccessPreset::WorkspaceOnly => PolicyDocument {
            preset,
            note: Some(
                "Workspace-relative FS only; command.run denied until OS process confinement exists"
                    .into(),
            ),
            rules: vec![
                PolicyRule {
                    id: "ws-deny-elevated".into(),
                    decision: Decision::Deny,
                    priority: 100,
                    capability: "*".into(),
                    when_elevated: Some(true),
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some("elevated ops denied in Workspace Only".into()),
                },
                // Arbitrary structured/raw commands can open absolute paths and escape
                // registered workspace roots. Fail closed until OS-level confinement exists.
                PolicyRule {
                    id: "ws-deny-command-until-confinement".into(),
                    decision: Decision::Deny,
                    priority: 95,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some(
                        "command.run denied in workspace_only until OS process confinement"
                            .into(),
                    ),
                },
                // Interactive PTY/shell sessions are command execution: stdin can run
                // arbitrary commands outside workspace custody. Deny until confinement.
                PolicyRule {
                    id: "ws-deny-session-open-until-confinement".into(),
                    decision: Decision::Deny,
                    priority: 95,
                    capability: "session.open".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some(
                        "session.open denied in workspace_only until OS process confinement"
                            .into(),
                    ),
                },
                PolicyRule {
                    id: "ws-ask-write".into(),
                    decision: Decision::Ask,
                    priority: 50,
                    capability: "filesystem.write".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some("confirm writes".into()),
                },
                sensitive_read_ask_rule("ws-ask-sensitive-read"),
            ],
        },
        AccessPreset::Recommended => PolicyDocument {
            preset,
            note: Some(
                "Balanced defaults: ask on write, allow reads; command.run denied until OS confinement"
                    .into(),
            ),
            rules: vec![
                PolicyRule {
                    id: "rec-ask-elevated".into(),
                    decision: Decision::Ask,
                    priority: 100,
                    capability: "*".into(),
                    when_elevated: Some(true),
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some("confirm elevated".into()),
                },
                // Same confinement gap as workspace_only: cwd binding alone cannot stop
                // interpreter/absolute-path escapes. Fail closed until a real sandbox exists.
                PolicyRule {
                    id: "rec-deny-command-until-confinement".into(),
                    decision: Decision::Deny,
                    priority: 95,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some(
                        "command.run denied in recommended until OS process confinement".into(),
                    ),
                },
                PolicyRule {
                    id: "rec-deny-session-open-until-confinement".into(),
                    decision: Decision::Deny,
                    priority: 95,
                    capability: "session.open".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some(
                        "session.open denied in recommended until OS process confinement".into(),
                    ),
                },
                PolicyRule {
                    id: "rec-ask-write".into(),
                    decision: Decision::Ask,
                    priority: 50,
                    capability: "filesystem.write".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some("confirm writes".into()),
                },
                PolicyRule {
                    id: "rec-allow-read".into(),
                    decision: Decision::Allow,
                    priority: 10,
                    capability: "filesystem.read".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: Some("allow reads".into()),
                },
                sensitive_read_ask_rule("rec-ask-sensitive-read"),
            ],
        },
        AccessPreset::FullUserAccess => PolicyDocument {
            preset,
            note: Some("User-level full access; elevated still asks".into()),
            rules: vec![PolicyRule {
                id: "fua-ask-elevated".into(),
                decision: Decision::Ask,
                priority: 100,
                capability: "*".into(),
                when_elevated: Some(true),
                when_kind: None,
                path_prefix: None,
                program_equals: None,
                when_tag: None,
                description: Some("confirm elevated only".into()),
            }],
        },
        AccessPreset::FullAccess => PolicyDocument {
            preset,
            note: Some("Full Access: all allow, no hidden denies".into()),
            // Intentionally empty — default allow. No hidden hard deny.
            rules: vec![],
        },
        AccessPreset::Custom => PolicyDocument {
            preset,
            note: Some("Empty custom policy; default allow until rules added".into()),
            rules: vec![],
        },
    }
}

/// Assert Full Access has no deny/ask rules (conformance).
#[must_use]
pub fn full_access_has_no_hidden_restrictive_rules(doc: &PolicyDocument) -> bool {
    doc.preset == AccessPreset::FullAccess
        && doc
            .rules
            .iter()
            .all(|r| matches!(r.decision, Decision::Allow))
}

/// Temporary grant overlay.
///
/// Grants are principal-scoped and time-bounded. Filesystem and other path-scoped
/// capabilities may reuse grants safely under their existing semantics.
///
/// `command.run` (and `command.*`) temporary grants are **never** issued or
/// applied — including structured, raw_shell, interpreter, legacy, and fully
/// identity-bound persisted rows. Program/identity pins cannot safely cover argv
/// mutation (e.g. `python3.12 --version` → `python3.12 -c payload`, `gawk`
/// script swaps). One-shot human approval remains the only path for command
/// execution reuse control. Client-supplied kind/digest/facts must never be
/// trusted — only server approval facts drive the approved operation itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemporaryGrant {
    pub id: String,
    pub capability: String,
    pub principal_id: String,
    pub expires_unix: i64,
    #[serde(default)]
    pub path_prefix: Option<String>,
    /// Legacy field retained for serde compatibility with persisted rows.
    /// `command.run` grants are never issued or matched regardless of this value.
    #[serde(default)]
    pub kind: Option<String>,
    /// Legacy field retained for serde compatibility with persisted rows.
    #[serde(default)]
    pub program_equals: Option<String>,
    /// Legacy field retained for serde compatibility with persisted rows.
    #[serde(default)]
    pub elevated: Option<bool>,
    /// Legacy field retained for serde compatibility with persisted rows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable_identity: Option<ExecutableIdentityBinding>,
    /// Workspace the `path_prefix` is resolved against.
    ///
    /// Absent on rows persisted before grants carried a scope; such rows are
    /// refused by [`temporary_grant_matches`] for path-scoped capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
}

/// Canonical MCP/CLI tool names a bounded tool grant may list.
///
/// No wildcards and no risk-class buckets. `command_run` is admitted here on
/// purpose: this type is the standing exception that [`TemporaryGrant`] refuses.
pub const BOUNDED_TOOL_GRANT_TOOLS: &[&str] = &[
    "command_run",
    "command_shell",
    "fs_list",
    "fs_stat",
    "fs_read",
    "fs_write",
    "fs_delete",
    "logs_query",
    "git_status",
    "git_diff",
];

/// Discriminator stored on every bounded tool grant row.
pub const BOUNDED_TOOL_GRANT_TYPE: &str = "bounded_tool";

/// Hard ceiling for bounded tool grant TTL (4 hours).
pub const MAX_BOUNDED_TOOL_GRANT_TTL_SECS: i64 = 4 * 60 * 60;

/// Maximum distinct tools on one bounded grant.
pub const MAX_BOUNDED_TOOL_GRANT_TOOLS: usize = 8;

/// Optional max-use ceiling.
pub const MAX_BOUNDED_TOOL_GRANT_USES: u32 = 10_000;

/// Discriminator enum so `grant_type` cannot be a free-form string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundedToolGrantType {
    BoundedTool,
}

/// Passkey-minted, time- and use-bounded overlay that lifts **Ask only**.
///
/// Distinct from [`TemporaryGrant`]: this type may list `command_run`, carries
/// a mandatory `grant_type`, and never matches a document Deny.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedToolGrant {
    pub grant_type: BoundedToolGrantType,
    pub id: String,
    pub principal_id: String,
    pub device_id: String,
    pub tools: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<String>,
    pub expires_unix: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    #[serde(default)]
    pub uses: u32,
    pub minted_at_unix: i64,
}

impl BoundedToolGrant {
    /// Fail-closed field checks used at mint and at load.
    pub fn validate(&self) -> Result<(), String> {
        if self.grant_type != BoundedToolGrantType::BoundedTool {
            return Err("bounded tool grant requires grant_type bounded_tool".into());
        }
        if self.id.trim().is_empty() || self.id.len() > 128 {
            return Err("bounded tool grant id is invalid".into());
        }
        if self.principal_id.trim().is_empty() || self.principal_id.len() > 512 {
            return Err("bounded tool grant principal is invalid".into());
        }
        if self.device_id.trim().is_empty() || self.device_id.len() > 256 {
            return Err("bounded tool grant device_id is invalid".into());
        }
        if self.tools.is_empty() || self.tools.len() > MAX_BOUNDED_TOOL_GRANT_TOOLS {
            return Err("bounded tool grant must list 1-8 canonical tools".into());
        }
        let mut seen = BTreeMap::new();
        for tool in &self.tools {
            let canonical = canonical_bounded_tool(tool).ok_or_else(|| {
                format!("bounded tool grant lists unknown or wildcard tool {tool}")
            })?;
            if seen.insert(canonical, ()).is_some() {
                return Err(format!(
                    "bounded tool grant lists duplicate tool {canonical}"
                ));
            }
        }
        if let Some(workspace) = &self.workspace_id {
            if workspace.trim().is_empty() || workspace.len() > 128 {
                return Err("bounded tool grant workspace_id is invalid".into());
            }
        }
        if self.expires_unix <= 0 {
            return Err("bounded tool grant expiry is invalid".into());
        }
        if let Some(max_uses) = self.max_uses {
            if max_uses == 0 || max_uses > MAX_BOUNDED_TOOL_GRANT_USES {
                return Err("bounded tool grant max_uses is invalid".into());
            }
            if self.uses > max_uses {
                return Err("bounded tool grant uses exceed max_uses".into());
            }
        }
        Ok(())
    }

    /// Remaining uses, if capped.
    #[must_use]
    pub fn remaining_uses(&self) -> Option<u32> {
        self.max_uses.map(|max| max.saturating_sub(self.uses))
    }
}

/// Device-local `grants.json` row. Unknown `grant_type` values fail closed.
#[derive(Debug, Clone, Serialize)]
#[serde(untagged)]
pub enum StoredGrant {
    BoundedTool(BoundedToolGrant),
    Temporary(TemporaryGrant),
}

impl<'de> Deserialize<'de> for StoredGrant {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value.get("grant_type") {
            None => TemporaryGrant::deserialize(value)
                .map(Self::Temporary)
                .map_err(serde::de::Error::custom),
            Some(serde_json::Value::String(kind)) if kind == BOUNDED_TOOL_GRANT_TYPE => {
                let grant =
                    BoundedToolGrant::deserialize(value).map_err(serde::de::Error::custom)?;
                grant.validate().map_err(serde::de::Error::custom)?;
                Ok(Self::BoundedTool(grant))
            }
            Some(other) => Err(serde::de::Error::custom(format!(
                "unknown grant_type {other}"
            ))),
        }
    }
}

impl From<TemporaryGrant> for StoredGrant {
    fn from(grant: TemporaryGrant) -> Self {
        Self::Temporary(grant)
    }
}

impl From<BoundedToolGrant> for StoredGrant {
    fn from(grant: BoundedToolGrant) -> Self {
        Self::BoundedTool(grant)
    }
}

impl StoredGrant {
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::BoundedTool(grant) => &grant.id,
            Self::Temporary(grant) => &grant.id,
        }
    }

    #[must_use]
    pub fn as_temporary(&self) -> Option<&TemporaryGrant> {
        match self {
            Self::Temporary(grant) => Some(grant),
            Self::BoundedTool(_) => None,
        }
    }

    #[must_use]
    pub fn as_bounded_tool(&self) -> Option<&BoundedToolGrant> {
        match self {
            Self::BoundedTool(grant) => Some(grant),
            Self::Temporary(_) => None,
        }
    }

    #[must_use]
    pub fn as_bounded_tool_mut(&mut self) -> Option<&mut BoundedToolGrant> {
        match self {
            Self::BoundedTool(grant) => Some(grant),
            Self::Temporary(_) => None,
        }
    }
}

/// Canonicalize a caller-supplied tool name to the bounded-grant allowlist.
#[must_use]
pub fn canonical_bounded_tool(raw: &str) -> Option<&'static str> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains('*') || trimmed.contains('.') {
        return None;
    }
    let stripped = trimmed
        .strip_prefix("ownmesh_")
        .unwrap_or(trimmed)
        .to_ascii_lowercase()
        .replace('-', "_");
    let canonical = match stripped.as_str() {
        "run_command" => "command_run",
        "run_shell" => "command_shell",
        "list_files" => "fs_list",
        "read_file" => "fs_read",
        "write_file" => "fs_write",
        "delete_file" => "fs_delete",
        other => other,
    };
    BOUNDED_TOOL_GRANT_TOOLS
        .iter()
        .copied()
        .find(|tool| *tool == canonical)
}

/// Capabilities whose grants are meaningless without a path scope.
///
/// A `filesystem.*` grant with no recorded path would authorize every path the
/// principal can reach for the whole grant lifetime, which is never what a
/// single approved file operation asked for. Issuance requires a scope and
/// matching refuses rows that lack one.
#[must_use]
pub fn temporary_grant_requires_path_scope(capability: &str) -> bool {
    capability == "filesystem" || capability.starts_with("filesystem.")
}

/// Capabilities for which temporary grants are never safe (command execution).
///
/// Runtime uses this to route `temporary_grant:true` through fail-closed issuance
/// before approval state mutation. Matching also refuses these capabilities.
#[must_use]
pub fn temporary_grant_requires_operation_binding(capability: &str) -> bool {
    capability == "command.run" || capability.starts_with("command.")
}

/// True when `kind` is a raw shell classification (legacy helper; command.run
/// temporary grants are forbidden for every kind).
#[must_use]
pub fn temporary_grant_forbids_kind(kind: &str) -> bool {
    let k = kind.trim();
    k.eq_ignore_ascii_case("raw_shell") || k.eq_ignore_ascii_case("raw")
}

/// Build a temporary grant from **server-side** approval facts only.
///
/// This is the *only* supported way to mint a grant: callers must not assemble
/// [`TemporaryGrant`] literals, because doing so is how an unscoped
/// (all-paths) filesystem grant gets created by accident.
///
/// Client-supplied facts must never be passed here. `command.run` / `command.*`
/// temporary grants are always rejected fail-closed (structured, raw_shell,
/// interpreter, or otherwise) — argv/content cannot be pinned safely for reuse.
/// One-shot approval without `temporary_grant` remains the only command path.
///
/// Path-scoped capabilities (see [`temporary_grant_requires_path_scope`]) must
/// carry the approved path; the resulting grant covers that path and its
/// descendants inside the same workspace, and nothing else.
pub fn temporary_grant_from_facts(
    id: String,
    principal_id: String,
    expires_unix: i64,
    facts: &OperationFacts,
) -> Result<TemporaryGrant, String> {
    let capability = facts.capability.trim();
    if capability.is_empty() {
        return Err("temporary grant requires capability from server approval facts".into());
    }

    // Systemic fail-closed: no command.run temporary grants of any kind/raw/
    // structured/program/argv shape. Interpreters keep the same pinned executable
    // while argv changes payload (--version → -c / -e / script path).
    if temporary_grant_requires_operation_binding(capability) {
        return Err(
            "temporary grant for command.run is not permitted; approve once without temporary grant"
                .into(),
        );
    }

    let path_prefix = facts
        .path
        .as_ref()
        .filter(|p| !p.trim().is_empty())
        .map(ToOwned::to_owned);

    if temporary_grant_requires_path_scope(capability) {
        // An unscoped filesystem grant is indistinguishable from "allow every
        // path for the grant lifetime". Refuse rather than silently widen the
        // single operation the human approved.
        let scope = path_prefix
            .as_deref()
            .ok_or("temporary grant for a filesystem capability requires an approved path scope")?;
        if path_components(scope).is_none() {
            return Err(
                "temporary grant path scope must be a normalized path without `..` traversal"
                    .into(),
            );
        }
        if !facts.workspace_relative {
            return Err("temporary grant path scope must be workspace-relative".into());
        }
        let workspace_id = facts
            .workspace_id
            .as_deref()
            .map(str::trim)
            .filter(|workspace| !workspace.is_empty())
            .ok_or("temporary grant for a filesystem capability requires an approved workspace")?;
        if workspace_id.len() > 128
            || !workspace_id.starts_with("ws_")
            || !workspace_id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err("temporary grant workspace must be a canonical ws_... id".into());
        }
        if matches!(
            Path::new(scope).components().next(),
            Some(Component::RootDir | Component::Prefix(_))
        ) {
            return Err("temporary grant path scope must be workspace-relative".into());
        }
    }

    Ok(TemporaryGrant {
        id,
        capability: capability.to_owned(),
        principal_id,
        expires_unix,
        path_prefix,
        kind: None,
        program_equals: None,
        elevated: None,
        executable_identity: None,
        workspace_id: facts
            .workspace_id
            .as_ref()
            .map(|w| w.trim())
            .filter(|w| !w.is_empty())
            .map(ToOwned::to_owned),
    })
}

fn temporary_grant_matches(
    grant: &TemporaryGrant,
    facts: &OperationFacts,
    principal_id: &str,
    now_unix: i64,
) -> bool {
    if grant.principal_id != principal_id || grant.expires_unix <= now_unix {
        return false;
    }
    if !capability_match(&grant.capability, &facts.capability) {
        return false;
    }
    // Fail closed: never issue-match command.run grants — including legacy/
    // forged/persisted rows with kind/program/elevated/identity bindings.
    // Same pinned interpreter + changed argv must always re-enter human approval.
    if temporary_grant_requires_operation_binding(&grant.capability)
        || temporary_grant_requires_operation_binding(&facts.capability)
    {
        return false;
    }
    // Fail closed for path-scoped capabilities: a grant row with no recorded
    // scope (legacy persisted row, or a forged row) must never stand in for
    // "every path". Only an explicit scope can authorize reuse.
    if temporary_grant_requires_path_scope(&grant.capability)
        || temporary_grant_requires_path_scope(&facts.capability)
    {
        let (Some(scope), Some(path)) = (grant.path_prefix.as_deref(), facts.path.as_deref())
        else {
            return false;
        };
        if !path_scope_contains(scope, path) {
            return false;
        }
        // A workspace-relative scope means nothing across workspaces. Legacy or
        // forged rows without either side of this binding fail closed.
        let (Some(grant_workspace), Some(facts_workspace)) =
            (grant.workspace_id.as_deref(), facts.workspace_id.as_deref())
        else {
            return false;
        };
        if facts_workspace != grant_workspace {
            return false;
        }
        return true;
    }
    if let Some(prefix) = &grant.path_prefix {
        match &facts.path {
            Some(p) if path_scope_contains(prefix, p) => {}
            _ => return false,
        }
    }
    true
}

/// Evaluate with stored grants that force Allow when still valid.
///
/// A grant may only lift an `Ask`. An explicit `Deny` rule outranks every grant
/// (specification §7.7: explicit deny precedes explicit ask and allow), so a
/// deny added after a grant was issued takes effect immediately instead of
/// waiting for the grant to expire. Bounded tool grants never run unless the
/// document decided Ask.
#[must_use]
pub fn evaluate_with_grants(
    doc: &PolicyDocument,
    facts: &OperationFacts,
    grants: &[StoredGrant],
    now_unix: i64,
    principal_id: &str,
) -> PolicyVerdict {
    let verdict = evaluate(doc, facts);
    if verdict.decision == Decision::Deny {
        return verdict;
    }
    for grant in grants {
        let StoredGrant::Temporary(g) = grant else {
            continue;
        };
        if !temporary_grant_matches(g, facts, principal_id, now_unix) {
            continue;
        }
        return PolicyVerdict {
            decision: Decision::Allow,
            matched_rule_id: Some(g.id.clone()),
            reason: format!("temporary grant {}", g.id),
        };
    }
    if verdict.decision != Decision::Ask {
        return verdict;
    }
    for grant in grants {
        let StoredGrant::BoundedTool(g) = grant else {
            continue;
        };
        if !bounded_tool_grant_matches(g, facts, principal_id, now_unix) {
            continue;
        }
        return PolicyVerdict {
            decision: Decision::Allow,
            matched_rule_id: Some(g.id.clone()),
            reason: format!("bounded tool grant {}", g.id),
        };
    }
    verdict
}

fn bounded_tool_grant_matches(
    grant: &BoundedToolGrant,
    facts: &OperationFacts,
    principal_id: &str,
    now_unix: i64,
) -> bool {
    if grant.validate().is_err() {
        return false;
    }
    if grant.principal_id != principal_id || grant.expires_unix <= now_unix {
        return false;
    }
    if grant.max_uses.is_some_and(|max| grant.uses >= max) {
        return false;
    }
    if let Some(workspace) = grant.workspace_id.as_deref() {
        match facts
            .workspace_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(facts_workspace) if facts_workspace == workspace => {}
            _ => return false,
        }
    }
    let Some(tool) = facts_bounded_tool(facts) else {
        return false;
    };
    grant
        .tools
        .iter()
        .any(|listed| canonical_bounded_tool(listed) == Some(tool))
}

/// Tool name used to match a bounded grant against operation facts.
#[must_use]
pub fn facts_bounded_tool(facts: &OperationFacts) -> Option<&'static str> {
    if let Some(tool) = facts.tool.as_deref() {
        if let Some(canonical) = canonical_bounded_tool(tool) {
            return Some(canonical);
        }
    }
    match facts.capability.as_str() {
        "command.run"
            if facts.kind.eq_ignore_ascii_case("raw_shell")
                || facts.kind.eq_ignore_ascii_case("raw") =>
        {
            Some("command_shell")
        }
        "command.run" => Some("command_run"),
        "logs.read" => Some("logs_query"),
        _ => None,
    }
}

/// Summarize rule counts by decision (for UI).
#[must_use]
pub fn decision_histogram(doc: &PolicyDocument) -> BTreeMap<&'static str, usize> {
    let mut m = BTreeMap::from([("allow", 0usize), ("ask", 0), ("deny", 0)]);
    for r in &doc.rules {
        let key = match r.decision {
            Decision::Allow => "allow",
            Decision::Ask => "ask",
            Decision::Deny => "deny",
        };
        *m.entry(key).or_default() += 1;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn as_stored(grants: Vec<TemporaryGrant>) -> Vec<StoredGrant> {
        grants.into_iter().map(StoredGrant::from).collect()
    }

    #[test]
    fn full_access_allows_everything_without_hidden_deny() {
        let doc = preset_document(AccessPreset::FullAccess);
        assert!(full_access_has_no_hidden_restrictive_rules(&doc));
        let facts = OperationFacts {
            capability: "broker.elevated".into(),
            kind: "elevated".into(),
            elevated: true,
            program: Some("diskpart".into()),
            ..Default::default()
        };
        let v = evaluate(&doc, &facts);
        assert_eq!(v.decision, Decision::Allow);
    }

    #[test]
    fn restricted_presets_deny_command_until_os_confinement() {
        for preset in [AccessPreset::WorkspaceOnly, AccessPreset::Recommended] {
            let doc = preset_document(preset);
            let session_facts = OperationFacts {
                capability: "session.open".into(),
                kind: "session".into(),
                ..Default::default()
            };
            let session_v = evaluate(&doc, &session_facts);
            assert_eq!(
                session_v.decision,
                Decision::Deny,
                "{preset:?} must deny session.open until confinement"
            );
            for kind in ["structured", "raw_shell"] {
                let facts = OperationFacts {
                    capability: "command.run".into(),
                    kind: kind.into(),
                    program: Some("python".into()),
                    path: Some("/tmp".into()),
                    workspace_relative: false,
                    ..Default::default()
                };
                let v = evaluate(&doc, &facts);
                assert_eq!(
                    v.decision,
                    Decision::Deny,
                    "{preset:?}/{kind} must fail closed: {v:?}"
                );
            }
        }
    }

    #[test]
    fn deny_beats_allow() {
        let doc = PolicyDocument {
            preset: AccessPreset::Custom,
            note: None,
            rules: vec![
                PolicyRule {
                    id: "allow-all".into(),
                    decision: Decision::Allow,
                    priority: 1000,
                    capability: "*".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: None,
                },
                PolicyRule {
                    id: "deny-shell".into(),
                    decision: Decision::Deny,
                    priority: 1,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("raw_shell".into()),
                    path_prefix: None,
                    program_equals: None,
                    when_tag: None,
                    description: None,
                },
            ],
        };
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: "raw_shell".into(),
            ..Default::default()
        };
        assert_eq!(evaluate(&doc, &facts).decision, Decision::Deny);
    }

    #[test]
    fn combined_takes_tighter() {
        let cloud = preset_document(AccessPreset::FullAccess);
        let local = preset_document(AccessPreset::WorkspaceOnly);
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: "raw_shell".into(),
            elevated: false,
            ..Default::default()
        };
        let v = evaluate_combined(&cloud, &local, &facts);
        assert_eq!(v.decision, Decision::Deny);
    }

    fn sample_identity(path: &str, digest: &str) -> ExecutableIdentityBinding {
        ExecutableIdentityBinding {
            path: path.into(),
            content_sha256: digest.into(),
            len: 32,
            device: Some(1),
            inode: Some(2),
            policy_kind: "structured".into(),
        }
    }

    #[test]
    fn filesystem_temporary_grant_still_overrides() {
        let doc = preset_document(AccessPreset::WorkspaceOnly);
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some("out.txt".into()),
            workspace_relative: true,
            workspace_id: Some("ws_default".into()),
            ..Default::default()
        };
        let grants = as_stored(vec![
                temporary_grant_from_facts("g-fs".into(), "user-1".into(), 9_999_999_999, &facts)
                    .expect("scoped filesystem grant is issuable"),
            ]);
        let v = evaluate_with_grants(&doc, &facts, &grants, 1_700_000_000, "user-1");
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.reason.contains("temporary grant"), "{}", v.reason);
    }

    /// A filesystem grant covers the approved path and its descendants — and
    /// nothing else. The sibling case is the one that used to slip through when
    /// matching compared raw string prefixes.
    #[test]
    fn filesystem_grant_scope_is_component_bounded() {
        let doc = preset_document(AccessPreset::WorkspaceOnly);
        let approved = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some("proj".into()),
            workspace_relative: true,
            workspace_id: Some("ws_default".into()),
            ..Default::default()
        };
        let grants = as_stored(vec![temporary_grant_from_facts(
            "g-scope".into(),
            "user-1".into(),
            9_999_999_999,
            &approved,
        )
        .expect("scoped grant")]);

        let allowed = |path: &str, workspace: &str| OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(path.into()),
            workspace_relative: true,
            workspace_id: Some(workspace.into()),
            ..Default::default()
        };

        for inside in ["proj", "proj/src", "proj/src/deep/file.txt"] {
            assert_eq!(
                evaluate_with_grants(
                    &doc,
                    &allowed(inside, "ws_default"),
                    &grants,
                    1_700_000_000,
                    "user-1"
                )
                .decision,
                Decision::Allow,
                "{inside} is inside the approved scope"
            );
        }

        // Sibling directory sharing a string prefix, an unrelated path, a
        // traversal attempt, and the same relative path in another workspace
        // must all fall back to the preset (Ask for writes here).
        for outside in ["proj-secret", "proj-secret/creds", "other", "proj/../other"] {
            assert_ne!(
                evaluate_with_grants(
                    &doc,
                    &allowed(outside, "ws_default"),
                    &grants,
                    1_700_000_000,
                    "user-1"
                )
                .decision,
                Decision::Allow,
                "{outside} must not ride the `proj` grant"
            );
        }
        assert_ne!(
            evaluate_with_grants(
                &doc,
                &allowed("proj/src", "ws_other"),
                &grants,
                1_700_000_000,
                "user-1"
            )
            .decision,
            Decision::Allow,
            "a workspace-relative scope must not cross workspaces"
        );

        #[cfg(unix)]
        {
            assert!(path_scope_contains(r"proj\secret", r"proj\secret/file"));
            assert!(
                !path_scope_contains(r"proj\secret", "proj/secret/file"),
                "a Unix backslash is a filename byte, not a path separator"
            );
        }
    }

    #[test]
    fn rule_prefix_uses_normalized_target_without_losing_prefix_compatibility() {
        let rule = |decision, prefix: &str| PolicyRule {
            id: "path-rule".into(),
            decision,
            priority: 1,
            capability: "filesystem.read".into(),
            when_elevated: None,
            when_kind: None,
            path_prefix: Some(prefix.into()),
            program_equals: None,
            when_tag: None,
            description: None,
        };
        let facts = |path: &str| OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(path.into()),
            ..Default::default()
        };

        for (prefix, path) in [
            (".env", ".env.production"),
            ("secret", "secrets.txt"),
            ("secrets", "secrets/../secrets/key.pem"),
            ("secrets", "other/../secrets/key.pem"),
            ("secrets/", "secrets/other/../key.pem"),
        ] {
            assert!(
                rule(Decision::Deny, prefix).matches(&facts(path)),
                "{prefix:?} must match the resolved target of {path:?}"
            );
        }

        assert!(
            !rule(Decision::Allow, "proj").matches(&facts("proj/../secrets/key.pem")),
            "traversal must not escape an allow prefix"
        );
    }

    /// Issuance refuses to mint a filesystem grant with no path, and matching
    /// refuses any such row that reaches it anyway (legacy or forged).
    #[test]
    fn unscoped_filesystem_grants_are_refused() {
        let no_path = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            ..Default::default()
        };
        let err = temporary_grant_from_facts("g".into(), "user-1".into(), 9_999_999_999, &no_path)
            .expect_err("an unscoped filesystem grant must not be issuable");
        assert!(err.contains("path scope"), "{err}");

        let no_workspace = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some("scoped.txt".into()),
            workspace_relative: true,
            ..Default::default()
        };
        let err = temporary_grant_from_facts(
            "g-workspace".into(),
            "user-1".into(),
            9_999_999_999,
            &no_workspace,
        )
        .expect_err("a workspace-relative grant must bind its workspace");
        assert!(err.contains("workspace"), "{err}");

        let forged = TemporaryGrant {
            id: "legacy-unscoped-fs".into(),
            capability: "filesystem.write".into(),
            principal_id: "user-1".into(),
            expires_unix: 9_999_999_999,
            path_prefix: None,
            kind: None,
            program_equals: None,
            elevated: None,
            executable_identity: None,
            workspace_id: None,
        };
        let doc = preset_document(AccessPreset::WorkspaceOnly);
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some("anything/at/all".into()),
            ..Default::default()
        };
        let v = evaluate_with_grants(
            &doc,
            &facts,
            &[StoredGrant::from(forged)],
            1_700_000_000,
            "user-1",
        );
        assert_ne!(
            v.decision,
            Decision::Allow,
            "an unscoped filesystem row must never stand in for every path: {v:?}"
        );
    }

    #[test]
    fn command_run_temporary_grants_never_issue_for_any_kind() {
        let identity = sample_identity("/usr/bin/python3.12", "aa".repeat(32).as_str());
        for (label, facts) in [
            (
                "structured-python",
                OperationFacts {
                    capability: "command.run".into(),
                    kind: "structured".into(),
                    program: Some("/usr/bin/python3.12".into()),
                    elevated: false,
                    executable_identity: Some(identity.clone()),
                    ..Default::default()
                },
            ),
            (
                "raw_shell",
                OperationFacts {
                    capability: "command.run".into(),
                    kind: "raw_shell".into(),
                    program: Some("/bin/bash".into()),
                    elevated: false,
                    ..Default::default()
                },
            ),
            (
                "structured-gawk",
                OperationFacts {
                    capability: "command.run".into(),
                    kind: "structured".into(),
                    program: Some("/usr/bin/gawk".into()),
                    elevated: false,
                    executable_identity: Some(sample_identity(
                        "/usr/bin/gawk",
                        "bb".repeat(32).as_str(),
                    )),
                    ..Default::default()
                },
            ),
            (
                "command-star-prefix",
                OperationFacts {
                    capability: "command.exec".into(),
                    kind: "structured".into(),
                    program: Some("/bin/echo".into()),
                    elevated: false,
                    executable_identity: Some(sample_identity(
                        "/bin/echo",
                        "cc".repeat(32).as_str(),
                    )),
                    ..Default::default()
                },
            ),
        ] {
            let err = temporary_grant_from_facts(
                format!("g-{label}"),
                "agent-1".into(),
                9_999_999_999,
                &facts,
            )
            .expect_err(label);
            let lower = err.to_ascii_lowercase();
            assert!(
                lower.contains("command.run") && lower.contains("not permitted"),
                "{label}: {err}"
            );
        }
    }

    #[test]
    fn legacy_and_forged_command_run_temporary_grants_never_allow() {
        let doc = preset_document(AccessPreset::Recommended);
        let py = "/usr/bin/python3.12";
        let py_id = sample_identity(py, "dd".repeat(32).as_str());
        let gawk = "/usr/bin/gawk";
        let gawk_id = sample_identity(gawk, "ee".repeat(32).as_str());

        // Fully "bound" legacy/forged rows that older builds would have accepted.
        let grants = as_stored(vec![
            TemporaryGrant {
                id: "legacy-unbound".into(),
                capability: "command.run".into(),
                principal_id: "agent-1".into(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: None,
                program_equals: None,
                elevated: None,
                executable_identity: None,
                workspace_id: None,
            },
            TemporaryGrant {
                id: "forged-python-identity".into(),
                capability: "command.run".into(),
                principal_id: "agent-1".into(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: Some("structured".into()),
                program_equals: Some(py.into()),
                elevated: Some(false),
                executable_identity: Some(py_id.clone()),
                workspace_id: None,
            },
            TemporaryGrant {
                id: "forged-gawk-identity".into(),
                capability: "command.run".into(),
                principal_id: "agent-1".into(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: Some("structured".into()),
                program_equals: Some(gawk.into()),
                elevated: Some(false),
                executable_identity: Some(gawk_id.clone()),
                workspace_id: None,
            },
            TemporaryGrant {
                id: "forged-raw".into(),
                capability: "command.run".into(),
                principal_id: "agent-1".into(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: Some("raw_shell".into()),
                program_equals: Some("/bin/bash".into()),
                elevated: Some(false),
                executable_identity: Some(ExecutableIdentityBinding {
                    path: "/bin/bash".into(),
                    content_sha256: "ff".repeat(32),
                    len: 1,
                    device: None,
                    inode: None,
                    policy_kind: "raw_shell".into(),
                }),
                workspace_id: None,
            },
        ]);

        // Same pinned python3.12 identity with argv changed from --version to -c payload.
        for (label, facts) in [
            (
                "python --version (benign argv)",
                OperationFacts {
                    capability: "command.run".into(),
                    kind: "structured".into(),
                    program: Some(py.into()),
                    elevated: false,
                    executable_identity: Some(py_id.clone()),
                    tags: vec!["--version".into()],
                    ..Default::default()
                },
            ),
            (
                "python -c payload (same pin)",
                OperationFacts {
                    capability: "command.run".into(),
                    kind: "structured".into(),
                    program: Some(py.into()),
                    elevated: false,
                    executable_identity: Some(py_id.clone()),
                    tags: vec!["-c".into(), "import os; os.system('id')".into()],
                    ..Default::default()
                },
            ),
            (
                "gawk script argv",
                OperationFacts {
                    capability: "command.run".into(),
                    kind: "structured".into(),
                    program: Some(gawk.into()),
                    elevated: false,
                    executable_identity: Some(gawk_id.clone()),
                    tags: vec!["BEGIN{system(\"id\")}".into()],
                    ..Default::default()
                },
            ),
            (
                "raw_shell",
                OperationFacts {
                    capability: "command.run".into(),
                    kind: "raw_shell".into(),
                    program: Some("/bin/bash".into()),
                    elevated: false,
                    ..Default::default()
                },
            ),
        ] {
            let v = evaluate_with_grants(&doc, &facts, &grants, 1, "agent-1");
            assert_ne!(
                v.decision,
                Decision::Allow,
                "{label} must not ride command.run temporary grant: {v:?}"
            );
            assert!(
                !v.reason.contains("temporary grant"),
                "{label}: grant overlay must not match: {}",
                v.reason
            );
        }
    }

    /// §7.7 puts explicit deny above every allow source. A grant issued before
    /// the deny existed must not keep authorizing the operation until it expires.
    #[test]
    fn explicit_deny_outranks_a_matching_temporary_grant() {
        let approved = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some("proj".into()),
            workspace_relative: true,
            workspace_id: Some("ws_default".into()),
            ..Default::default()
        };
        let grants = as_stored(vec![temporary_grant_from_facts(
            "g-deny".into(),
            "user-1".into(),
            9_999_999_999,
            &approved,
        )
        .expect("scoped grant")]);

        let doc = PolicyDocument {
            preset: AccessPreset::Custom,
            note: None,
            rules: vec![PolicyRule {
                id: "deny-proj-writes".into(),
                decision: Decision::Deny,
                priority: 0,
                capability: "filesystem.write".into(),
                when_elevated: None,
                when_kind: None,
                path_prefix: Some("proj".into()),
                program_equals: None,
                when_tag: None,
                description: Some("operator added this after the grant".into()),
            }],
        };

        let v = evaluate_with_grants(&doc, &approved, &grants, 1_700_000_000, "user-1");
        assert_eq!(v.decision, Decision::Deny, "{v:?}");
        assert!(!v.reason.contains("temporary grant"), "{}", v.reason);

        // A grant still lifts an Ask — that is the feature it exists for.
        let ask_only = preset_document(AccessPreset::WorkspaceOnly);
        assert_eq!(
            evaluate_with_grants(&ask_only, &approved, &grants, 1_700_000_000, "user-1").decision,
            Decision::Allow
        );
    }

    /// Restricted presets confirm credential-like reads (§7.1); full access does not.
    #[test]
    fn restricted_presets_ask_before_reading_sensitive_paths() {
        let sensitive = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(".env".into()),
            workspace_relative: true,
            workspace_id: Some("ws_default".into()),
            tags: vec![TAG_READS_SENSITIVE_LOCATION.into()],
            ..Default::default()
        };
        let ordinary = OperationFacts {
            tags: Vec::new(),
            path: Some("src/main.rs".into()),
            ..sensitive.clone()
        };

        for preset in [AccessPreset::WorkspaceOnly, AccessPreset::Recommended] {
            let doc = preset_document(preset);
            assert_eq!(
                evaluate(&doc, &sensitive).decision,
                Decision::Ask,
                "{preset:?} must confirm credential-like reads"
            );
            assert_eq!(
                evaluate(&doc, &ordinary).decision,
                Decision::Allow,
                "{preset:?} must not disturb ordinary reads"
            );
        }

        for preset in [AccessPreset::FullUserAccess, AccessPreset::FullAccess] {
            let doc = preset_document(preset);
            assert_eq!(
                evaluate(&doc, &sensitive).decision,
                Decision::Allow,
                "{preset:?} keeps the user's explicit choice without hidden friction"
            );
        }
    }

    /// A tag condition is a machine fact filter, not a free-text match.
    #[test]
    fn tag_conditioned_rules_require_the_exact_tag() {
        let doc = PolicyDocument {
            preset: AccessPreset::Custom,
            note: None,
            rules: vec![sensitive_read_ask_rule("t")],
        };
        let mut facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(".env".into()),
            ..Default::default()
        };
        assert_eq!(evaluate(&doc, &facts).decision, Decision::Allow);
        facts.tags = vec!["reads_sensitive".into()];
        assert_eq!(evaluate(&doc, &facts).decision, Decision::Allow);
        facts.tags = vec![TAG_READS_SENSITIVE_LOCATION.into()];
        assert_eq!(evaluate(&doc, &facts).decision, Decision::Ask);
    }

    #[test]
    fn non_command_temporary_grant_from_facts_still_works() {
        let grant = temporary_grant_from_facts(
            "g-fs".into(),
            "agent-1".into(),
            9_999_999_999,
            &OperationFacts {
                capability: "filesystem.write".into(),
                kind: "file".into(),
                path: Some("a".into()),
                workspace_relative: true,
                workspace_id: Some("ws_default".into()),
                ..Default::default()
            },
        )
        .expect("fs grant");
        assert_eq!(grant.capability, "filesystem.write");
        assert_eq!(grant.path_prefix.as_deref(), Some("a"));
        assert_eq!(grant.workspace_id.as_deref(), Some("ws_default"));

        let spaced = temporary_grant_from_facts(
            "g-spaced".into(),
            "agent-1".into(),
            9_999_999_999,
            &OperationFacts {
                capability: "filesystem.write".into(),
                kind: "file".into(),
                path: Some(" proj".into()),
                workspace_relative: true,
                workspace_id: Some("ws_default".into()),
                ..Default::default()
            },
        )
        .expect("spaces are part of a valid filename");
        assert_eq!(spaced.path_prefix.as_deref(), Some(" proj"));
    }

    fn sample_bounded_grant(tools: &[&str], max_uses: Option<u32>) -> BoundedToolGrant {
        BoundedToolGrant {
            grant_type: BoundedToolGrantType::BoundedTool,
            id: "grant_bounded_1".into(),
            principal_id: "user-1".into(),
            device_id: "dev_1".into(),
            tools: tools.iter().map(|t| (*t).to_string()).collect(),
            workspace_id: Some("ws_default".into()),
            expires_unix: 9_999_999_999,
            max_uses,
            uses: 0,
            minted_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn bounded_tool_grant_lifts_ask_not_deny() {
        let grant = sample_bounded_grant(&["fs_write"], Some(2));
        grant.validate().expect("valid grant");
        let grants = vec![StoredGrant::from(grant)];
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some("out.txt".into()),
            workspace_relative: true,
            workspace_id: Some("ws_default".into()),
            tool: Some("fs_write".into()),
            ..Default::default()
        };
        let ask = preset_document(AccessPreset::WorkspaceOnly);
        let lifted = evaluate_with_grants(&ask, &facts, &grants, 1_700_000_000, "user-1");
        assert_eq!(lifted.decision, Decision::Allow, "{lifted:?}");
        assert!(lifted.reason.contains("bounded tool grant"), "{}", lifted.reason);

        let deny = PolicyDocument {
            preset: AccessPreset::Custom,
            note: None,
            rules: vec![PolicyRule {
                id: "deny-writes".into(),
                decision: Decision::Deny,
                priority: 0,
                capability: "filesystem.write".into(),
                when_elevated: None,
                when_kind: None,
                path_prefix: None,
                program_equals: None,
                when_tag: None,
                description: Some("deny writes".into()),
            }],
        };
        let denied = evaluate_with_grants(&deny, &facts, &grants, 1_700_000_000, "user-1");
        assert_eq!(denied.decision, Decision::Deny, "{denied:?}");
    }

    #[test]
    fn bounded_tool_grant_refuses_wildcards_and_unknown_types() {
        assert!(canonical_bounded_tool("command.*").is_none());
        assert!(canonical_bounded_tool("*").is_none());
        assert!(canonical_bounded_tool("ownmesh_command_run") == Some("command_run"));
        let unknown = serde_json::json!([{
            "grant_type": "standing_allow",
            "id": "g1",
            "principal_id": "user-1",
            "expires_unix": 1_700_000_000
        }]);
        let err = serde_json::from_value::<Vec<StoredGrant>>(unknown).expect_err("unknown type");
        assert!(err.to_string().contains("grant_type"), "{err}");

        let legacy = serde_json::json!([{
            "id": "g-legacy",
            "capability": "logs.read",
            "principal_id": "user-1",
            "expires_unix": 1_700_000_000
        }]);
        let loaded: Vec<StoredGrant> = serde_json::from_value(legacy).expect("legacy temporary");
        assert!(loaded[0].as_temporary().is_some());
    }

    #[test]
    fn recommended_command_run_deny_is_not_lifted_by_bounded_grant() {
        let grant = sample_bounded_grant(&["command_run"], None);
        let grants = vec![StoredGrant::from(grant)];
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: "structured".into(),
            program: Some("true".into()),
            tool: Some("command_run".into()),
            ..Default::default()
        };
        let v = evaluate_with_grants(
            &preset_document(AccessPreset::Recommended),
            &facts,
            &grants,
            1_700_000_000,
            "user-1",
        );
        assert_eq!(v.decision, Decision::Deny, "{v:?}");
    }
}
