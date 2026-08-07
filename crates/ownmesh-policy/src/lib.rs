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
}

/// Single policy rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        if let Some(prefix) = &self.path_prefix {
            match &facts.path {
                Some(p) if p.starts_with(prefix) => {}
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

/// Built-in presets.
#[must_use]
// Keeping each complete preset together makes its security rules auditable.
#[allow(clippy::too_many_lines)]
pub fn preset_document(preset: AccessPreset) -> PolicyDocument {
    match preset {
        AccessPreset::WorkspaceOnly => PolicyDocument {
            preset,
            note: Some("Only workspace-relative non-elevated ops; everything else deny".into()),
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
                    description: Some("elevated ops denied in Workspace Only".into()),
                },
                PolicyRule {
                    id: "ws-deny-raw-shell".into(),
                    decision: Decision::Deny,
                    priority: 90,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("raw_shell".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: Some("raw shell denied".into()),
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
                    description: Some("confirm writes".into()),
                },
                PolicyRule {
                    id: "ws-ask-command".into(),
                    decision: Decision::Ask,
                    priority: 50,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    description: Some("confirm commands".into()),
                },
            ],
        },
        AccessPreset::Recommended => PolicyDocument {
            preset,
            note: Some("Balanced defaults: ask on write/exec, allow reads".into()),
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
                    description: Some("confirm elevated".into()),
                },
                PolicyRule {
                    id: "rec-ask-raw-shell".into(),
                    decision: Decision::Ask,
                    priority: 90,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("raw_shell".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: Some("confirm raw shell".into()),
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
                    description: Some("confirm writes".into()),
                },
                PolicyRule {
                    id: "rec-ask-command".into(),
                    decision: Decision::Ask,
                    priority: 40,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    description: Some("confirm commands".into()),
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
                    description: Some("allow reads".into()),
                },
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
/// Client-supplied facts must never be passed here. `command.run` / `command.*`
/// temporary grants are always rejected fail-closed (structured, raw_shell,
/// interpreter, or otherwise) — argv/content cannot be pinned safely for reuse.
/// One-shot approval without `temporary_grant` remains the only command path.
/// Non-command capabilities may still mint principal/time-bounded grants.
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

    Ok(TemporaryGrant {
        id,
        capability: capability.to_owned(),
        principal_id,
        expires_unix,
        path_prefix: facts
            .path
            .as_ref()
            .map(|p| p.trim())
            .filter(|p| !p.is_empty())
            .map(ToOwned::to_owned),
        kind: None,
        program_equals: None,
        elevated: None,
        executable_identity: None,
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
    if let Some(prefix) = &grant.path_prefix {
        match &facts.path {
            Some(p) if p.starts_with(prefix.as_str()) => {}
            _ => return false,
        }
    }
    true
}

/// Evaluate with temporary grants that force Allow when still valid.
#[must_use]
pub fn evaluate_with_grants(
    doc: &PolicyDocument,
    facts: &OperationFacts,
    grants: &[TemporaryGrant],
    now_unix: i64,
    principal_id: &str,
) -> PolicyVerdict {
    for g in grants {
        if !temporary_grant_matches(g, facts, principal_id, now_unix) {
            continue;
        }
        return PolicyVerdict {
            decision: Decision::Allow,
            matched_rule_id: Some(g.id.clone()),
            reason: format!("temporary grant {}", g.id),
        };
    }
    evaluate(doc, facts)
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
    fn recommended_asks_on_command() {
        let doc = preset_document(AccessPreset::Recommended);
        let facts = OperationFacts {
            capability: "command.run".into(),
            kind: "structured".into(),
            program: Some("cargo".into()),
            ..Default::default()
        };
        assert_eq!(evaluate(&doc, &facts).decision, Decision::Ask);
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
            path: Some("/workspace/out.txt".into()),
            ..Default::default()
        };
        let grants = vec![TemporaryGrant {
            id: "g-fs".into(),
            capability: "filesystem.write".into(),
            principal_id: "user-1".into(),
            expires_unix: 9_999_999_999,
            path_prefix: None,
            kind: None,
            program_equals: None,
            elevated: None,
            executable_identity: None,
        }];
        let v = evaluate_with_grants(&doc, &facts, &grants, 1_700_000_000, "user-1");
        assert_eq!(v.decision, Decision::Allow);
        assert!(v.reason.contains("temporary grant"), "{}", v.reason);
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
        let grants = vec![
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
            },
        ];

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

    #[test]
    fn non_command_temporary_grant_from_facts_still_works() {
        let grant = temporary_grant_from_facts(
            "g-fs".into(),
            "agent-1".into(),
            9_999_999_999,
            &OperationFacts {
                capability: "filesystem.write".into(),
                kind: "file".into(),
                path: Some("/workspace/a".into()),
                ..Default::default()
            },
        )
        .expect("fs grant");
        assert_eq!(grant.capability, "filesystem.write");
        assert_eq!(grant.path_prefix.as_deref(), Some("/workspace/a"));
    }
}
