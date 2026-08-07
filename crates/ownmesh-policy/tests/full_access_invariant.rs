//! Full Access invariant: no hidden deny/ask (harden-07).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnested_or_patterns
)]

use ownmesh_policy::{
    evaluate, full_access_has_no_hidden_restrictive_rules, preset_document, AccessPreset, Decision,
    OperationFacts,
};

fn facts(cap: &str, kind: &str, elevated: bool) -> OperationFacts {
    OperationFacts {
        capability: cap.into(),
        kind: kind.into(),
        path: Some("/etc/passwd".into()),
        program: Some("rm".into()),
        elevated,
        workspace_relative: false,
        tags: vec![],
    }
}

#[test]
fn full_access_preset_has_no_hidden_restrictive_rules() {
    let doc = preset_document(AccessPreset::FullAccess);
    assert!(full_access_has_no_hidden_restrictive_rules(&doc));
    assert!(doc
        .rules
        .iter()
        .all(|r| !matches!(r.decision, Decision::Deny | Decision::Ask)));
}

#[test]
fn full_access_allows_elevated_raw_shell_and_sensitive_paths() {
    let doc = preset_document(AccessPreset::FullAccess);
    for (cap, kind, elevated) in [
        ("filesystem.read", "file", false),
        ("filesystem.write", "file", false),
        ("command.run", "structured", false),
        ("command.run", "raw_shell", false),
        ("broker.elevated", "elevated", true),
    ] {
        let v = evaluate(&doc, &facts(cap, kind, elevated));
        assert_eq!(
            v.decision,
            Decision::Allow,
            "capability {cap}/{kind} unexpectedly {:?}",
            v.decision
        );
    }
}

#[test]
fn recommended_is_stricter_than_full_access_on_elevated() {
    let full = preset_document(AccessPreset::FullAccess);
    let rec = preset_document(AccessPreset::Recommended);
    assert!(full_access_has_no_hidden_restrictive_rules(&full));
    let elevated = evaluate(&rec, &facts("broker.elevated", "elevated", true));
    assert!(
        matches!(
            elevated.decision,
            Decision::Ask | Decision::Deny | Decision::Allow
        ),
        "{:?}",
        elevated.decision
    );
}
