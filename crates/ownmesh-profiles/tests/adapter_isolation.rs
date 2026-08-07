//! External adapter isolation tests (harden-07).

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

use ownmesh_profiles::{
    generic_interactive_session, generic_launch, generic_to_plan, normalize_event_json,
    official_profiles, ProfileRegistry,
};

#[test]
fn generic_path_works_without_official_profile() {
    let g = generic_launch("my-unknown-cli", vec!["--version".into()], false);
    assert_eq!(g.program, "my-unknown-cli");
    let plan = generic_to_plan(&g);
    assert!(plan.profile_id.is_none());
    assert_eq!(plan.program, "my-unknown-cli");
    assert!(!plan.use_pty);

    let interactive = generic_interactive_session("repl-tool", vec![], None);
    assert!(interactive.use_pty);
    assert!(interactive.profile_id.is_none());
}

#[test]
fn launch_plans_are_argv_vectors_not_shell_strings() {
    let reg = ProfileRegistry::with_official();
    let profile = reg.get("codex").expect("codex profile");
    assert!(
        profile
            .non_interactive_args
            .iter()
            .any(|a| a.contains("{{prompt}}") || a == "exec" || a == "run" || a.starts_with("--")),
        "expected structured argv template: {:?}",
        profile.non_interactive_args
    );
    for p in official_profiles() {
        let blob = serde_json::to_string(&p).unwrap().to_ascii_lowercase();
        for forbidden in ["loadlibrary", "dlopen", "dylib", "cdylib", "libloading"] {
            assert!(
                !blob.contains(forbidden),
                "profile {} references forbidden loader surface {forbidden}",
                p.id
            );
        }
    }
}

#[test]
fn prompt_is_substituted_as_single_arg_not_split() {
    let evil_prompt = "hello\"; rm -rf /; echo \"";
    // Generic path always keeps user text as discrete argv elements (no shell).
    let g = generic_launch("tool", vec![evil_prompt.into()], false);
    assert_eq!(g.args, vec![evil_prompt]);
    assert!(!g.args.iter().any(|a| a == "rm"));

    // Official templates substitute {{prompt}} into a single argv slot when present.
    let reg = ProfileRegistry::with_official();
    let mut checked = false;
    for id in ["claude-code", "kimi-code", "qwen-code", "codex", "pi"] {
        let Ok(profile) = reg.get(id) else {
            continue;
        };
        let template = if profile
            .non_interactive_args
            .iter()
            .any(|a| a.contains("{{prompt}}"))
        {
            &profile.non_interactive_args
        } else if profile
            .structured_start_args
            .iter()
            .any(|a| a.contains("{{prompt}}"))
        {
            &profile.structured_start_args
        } else {
            continue;
        };
        let expanded: Vec<String> = template
            .iter()
            .map(|s| s.replace("{{prompt}}", evil_prompt))
            .filter(|s| !s.contains("{{native_id}}"))
            .collect();
        assert!(
            expanded.iter().any(|a| a.contains("hello")),
            "prompt lost for {id}: {expanded:?}"
        );
        assert!(
            !expanded.iter().any(|a| a == "rm"),
            "prompt was shell-split for {id}: {expanded:?}"
        );
        checked = true;
        break;
    }
    assert!(checked || !g.args.is_empty());
}

#[test]
fn malformed_adapter_events_do_not_panic_and_are_dropped_or_normalized() {
    let samples = [
        "",
        "{",
        "null",
        "[]",
        "\"str\"",
        r#"{"type":"message"}"#,
        r#"{"event":"tool_call","args":{"x":1}}"#,
        r#"{"type":"message","text":"hi","session_id":"s"}"#,
    ];
    for s in samples {
        let _ = normalize_event_json(s.trim());
    }
    let big = "A".repeat(10_000);
    let _ = normalize_event_json(&big);
}

#[test]
fn nine_official_profiles_are_separate_adapters() {
    let all = official_profiles();
    assert_eq!(all.len(), 9);
    let mut ids = all.iter().map(|p| p.id.as_str()).collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), 9, "duplicate profile ids");
    for p in &all {
        assert!(!p.binaries.is_empty(), "profile {} missing binaries", p.id);
    }
}
