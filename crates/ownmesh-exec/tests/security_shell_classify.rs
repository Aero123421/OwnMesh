//! Adversarial classification tests: shell binaries must never downgrade to structured.

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

use ownmesh_exec::{
    args_have_shell_exec_flag, classify_from_request, is_shell_binary, CommandKind,
};
#[cfg(unix)]
use ownmesh_exec::{classify_from_request_in_dir, resolve_executable_path};

fn assert_raw(program: &str, args: &[&str]) {
    let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let kind = classify_from_request(Some("structured"), program, &argv);
    assert_eq!(
        kind,
        CommandKind::RawShell,
        "expected RawShell for program={program:?} args={args:?}"
    );
    assert!(
        is_shell_binary(program),
        "expected is_shell_binary({program})"
    );
}

#[test]
fn known_shells_are_raw_regardless_of_argv() {
    let programs = [
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "csh",
        "tcsh",
        "fish",
        "cmd",
        "cmd.exe",
        "CMD.EXE",
        "powershell",
        "powershell.exe",
        "pwsh",
        "pwsh.exe",
        "/bin/sh",
        "/bin/bash",
        "/usr/bin/zsh",
        r"C:\Windows\System32\cmd.exe",
        "bash.exe",
        "Bash.EXE",
        "SH",
        "Pwsh.EXE",
    ];
    for program in programs {
        assert_raw(program, &[]);
        assert_raw(program, &["--version"]);
        assert_raw(program, &["-c", "id"]);
    }
}

#[test]
fn clustered_and_joined_exec_flag_bypasses_stay_raw() {
    let cases: &[(&str, &[&str])] = &[
        ("bash", &["-lc", "id"]),
        ("/bin/bash", &["-lc", "whoami"]),
        ("sh", &["-ic", "echo hi"]),
        ("zsh", &["-lc", "true"]),
        ("csh", &["-c", "id"]),
        ("tcsh", &["-c", "id"]),
        ("bash", &["-ce", "echo x"]),
        ("cmd.exe", &["/c:echo hi"]),
        ("CMD", &["/C:dir"]),
        ("cmd", &["/k", "dir"]),
        ("powershell", &["-Command:Get-Process"]),
        ("powershell.exe", &["-EncodedCommand:QQA="]),
        ("pwsh", &["-EncodedCommand", "QQA="]),
        ("pwsh.exe", &["-enc", "QQA="]),
        ("powershell", &["-command", "Get-Host"]),
        ("bash", &["-c", "id"]),
    ];
    for (program, args) in cases {
        assert_raw(program, args);
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        assert!(
            args_have_shell_exec_flag(&argv),
            "exec-flag helper should detect {args:?}"
        );
    }
}

#[test]
fn env_direct_shell_indirection_is_raw_and_compound_options_fail_closed() {
    let cases: &[(&str, &[&str])] = &[
        ("env", &["bash", "--version"]),
        ("/usr/bin/env", &["sh", "script.sh"]),
        ("env.exe", &["pwsh.exe", "-NoProfile"]),
        ("env", &["NAME=value", "bash", "-lc", "id"]),
        ("env", &["-S", "bash -lc 'id'"]),
        ("env", &["-S", "NAME=value bash -lc 'id'"]),
        ("env", &["--split-string=sh -c id"]),
        ("env", &["-S", r"sh\_-c\_id"]),
        ("env", &["-S", "${SHELL} -c id"]),
        ("env", &["env", "sh", "-c", "id"]),
        ("env", &["PATH=/attacker", "innocent", "-c", "id"]),
        ("env", &["-iS", "bash -lc id"]),
        // All env is conservative raw, avoiding parser-specific bypasses.
        ("env", &["echo", "benign"]),
    ];
    for (program, args) in cases {
        let argv = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            classify_from_request(Some("structured"), program, &argv),
            CommandKind::RawShell,
            "env bypass must be raw: {program:?} {args:?}"
        );
    }
}

#[cfg(unix)]
#[test]
fn resolved_shell_symlink_is_raw_including_relative_to_request_cwd() {
    use std::os::unix::fs::symlink;

    let dir = tempfile::tempdir().unwrap();
    let alias = dir.path().join("innocent-tool");
    symlink("/bin/sh", &alias).unwrap();
    let no_args = Vec::<String>::new();
    assert!(is_shell_binary(alias.to_str().unwrap()));
    let resolved = resolve_executable_path("./innocent-tool", Some(dir.path())).unwrap();
    assert!(
        is_shell_binary(resolved.to_str().unwrap()),
        "resolved target must retain shell classification: {}",
        resolved.display()
    );
    assert_eq!(
        classify_from_request(Some("structured"), alias.to_str().unwrap(), &no_args),
        CommandKind::RawShell
    );
    assert_eq!(
        classify_from_request_in_dir(
            Some("structured"),
            "./innocent-tool",
            &no_args,
            Some(dir.path()),
        ),
        CommandKind::RawShell
    );
}

#[test]
fn non_shell_programs_remain_structured() {
    let cases: &[(&str, &[&str])] = &[
        ("echo", &["hi"]),
        ("/bin/ls", &["-la"]),
        ("git", &["status", "-c", "foo=bar"]),
        ("python3", &["-c", "print(1)"]),
        ("node", &["-e", "1"]),
        ("cargo", &["test"]),
    ];
    for (program, args) in cases {
        let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let kind = classify_from_request(Some("structured"), program, &argv);
        assert_eq!(
            kind,
            CommandKind::Structured,
            "non-shell must stay structured: {program:?} {args:?}"
        );
        assert!(!is_shell_binary(program));
    }
}

#[test]
fn client_structured_claim_cannot_launder_shell() {
    let kind = classify_from_request(Some("structured"), "bash", &["-lc".into(), "id".into()]);
    assert_eq!(kind, CommandKind::RawShell);
    assert_eq!(kind.as_str(), "raw_shell");

    let kind = classify_from_request(Some("STRUCTURED"), "cmd.exe", &["/c:whoami".into()]);
    assert_eq!(kind, CommandKind::RawShell);
}
