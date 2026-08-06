//! Local IPC spoofing / auth gate tests (sec-01 / harden-07).

use ownmesh_ipc::{
    canonicalize_principal_key, generate_token, normalize_principal_part, read_token_file,
    redact_secrets, write_token_file, AuthGate, FrameDecoder, OsPeerIdentity, PeerCredential,
    MAX_FRAME_BYTES,
};
use tempfile::tempdir;

#[test]
fn rejects_shared_token_path() {
    let gate = AuthGate::for_user("1000");
    for token in ["shared", "expected-secret-token", "x"] {
        let peer = PeerCredential {
            token: token.into(),
            client_name: "ownmesh".into(),
            os_user_id: Some("1000".into()),
            pid: Some(1),
            client_credential: None,
        };
        let err = gate.verify(&peer).unwrap_err();
        assert_eq!(err.code(), "ipc_unauthorized", "{token:?}");
    }
}

#[test]
fn principal_ignores_self_reported_client_name() {
    let gate = AuthGate::for_user("1000");
    let os = OsPeerIdentity {
        pid: 9,
        user_id: "1000".into(),
        exe_path: Some("/bin/ownmesh".into()),
    };
    let a = PeerCredential {
        token: String::new(),
        client_name: "admin".into(),
        os_user_id: None,
        pid: None,
        client_credential: None,
    };
    let b = PeerCredential {
        token: String::new(),
        client_name: "root".into(),
        os_user_id: None,
        pid: None,
        client_credential: None,
    };
    let pa = gate.resolve_principal(&os, &a).unwrap();
    let pb = gate.resolve_principal(&os, &b).unwrap();
    assert_eq!(pa, pb);
    assert_eq!(pa, os.principal_key());
    assert!(!pa.contains("admin"));
    assert!(!pa.contains("root"));
}

#[test]
fn unknown_client_credential_rejected() {
    let gate = AuthGate::for_user("alice");
    let os = OsPeerIdentity {
        pid: 1,
        user_id: "alice".into(),
        exe_path: None,
    };
    let presented = PeerCredential {
        token: String::new(),
        client_name: "x".into(),
        os_user_id: None,
        pid: None,
        client_credential: Some("not-issued".into()),
    };
    let err = gate.resolve_principal(&os, &presented).unwrap_err();
    assert_eq!(err.code(), "ipc_unauthorized");
}

#[test]
fn same_client_credential_different_names_map_to_same_principal() {
    let gate = AuthGate::for_user("alice");
    let secret = gate
        .issue_client_credential("agent-chatgpt", "alice")
        .unwrap();
    let os = OsPeerIdentity {
        pid: 11,
        user_id: "alice".into(),
        exe_path: Some("/opt/ownmesh".into()),
    };
    let names = ["chatgpt", "ChatGPT", "admin", "root", ""];
    let mut principals = Vec::new();
    for name in names {
        let presented = PeerCredential {
            token: String::new(),
            client_name: name.into(),
            os_user_id: None,
            pid: None,
            client_credential: Some(secret.clone()),
        };
        principals.push(gate.resolve_principal(&os, &presented).unwrap());
    }
    assert!(principals.iter().all(|p| p == "agent-chatgpt"));
    assert!(principals
        .iter()
        .all(|p| !p.contains("admin") && !p.contains("root")));
}

#[test]
fn shared_token_rejected_even_when_os_peer_would_pass() {
    let gate = AuthGate::for_user("1000");
    let os = OsPeerIdentity {
        pid: 1,
        user_id: "1000".into(),
        exe_path: Some("/bin/ownmesh".into()),
    };
    let presented = PeerCredential {
        token: "leftover-daemon-token".into(),
        client_name: "ownmesh".into(),
        os_user_id: Some("1000".into()),
        pid: Some(1),
        client_credential: None,
    };
    let err = gate.resolve_principal(&os, &presented).unwrap_err();
    assert_eq!(err.code(), "ipc_unauthorized");
    assert!(err.to_string().to_ascii_lowercase().contains("disabled"));
}

#[test]
fn principal_key_is_stable_across_pid_and_executable_availability() {
    let a = OsPeerIdentity {
        pid: 1,
        user_id: "1000".into(),
        exe_path: Some(r"C:\OwnMesh\bin\ownmesh.exe".into()),
    };
    let b = OsPeerIdentity {
        pid: 9999,
        user_id: "1000".into(),
        exe_path: Some("c:/ownmesh/bin/ownmesh.exe".into()),
    };
    assert_eq!(a.principal_key(), b.principal_key());
    assert_eq!(a.principal_key(), "user:1000");
    assert!(!a.principal_key().contains("9999"));
    assert!(!a.principal_key().contains("exe:"));
}

#[test]
fn normalize_principal_collapses_path_aliases() {
    let a = normalize_principal_part(r"C:\OwnMesh\bin\..\ownmesh.exe");
    let b = normalize_principal_part("c:/ownmesh/ownmesh.exe");
    assert_eq!(a, b);
}

#[test]
fn legacy_process_scoped_revocation_aliases_cannot_escape_stable_user() {
    let gate = AuthGate::for_user("Alice");
    let secret = gate
        .issue_client_credential(
            r#" USER : ALICE : EXE : "C:\OwnMesh\bin\..\ownmesh.exe" "#,
            " ALICE ",
        )
        .unwrap();
    let os = OsPeerIdentity {
        pid: 123,
        user_id: "alice".into(),
        exe_path: None,
    };
    let presented = PeerCredential {
        token: String::new(),
        client_name: "ignored".into(),
        os_user_id: None,
        pid: None,
        client_credential: Some(secret),
    };
    let issued = gate.resolve_principal(&os, &presented).unwrap();
    assert_eq!(issued, "user:alice");
    for revoke_alias in [
        "user:alice:exe:c:/ownmesh/ownmesh.exe",
        "user:alice:pid:123",
        "user:alice:exe:c:/crafted:pid:456",
        "user:alice:pid:456:exe:c:/crafted",
    ] {
        assert_eq!(canonicalize_principal_key(revoke_alias), issued);
    }
}

#[test]
fn default_os_principal_survives_reconnect_without_executable() {
    let first = OsPeerIdentity {
        pid: 1,
        user_id: "1000".into(),
        exe_path: None,
    };
    let reconnect = OsPeerIdentity {
        pid: 65_535,
        user_id: "1000".into(),
        exe_path: None,
    };
    assert_eq!(first.principal_key(), reconnect.principal_key());
    assert_eq!(first.principal_key(), "user:1000");
    assert!(!first.principal_key().contains("pid"));
}

#[test]
fn legacy_token_file_roundtrip_does_not_echo_into_redacted_logs() {
    let dir = tempdir().unwrap();
    let token = generate_token();
    write_token_file(dir.path(), &token).unwrap();
    let loaded = read_token_file(dir.path()).unwrap();
    assert_eq!(loaded, token);

    let log_line = format!("connecting with token={token}");
    let redacted = redact_secrets(&log_line, &[&token]);
    assert!(!redacted.contains(&token));
    assert!(redacted.contains("[REDACTED]"));
}

#[test]
fn frame_decoder_rejects_oversize_length_prefix() {
    let mut dec = FrameDecoder::new();
    let evil_len = (MAX_FRAME_BYTES as u64 + 1).to_be_bytes();
    let err = dec.push(&evil_len).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("exceeds") || msg.to_ascii_lowercase().contains("frame"),
        "{msg}"
    );
}

#[test]
fn frame_decoder_tolerates_garbage_without_panic() {
    let mut dec = FrameDecoder::new();
    for chunk in [
        &b""[..],
        &[0xff, 0xff],
        &[0x00, 0x00, 0x00, 0x02, b'{', b'}'],
        &[0x00, 0x00, 0x00, 0x00],
    ] {
        let _ = dec.push(chunk);
    }
}

#[cfg(windows)]
#[test]
fn windows_current_user_is_os_attested_sid_not_environment_label_or_pid() {
    let user = ownmesh_ipc::current_os_user_id();
    assert!(user.starts_with("sid:"), "{user}");
    assert!(!user.contains("pid"), "{user}");
    assert_eq!(user, ownmesh_ipc::current_os_user_id());
}

#[test]
fn generate_token_has_high_entropy_length() {
    let a = generate_token();
    let b = generate_token();
    assert_ne!(a, b);
    assert!(a.len() >= 32);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}
