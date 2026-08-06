//! Local IPC spoofing / auth gate tests (harden-07).

use ownmesh_ipc::{
    generate_token, read_token_file, redact_secrets, write_token_file, AuthGate, FrameDecoder,
    PeerCredential, MAX_FRAME_BYTES,
};
use tempfile::tempdir;

#[test]
fn rejects_missing_empty_and_wrong_tokens() {
    let gate = AuthGate::new("expected-secret-token");
    for (token, client_name) in [
        ("", "ownmesh"),
        ("wrong", "ownmesh"),
        ("expected-secret-token", ""),
        ("expected-secret-token ", "ownmesh"),
    ] {
        let peer = PeerCredential {
            token: token.into(),
            client_name: client_name.into(),
            os_user_id: Some("other-user".into()),
            pid: Some(1),
        };
        let err = gate.verify(&peer).unwrap_err();
        assert_eq!(err.code(), "ipc_unauthorized", "{token:?} {client_name:?}");
    }
}

#[test]
fn accepts_only_exact_token_and_named_client() {
    let token = generate_token();
    let gate = AuthGate::new(token.clone());
    let peer = PeerCredential {
        token: token.clone(),
        client_name: "ownmesh-cli".into(),
        os_user_id: None,
        pid: Some(std::process::id()),
    };
    gate.verify(&peer).unwrap();
    let spoofed = PeerCredential {
        token: generate_token(),
        client_name: "ownmesh-cli".into(),
        os_user_id: peer.os_user_id.clone(),
        pid: peer.pid,
    };
    assert!(gate.verify(&spoofed).is_err());
}

#[test]
fn token_file_roundtrip_does_not_echo_into_redacted_logs() {
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

#[test]
fn generate_token_has_high_entropy_length() {
    let a = generate_token();
    let b = generate_token();
    assert_ne!(a, b);
    assert!(a.len() >= 32);
    assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
}
