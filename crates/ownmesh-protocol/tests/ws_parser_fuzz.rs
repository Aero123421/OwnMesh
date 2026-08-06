//! WebSocket / device envelope parser fuzz target (harden-07).

use ownmesh_protocol::{fuzz_parse_envelope, Envelope, PROTOCOL_DEVICE_V1};

fn valid_minimal() -> String {
    format!(
        r#"{{"protocol":"{PROTOCOL_DEVICE_V1}","message_id":"msg_fuzz1","type":"ping","device_id":"dev_fuzz","seq":1,"sent_at":"2026-08-06T00:00:00Z","payload":{{}}}}"#
    )
}

#[test]
fn fuzz_randomish_corpus_does_not_panic() {
    let mut corpus: Vec<Vec<u8>> = vec![
        vec![],
        b"{".to_vec(),
        b"}".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"\"str\"".to_vec(),
        vec![0x00],
        vec![0xff, 0xfe, 0xfd],
        vec![b'A'; 16],
        vec![b'A'; 64 * 1024],
        valid_minimal().into_bytes(),
    ];

    let base = valid_minimal().into_bytes();
    for i in 0..base.len() {
        let mut m = base.clone();
        m[i] ^= 0x55;
        corpus.push(m);
        corpus.push(base[..i].to_vec());
    }

    corpus.push(valid_minimal().replace("ping", "ping\u{0000}").into_bytes());
    corpus.push(
        format!(
            r#"{{"protocol":"{PROTOCOL_DEVICE_V1}","message_id":"msg_x","type":"t","device_id":"dev_x","seq":1,"sent_at":"not-a-date","payload":null}}"#
        )
        .into_bytes(),
    );
    corpus.push(
        r#"{"protocol":"ownmesh.device/0.1","message_id":"msg_x","type":"t","device_id":"dev_x","seq":0,"sent_at":"2026-08-06T00:00:00Z","payload":{}}"#
            .as_bytes()
            .to_vec(),
    );
    corpus.push(vec![b'x'; 1024 * 1024 + 8]);

    for item in &corpus {
        fuzz_parse_envelope(item);
    }
}

#[test]
fn rejects_unsupported_protocol_and_non_object_payload() {
    let bad_proto = r#"{"protocol":"ownmesh.device/9.9","message_id":"msg_a","type":"ping","device_id":"dev_a","seq":1,"sent_at":"2026-08-06T00:00:00Z","payload":{}}"#;
    assert!(Envelope::parse_str(bad_proto).is_err());

    let bad_payload = format!(
        r#"{{"protocol":"{PROTOCOL_DEVICE_V1}","message_id":"msg_a","type":"ping","device_id":"dev_a","seq":1,"sent_at":"2026-08-06T00:00:00Z","payload":[]}}"#
    );
    assert!(Envelope::parse_str(&bad_payload).is_err());
}

#[test]
fn accepts_valid_and_roundtrips() {
    let raw = valid_minimal();
    let env = Envelope::parse_str(&raw).unwrap();
    let bytes = env.to_vec().unwrap();
    let again = Envelope::parse_slice(&bytes).unwrap();
    assert_eq!(again.message_type, "ping");
    assert_eq!(again.protocol, PROTOCOL_DEVICE_V1);
}
