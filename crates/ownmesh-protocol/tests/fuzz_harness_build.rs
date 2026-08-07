//! Stable equivalent of the cargo-fuzz target: builds with `cargo test` and
//! feeds adversarial inputs into the protocol parser without panicking.

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

use ownmesh_protocol::fuzz_parse_envelope;

#[test]
fn harness_builds_and_runs_on_corpus() {
    let corpus: &[&[u8]] = &[
        b"",
        b"\x00\x01\x02",
        b"{",
        b"}",
        b"null",
        b"[]",
        b"\"string\"",
        br#"{"protocol":"ownmesh.device/1.0"}"#,
        br#"{"protocol":"ownmesh.device/1.0","message_id":"msg_x","type":"t","device_id":"dev_x","seq":0,"sent_at":"2026-08-06T00:00:00Z","payload":{}}"#,
        br#"{"protocol":"ownmesh.device/9.9","message_id":"msg_x","type":"t","device_id":"dev_x","seq":0,"sent_at":"2026-08-06T00:00:00Z","payload":{}}"#,
        // oversized-ish repetitive payload prefix
        &[b'A'; 4096],
    ];

    for item in corpus {
        fuzz_parse_envelope(item);
    }

    // Structured walk of single-byte mutations of a valid minimal envelope.
    let base = br#"{"protocol":"ownmesh.device/1.0","message_id":"msg_a","type":"ping","device_id":"dev_a","seq":1,"sent_at":"2026-08-06T00:00:00Z","payload":{}}"#;
    for i in 0..base.len() {
        let mut mutated = base.to_vec();
        mutated[i] ^= 0x7f;
        fuzz_parse_envelope(&mutated);
    }
}
