//! OwnMesh device protocol envelopes and version negotiation.
//!
//! Design authority: `OWNMESH_SPECIFICATION.ja.md` §21.

#![forbid(unsafe_code)]

mod envelope;
mod version;

pub use envelope::{fuzz_parse_envelope, Envelope, PROTOCOL_DEVICE_V1};
pub use version::{
    assert_current_wire_constant, default_supported_versions, negotiate, NegotiatedProtocol,
    ProtocolVersion,
};

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

/// Shared fixtures directory (same files as TypeScript package).
pub const SHARED_FIXTURES_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec-bundle/examples/fixtures"
);

/// Shared JSON Schema directory.
pub const SHARED_SCHEMAS_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec-bundle/schemas");

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_domain::{ErrorCode, ExitCode, Timestamp};
    use std::fs;
    use std::path::Path;
    use std::time::Duration;
    use time::macros::datetime;

    #[test]
    fn crate_metadata_is_stable() {
        assert_eq!(crate_name(), "ownmesh-protocol");
        assert!(!crate_version().is_empty());
        assert_current_wire_constant().unwrap();
    }

    #[test]
    fn fixture_envelope_roundtrip() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("protocol_envelope.json");
        let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let env = Envelope::parse_str(&raw).expect("parse fixture");
        let encoded = serde_json::to_value(&env).unwrap();
        let original: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(encoded, original);
        let pretty = env.to_pretty_json().unwrap();
        let tmp = path.with_extension("json.roundtrip-tmp");
        fs::write(&tmp, format!("{pretty}\n")).expect("write temp fixture");
        let reloaded = fs::read_to_string(&tmp).expect("read temp");
        let _ = fs::remove_file(&tmp);
        let again = Envelope::parse_str(&reloaded).unwrap();
        assert_eq!(again, env);
    }

    #[test]
    fn schema_validates_envelope_fixture() {
        let schema_path = Path::new(SHARED_SCHEMAS_DIR).join("protocol-envelope.schema.json");
        let schema_raw = fs::read_to_string(&schema_path).expect("schema");
        let schema_json: serde_json::Value = serde_json::from_str(&schema_raw).unwrap();
        let validator = jsonschema::validator_for(&schema_json).expect("compile");

        let fixture_path = Path::new(SHARED_FIXTURES_DIR).join("protocol_envelope.json");
        let data: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(fixture_path).unwrap()).unwrap();
        if let Err(err) = validator.validate(&data) {
            panic!("envelope fixture failed schema validation: {err}");
        }
    }

    #[test]
    fn bad_envelope_taxonomy() {
        let cases: &[(&[u8], ErrorCode)] = &[
            (b"", ErrorCode::BadEnvelope),
            (b"{", ErrorCode::BadEnvelope),
            (
                br#"{"protocol":"ownmesh.device/9.9","message_id":"msg_x","type":"t","device_id":"dev_x","seq":0,"sent_at":"2026-08-06T00:00:00Z","payload":{}}"#,
                ErrorCode::UnsupportedProtocol,
            ),
        ];
        for (bytes, code) in cases {
            let err = Envelope::parse_slice(bytes).unwrap_err();
            assert_eq!(err.code, *code, "input={bytes:?}");
            assert_eq!(err.exit_code(), code.exit_code());
        }
    }

    #[test]
    fn hello_fixture_version_negotiation() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("protocol_hello.json");
        let raw = fs::read_to_string(path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let offered: Vec<ProtocolVersion> = v["offered"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| ProtocolVersion::parse(x.as_str().unwrap()).unwrap())
            .collect();
        let supported: Vec<ProtocolVersion> = v["supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| ProtocolVersion::parse(x.as_str().unwrap()).unwrap())
            .collect();
        let negotiated = negotiate(&offered, &supported).unwrap();
        assert_eq!(negotiated.wire, v["selected"].as_str().unwrap());
    }

    #[test]
    fn expired_envelope_unit() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("protocol_envelope.json");
        let raw = fs::read_to_string(path).unwrap();
        let env = Envelope::parse_str(&raw).unwrap();
        let now = Timestamp::from_offset(datetime!(2099-01-01 00:00:00 UTC));
        let err = env
            .validate_expiry_at(now, Duration::from_secs(0))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Expired);
        assert_eq!(err.exit_code(), ExitCode::TimeoutCancelled);
    }
}
