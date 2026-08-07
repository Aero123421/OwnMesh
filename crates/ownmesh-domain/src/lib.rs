//! OwnMesh domain types, stable identifiers, shared models, and error taxonomy.
//!
//! Design authority: `OWNMESH_SPECIFICATION.ja.md` (§7, §12, §14.7, §16.3, §20, §21).

#![forbid(unsafe_code)]

mod entities;
mod error;
mod ids;
mod pagination;
mod time;

pub use entities::*;
pub use error::*;
pub use ids::*;
pub use pagination::*;
pub use time::*;

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

/// Workspace-relative path to shared JSON fixtures (Rust ↔ TypeScript).
pub const SHARED_FIXTURES_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../spec-bundle/examples/fixtures"
);

/// Workspace-relative path to JSON Schema documents.
pub const SHARED_SCHEMAS_DIR: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec-bundle/schemas");

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn crate_metadata_is_stable() {
        assert_eq!(crate_name(), "ownmesh-domain");
        assert!(!crate_version().is_empty());
    }

    fn read_fixture(name: &str) -> String {
        let path = Path::new(SHARED_FIXTURES_DIR).join(name);
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
    }

    fn assert_json_roundtrip<T>(name: &str)
    where
        T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let path = Path::new(SHARED_FIXTURES_DIR).join(name);
        let raw =
            fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let value: T = serde_json::from_str(&raw).unwrap_or_else(|e| {
            panic!("deserialize {name}: {e}\n{raw}");
        });
        let encoded = serde_json::to_value(&value).expect("serialize");
        let original: serde_json::Value = serde_json::from_str(&raw).expect("parse original");
        assert_eq!(encoded, original, "round-trip mismatch for fixture {name}");
        // write path: serialize to a temp file beside the shared fixtures, then reload
        let pretty = serde_json::to_string_pretty(&value).expect("pretty");
        let tmp = path.with_extension("json.roundtrip-tmp");
        fs::write(&tmp, format!("{pretty}\n")).expect("write temp fixture");
        let reloaded_raw = fs::read_to_string(&tmp).expect("read temp fixture");
        let _ = fs::remove_file(&tmp);
        let again: T = serde_json::from_str(&reloaded_raw).expect("re-parse written fixture");
        assert_eq!(again, value);
    }

    #[test]
    fn fixtures_roundtrip_all_entities() {
        assert_json_roundtrip::<Tenant>("tenant.json");
        assert_json_roundtrip::<Principal>("principal.json");
        assert_json_roundtrip::<Membership>("membership.json");
        assert_json_roundtrip::<Device>("device.json");
        assert_json_roundtrip::<Workspace>("workspace.json");
        assert_json_roundtrip::<CapabilityGrant>("capability_grant.json");
        assert_json_roundtrip::<PolicyRule>("policy_rule.json");
        assert_json_roundtrip::<Approval>("approval.json");
        assert_json_roundtrip::<Operation>("operation.json");
        assert_json_roundtrip::<Session>("session.json");
        assert_json_roundtrip::<AuditEvent>("audit_event.json");
        assert_json_roundtrip::<ErrorEnvelope>("error_envelope.json");
        assert_json_roundtrip::<PageRequest>("page_request.json");
    }

    #[test]
    fn schema_validates_domain_fixtures() {
        let schema_path = Path::new(SHARED_SCHEMAS_DIR).join("domain-entities.schema.json");
        let schema_raw = fs::read_to_string(&schema_path)
            .unwrap_or_else(|e| panic!("read schema {}: {e}", schema_path.display()));
        let schema_json: serde_json::Value =
            serde_json::from_str(&schema_raw).expect("parse schema");

        let cases = [
            ("tenant.json", "tenant"),
            ("principal.json", "principal"),
            ("membership.json", "membership"),
            ("device.json", "device"),
            ("workspace.json", "workspace"),
            ("capability_grant.json", "capability_grant"),
            ("policy_rule.json", "policy_rule"),
            ("approval.json", "approval"),
            ("operation.json", "operation"),
            ("session.json", "session"),
            ("audit_event.json", "audit_event"),
        ];

        for (file, def) in cases {
            let data: serde_json::Value =
                serde_json::from_str(&read_fixture(file)).expect("fixture json");
            // Validate against the $defs entry by wrapping with a one-shot schema ref.
            let focused = serde_json::json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$ref": format!("#/$defs/{def}"),
                "$defs": schema_json.get("$defs").cloned().unwrap_or_default(),
            });
            let focused_validator = jsonschema::validator_for(&focused).expect("compile focused");
            if let Err(err) = focused_validator.validate(&data) {
                panic!("schema validation failed for {file} ({def}): {err}");
            }
        }
    }

    #[test]
    fn taxonomy_unknown_id_and_expired() {
        let err = DeviceId::parse("nope_123").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
        assert_eq!(err.exit_code(), ExitCode::UsageConfig);

        let exp = Expiry::new(Timestamp::parse("2020-01-01T00:00:00Z").unwrap());
        let now = Timestamp::parse("2026-01-01T00:00:00Z").unwrap();
        let err = exp
            .check_at(now, std::time::Duration::from_secs(0))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Expired);
        assert_eq!(err.exit_code(), ExitCode::TimeoutCancelled);
    }
}
