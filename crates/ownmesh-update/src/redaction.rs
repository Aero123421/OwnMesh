//! Secret / URL redaction for JSON and human diagnostics.

use serde_json::{Map, Value};

const REDACTED: &str = "[REDACTED]";

/// True when a key or value looks secret-bearing.
#[must_use]
pub fn looks_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("private")
        || lower.contains("authorization")
        || lower.contains("api_key")
        || lower.contains("apikey")
}

/// Redact query strings and userinfo from a URL for logs.
#[must_use]
pub fn redact_url(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return if looks_secret(raw) {
            REDACTED.to_owned()
        } else {
            raw.to_owned()
        };
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

/// Recursively redact secret-looking object keys in JSON.
#[must_use]
pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                if looks_secret(k) {
                    out.insert(k.clone(), Value::String(REDACTED.into()));
                } else {
                    out.insert(k.clone(), redact_json(v));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(redact_json).collect()),
        Value::String(s) if looks_secret(s) => Value::String(REDACTED.into()),
        other => other.clone(),
    }
}
