//! SHA-256 helpers and `SHA256SUMS` parsing.

use crate::error::{UpdateError, UpdateResult};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Compute lowercase hex SHA-256 of `data`.
#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Verifies artifact bytes against a hexadecimal checksum (case-insensitive).
///
/// # Errors
///
/// Returns [`UpdateError::BadChecksum`] when the computed checksum differs.
pub fn verify_checksum(data: &[u8], expected_hex: &str) -> UpdateResult<()> {
    let actual = sha256_hex(data);
    if !actual.eq_ignore_ascii_case(expected_hex.trim()) {
        return Err(UpdateError::BadChecksum);
    }
    Ok(())
}

/// Parse a GNU `sha256sum`-style file into asset name → lowercase hex digest.
///
/// # Errors
///
/// Returns [`UpdateError::MissingMetadata`] when the file is empty or malformed.
pub fn parse_sha256sums(text: &str) -> UpdateResult<BTreeMap<String, String>> {
    let mut out = BTreeMap::new();
    for (idx, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let digest = parts.next().ok_or_else(|| {
            UpdateError::MissingMetadata(format!("SHA256SUMS line {}: missing digest", idx + 1))
        })?;
        if digest.len() != 64 || !digest.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(UpdateError::MissingMetadata(format!(
                "SHA256SUMS line {}: invalid digest",
                idx + 1
            )));
        }
        let name = parts.next().ok_or_else(|| {
            UpdateError::MissingMetadata(format!("SHA256SUMS line {}: missing file name", idx + 1))
        })?;
        let name = name.trim_start_matches('*');
        if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
            return Err(UpdateError::MissingMetadata(format!(
                "SHA256SUMS line {}: refused file name '{name}'",
                idx + 1
            )));
        }
        out.insert(name.to_owned(), digest.to_ascii_lowercase());
    }
    if out.is_empty() {
        return Err(UpdateError::MissingMetadata(
            "SHA256SUMS contained no entries".into(),
        ));
    }
    Ok(out)
}
