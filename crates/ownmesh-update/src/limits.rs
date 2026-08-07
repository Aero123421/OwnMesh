//! Fail-closed size and time budgets.

/// Maximum GitHub release JSON body size.
pub const MAX_METADATA_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum `SHA256SUMS` body size.
pub const MAX_CHECKSUMS_BYTES: u64 = 1024 * 1024;
/// Maximum signature body size.
pub const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
/// Maximum portable archive size (compressed download).
pub const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum release-meta JSON size.
pub const MAX_RELEASE_META_BYTES: u64 = 64 * 1024;
/// Default HTTP timeout for metadata requests (seconds).
pub const METADATA_TIMEOUT_SECS: u64 = 30;
/// Default HTTP timeout for archive downloads (seconds).
pub const DOWNLOAD_TIMEOUT_SECS: u64 = 600;

/// Maximum number of archive members (files + directories) accepted.
///
/// Portable releases ship five binaries plus a small doc set; anything larger is
/// treated as a zip/tar bomb or unexpected payload.
pub const MAX_ARCHIVE_ENTRIES: usize = 64;

/// Maximum uncompressed size of a single archive member (bytes).
pub const MAX_ENTRY_UNCOMPRESSED_BYTES: u64 = 256 * 1024 * 1024;

/// Maximum total uncompressed bytes across all accepted members.
pub const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 512 * 1024 * 1024;

/// Documentation / license files permitted beside the five required binaries.
pub const ALLOWED_DOC_FILES: &[&str] = &[
    "LICENSE",
    "NOTICE",
    "README.md",
    "RELEASE_NOTES.md",
    "CHANGELOG.md",
];
