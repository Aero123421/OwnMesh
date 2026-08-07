//! Fail-closed size and time budgets.

/// Maximum GitHub release JSON body size.
pub const MAX_METADATA_BYTES: u64 = 2 * 1024 * 1024;
/// Maximum `SHA256SUMS` body size.
pub const MAX_CHECKSUMS_BYTES: u64 = 1024 * 1024;
/// Maximum signature body size.
pub const MAX_SIGNATURE_BYTES: u64 = 64 * 1024;
/// Maximum portable archive size.
pub const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;
/// Maximum release-meta JSON size.
pub const MAX_RELEASE_META_BYTES: u64 = 64 * 1024;
/// Default HTTP timeout for metadata requests (seconds).
pub const METADATA_TIMEOUT_SECS: u64 = 30;
/// Default HTTP timeout for archive downloads (seconds).
pub const DOWNLOAD_TIMEOUT_SECS: u64 = 600;
