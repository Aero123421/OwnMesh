//! Platform endpoint paths for the local IPC bus.
//!
//! Endpoint resolution is a pure function of `(runtime_dir, bus)` so every
//! producer and consumer — CLI, TUI, daemon, updater, session supervisor —
//! derives the identical endpoint without consulting the filesystem.
//!
//! Two platform limits are enforced here rather than deferred to `bind`:
//!
//! - Unix pathname sockets cannot exceed `sockaddr_un::sun_path`. A runtime
//!   directory can be a perfectly valid owner-controlled directory whose
//!   derived socket pathname is nevertheless unbindable, so default endpoints
//!   fall back to a deterministic short owner-scoped pathname and explicitly
//!   configured paths are rejected with the required reduction.
//! - Windows named pipes are scoped by a cryptographic digest of the
//!   normalized runtime directory so distinct installations never share a pipe.

use crate::{IpcError, IpcResult};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Domain separator for endpoint key derivation. Bump with any change to the
/// hashed input so a key change is deliberate and reviewable.
const ENDPOINT_KEY_DOMAIN: &[u8] = b"ownmesh/ipc-endpoint/v1\0";

/// Logical IPC bus kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpcBus {
    /// User-level `ownmeshd` bus used by CLI/TUI/session-host.
    Daemon,
    /// Persistent unprivileged PTY session supervisor; local IPC only.
    SessionSupervisor,
    /// Privileged broker bus (separate endpoint; not opened by default here).
    Privileged,
}

impl IpcBus {
    /// Stable file / pipe suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::SessionSupervisor => "session-supervisor",
            Self::Privileged => "privileged",
        }
    }

    /// Compact bus tag used by the shortened Unix fallback pathname, where every
    /// byte counts against `sun_path`. Distinct from [`Self::suffix`] only in
    /// length; the mapping stays injective.
    #[must_use]
    pub const fn short_tag(self) -> &'static str {
        match self {
            Self::Daemon => "d",
            Self::SessionSupervisor => "s",
            Self::Privileged => "p",
        }
    }
}

/// Unix pathname-socket helpers.
#[cfg(unix)]
mod unix_limits {
    /// Bytes usable by a pathname socket address, excluding the NUL terminator.
    ///
    /// Derived from the platform `sockaddr_un` layout (108 on Linux, 104 on
    /// macOS) rather than a hard-coded constant, and reduced by one because
    /// `SocketAddr::from_pathname` requires room for the terminator.
    pub const MAX_SOCKET_PATH_BYTES: usize = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path)
        - 1;

    // Guard the layout arithmetic on every supported target at compile time:
    // a nonsensical capacity would otherwise silently disable the fallback.
    const _: () = assert!(
        MAX_SOCKET_PATH_BYTES >= 92 && MAX_SOCKET_PATH_BYTES <= 128,
        "unexpected sockaddr_un::sun_path capacity"
    );

    /// Encoded length of `path` as the OS will pass it to `bind`/`connect`.
    #[must_use]
    pub fn encoded_len(path: &std::path::Path) -> usize {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().len()
    }
}

#[cfg(unix)]
use unix_limits::{encoded_len, MAX_SOCKET_PATH_BYTES};

/// Deterministic owner-scoped root for shortened Unix endpoints.
///
/// Deliberately independent of `TMPDIR` and of any filesystem probe: the
/// listener and every client must derive the same pathname from the same
/// runtime directory even when their environments differ. Custody of this
/// directory is validated at bind time.
#[cfg(unix)]
#[must_use]
pub fn short_socket_root() -> PathBuf {
    PathBuf::from(format!(
        "/tmp/.ownmesh-{}",
        rustix::process::getuid().as_raw()
    ))
}

/// Fully resolved local IPC endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Endpoint {
    /// Windows named pipe path (`\\.\pipe\...`).
    NamedPipe(String),
    /// Unix domain socket filesystem path.
    UnixSocket(PathBuf),
}

impl Endpoint {
    /// Render a human-readable endpoint string for status / logs.
    #[must_use]
    pub fn display(&self) -> String {
        match self {
            Self::NamedPipe(name) => name.clone(),
            Self::UnixSocket(path) => path.display().to_string(),
        }
    }

    /// Bytes available to a Unix-domain socket pathname on this platform.
    #[cfg(unix)]
    #[must_use]
    pub const fn unix_path_capacity() -> usize {
        MAX_SOCKET_PATH_BYTES
    }

    /// Verify that this endpoint can be bound and connected on this platform.
    ///
    /// Callers that validate configuration ahead of time (setup, config
    /// validation, `service install`) use this so a guaranteed-unbindable
    /// endpoint is refused with an actionable message instead of surfacing as a
    /// generic disconnected/offline error later.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Protocol`] when the endpoint exceeds a platform limit.
    pub fn ensure_bindable(&self) -> IpcResult<()> {
        match self {
            #[cfg(unix)]
            Self::UnixSocket(path) => {
                if encoded_len(path) > MAX_SOCKET_PATH_BYTES {
                    return Err(unix_path_too_long(path));
                }
                Ok(())
            }
            #[cfg(not(unix))]
            Self::UnixSocket(_) => Ok(()),
            Self::NamedPipe(_) => Ok(()),
        }
    }

    /// Resolve the daemon endpoint from `service_socket.path`, or use the default.
    ///
    /// Relative Unix paths are resolved beneath `runtime_dir`. Windows supports
    /// named-pipe overrides only (`pipe:name` or `\\.\pipe\name`); filesystem
    /// socket paths are rejected rather than silently ignored.
    ///
    /// An explicitly configured Unix path is never relocated: an operator named
    /// an exact pathname, so one that cannot be bound is reported with the
    /// required reduction instead of being silently replaced.
    ///
    /// # Errors
    ///
    /// Returns a protocol error for an empty override, an unsupported Windows
    /// path, or a configured Unix path that exceeds the platform socket limit.
    pub fn configured_daemon(runtime_dir: &Path, configured_path: Option<&str>) -> IpcResult<Self> {
        let Some(raw) = configured_path else {
            return Ok(Self::default_for(runtime_dir, IpcBus::Daemon));
        };
        let raw = raw.trim();
        if raw.is_empty() {
            return Err(IpcError::Protocol(
                "service_socket.path must not be empty when configured".into(),
            ));
        }
        #[cfg(unix)]
        {
            let path = PathBuf::from(raw);
            let endpoint = Self::UnixSocket(if path.is_absolute() {
                path
            } else {
                runtime_dir.join(path)
            });
            endpoint.ensure_bindable()?;
            Ok(endpoint)
        }
        #[cfg(windows)]
        {
            if let Some(name) = raw.strip_prefix("pipe:") {
                if name.trim().is_empty() {
                    return Err(IpcError::Protocol(
                        "service_socket.path pipe name must not be empty".into(),
                    ));
                }
                return Ok(Self::NamedPipe(if name.starts_with(r"\\.\pipe\") {
                    name.to_owned()
                } else {
                    format!(r"\\.\pipe\{name}")
                }));
            }
            if raw.starts_with(r"\\.\pipe\") {
                return Ok(Self::NamedPipe(raw.to_owned()));
            }
            Err(IpcError::Protocol(format!(
                "service_socket.path '{raw}' is unsupported on Windows; use pipe:<name> or \\\\.\\pipe\\<name>"
            )))
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = runtime_dir;
            Err(IpcError::Protocol(
                "configured service_socket.path is unsupported on this platform".into(),
            ))
        }
    }

    /// Build the default endpoint for `bus` under `runtime_dir`.
    ///
    /// On Windows this returns a named pipe scoped by a cryptographic digest of
    /// the normalized runtime directory, so distinct installations and concurrent
    /// test instances never share a pipe. On Unix it uses
    /// `{runtime_dir}/ownmesh-{bus}.sock`, falling back to a deterministic short
    /// owner-scoped pathname when that would exceed `sun_path`.
    #[must_use]
    pub fn default_for(runtime_dir: &Path, bus: IpcBus) -> Self {
        #[cfg(windows)]
        {
            Self::NamedPipe(format!(
                r"\\.\pipe\ownmesh-{}-{}",
                bus.suffix(),
                windows_runtime_key(runtime_dir)
            ))
        }
        #[cfg(not(windows))]
        {
            let direct = runtime_dir.join(format!("ownmesh-{}.sock", bus.suffix()));
            #[cfg(unix)]
            if encoded_len(&direct) > MAX_SOCKET_PATH_BYTES {
                return Self::UnixSocket(short_unix_socket_path(runtime_dir, bus));
            }
            Self::UnixSocket(direct)
        }
    }

    /// Named pipe produced by releases before the digest-based runtime key.
    ///
    /// Retained so an upgraded CLI can explain a still-running old daemon
    /// instead of reporting an unexplained offline endpoint.
    #[cfg(windows)]
    #[must_use]
    pub fn legacy_default_for(runtime_dir: &Path, bus: IpcBus) -> Self {
        Self::NamedPipe(format!(
            r"\\.\pipe\ownmesh-{}-{}",
            bus.suffix(),
            legacy_windows_runtime_key(runtime_dir)
        ))
    }

    /// True when `path` is the shortened-endpoint root managed by OwnMesh.
    #[cfg(unix)]
    #[must_use]
    pub fn is_short_socket_root(path: &Path) -> bool {
        path == short_socket_root()
    }
}

/// Deterministic short pathname for a runtime directory that cannot host a
/// bindable socket. Installation isolation is preserved by digesting the requested
/// runtime directory; the bus tag keeps buses distinct without a digest input.
#[cfg(unix)]
fn short_unix_socket_path(runtime_dir: &Path, bus: IpcBus) -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    let mut hasher = Sha256::new();
    hasher.update(ENDPOINT_KEY_DOMAIN);
    hasher.update(runtime_dir.as_os_str().as_bytes());
    let digest = hasher.finalize();
    let key = hex16(&digest);
    short_socket_root().join(format!("om-{key}-{}.sock", bus.short_tag()))
}

#[cfg(unix)]
fn unix_path_too_long(path: &Path) -> IpcError {
    let len = encoded_len(path);
    let excess = len.saturating_sub(MAX_SOCKET_PATH_BYTES);
    IpcError::Protocol(format!(
        "unix socket path is {len} bytes but this platform binds at most \
         {MAX_SOCKET_PATH_BYTES}; shorten it by {excess} byte(s): {}",
        path.display()
    ))
}

/// Lowercase hex of the first 8 digest bytes (64 bits): collision-negligible for
/// the number of installations one machine can host, and short enough for `sun_path`.
#[cfg(any(unix, windows))]
fn hex16(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    digest.iter().take(8).fold(String::new(), |mut acc, byte| {
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

/// Digest-based Windows runtime key.
///
/// The input is a normalized *textual* representation only: OwnMesh never
/// resolves a path through reparse points merely to build an endpoint name.
#[cfg(windows)]
fn windows_runtime_key(runtime_dir: &Path) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ENDPOINT_KEY_DOMAIN);
    hasher.update(normalize_windows_path(&runtime_dir.to_string_lossy()).as_bytes());
    let digest = hasher.finalize();
    // 128 bits keeps accidental collision negligible; the full name stays far
    // below the 256-character named-pipe limit.
    format!("{}{}", hex16(&digest), hex16(&digest[8..16]))
}

/// Fingerprint used before the digest key. Reproduced verbatim for migration
/// diagnostics only; never used to bind a new endpoint.
#[cfg(windows)]
fn legacy_windows_runtime_key(runtime_dir: &Path) -> String {
    let raw = runtime_dir.to_string_lossy();
    let key: String = raw
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(40)
        .collect();
    if !key.is_empty() {
        return key;
    }
    let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
    for b in raw.as_bytes() {
        acc = acc
            .wrapping_mul(0x0100_0000_01b3)
            .wrapping_add(u64::from(*b));
    }
    format!("{acc:016x}")
}

/// Normalize the spellings Windows treats as one path, without touching disk.
///
/// Case folding, separator form, redundant separators, verbatim (`\\?\`)
/// prefixes, and trailing separators are all normalized; nothing else is.
#[cfg(windows)]
fn normalize_windows_path(raw: &str) -> String {
    let unified: String = raw
        .chars()
        .map(|c| if c == '/' { '\\' } else { c })
        .collect();

    // `\\?\UNC\server\share` denotes the same object as `\\server\share`.
    let stripped = if let Some(rest) = unified.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = unified.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        unified
    };

    // Keep exactly one leading root marker (`\\` for UNC, `\` for a rooted
    // driveless path) and collapse every other separator run.
    let (root, body) = if let Some(rest) = stripped.strip_prefix(r"\\") {
        (r"\\", rest)
    } else if let Some(rest) = stripped.strip_prefix('\\') {
        (r"\", rest)
    } else {
        ("", stripped.as_str())
    };
    let collapsed = body
        .split('\\')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("\\");
    format!("{root}{collapsed}").to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_endpoint_is_platform_specific() {
        let ep = Endpoint::default_for(Path::new("/tmp/ownmesh-test"), IpcBus::Daemon);
        let text = ep.display();
        assert!(text.contains("daemon") || text.contains("ownmesh"));
        let _ = PathBuf::from(text);
    }

    #[test]
    fn configured_daemon_uses_shared_platform_resolution() {
        let runtime = Path::new("runtime-root");
        #[cfg(unix)]
        assert_eq!(
            Endpoint::configured_daemon(runtime, Some("custom.sock")).unwrap(),
            Endpoint::UnixSocket(runtime.join("custom.sock"))
        );
        #[cfg(windows)]
        assert_eq!(
            Endpoint::configured_daemon(runtime, Some("pipe:custom")).unwrap(),
            Endpoint::NamedPipe(r"\\.\pipe\custom".into())
        );
        assert!(Endpoint::configured_daemon(runtime, Some("   ")).is_err());
    }

    #[test]
    fn bus_tags_stay_injective() {
        let buses = [
            IpcBus::Daemon,
            IpcBus::SessionSupervisor,
            IpcBus::Privileged,
        ];
        for (i, a) in buses.iter().enumerate() {
            for b in &buses[i + 1..] {
                assert_ne!(a.short_tag(), b.short_tag());
                assert_ne!(a.suffix(), b.suffix());
            }
        }
    }

    #[cfg(unix)]
    mod unix {
        use super::*;

        /// Runtime directory whose derived socket pathname exceeds `sun_path`.
        fn over_limit_runtime_dir() -> PathBuf {
            PathBuf::from(format!("/tmp/{}", "a".repeat(MAX_SOCKET_PATH_BYTES)))
        }

        #[test]
        fn platform_capacity_matches_sockaddr_un() {
            // Linux stores 108 bytes, macOS 104; one byte is the NUL terminator.
            assert!(
                (100..=110).contains(&Endpoint::unix_path_capacity()),
                "unexpected sun_path capacity {}",
                Endpoint::unix_path_capacity()
            );
        }

        #[test]
        fn endpoint_just_below_the_limit_is_used_verbatim() {
            let basename = format!("ownmesh-{}.sock", IpcBus::Daemon.suffix());
            // Longest runtime dir whose daemon socket still fits.
            let dir_len = MAX_SOCKET_PATH_BYTES - basename.len() - 1;
            let runtime = PathBuf::from(format!("/{}", "a".repeat(dir_len - 1)));
            let endpoint = Endpoint::default_for(&runtime, IpcBus::Daemon);
            assert_eq!(endpoint, Endpoint::UnixSocket(runtime.join(&basename)));
            endpoint.ensure_bindable().unwrap();
        }

        #[test]
        fn endpoint_above_the_limit_falls_back_to_a_bindable_path() {
            for bus in [
                IpcBus::Daemon,
                IpcBus::SessionSupervisor,
                IpcBus::Privileged,
            ] {
                let endpoint = Endpoint::default_for(&over_limit_runtime_dir(), bus);
                let Endpoint::UnixSocket(path) = &endpoint else {
                    panic!("expected a unix socket endpoint");
                };
                assert!(path.starts_with(short_socket_root()));
                endpoint.ensure_bindable().unwrap();
            }
        }

        #[test]
        fn session_supervisor_basename_reaches_the_limit_first() {
            let basename = format!("ownmesh-{}.sock", IpcBus::SessionSupervisor.suffix());
            let dir_len = MAX_SOCKET_PATH_BYTES - basename.len() + 1;
            let runtime = PathBuf::from(format!("/{}", "a".repeat(dir_len - 1)));
            // The daemon bus still fits at this length; the supervisor does not.
            assert!(!matches!(
                Endpoint::default_for(&runtime, IpcBus::SessionSupervisor),
                Endpoint::UnixSocket(ref p) if p.starts_with(&runtime)
            ));
            Endpoint::default_for(&runtime, IpcBus::Daemon)
                .ensure_bindable()
                .unwrap();
        }

        #[test]
        fn listener_and_client_derive_the_same_fallback() {
            let runtime = over_limit_runtime_dir();
            assert_eq!(
                Endpoint::default_for(&runtime, IpcBus::Daemon),
                Endpoint::default_for(&runtime, IpcBus::Daemon)
            );
        }

        #[test]
        fn distinct_long_runtime_dirs_stay_isolated() {
            let mut seen = std::collections::HashSet::new();
            for i in 0..512 {
                let runtime =
                    PathBuf::from(format!("/tmp/{}{i}", "b".repeat(MAX_SOCKET_PATH_BYTES)));
                let endpoint = Endpoint::default_for(&runtime, IpcBus::Daemon);
                endpoint.ensure_bindable().unwrap();
                assert!(seen.insert(endpoint.display()), "duplicate endpoint at {i}");
            }
        }

        #[test]
        fn buses_do_not_collide_under_the_fallback() {
            let runtime = over_limit_runtime_dir();
            let daemon = Endpoint::default_for(&runtime, IpcBus::Daemon);
            let supervisor = Endpoint::default_for(&runtime, IpcBus::SessionSupervisor);
            let privileged = Endpoint::default_for(&runtime, IpcBus::Privileged);
            assert_ne!(daemon, supervisor);
            assert_ne!(daemon, privileged);
            assert_ne!(supervisor, privileged);
        }

        #[test]
        fn non_utf8_runtime_bytes_are_measured_as_encoded_bytes() {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;

            let mut bytes = b"/tmp/".to_vec();
            bytes.extend(std::iter::repeat_n(0xff_u8, MAX_SOCKET_PATH_BYTES));
            let runtime = PathBuf::from(OsString::from_vec(bytes));
            let endpoint = Endpoint::default_for(&runtime, IpcBus::Daemon);
            endpoint.ensure_bindable().unwrap();
            let Endpoint::UnixSocket(path) = &endpoint else {
                panic!("expected a unix socket endpoint");
            };
            assert!(path.starts_with(short_socket_root()));
        }

        #[test]
        fn configured_absolute_path_over_the_limit_is_rejected_with_the_reduction() {
            let long = format!("/tmp/{}.sock", "c".repeat(MAX_SOCKET_PATH_BYTES));
            let err = Endpoint::configured_daemon(Path::new("/tmp"), Some(&long)).unwrap_err();
            let message = err.to_string();
            assert!(message.contains("shorten it by"), "{message}");
            assert!(
                message.contains(&MAX_SOCKET_PATH_BYTES.to_string()),
                "{message}"
            );
        }

        #[test]
        fn configured_relative_path_over_the_limit_is_rejected() {
            let runtime = over_limit_runtime_dir();
            assert!(Endpoint::configured_daemon(&runtime, Some("custom.sock")).is_err());
        }
    }

    #[cfg(windows)]
    mod windows {
        use super::*;

        #[test]
        fn punctuation_differences_do_not_collide() {
            assert_ne!(
                Endpoint::default_for(Path::new(r"C:\OwnMesh\instances\a-b\run"), IpcBus::Daemon),
                Endpoint::default_for(Path::new(r"C:\OwnMesh\instances\ab\run"), IpcBus::Daemon)
            );
        }

        #[test]
        fn paths_differing_after_forty_characters_do_not_collide() {
            let prefix = r"C:\OwnMesh\instances\averylongcommonprefixsegment\run";
            assert_ne!(
                Endpoint::default_for(&PathBuf::from(format!(r"{prefix}\alpha")), IpcBus::Daemon),
                Endpoint::default_for(&PathBuf::from(format!(r"{prefix}\bravo")), IpcBus::Daemon)
            );
        }

        #[test]
        fn equivalent_spellings_resolve_to_the_same_endpoint() {
            let canonical = Endpoint::default_for(Path::new(r"C:\OwnMesh\run"), IpcBus::Daemon);
            for spelling in [
                r"c:\ownmesh\run",
                r"C:/OwnMesh/run",
                r"C:\OwnMesh\\run\",
                r"\\?\C:\OwnMesh\run",
            ] {
                assert_eq!(
                    Endpoint::default_for(Path::new(spelling), IpcBus::Daemon),
                    canonical,
                    "spelling {spelling} did not normalize"
                );
            }
        }

        #[test]
        fn buses_remain_distinct() {
            let runtime = Path::new(r"C:\OwnMesh\run");
            assert_ne!(
                Endpoint::default_for(runtime, IpcBus::Daemon),
                Endpoint::default_for(runtime, IpcBus::SessionSupervisor)
            );
            assert_ne!(
                Endpoint::default_for(runtime, IpcBus::SessionSupervisor),
                Endpoint::default_for(runtime, IpcBus::Privileged)
            );
        }

        #[test]
        fn generated_temp_paths_have_no_duplicate_endpoint() {
            let mut seen = std::collections::HashSet::new();
            for i in 0..512 {
                let runtime = PathBuf::from(format!(
                    r"C:\Users\runner\AppData\Local\Temp\ownmesh-{i}\run"
                ));
                let endpoint = Endpoint::default_for(&runtime, IpcBus::Daemon);
                assert!(seen.insert(endpoint.display()), "duplicate endpoint at {i}");
            }
        }

        #[test]
        fn digest_endpoint_differs_from_the_legacy_name() {
            let runtime = Path::new(r"C:\OwnMesh\run");
            assert_ne!(
                Endpoint::default_for(runtime, IpcBus::Daemon),
                Endpoint::legacy_default_for(runtime, IpcBus::Daemon)
            );
        }

        #[test]
        fn pipe_name_stays_within_the_windows_limit() {
            let runtime = PathBuf::from(format!(r"C:\{}\run", "d".repeat(400)));
            let Endpoint::NamedPipe(name) =
                Endpoint::default_for(&runtime, IpcBus::SessionSupervisor)
            else {
                panic!("expected a named pipe endpoint");
            };
            assert!(name.len() < 256, "pipe name too long: {}", name.len());
        }
    }
}
