//! OS-specific local stream transport (Named Pipe / Unix socket).
//!
//! Unix domain sockets honor a process-wide privilege boundary configured via
//! [`LocalListener::configure_unix_security`]: owner/group/mode at bind time and
//! allowed peer uids at accept time. ACL application failures are fail-closed.

use crate::auth::OsPeerIdentity;
use crate::endpoint::Endpoint;
use crate::error::{IpcError, IpcResult};
use std::sync::{Mutex as StdMutex, OnceLock};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::os::windows::io::{FromRawHandle, OwnedHandle};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(windows)]
use tokio::sync::Mutex as TokioMutex;

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Accepted server-side connection.
pub struct ServerConnection {
    inner: ConnInner,
    /// OS peer identity captured at accept time (server-side only).
    peer: OsPeerIdentity,
}

/// Client-side connection.
pub struct ClientConnection {
    inner: ConnInner,
}

/// Immutable facts attested by Windows for one connected named-pipe client.
///
/// The process and image handles are retained for the lifetime of this value.
/// A caller must keep this value (rather than only copying the scalar fields)
/// until it has completed authorization and request processing.  That makes a
/// PID reuse after pipe accept detectable by a fresh process-time check and
/// prevents the image handle from being closed under the authorization check.
///
/// This is deliberately a safe façade.  The small audited Win32 FFI boundary
/// stays private to this transport module; consumers cannot manufacture these
/// facts from JSON or caller-supplied fields.
#[cfg(windows)]
pub struct WindowsPipePeerFacts {
    pid: u32,
    user_sid: String,
    integrity_rid: u32,
    session_id: u32,
    process: WindowsProcessFacts,
}

/// Immutable process identity held through the authorization decision.
/// Constructed only from a Windows process handle and a second image file
/// handle; user-provided PID/path strings cannot create this value.
#[cfg(windows)]
pub struct WindowsProcessFacts {
    pid: u32,
    creation_filetime: u64,
    image_path: String,
    image_volume_serial: u64,
    image_file_id: [u8; 16],
    image_sha256: [u8; 32],
    process_handle: OwnedHandle,
    image_handle: std::fs::File,
}

#[cfg(windows)]
type WindowsOpenedProcess = (
    OwnedHandle,
    std::fs::File,
    String,
    u64,
    [u8; 16],
    [u8; 32],
    u64,
);

#[cfg(windows)]
impl std::fmt::Debug for WindowsPipePeerFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsPipePeerFacts")
            .field("pid", &self.pid)
            .field("user_sid", &self.user_sid)
            .field("integrity_rid", &self.integrity_rid)
            .field("session_id", &self.session_id)
            .field("process", &self.process)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl WindowsPipePeerFacts {
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }
    #[must_use]
    pub fn user_sid(&self) -> &str {
        &self.user_sid
    }
    #[must_use]
    pub const fn integrity_rid(&self) -> u32 {
        self.integrity_rid
    }
    #[must_use]
    pub const fn session_id(&self) -> u32 {
        self.session_id
    }
    #[must_use]
    pub const fn creation_filetime(&self) -> u64 {
        self.process.creation_filetime()
    }
    #[must_use]
    pub fn image_path(&self) -> &str {
        self.process.image_path()
    }
    #[must_use]
    pub const fn image_volume_serial(&self) -> u64 {
        self.process.image_volume_serial()
    }
    #[must_use]
    pub const fn image_file_id(&self) -> [u8; 16] {
        self.process.image_file_id()
    }
    #[must_use]
    pub const fn image_sha256(&self) -> [u8; 32] {
        self.process.image_sha256()
    }

    /// Re-read the process creation time through the retained process handle.
    /// A mismatch means PID reuse or a closed/replaced process and is denied.
    pub fn revalidate_process_birth(&self) -> IpcResult<()> {
        self.process.revalidate_process_birth()
    }

    /// Re-read the held image handle's file identity and digest.  This catches
    /// replacement attempts between pipe accept and the privileged action.
    pub fn revalidate_image(&self) -> IpcResult<()> {
        self.process.revalidate_image()
    }
}

#[cfg(windows)]
impl std::fmt::Debug for WindowsProcessFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsProcessFacts")
            .field("pid", &self.pid)
            .field("creation_filetime", &self.creation_filetime)
            .field("image_path", &self.image_path)
            .field("image_volume_serial", &self.image_volume_serial)
            .field("image_file_id", &self.image_file_id)
            .field("image_sha256", &self.image_sha256)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl WindowsProcessFacts {
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }
    #[must_use]
    pub const fn creation_filetime(&self) -> u64 {
        self.creation_filetime
    }
    #[must_use]
    pub fn image_path(&self) -> &str {
        &self.image_path
    }
    #[must_use]
    pub const fn image_volume_serial(&self) -> u64 {
        self.image_volume_serial
    }
    #[must_use]
    pub const fn image_file_id(&self) -> [u8; 16] {
        self.image_file_id
    }
    #[must_use]
    pub const fn image_sha256(&self) -> [u8; 32] {
        self.image_sha256
    }
    pub fn revalidate_process_birth(&self) -> IpcResult<()> {
        let observed = unsafe { process_creation_filetime(self.process_handle.as_raw_handle()) }
            .map_err(|error| {
                IpcError::Unauthorized(format!(
                    "cannot revalidate process birth (fail-closed): {error}"
                ))
            })?;
        if observed != self.creation_filetime {
            return Err(IpcError::Unauthorized(
                "process PID was reused or process birth changed (fail-closed)".into(),
            ));
        }
        Ok(())
    }
    pub fn revalidate_image(&self) -> IpcResult<()> {
        let (volume, file_id) = unsafe { windows_file_id(self.image_handle.as_raw_handle()) }
            .map_err(|error| {
                IpcError::Unauthorized(format!(
                    "cannot revalidate process image identity (fail-closed): {error}"
                ))
            })?;
        let digest = sha256_file(&self.image_handle).map_err(|error| {
            IpcError::Unauthorized(format!(
                "cannot revalidate process image digest (fail-closed): {error}"
            ))
        })?;
        if volume != self.image_volume_serial
            || file_id != self.image_file_id
            || digest != self.image_sha256
        {
            return Err(IpcError::Unauthorized(
                "process image changed after attestation (fail-closed)".into(),
            ));
        }
        Ok(())
    }
}

enum ConnInner {
    #[cfg(windows)]
    PipeServer(NamedPipeServer),
    #[cfg(windows)]
    PipeClient(NamedPipeClient),
    #[cfg(unix)]
    Unix(UnixStream),
}

macro_rules! poll_read_inner {
    ($self:expr, $cx:expr, $buf:expr) => {
        match &mut $self.inner {
            #[cfg(windows)]
            ConnInner::PipeServer(s) => std::pin::Pin::new(s).poll_read($cx, $buf),
            #[cfg(windows)]
            ConnInner::PipeClient(s) => std::pin::Pin::new(s).poll_read($cx, $buf),
            #[cfg(unix)]
            ConnInner::Unix(s) => std::pin::Pin::new(s).poll_read($cx, $buf),
        }
    };
}

macro_rules! poll_write_inner {
    ($self:expr, $cx:expr, $buf:expr) => {
        match &mut $self.inner {
            #[cfg(windows)]
            ConnInner::PipeServer(s) => std::pin::Pin::new(s).poll_write($cx, $buf),
            #[cfg(windows)]
            ConnInner::PipeClient(s) => std::pin::Pin::new(s).poll_write($cx, $buf),
            #[cfg(unix)]
            ConnInner::Unix(s) => std::pin::Pin::new(s).poll_write($cx, $buf),
        }
    };
}

macro_rules! poll_flush_inner {
    ($self:expr, $cx:expr) => {
        match &mut $self.inner {
            #[cfg(windows)]
            ConnInner::PipeServer(s) => std::pin::Pin::new(s).poll_flush($cx),
            #[cfg(windows)]
            ConnInner::PipeClient(s) => std::pin::Pin::new(s).poll_flush($cx),
            #[cfg(unix)]
            ConnInner::Unix(s) => std::pin::Pin::new(s).poll_flush($cx),
        }
    };
}

macro_rules! poll_shutdown_inner {
    ($self:expr, $cx:expr) => {
        match &mut $self.inner {
            #[cfg(windows)]
            ConnInner::PipeServer(s) => std::pin::Pin::new(s).poll_shutdown($cx),
            #[cfg(windows)]
            ConnInner::PipeClient(s) => std::pin::Pin::new(s).poll_shutdown($cx),
            #[cfg(unix)]
            ConnInner::Unix(s) => std::pin::Pin::new(s).poll_shutdown($cx),
        }
    };
}

impl AsyncRead for ServerConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        poll_read_inner!(self, cx, buf)
    }
}

impl AsyncWrite for ServerConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        poll_write_inner!(self, cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        poll_flush_inner!(self, cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        poll_shutdown_inner!(self, cx)
    }
}

impl ServerConnection {
    /// Return the server-attested OS peer identity.
    ///
    /// On Windows this must be called after reading the first pipe message so
    /// `ImpersonateNamedPipeClient` is bound to that message's security context.
    pub fn peer_identity(&mut self) -> IpcResult<OsPeerIdentity> {
        #[cfg(windows)]
        if let ConnInner::PipeServer(server) = &self.inner {
            self.peer = windows_pipe_peer_identity(server)?;
        }
        Ok(self.peer.clone())
    }

    /// Capture non-forgeable Windows named-pipe client facts after the first
    /// message has arrived.  The SID/token values are acquired while the pipe
    /// client is impersonated and process/image values come from OS handles,
    /// never from the protocol payload.
    #[cfg(windows)]
    pub fn windows_pipe_peer_facts(&mut self) -> IpcResult<WindowsPipePeerFacts> {
        match &self.inner {
            ConnInner::PipeServer(server) => windows_pipe_peer_facts(server),
            ConnInner::PipeClient(_) => Err(IpcError::Protocol(
                "server peer facts requested from a client connection (fail-closed)".into(),
            )),
        }
    }
}

impl AsyncRead for ClientConnection {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        poll_read_inner!(self, cx, buf)
    }
}

impl AsyncWrite for ClientConnection {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        poll_write_inner!(self, cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        poll_flush_inner!(self, cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        poll_shutdown_inner!(self, cx)
    }
}

impl ClientConnection {
    /// Return the server PID reported by Windows for this exact pipe handle.
    /// Clients use this before sending authority-bearing broker requests to
    /// reject a same-name pipe substituted by an untrusted process.
    #[cfg(windows)]
    pub fn windows_pipe_server_pid(&self) -> IpcResult<u32> {
        match &self.inner {
            ConnInner::PipeClient(client) => {
                unsafe { named_pipe_server_pid(client.as_raw_handle()) }.map_err(|error| {
                    IpcError::Unauthorized(format!(
                        "named pipe server PID retrieval failed (fail-closed): {error}"
                    ))
                })
            }
            ConnInner::PipeServer(_) => Err(IpcError::Protocol(
                "server PID requested from a server connection (fail-closed)".into(),
            )),
        }
    }
}

/// Process-wide Unix socket privilege boundary (owner/group/mode + allowed peer uids).
#[derive(Debug, Clone, PartialEq, Eq)]
struct UnixSocketSecurity {
    owner_uid: Option<u32>,
    group_gid: Option<u32>,
    /// Mode bits; `None` means default `0o600`.
    mode: Option<u32>,
    /// Empty ⇒ accept any peer that can connect (AuthGate still applies).
    /// Non-empty ⇒ peer uid must be listed (fail-closed).
    allowed_uids: Vec<u32>,
}

impl Default for UnixSocketSecurity {
    fn default() -> Self {
        Self {
            owner_uid: None,
            group_gid: None,
            mode: Some(0o600),
            allowed_uids: Vec::new(),
        }
    }
}

fn socket_security_slot() -> &'static StdMutex<UnixSocketSecurity> {
    static SLOT: OnceLock<StdMutex<UnixSocketSecurity>> = OnceLock::new();
    SLOT.get_or_init(|| StdMutex::new(UnixSocketSecurity::default()))
}

fn current_socket_security() -> UnixSocketSecurity {
    socket_security_slot()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

fn validate_mode_bits(mode: u32) -> IpcResult<()> {
    if mode > 0o777 {
        return Err(IpcError::Protocol(format!(
            "unix socket mode {mode:#o} out of range (fail-closed)"
        )));
    }
    // Never permit "other" access (blocks 0666 / world-readable sockets).
    if mode & 0o007 != 0 {
        return Err(IpcError::Protocol(format!(
            "unix socket mode {mode:#o} grants access to other; refused (fail-closed)"
        )));
    }
    Ok(())
}

/// Listening socket / named-pipe factory.
pub struct LocalListener {
    endpoint: Endpoint,
    #[cfg(windows)]
    pipe_name: String,
    /// Present only for the fixed privileged-broker pipe.  The SID is used to
    /// recreate and attest the same protected DACL for every pipe instance.
    #[cfg(windows)]
    secure_broker_daemon_sid: Option<String>,
    #[cfg(windows)]
    pending: TokioMutex<Option<NamedPipeServer>>,
    #[cfg(unix)]
    listener: UnixListener,
    /// Snapshot of allowed peer uids at bind time (enforced on Unix accept).
    #[allow(dead_code)] // read on Unix accept path; retained on Windows for API parity
    allowed_uids: Vec<u32>,
}

impl LocalListener {
    /// Fixed, non-configurable endpoint for the privileged Windows broker.
    /// Keeping this name out of user configuration prevents an attacker from
    /// redirecting a high-capability client to a lookalike pipe.
    #[cfg(windows)]
    pub const SECURE_BROKER_PIPE_NAME: &'static str = r"\\.\pipe\ownmesh-privileged";

    /// Configure the process-wide Unix socket privilege boundary used by [`Self::bind`].
    ///
    /// - `mode`: octal bits; default `0o600` when `None`. Modes with "other" bits are refused.
    /// - `allowed_uids`: when non-empty, accept path rejects peers whose uid is absent.
    /// - ACL application failures during bind are fail-closed.
    ///
    /// # Errors
    ///
    /// Returns [`IpcError::Protocol`] when the requested mode is unsafe.
    pub fn configure_unix_security(
        owner_uid: Option<u32>,
        group_gid: Option<u32>,
        mode: Option<u32>,
        allowed_uids: Vec<u32>,
    ) -> IpcResult<()> {
        if let Some(m) = mode {
            validate_mode_bits(m)?;
        }
        if mode.is_some_and(|m| m & 0o070 != 0) && group_gid.is_none() {
            return Err(IpcError::Protocol(
                "unix socket mode grants group access but group_gid is unset (fail-closed)".into(),
            ));
        }
        let mut guard = socket_security_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = UnixSocketSecurity {
            owner_uid,
            group_gid,
            mode: Some(mode.unwrap_or(0o600)),
            allowed_uids,
        };
        Ok(())
    }

    /// Reset process-wide Unix socket security to defaults (`0o600`, no owner/group, no uid list).
    pub fn clear_unix_security() {
        let mut guard = socket_security_slot()
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        *guard = UnixSocketSecurity::default();
    }

    /// Bind a new listener on `endpoint`.
    ///
    /// On Unix, applies the process-wide security from [`Self::configure_unix_security`]
    /// (owner/group/mode). Failure to apply ACL is fail-closed.
    ///
    /// # Errors
    ///
    /// Returns transport IO errors or ACL failures.
    pub async fn bind(endpoint: Endpoint) -> IpcResult<Self> {
        let security = current_socket_security();
        match &endpoint {
            #[cfg(windows)]
            Endpoint::NamedPipe(name) => {
                let first = ServerOptions::new()
                    .first_pipe_instance(true)
                    .reject_remote_clients(true)
                    .create(name)?;
                Ok(Self {
                    pipe_name: name.clone(),
                    secure_broker_daemon_sid: None,
                    pending: TokioMutex::new(Some(first)),
                    endpoint,
                    allowed_uids: security.allowed_uids,
                })
            }
            #[cfg(unix)]
            Endpoint::UnixSocket(path) => {
                prepare_unix_path(path)?;
                let listener = UnixListener::bind(path)?;
                apply_unix_socket_security(path, &security)?;
                Ok(Self {
                    listener,
                    endpoint,
                    allowed_uids: security.allowed_uids,
                })
            }
            #[cfg(windows)]
            Endpoint::UnixSocket(_) => Err(IpcError::Protocol(
                "unix socket endpoints are not supported on Windows".into(),
            )),
            #[cfg(unix)]
            Endpoint::NamedPipe(_) => Err(IpcError::Protocol(
                "named pipe endpoints are not supported on Unix".into(),
            )),
        }
    }

    /// Bind the fixed privileged-broker pipe with a protected DACL that grants
    /// access only to the configured daemon SID, LocalSystem, and Builtin
    /// Administrators. Remote clients are rejected and first-instance
    /// substitution is refused.  This is intentionally separate from generic
    /// [`Self::bind`]: a configurable pipe name must never gain this authority.
    #[cfg(windows)]
    pub async fn bind_secure_broker_pipe(daemon_sid: &str) -> IpcResult<Self> {
        let daemon_sid = validate_windows_sid_text(daemon_sid)?;
        let pipe_name = Self::SECURE_BROKER_PIPE_NAME.to_owned();
        let first = create_secure_broker_pipe(&pipe_name, &daemon_sid, true)?;
        Ok(Self {
            endpoint: Endpoint::NamedPipe(pipe_name.clone()),
            pipe_name,
            secure_broker_daemon_sid: Some(daemon_sid),
            pending: TokioMutex::new(Some(first)),
            allowed_uids: Vec::new(),
        })
    }

    /// Endpoint currently served.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Accept the next client connection and capture OS peer credentials.
    ///
    /// On Unix, when `allowed_uids` was configured, peer uid must match (fail-closed).
    ///
    /// # Errors
    ///
    /// Returns transport IO errors or peer-credential retrieval failures (fail-closed).
    pub async fn accept(&self) -> IpcResult<ServerConnection> {
        #[cfg(windows)]
        {
            let mut guard = self.pending.lock().await;
            let server = match guard.take() {
                Some(s) => s,
                None => match &self.secure_broker_daemon_sid {
                    Some(daemon_sid) => {
                        create_secure_broker_pipe(&self.pipe_name, daemon_sid, false)?
                    }
                    None => ServerOptions::new()
                        .reject_remote_clients(true)
                        .create(&self.pipe_name)?,
                },
            };
            server.connect().await?;
            *guard = Some(match &self.secure_broker_daemon_sid {
                Some(daemon_sid) => create_secure_broker_pipe(&self.pipe_name, daemon_sid, false)?,
                None => ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&self.pipe_name)?,
            });
            // SID attribution via pipe impersonation is deferred until after the
            // server reads the first message from this exact pipe instance.
            let pid = unsafe { named_pipe_client_pid(server.as_raw_handle()) }.map_err(|err| {
                IpcError::Unauthorized(format!(
                    "named pipe client PID retrieval failed (fail-closed): {err}"
                ))
            })?;
            let peer = OsPeerIdentity {
                pid,
                user_id: String::new(),
                exe_path: unsafe { process_image_path(pid) },
            };
            Ok(ServerConnection {
                inner: ConnInner::PipeServer(server),
                peer,
            })
        }
        #[cfg(unix)]
        {
            let (stream, _addr) = self.listener.accept().await?;
            let peer = unix_peer_identity(&stream)?;
            enforce_allowed_uid(&peer, &self.allowed_uids)?;
            Ok(ServerConnection {
                inner: ConnInner::Unix(stream),
                peer,
            })
        }
    }
}

impl Drop for LocalListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Endpoint::UnixSocket(path) = &self.endpoint {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Connect to a local endpoint.
///
/// # Errors
///
/// Returns transport IO / disconnect errors.
pub async fn connect(endpoint: &Endpoint) -> IpcResult<ClientConnection> {
    match endpoint {
        #[cfg(windows)]
        Endpoint::NamedPipe(name) => {
            let mut last_err = None;
            for _ in 0..80 {
                match ClientOptions::new().open(name) {
                    Ok(client) => {
                        return Ok(ClientConnection {
                            inner: ConnInner::PipeClient(client),
                        });
                    }
                    Err(err) => {
                        last_err = Some(err);
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    }
                }
            }
            Err(IpcError::Disconnected(format!(
                "failed to open named pipe {name}: {}; a daemon started by a release that \
                 predates the digest-scoped pipe name listens on a different pipe — run \
                 `ownmesh service restart` after upgrading",
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".into())
            )))
        }
        #[cfg(unix)]
        Endpoint::UnixSocket(path) => {
            let stream = UnixStream::connect(path).await.map_err(|err| {
                IpcError::Disconnected(format!(
                    "failed to connect to unix socket {}: {err}",
                    path.display()
                ))
            })?;
            Ok(ClientConnection {
                inner: ConnInner::Unix(stream),
            })
        }
        #[cfg(windows)]
        Endpoint::UnixSocket(path) => Err(IpcError::Protocol(format!(
            "unix socket {} is not supported on Windows",
            path.display()
        ))),
        #[cfg(unix)]
        Endpoint::NamedPipe(name) => Err(IpcError::Protocol(format!(
            "named pipe {name} is not supported on Unix"
        ))),
    }
}

#[cfg(unix)]
fn unix_peer_identity(stream: &UnixStream) -> IpcResult<OsPeerIdentity> {
    let ucred = stream.peer_cred().map_err(|err| {
        IpcError::Unauthorized(format!(
            "peer credential retrieval failed (SO_PEERCRED/fail-closed): {err}"
        ))
    })?;
    let pid = u32::try_from(ucred.pid().unwrap_or(0)).unwrap_or(0);
    let uid = ucred.uid();
    let exe_path = read_exe_path_for_pid(pid);
    Ok(OsPeerIdentity {
        pid,
        user_id: format!("{uid}"),
        exe_path,
    })
}

#[cfg(unix)]
fn read_exe_path_for_pid(pid: u32) -> Option<String> {
    if pid == 0 {
        return None;
    }
    // Linux: /proc/<pid>/exe. Other Unix: best-effort none.
    let link = std::path::PathBuf::from(format!("/proc/{pid}/exe"));
    std::fs::read_link(link)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

#[cfg(windows)]
fn windows_pipe_peer_identity(server: &NamedPipeServer) -> IpcResult<OsPeerIdentity> {
    let handle = server.as_raw_handle();
    let pid = unsafe { named_pipe_client_pid(handle) }.map_err(|err| {
        IpcError::Unauthorized(format!(
            "named pipe client PID retrieval failed (fail-closed): {err}"
        ))
    })?;
    let exe_path = unsafe { process_image_path(pid) };
    let user_id = unsafe { named_pipe_client_user_sid(handle) }.map_err(|err| {
        IpcError::Unauthorized(format!(
            "named pipe client user SID retrieval failed (fail-closed): {err}"
        ))
    })?;
    Ok(OsPeerIdentity {
        pid,
        user_id,
        exe_path,
    })
}

/// Get the client PID for a connected named pipe server instance.
///
/// # Safety
///
/// `handle` must be a valid open named-pipe server handle with an active client.
#[cfg(windows)]
unsafe fn named_pipe_client_pid(handle: std::os::windows::io::RawHandle) -> Result<u32, String> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::Pipes::GetNamedPipeClientProcessId;

    let mut pid: u32 = 0;
    let ok = GetNamedPipeClientProcessId(handle, &mut pid);
    if ok == FALSE {
        let err = std::io::Error::last_os_error();
        return Err(err.to_string());
    }
    if pid == 0 {
        return Err("GetNamedPipeClientProcessId returned pid 0".into());
    }
    Ok(pid)
}

/// Get the server PID for a connected named-pipe client instance.
///
/// # Safety
///
/// `handle` must be a valid open named-pipe client handle connected to a server.
#[cfg(windows)]
unsafe fn named_pipe_server_pid(handle: std::os::windows::io::RawHandle) -> Result<u32, String> {
    use windows_sys::Win32::Foundation::FALSE;
    use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

    let mut pid = 0_u32;
    if GetNamedPipeServerProcessId(handle, &mut pid) == FALSE {
        return Err(std::io::Error::last_os_error().to_string());
    }
    if pid == 0 {
        return Err("GetNamedPipeServerProcessId returned pid 0".into());
    }
    Ok(pid)
}

#[cfg(windows)]
fn windows_pipe_peer_facts(server: &NamedPipeServer) -> IpcResult<WindowsPipePeerFacts> {
    let handle = server.as_raw_handle();
    let pid = unsafe { named_pipe_client_pid(handle) }.map_err(|error| {
        IpcError::Unauthorized(format!(
            "named pipe client PID retrieval failed (fail-closed): {error}"
        ))
    })?;
    let user_sid = unsafe { named_pipe_client_user_sid(handle) }.map_err(|error| {
        IpcError::Unauthorized(format!(
            "named pipe client SID retrieval failed (fail-closed): {error}"
        ))
    })?;
    let (integrity_rid, session_id) =
        unsafe { named_pipe_client_token_context(handle) }.map_err(|error| {
            IpcError::Unauthorized(format!(
                "named pipe client token context retrieval failed (fail-closed): {error}"
            ))
        })?;
    let process = windows_process_facts(pid)?;
    Ok(WindowsPipePeerFacts {
        pid,
        user_sid,
        integrity_rid,
        session_id,
        process,
    })
}

/// Attest a process using a retained process handle and a retained canonical
/// image handle.  Clients use this after `GetNamedPipeServerProcessId` before
/// sending a broker request, and again after receiving its response.
#[cfg(windows)]
pub fn windows_process_facts(pid: u32) -> IpcResult<WindowsProcessFacts> {
    let (
        process_handle,
        image_handle,
        image_path,
        image_volume_serial,
        image_file_id,
        image_sha256,
        creation_filetime,
    ) = unsafe { open_process_and_image(pid) }.map_err(|error| {
        IpcError::Unauthorized(format!(
            "Windows process attestation failed (fail-closed): {error}"
        ))
    })?;
    Ok(WindowsProcessFacts {
        pid,
        creation_filetime,
        image_path,
        image_volume_serial,
        image_file_id,
        image_sha256,
        process_handle,
        image_handle,
    })
}

/// SCM-attested identity for a running Windows service.  The service manager,
/// rather than pipe metadata or a caller-supplied service name, supplies the
/// PID and configured binary command line.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsServiceFacts {
    service_name: String,
    pid: u32,
    binary_command_line: String,
}

#[cfg(windows)]
impl WindowsServiceFacts {
    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }
    #[must_use]
    pub fn binary_command_line(&self) -> &str {
        &self.binary_command_line
    }
}

/// Query the local Service Control Manager and require a currently-running
/// service PID to equal the PID reported by the exact Named Pipe handle.
/// Callers must additionally attest that PID with [`windows_process_facts`]
/// and compare its canonical image identity with the installed service image.
#[cfg(windows)]
pub fn windows_running_service_facts(
    service_name: &str,
    expected_pid: u32,
) -> IpcResult<WindowsServiceFacts> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceConfigW,
        QueryServiceStatusEx, QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO,
        SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
    };

    if expected_pid == 0
        || service_name.is_empty()
        || service_name.len() > 256
        || !service_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(IpcError::Protocol(
            "Windows service identity input is invalid (fail-closed)".into(),
        ));
    }
    let wide: Vec<u16> = std::ffi::OsStr::new(service_name)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(IpcError::Unauthorized(format!(
            "open local Service Control Manager failed (fail-closed): {}",
            std::io::Error::last_os_error()
        )));
    }
    let result = (|| {
        let service = unsafe {
            OpenServiceW(
                manager,
                wide.as_ptr(),
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG,
            )
        };
        if service.is_null() {
            return Err(IpcError::Unauthorized(format!(
                "open expected broker service failed (fail-closed): {}",
                std::io::Error::last_os_error()
            )));
        }
        let service_result = (|| {
            let mut status = unsafe { std::mem::zeroed::<SERVICE_STATUS_PROCESS>() };
            let mut status_needed = 0_u32;
            if unsafe {
                QueryServiceStatusEx(
                    service,
                    SC_STATUS_PROCESS_INFO,
                    std::ptr::from_mut(&mut status).cast(),
                    u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>())
                        .unwrap_or(u32::MAX),
                    &mut status_needed,
                )
            } == 0
            {
                return Err(IpcError::Unauthorized(format!(
                    "query broker service status failed (fail-closed): {}",
                    std::io::Error::last_os_error()
                )));
            }
            if status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId != expected_pid {
                return Err(IpcError::Unauthorized(format!(
                    "broker service is not running at the pipe-attested PID {expected_pid} (fail-closed)"
                )));
            }
            let mut needed = 0_u32;
            let _ = unsafe { QueryServiceConfigW(service, ptr::null_mut(), 0, &mut needed) };
            if needed
                < u32::try_from(std::mem::size_of::<QUERY_SERVICE_CONFIGW>()).unwrap_or(u32::MAX)
            {
                return Err(IpcError::Unauthorized(format!(
                    "query broker service image size failed (fail-closed): {}",
                    std::io::Error::last_os_error()
                )));
            }
            let bytes = usize::try_from(needed).map_err(|_| {
                IpcError::Unauthorized("broker service image buffer length overflow".into())
            })?;
            let words = bytes.div_ceil(std::mem::size_of::<usize>());
            let mut buffer = vec![0_usize; words];
            let mut returned = needed;
            if unsafe {
                QueryServiceConfigW(service, buffer.as_mut_ptr().cast(), needed, &mut returned)
            } == 0
                || returned > needed
            {
                return Err(IpcError::Unauthorized(format!(
                    "query broker service image failed (fail-closed): {}",
                    std::io::Error::last_os_error()
                )));
            }
            let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
            let command_ptr = config.lpBinaryPathName;
            let start = buffer.as_ptr() as usize;
            let end = start.checked_add(bytes).ok_or_else(|| {
                IpcError::Unauthorized("broker service image buffer overflow".into())
            })?;
            let command_start = command_ptr as usize;
            if command_ptr.is_null()
                || command_start < start
                || command_start >= end
                || !command_start.is_multiple_of(std::mem::align_of::<u16>())
            {
                return Err(IpcError::Unauthorized(
                    "broker service image command line is outside SCM buffer (fail-closed)".into(),
                ));
            }
            let units = (end - command_start) / std::mem::size_of::<u16>();
            let command = unsafe { std::slice::from_raw_parts(command_ptr, units) };
            let nul = command.iter().position(|unit| *unit == 0).ok_or_else(|| {
                IpcError::Unauthorized(
                    "broker service image command line is unterminated (fail-closed)".into(),
                )
            })?;
            let binary_command_line = String::from_utf16(&command[..nul]).map_err(|_| {
                IpcError::Unauthorized(
                    "broker service image command line is invalid UTF-16 (fail-closed)".into(),
                )
            })?;
            if binary_command_line.trim().is_empty() {
                return Err(IpcError::Unauthorized(
                    "broker service image command line is empty (fail-closed)".into(),
                ));
            }
            Ok(WindowsServiceFacts {
                service_name: service_name.to_owned(),
                pid: status.dwProcessId,
                binary_command_line,
            })
        })();
        unsafe {
            let _ = CloseServiceHandle(service);
        }
        service_result
    })();
    unsafe {
        let _ = CloseServiceHandle(manager);
    }
    result
}

/// Capture the fields from an impersonated client token required to distinguish
/// a normal user daemon from a service/admin process.  The caller must only use
/// this after the pipe has received a message; otherwise Windows can report an
/// unrelated/default client security context.
///
/// # Safety
///
/// `handle` must be a connected server-side pipe handle.
#[cfg(windows)]
unsafe fn named_pipe_client_token_context(
    handle: std::os::windows::io::RawHandle,
) -> Result<(u32, u32), String> {
    use std::mem::{size_of, MaybeUninit};
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, IsValidSid,
        TokenIntegrityLevel, TokenSessionId, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    if ImpersonateNamedPipeClient(handle) == 0 {
        return Err(format!(
            "ImpersonateNamedPipeClient failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = (|| {
        let mut token: HANDLE = ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 || token.is_null() {
            return Err(format!(
                "OpenThreadToken failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let token_result = (|| {
            let mut session_id = 0_u32;
            let mut returned = 0_u32;
            if GetTokenInformation(
                token,
                TokenSessionId,
                std::ptr::from_mut(&mut session_id).cast(),
                u32::try_from(size_of::<u32>()).map_err(|_| "session size overflow")?,
                &mut returned,
            ) == 0
                || returned
                    != u32::try_from(size_of::<u32>()).map_err(|_| "session size overflow")?
            {
                return Err(format!(
                    "GetTokenInformation(TokenSessionId) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let mut required = 0_u32;
            let _ = GetTokenInformation(
                token,
                TokenIntegrityLevel,
                ptr::null_mut(),
                0,
                &mut required,
            );
            if required
                < u32::try_from(size_of::<TOKEN_MANDATORY_LABEL>())
                    .map_err(|_| "integrity label size overflow")?
            {
                return Err(format!(
                    "GetTokenInformation(TokenIntegrityLevel) size query failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let required =
                usize::try_from(required).map_err(|_| "integrity label length overflow")?;
            let element_size = size_of::<TOKEN_MANDATORY_LABEL>();
            let elements = required
                .checked_add(element_size - 1)
                .map(|bytes| bytes / element_size)
                .ok_or("integrity label length overflow")?;
            // TokenMandatoryLabel has pointer alignment. Never cast a byte Vec
            // to it, because a misaligned allocation is undefined behavior.
            let mut buffer: Vec<MaybeUninit<TOKEN_MANDATORY_LABEL>> = Vec::new();
            buffer
                .try_reserve_exact(elements)
                .map_err(|_| "integrity label allocation failed")?;
            buffer.resize_with(elements, MaybeUninit::uninit);
            let buffer_bytes = buffer
                .len()
                .checked_mul(element_size)
                .ok_or("integrity label length overflow")?;
            let required_u32 =
                u32::try_from(required).map_err(|_| "integrity label length overflow")?;
            let mut returned = required_u32;
            if GetTokenInformation(
                token,
                TokenIntegrityLevel,
                buffer.as_mut_ptr().cast(),
                required_u32,
                &mut returned,
            ) == 0
                || returned
                    < u32::try_from(size_of::<TOKEN_MANDATORY_LABEL>())
                        .map_err(|_| "integrity label size overflow")?
                || usize::try_from(returned).map_err(|_| "integrity returned length overflow")?
                    > required
            {
                return Err(format!(
                    "GetTokenInformation(TokenIntegrityLevel) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let returned =
                usize::try_from(returned).map_err(|_| "integrity returned length overflow")?;
            if returned > buffer_bytes {
                return Err("TokenIntegrityLevel returned an out-of-bounds length".into());
            }
            let label = buffer
                .first()
                .ok_or("TokenIntegrityLevel buffer is empty")?
                .assume_init_ref();
            let sid = label.Label.Sid;
            let buffer_start = buffer.as_ptr() as usize;
            let sid_start = sid as usize;
            let sid_offset = sid_start
                .checked_sub(buffer_start)
                .ok_or("TokenIntegrityLevel SID points before its buffer")?;
            let sid_remaining = returned
                .checked_sub(sid_offset)
                .ok_or("TokenIntegrityLevel SID points outside its buffer")?;
            if sid.is_null() || sid_remaining < 8 {
                return Err("TokenIntegrityLevel returned an invalid SID".into());
            }
            let sub_authority_count = usize::from(*sid.cast::<u8>().add(1));
            let sid_len = 8_usize
                .checked_add(
                    sub_authority_count
                        .checked_mul(4)
                        .ok_or("integrity SID length overflow")?,
                )
                .ok_or("integrity SID length overflow")?;
            if sid_len > sid_remaining || IsValidSid(sid) == 0 {
                return Err("TokenIntegrityLevel returned an invalid SID".into());
            }
            let count_ptr = GetSidSubAuthorityCount(sid);
            if count_ptr.is_null()
                || *count_ptr == 0
                || usize::from(*count_ptr) != sub_authority_count
            {
                return Err("TokenIntegrityLevel SID has no subauthority".into());
            }
            let rid_ptr = GetSidSubAuthority(sid, u32::from(*count_ptr - 1));
            if rid_ptr.is_null() {
                return Err("TokenIntegrityLevel SID has no integrity RID".into());
            }
            Ok((*rid_ptr, session_id))
        })();
        let _ = CloseHandle(token);
        token_result
    })();
    if windows_sys::Win32::Security::RevertToSelf() == 0 {
        return Err(format!(
            "RevertToSelf failed after pipe impersonation: {}",
            std::io::Error::last_os_error()
        ));
    }
    result
}

/// Open the live process and an image file handle, then attest all immutable
/// identity data through those handles.  Failure to query any field is an
/// authorization failure, never a best-effort fallback to a caller path.
///
/// # Safety
///
/// Calls Win32 process/file APIs with a kernel-supplied PID.  Returned handles
/// are immediately transferred to RAII owners before this function returns.
#[cfg(windows)]
unsafe fn open_process_and_image(pid: u32) -> Result<WindowsOpenedProcess, String> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    let raw = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if raw.is_null() {
        return Err(format!(
            "OpenProcess({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    let process_handle = OwnedHandle::from_raw_handle(raw);
    let creation_filetime = process_creation_filetime(process_handle.as_raw_handle())?;
    let image_query_path = process_image_path_from_handle(process_handle.as_raw_handle())?;
    let canonical = std::fs::canonicalize(&image_query_path)
        .map_err(|error| format!("canonicalize live process image {image_query_path}: {error}"))?;
    let image_handle = std::fs::File::open(&canonical).map_err(|error| {
        format!(
            "open canonical live process image {}: {error}",
            canonical.display()
        )
    })?;
    let (image_volume_serial, image_file_id) = windows_file_id(image_handle.as_raw_handle())?;
    let image_sha256 = sha256_file(&image_handle)?;
    Ok((
        process_handle,
        image_handle,
        canonical.to_string_lossy().into_owned(),
        image_volume_serial,
        image_file_id,
        image_sha256,
        creation_filetime,
    ))
}

#[cfg(windows)]
unsafe fn process_creation_filetime(
    handle: std::os::windows::io::RawHandle,
) -> Result<u64, String> {
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::System::Threading::GetProcessTimes;

    let mut created = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut exited = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut kernel = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let mut user = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    if GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) == 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(u64::from(created.dwLowDateTime) | (u64::from(created.dwHighDateTime) << 32))
}

/// Return an OS-derived process birth identifier for a still-live PID.
///
/// `None` means the OS confirmed that the PID no longer exists.  An inability
/// to inspect a live PID is an error, never a false "dead" result.  Callers
/// can persist this value with a PID and reject a later PID reuse.
#[cfg(windows)]
pub fn process_birth_id(pid: u32) -> Result<Option<u64>, String> {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    // SAFETY: `OpenProcess` receives a scalar PID and the returned kernel
    // handle is immediately wrapped in `OwnedHandle` for RAII cleanup.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        // ERROR_INVALID_PARAMETER is Windows' documented no-such-PID result.
        return if error.raw_os_error() == Some(87) {
            Ok(None)
        } else {
            Err(format!("OpenProcess({pid}) failed: {error}"))
        };
    }
    // SAFETY: ownership of the non-null handle returned above is transferred
    // exactly once to `OwnedHandle`.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: the owned process handle remains live for this call.
    unsafe { process_creation_filetime(process.as_raw_handle()).map(Some) }
}

/// Read the process state character and start time from `/proc/<pid>/stat`.
///
/// One parser for both [`process_birth_id`] and [`running_process_birth_id`]:
/// the field offsets must agree exactly between them or the zombie regression
/// in #31 silently returns, and the surest way to keep two copies in agreement
/// is not to have two copies.
///
/// `Ok(None)` means the OS confirmed the PID no longer exists. Permission or
/// parse failures are `Err` — indeterminate, never a false "dead".
#[cfg(target_os = "linux")]
fn read_proc_stat_fields(pid: u32) -> Result<Option<(char, u64)>, String> {
    let path = format!("/proc/{pid}/stat");
    let stat = match std::fs::read_to_string(&path) {
        Ok(stat) => stat,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read {path}: {error}")),
    };
    // Field 2 (`comm`) is parenthesized and may itself contain spaces and
    // parentheses, so every later field is located from the last `)`.
    let end = stat
        .rfind(')')
        .ok_or_else(|| format!("parse {path}: missing comm terminator"))?;
    let rest = stat
        .get(end + 2..)
        .ok_or_else(|| format!("parse {path}: missing fields"))?;
    let mut fields = rest.split_whitespace();
    // Field 3: process state character.
    let state = fields
        .next()
        .and_then(|field| field.chars().next())
        .ok_or_else(|| format!("parse {path}: missing process state"))?;
    // Field 22 (`starttime`) is 19 fields further along from field 3.
    let birth = fields
        .nth(18)
        .ok_or_else(|| format!("parse {path}: missing start time"))?
        .parse::<u64>()
        .map_err(|error| format!("parse {path} start time: {error}"))?;
    Ok(Some((state, birth)))
}

/// Linux `/proc/<pid>/stat` start time is kernel-supplied and changes on PID
/// reuse.  Permission or parse failures fail closed rather than claiming a
/// process is absent.
#[cfg(target_os = "linux")]
pub fn process_birth_id(pid: u32) -> Result<Option<u64>, String> {
    // The process state is deliberately ignored here: this is a birth witness,
    // and an exited-but-unreaped process still owns the identity it names.
    Ok(read_proc_stat_fields(pid)?.map(|(_state, birth)| birth))
}

/// macOS exposes the kernel-recorded process start timestamp through
/// `proc_pidinfo(PROC_PIDTBSDINFO)`. Its second/microsecond pair changes when
/// a numeric PID is reused, so encode it as a checked microsecond timestamp.
#[cfg(target_os = "macos")]
pub fn process_birth_id(pid: u32) -> Result<Option<u64>, String> {
    use std::mem::{size_of, MaybeUninit};

    let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>())
        .map_err(|_| "proc_bsdinfo size exceeds c_int")?;
    // SAFETY: `info` has exactly `size` writable bytes and `proc_pidinfo`
    // initializes them on a successful full-size reply.
    let copied = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid).map_err(|_| format!("PID {pid} exceeds c_int"))?,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if copied == 0 {
        let error = std::io::Error::last_os_error();
        // proc_pidinfo reports an unknown/exited process as ESRCH (and some
        // Darwin releases expose ENOENT for the same race). Other failures,
        // including permission denial, remain indeterminate and fail closed.
        return match error.raw_os_error() {
            Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(None),
            _ => Err(format!("proc_pidinfo({pid}) failed: {error}")),
        };
    }
    if copied != size {
        return Err(format!(
            "proc_pidinfo({pid}) returned incomplete proc_bsdinfo ({copied} of {size} bytes)"
        ));
    }
    // SAFETY: exact-size successful `proc_pidinfo` reply initialized info.
    let info = unsafe { info.assume_init() };
    const MICROS_PER_SECOND: u64 = 1_000_000;
    if info.pbi_start_tvusec >= MICROS_PER_SECOND {
        return Err(format!(
            "proc_pidinfo({pid}) returned invalid start microseconds {}",
            info.pbi_start_tvusec
        ));
    }
    let birth = info
        .pbi_start_tvsec
        .checked_mul(MICROS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
        .filter(|birth| *birth != 0)
        .ok_or_else(|| format!("proc_pidinfo({pid}) returned invalid process start time"))?;
    Ok(Some(birth))
}

/// Other platforms do not currently expose a safe, dependency-free process
/// birth witness through the IPC crate.  Callers retain the session state
/// instead of risking a PID-only reconciliation.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn process_birth_id(_pid: u32) -> Result<Option<u64>, String> {
    Err("process birth identity is unavailable on this platform".into())
}

/// Return the birth witness of a PID that is **still running**.
///
/// This differs from [`process_birth_id`] in exactly one way: a process that
/// has already exited but has not yet been reaped by its parent reports
/// `Ok(None)` (exited) instead of `Ok(Some(birth))` (live).
///
/// A Unix zombie still owns its PID slot and its kernel-recorded start time,
/// so a pure birth-witness probe reports it as present. Session lifecycle
/// treats "the attested child is present" as "the child is alive", which is
/// how a short-lived session whose child had already exited stayed pinned as
/// `running` and refused reconciliation with "authenticated child is still
/// alive, refusing PID-only termination" (#31).
///
/// The PID-reuse protection is unchanged: the caller still compares the
/// returned witness against the one it persisted, and a reused PID reports a
/// different birth. This only stops an exited-but-unreaped process from being
/// mistaken for a live one — it never converts an indeterminate probe into a
/// "dead" answer, which stays an `Err` so callers keep failing closed.
#[cfg(target_os = "linux")]
pub fn running_process_birth_id(pid: u32) -> Result<Option<u64>, String> {
    let Some((state, birth)) = read_proc_stat_fields(pid)? else {
        return Ok(None);
    };
    // `Z` is a reaped-pending zombie and `X`/`x` is a fully dead task still
    // visible for an instant. Both have exited.
    if matches!(state, 'Z' | 'X' | 'x') {
        return Ok(None);
    }
    Ok(Some(birth))
}

/// Windows equivalent of the Unix zombie case: a process object stays
/// queryable while any handle to it is open, so `GetProcessTimes` keeps
/// answering for an exited process. `WaitForSingleObject` with a zero timeout
/// is the unambiguous liveness answer — unlike `GetExitCodeProcess`, it cannot
/// be confused by a live process that happens to be destined to exit with
/// `STILL_ACTIVE` (259).
#[cfg(windows)]
pub fn running_process_birth_id(pid: u32) -> Result<Option<u64>, String> {
    use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0};
    // `SYNCHRONIZE` is a standard access right shared by every waitable
    // object; windows-sys declares it once, under the file-system module.
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::{
        OpenProcess, WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: `OpenProcess` receives a scalar PID and the returned kernel
    // handle is immediately wrapped in `OwnedHandle` for RAII cleanup.
    let raw = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid) };
    if raw.is_null() {
        let error = std::io::Error::last_os_error();
        // ERROR_INVALID_PARAMETER is Windows' documented no-such-PID result.
        return if error.raw_os_error() == Some(87) {
            Ok(None)
        } else {
            Err(format!("OpenProcess({pid}) failed: {error}"))
        };
    }
    // SAFETY: ownership of the non-null handle returned above is transferred
    // exactly once to `OwnedHandle`.
    let process = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: the owned process handle remains live for this call.
    let wait = unsafe { WaitForSingleObject(process.as_raw_handle(), 0) };
    if wait == WAIT_OBJECT_0 {
        // The process object is signaled: the process has exited.
        return Ok(None);
    }
    if wait == WAIT_FAILED {
        return Err(format!(
            "WaitForSingleObject({pid}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the owned process handle remains live for this call.
    unsafe { process_creation_filetime(process.as_raw_handle()).map(Some) }
}

/// Darwin reports a reaped-pending child as `SZOMB` in `pbi_status`.
#[cfg(target_os = "macos")]
pub fn running_process_birth_id(pid: u32) -> Result<Option<u64>, String> {
    use std::mem::{size_of, MaybeUninit};

    /// `SZOMB` from `<sys/proc.h>`; `libc` does not re-export the `p_stat`
    /// constants that `proc_bsdinfo::pbi_status` uses. Typed to match
    /// `pbi_status` exactly so no conversion is needed at the comparison.
    const DARWIN_SZOMB: u32 = 5;

    let mut info = MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = i32::try_from(size_of::<libc::proc_bsdinfo>())
        .map_err(|_| "proc_bsdinfo size exceeds c_int")?;
    // SAFETY: `info` has exactly `size` writable bytes and `proc_pidinfo`
    // initializes them on a successful full-size reply.
    let copied = unsafe {
        libc::proc_pidinfo(
            i32::try_from(pid).map_err(|_| format!("PID {pid} exceeds c_int"))?,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    };
    if copied == 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ESRCH) | Some(libc::ENOENT) => Ok(None),
            _ => Err(format!("proc_pidinfo({pid}) failed: {error}")),
        };
    }
    if copied != size {
        return Err(format!(
            "proc_pidinfo({pid}) returned incomplete proc_bsdinfo ({copied} of {size} bytes)"
        ));
    }
    // SAFETY: exact-size successful `proc_pidinfo` reply initialized info.
    let info = unsafe { info.assume_init() };
    if info.pbi_status == DARWIN_SZOMB {
        return Ok(None);
    }
    const MICROS_PER_SECOND: u64 = 1_000_000;
    if info.pbi_start_tvusec >= MICROS_PER_SECOND {
        return Err(format!(
            "proc_pidinfo({pid}) returned invalid start microseconds {}",
            info.pbi_start_tvusec
        ));
    }
    let birth = info
        .pbi_start_tvsec
        .checked_mul(MICROS_PER_SECOND)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
        .filter(|birth| *birth != 0)
        .ok_or_else(|| format!("proc_pidinfo({pid}) returned invalid process start time"))?;
    Ok(Some(birth))
}

/// Other platforms keep the same fail-closed contract as
/// [`process_birth_id`]: no witness, no reconciliation.
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn running_process_birth_id(_pid: u32) -> Result<Option<u64>, String> {
    Err("process liveness is unavailable on this platform".into())
}

#[cfg(all(test, target_os = "linux"))]
mod linux_liveness_tests {
    use super::{process_birth_id, running_process_birth_id};

    /// #31: a child that exited but has not been reaped keeps its PID slot and
    /// its kernel start time, so a birth-witness probe still finds it. Session
    /// lifecycle must see it as exited or a dead session stays `running`
    /// forever and refuses reconciliation.
    #[test]
    fn a_zombie_child_is_exited_even_though_its_birth_witness_survives() {
        let mut child = std::process::Command::new("/bin/true")
            .spawn()
            .expect("spawn /bin/true");
        let pid = child.id();
        // Deliberately do NOT reap: wait for the kernel to publish state `Z`.
        let mut state = String::new();
        for _ in 0..200 {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            if let Some(end) = stat.rfind(')') {
                state = stat
                    .get(end + 2..)
                    .and_then(|rest| rest.split_whitespace().next())
                    .unwrap_or_default()
                    .to_owned();
            }
            if state == "Z" {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(state, "Z", "child did not become a zombie");

        // The plain birth witness still reports the PID as present ...
        assert!(
            process_birth_id(pid).expect("probe succeeds").is_some(),
            "a zombie keeps its PID slot and start time"
        );
        // ... while the liveness probe correctly reports it as exited.
        assert_eq!(
            running_process_birth_id(pid).expect("probe succeeds"),
            None,
            "a zombie must be treated as exited for session lifecycle"
        );

        child.wait().expect("reap the child");
    }

    /// PID-reuse protection is unchanged: a running process still returns the
    /// same stable witness the caller persisted.
    #[test]
    fn a_running_process_keeps_its_stable_birth_witness() {
        let pid = std::process::id();
        let live = running_process_birth_id(pid)
            .expect("probe succeeds")
            .expect("the current process is running");
        assert_eq!(Some(live), process_birth_id(pid).expect("probe succeeds"));
        assert_eq!(
            running_process_birth_id(pid).expect("probe succeeds"),
            Some(live),
        );
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::process_birth_id;

    #[test]
    fn process_birth_id_is_stable_for_the_current_process() {
        let first = process_birth_id(std::process::id())
            .unwrap()
            .expect("current process must have a Darwin birth witness");
        let second = process_birth_id(std::process::id())
            .unwrap()
            .expect("current process must retain a Darwin birth witness");
        assert_ne!(first, 0);
        assert_eq!(first, second);
    }
}

#[cfg(windows)]
unsafe fn process_image_path_from_handle(
    handle: std::os::windows::io::RawHandle,
) -> Result<String, String> {
    use windows_sys::Win32::System::Threading::QueryFullProcessImageNameW;

    let mut capacity = 1024_usize;
    loop {
        let mut buf = vec![0_u16; capacity];
        let mut length = u32::try_from(buf.len()).map_err(|_| "image path buffer too large")?;
        if QueryFullProcessImageNameW(handle, 0, buf.as_mut_ptr(), &mut length) != 0 && length > 0 {
            let length = usize::try_from(length).map_err(|_| "image path length overflow")?;
            return Ok(String::from_utf16_lossy(&buf[..length]));
        }
        let error = std::io::Error::last_os_error();
        if capacity >= 32 * 1024 {
            return Err(error.to_string());
        }
        capacity = capacity.saturating_mul(2);
    }
}

#[cfg(windows)]
unsafe fn windows_file_id(
    handle: std::os::windows::io::RawHandle,
) -> Result<(u64, [u8; 16]), String> {
    use std::mem::size_of;
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO,
    };

    let mut info = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
    if GetFileInformationByHandleEx(
        handle,
        FileIdInfo,
        info.as_mut_ptr().cast(),
        u32::try_from(size_of::<FILE_ID_INFO>()).map_err(|_| "FILE_ID_INFO size overflow")?,
    ) == 0
    {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let info = info.assume_init();
    Ok((info.VolumeSerialNumber, info.FileId.Identifier))
}

#[cfg(windows)]
fn sha256_file(file: &std::fs::File) -> Result<[u8; 32], String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};

    let mut reader = file.try_clone().map_err(|error| error.to_string())?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| error.to_string())?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

/// Validate the textual form before interpolating it into SDDL.  The Win32 SID
/// parser is the authority; the conservative character check prevents SDDL
/// grammar injection even if that parser changes its accepted syntax.
#[cfg(windows)]
fn validate_windows_sid_text(value: &str) -> IpcResult<String> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows_sys::Win32::Security::PSID;

    if !value.starts_with("S-")
        || value.len() > 184
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'-' || byte == b'S')
    {
        return Err(IpcError::Protocol(
            "daemon SID must be a canonical Windows S-... SID (fail-closed)".into(),
        ));
    }
    let wide: Vec<u16> = std::ffi::OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut sid: PSID = ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
        return Err(IpcError::Protocol(format!(
            "daemon SID is not recognized by Windows (fail-closed): {}",
            std::io::Error::last_os_error()
        )));
    }
    unsafe {
        let _ = LocalFree(sid.cast());
    }
    Ok(value.to_owned())
}

/// Create one protected privileged-broker pipe instance.  The only unsafe call
/// to Tokio's raw-security API is contained here, after the descriptor has been
/// constructed and before its lifetime ends; callers receive an ordinary safe
/// `NamedPipeServer` only after the actual handle DACL is re-attested.
#[cfg(windows)]
fn create_secure_broker_pipe(
    pipe_name: &str,
    daemon_sid: &str,
    first_instance: bool,
) -> IpcResult<NamedPipeServer> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

    let sddl_text = format!("D:P(A;;GRGW;;;{daemon_sid})(A;;GA;;;SY)(A;;GA;;;BA)");
    let sddl: Vec<u16> = sddl_text.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(IpcError::Protocol(format!(
            "construct protected broker pipe DACL failed (fail-closed): {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut attrs = SECURITY_ATTRIBUTES {
        nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let result = (|| {
        let server = unsafe {
            ServerOptions::new()
                .first_pipe_instance(first_instance)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    pipe_name,
                    std::ptr::from_mut(&mut attrs).cast(),
                )
        }
        .map_err(IpcError::Io)?;
        verify_secure_broker_pipe_dacl(server.as_raw_handle(), daemon_sid)?;
        Ok(server)
    })();
    unsafe {
        let _ = LocalFree(descriptor);
    }
    result
}

/// Inspect the live pipe handle rather than trusting the requested SDDL.  The
/// ACL must be protected and contain exactly the three non-inherited allow ACEs
/// in canonical order: daemon GR|GW, SYSTEM GA, BUILTIN\\Administrators GA.
#[cfg(windows)]
fn verify_secure_broker_pipe_dacl(
    handle: std::os::windows::io::RawHandle,
    daemon_sid_text: &str,
) -> IpcResult<()> {
    use std::ptr;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows_sys::Win32::Security::{
        AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION,
        DACL_SECURITY_INFORMATION, INHERITED_ACE, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    };

    fn sid_from_text(value: &str) -> IpcResult<PSID> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        let wide: Vec<u16> = std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut sid) } == 0 || sid.is_null() {
            return Err(IpcError::Unauthorized(
                "cannot parse expected broker DACL SID (fail-closed)".into(),
            ));
        }
        Ok(sid)
    }

    let daemon_sid = sid_from_text(daemon_sid_text)?;
    let system_sid = sid_from_text("S-1-5-18")?;
    let admin_sid = sid_from_text("S-1-5-32-544")?;
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    let result = (|| {
        if status != 0 || descriptor.is_null() {
            return Err(IpcError::Unauthorized(format!(
                "cannot inspect live broker pipe DACL (fail-closed): {}",
                std::io::Error::from_raw_os_error(status.cast_signed())
            )));
        }
        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err(IpcError::Unauthorized(
                "broker pipe DACL is not protected (fail-closed)".into(),
            ));
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
            == 0
            || present == 0
            || dacl.is_null()
        {
            return Err(IpcError::Unauthorized(
                "broker pipe DACL is absent (fail-closed)".into(),
            ));
        }
        let mut info = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
        if unsafe {
            GetAclInformation(
                dacl,
                std::ptr::from_mut(&mut info).cast(),
                u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
                AclSizeInformation,
            )
        } == 0
            || info.AceCount != 3
        {
            return Err(IpcError::Unauthorized(
                "broker pipe DACL has unexpected ACE count (fail-closed)".into(),
            ));
        }
        let expected = [
            // `CreateNamedPipeW` maps SDDL GR|GW to this pipe-specific access
            // mask before exposing the live kernel-object DACL.
            (daemon_sid, 0x0012_019f),
            // Likewise, GA is mapped by CreateNamedPipeW to the pipe's full
            // access mask before we inspect the live DACL.
            (system_sid, 0x001f_01ff),
            (admin_sid, 0x001f_01ff),
        ];
        for (index, (expected_sid, expected_mask)) in expected.into_iter().enumerate() {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, u32::try_from(index).unwrap_or(u32::MAX), &mut ace) } == 0
                || ace.is_null()
            {
                return Err(IpcError::Unauthorized(
                    "broker pipe DACL ACE retrieval failed (fail-closed)".into(),
                ));
            }
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let sid: PSID = (&raw const ace.SidStart).cast_mut().cast();
            if ace.Header.AceType != 0
                || u32::from(ace.Header.AceFlags) & INHERITED_ACE != 0
                || ace.Mask != expected_mask
                || unsafe { EqualSid(sid, expected_sid) } == 0
            {
                return Err(IpcError::Unauthorized(format!(
                    "broker pipe DACL is not the required canonical policy at ACE {index}: type={} flags={} mask={:#x} expected_mask={expected_mask:#x} sid_match={} (fail-closed)",
                    ace.Header.AceType,
                    ace.Header.AceFlags,
                    ace.Mask,
                    unsafe { EqualSid(sid, expected_sid) },
                )));
            }
        }
        Ok(())
    })();
    unsafe {
        let _ = LocalFree(daemon_sid.cast());
        let _ = LocalFree(system_sid.cast());
        let _ = LocalFree(admin_sid.cast());
        if !descriptor.is_null() {
            let _ = LocalFree(descriptor);
        }
    }
    result
}

/// Server-attested Windows user SID bound to this named-pipe connection.
///
/// # Safety
///
/// `handle` must be a connected named-pipe server handle. Impersonation is always
/// reverted and the opened thread token is always closed before return.
#[cfg(windows)]
unsafe fn named_pipe_client_user_sid(
    handle: std::os::windows::io::RawHandle,
) -> Result<String, String> {
    use std::mem::{size_of, MaybeUninit};
    use std::ptr;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetLengthSid, GetTokenInformation, IsValidSid, RevertToSelf, TokenUser, TOKEN_QUERY,
        TOKEN_USER,
    };
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

    if ImpersonateNamedPipeClient(handle) == 0 {
        return Err(format!(
            "ImpersonateNamedPipeClient failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let result = (|| {
        let mut token: HANDLE = ptr::null_mut();
        if OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) == 0 || token.is_null() {
            return Err(format!(
                "OpenThreadToken failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let token_result = (|| {
            let mut required = 0_u32;
            let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required);
            if required == 0 {
                return Err(format!(
                    "GetTokenInformation size query failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let required = usize::try_from(required)
                .map_err(|_| "TokenUser buffer length does not fit usize".to_owned())?;
            let element_size = size_of::<TOKEN_USER>();
            if required < element_size {
                return Err("TokenUser buffer is smaller than TOKEN_USER".into());
            }
            let elements = required
                .checked_add(element_size - 1)
                .map(|bytes| bytes / element_size)
                .ok_or_else(|| "TokenUser buffer length overflow".to_owned())?;
            // GetTokenInformation returns TOKEN_USER plus an inline variable SID.
            // Allocate with TOKEN_USER alignment rather than casting a byte Vec.
            let mut buffer: Vec<MaybeUninit<TOKEN_USER>> = Vec::new();
            buffer
                .try_reserve_exact(elements)
                .map_err(|_| "TokenUser buffer allocation failed".to_owned())?;
            buffer.resize_with(elements, MaybeUninit::uninit);
            let buffer_bytes = buffer
                .len()
                .checked_mul(element_size)
                .ok_or_else(|| "TokenUser buffer length overflow".to_owned())?;
            let query_len = u32::try_from(required)
                .map_err(|_| "TokenUser buffer length does not fit u32".to_owned())?;
            let mut returned = query_len;
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                query_len,
                &mut returned,
            ) == 0
            {
                return Err(format!(
                    "GetTokenInformation(TokenUser) failed: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let returned = usize::try_from(returned)
                .map_err(|_| "TokenUser returned length does not fit usize".to_owned())?;
            if returned < element_size || returned > required || returned > buffer_bytes {
                return Err("TokenUser returned an out-of-bounds buffer length".into());
            }
            let token_user = buffer
                .first()
                .ok_or_else(|| "TokenUser buffer is empty".to_owned())?
                .assume_init_ref();
            let sid = token_user.User.Sid;
            if sid.is_null() {
                return Err("TokenUser returned a null SID".into());
            }
            let buffer_start = buffer.as_ptr() as usize;
            let sid_start = sid as usize;
            let sid_offset = sid_start
                .checked_sub(buffer_start)
                .ok_or_else(|| "TokenUser SID points before its buffer".to_owned())?;
            let sid_remaining = returned
                .checked_sub(sid_offset)
                .ok_or_else(|| "TokenUser SID points outside its buffer".to_owned())?;
            // Validate the fixed 8-byte SID header before any Windows SID API can
            // inspect the variable-length pointer returned inside TOKEN_USER.
            if sid_remaining < 8 {
                return Err("TokenUser SID header is out of bounds".into());
            }
            let sub_authorities = usize::from(*sid.cast::<u8>().add(1));
            let sid_len = sub_authorities
                .checked_mul(4)
                .and_then(|bytes| 8_usize.checked_add(bytes))
                .ok_or_else(|| "TokenUser SID length overflow".to_owned())?;
            if sid_len > sid_remaining
                || IsValidSid(sid) == 0
                || GetLengthSid(sid) as usize != sid_len
            {
                return Err("TokenUser SID length is invalid".into());
            }
            let bytes = std::slice::from_raw_parts(sid.cast::<u8>(), sid_len);
            let mut encoded = String::with_capacity(4 + sid_len * 2);
            encoded.push_str("sid:");
            for byte in bytes {
                use std::fmt::Write as _;
                write!(&mut encoded, "{byte:02x}").map_err(|err| err.to_string())?;
            }
            Ok(encoded)
        })();
        let _ = CloseHandle(token);
        token_result
    })();

    if RevertToSelf() == 0 {
        return Err(format!(
            "RevertToSelf failed after pipe impersonation: {}",
            std::io::Error::last_os_error()
        ));
    }
    result
}

/// Best-effort full image path for `pid`.
///
/// # Safety
///
/// Opens the process with `PROCESS_QUERY_LIMITED_INFORMATION`; fails soft to `None`.
#[cfg(windows)]
unsafe fn process_image_path(pid: u32) -> Option<String> {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    let process: HANDLE = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
    if process.is_null() {
        return None;
    }
    let mut buf = vec![0u16; 1024];
    let mut size = buf.len() as u32;
    let ok = QueryFullProcessImageNameW(process, 0, buf.as_mut_ptr(), &mut size);
    let _ = CloseHandle(process);
    if ok == 0 || size == 0 {
        return None;
    }
    Some(String::from_utf16_lossy(&buf[..size as usize]))
}

#[cfg(unix)]
fn prepare_unix_path(path: &Path) -> IpcResult<()> {
    if let Some(parent) = path.parent() {
        if Endpoint::is_short_socket_root(parent) {
            // The shortened-endpoint root lives in a shared world-writable
            // directory, so it is created and re-validated as owner-only on
            // every bind rather than trusted because it already exists.
            ensure_owner_only_short_root(parent)?;
        } else {
            std::fs::create_dir_all(parent)?;
        }
    }
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Create (0700) or attest custody of the shortened-endpoint root.
///
/// Fail-closed: a pre-existing entry must be a real directory — not a symlink —
/// owned by this uid with no group/other bits. Anything else is refused instead
/// of being repaired, because a hostile pre-creation is indistinguishable from
/// a damaged one and binding into it would expose the socket.
#[cfg(unix)]
fn ensure_owner_only_short_root(root: &Path) -> IpcResult<()> {
    use std::fs::DirBuilder;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};

    match DirBuilder::new().mode(0o700).create(root) {
        Ok(()) => return Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(IpcError::Io(err)),
    }

    let meta = std::fs::symlink_metadata(root)?;
    if !meta.file_type().is_dir() {
        return Err(IpcError::Protocol(format!(
            "shortened socket root {} is not a directory (fail-closed)",
            root.display()
        )));
    }
    let uid = rustix::process::getuid().as_raw();
    if meta.uid() != uid {
        return Err(IpcError::Protocol(format!(
            "shortened socket root {} is owned by uid {} rather than {uid} (fail-closed)",
            root.display(),
            meta.uid()
        )));
    }
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(IpcError::Protocol(format!(
            "shortened socket root {} has mode {mode:04o}; owner-only 0700 is required (fail-closed)",
            root.display()
        )));
    }
    Ok(())
}

#[cfg(unix)]
fn enforce_allowed_uid(peer: &OsPeerIdentity, allowed_uids: &[u32]) -> IpcResult<()> {
    if allowed_uids.is_empty() {
        return Ok(());
    }
    let peer_uid: u32 = peer.user_id.parse().map_err(|_| {
        IpcError::Unauthorized(format!(
            "peer uid '{}' is not numeric (fail-closed)",
            peer.user_id
        ))
    })?;
    if allowed_uids.contains(&peer_uid) {
        Ok(())
    } else {
        Err(IpcError::Unauthorized(format!(
            "peer uid {peer_uid} not in allowed_uids {allowed_uids:?} (fail-closed)"
        )))
    }
}

/// Apply owner/group/mode to a freshly bound Unix socket. Fail-closed on any error.
#[cfg(unix)]
fn apply_unix_socket_security(path: &Path, security: &UnixSocketSecurity) -> IpcResult<()> {
    use std::os::unix::fs::{chown, PermissionsExt};

    let mode = security.mode.unwrap_or(0o600);
    validate_mode_bits(mode)?;
    if mode & 0o070 != 0 && security.group_gid.is_none() {
        return Err(IpcError::Protocol(
            "unix socket mode grants group access but group is unset (fail-closed)".into(),
        ));
    }

    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms).map_err(|err| {
        IpcError::Protocol(format!(
            "failed to set socket mode {mode:#o} on {}: {err} (fail-closed)",
            path.display()
        ))
    })?;

    if security.owner_uid.is_some() || security.group_gid.is_some() {
        // std::os::unix::fs::chown is fail-closed: any OS error aborts serve.
        chown(path, security.owner_uid, security.group_gid).map_err(|err| {
            IpcError::Protocol(format!(
                "failed to chown socket {} to owner={:?} group={:?}: {err} (fail-closed)",
                path.display(),
                security.owner_uid,
                security.group_gid
            ))
        })?;
    }

    // Verify mode stuck (detect races / bad FS).
    let meta = std::fs::metadata(path).map_err(|err| {
        IpcError::Protocol(format!(
            "failed to stat socket {} after ACL apply: {err} (fail-closed)",
            path.display()
        ))
    })?;
    let got = meta.permissions().mode() & 0o777;
    if got != mode {
        return Err(IpcError::Protocol(format!(
            "socket mode mismatch on {}: want {mode:#o} got {got:#o} (fail-closed)",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
#[allow(dead_code)]
fn enforce_allowed_uid(_peer: &OsPeerIdentity, _allowed_uids: &[u32]) -> IpcResult<()> {
    Ok(())
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn named_pipe_peer_facts_are_kernel_attested_and_revalidatable() {
        let endpoint = Endpoint::NamedPipe(format!(
            r"\\.\pipe\ownmesh-ipc-peer-facts-{}",
            uuid::Uuid::new_v4()
        ));
        let listener = LocalListener::bind(endpoint.clone()).await.unwrap();
        let client = tokio::spawn(async move {
            let mut client = connect(&endpoint).await.unwrap();
            assert_eq!(
                client.windows_pipe_server_pid().unwrap(),
                std::process::id()
            );
            client.write_all(b"x").await.unwrap();
            client.flush().await.unwrap();
        });

        let mut server = listener.accept().await.unwrap();
        let mut marker = [0_u8; 1];
        server.read_exact(&mut marker).await.unwrap();
        assert_eq!(marker, [b'x']);
        let facts = server.windows_pipe_peer_facts().unwrap();
        assert_eq!(facts.pid(), std::process::id());
        assert!(!facts.user_sid().is_empty());
        assert!(facts.creation_filetime() > 0);
        assert!(!facts.image_path().is_empty());
        assert_ne!(facts.image_file_id(), [0_u8; 16]);
        facts.revalidate_process_birth().unwrap();
        facts.revalidate_image().unwrap();
        client.await.unwrap();
    }

    #[tokio::test]
    async fn secure_broker_pipe_rejects_sid_injection_and_attests_live_dacl() {
        let Err(error) = LocalListener::bind_secure_broker_pipe("S-1-5-18)(A;;GA;;;WD").await
        else {
            panic!("SDDL injection must not reach pipe creation");
        };
        assert!(error.to_string().contains("SID"), "{error}");

        // Successful bind proves that the live handle, not just requested
        // SDDL text, passed the exact protected-DACL attestation. Connection
        // access is intentionally not asserted here: administrator membership
        // may be enabled or deny-only depending on the test runner token.
        let listener = LocalListener::bind_secure_broker_pipe("S-1-5-18")
            .await
            .expect("secure broker pipe DACL must be accepted");
        assert_eq!(
            listener.endpoint(),
            &Endpoint::NamedPipe(LocalListener::SECURE_BROKER_PIPE_NAME.into())
        );
    }
}
