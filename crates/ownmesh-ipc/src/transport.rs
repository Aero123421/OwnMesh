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
            .field("creation_filetime", &self.creation_filetime)
            .field("image_path", &self.image_path)
            .field("image_volume_serial", &self.image_volume_serial)
            .field("image_file_id", &self.image_file_id)
            .field("image_sha256", &self.image_sha256)
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

    /// Re-read the process creation time through the retained process handle.
    /// A mismatch means PID reuse or a closed/replaced process and is denied.
    pub fn revalidate_process_birth(&self) -> IpcResult<()> {
        let observed = unsafe { process_creation_filetime(self.process_handle.as_raw_handle()) }
            .map_err(|error| {
                IpcError::Unauthorized(format!(
                    "cannot revalidate named-pipe client process birth (fail-closed): {error}"
                ))
            })?;
        if observed != self.creation_filetime {
            return Err(IpcError::Unauthorized(
                "named-pipe client PID was reused or process birth changed (fail-closed)".into(),
            ));
        }
        Ok(())
    }

    /// Re-read the held image handle's file identity and digest.  This catches
    /// replacement attempts between pipe accept and the privileged action.
    pub fn revalidate_image(&self) -> IpcResult<()> {
        let (volume, file_id) = unsafe { windows_file_id(self.image_handle.as_raw_handle()) }
            .map_err(|error| {
                IpcError::Unauthorized(format!(
                    "cannot revalidate named-pipe client image identity (fail-closed): {error}"
                ))
            })?;
        let digest = sha256_file(&self.image_handle).map_err(|error| {
            IpcError::Unauthorized(format!(
                "cannot revalidate named-pipe client image digest (fail-closed): {error}"
            ))
        })?;
        if volume != self.image_volume_serial
            || file_id != self.image_file_id
            || digest != self.image_sha256
        {
            return Err(IpcError::Unauthorized(
                "named-pipe client image changed after accept (fail-closed)".into(),
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
    #[cfg(windows)]
    pending: TokioMutex<Option<NamedPipeServer>>,
    #[cfg(unix)]
    listener: UnixListener,
    /// Snapshot of allowed peer uids at bind time (enforced on Unix accept).
    #[allow(dead_code)] // read on Unix accept path; retained on Windows for API parity
    allowed_uids: Vec<u32>,
}

impl LocalListener {
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
                None => ServerOptions::new().create(&self.pipe_name)?,
            };
            server.connect().await?;
            *guard = Some(
                ServerOptions::new()
                    .reject_remote_clients(true)
                    .create(&self.pipe_name)?,
            );
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
                "failed to open named pipe {name}: {}",
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
            "named pipe client image attestation failed (fail-closed): {error}"
        ))
    })?;
    Ok(WindowsPipePeerFacts {
        pid,
        user_sid,
        integrity_rid,
        session_id,
        creation_filetime,
        image_path,
        image_volume_serial,
        image_file_id,
        image_sha256,
        process_handle,
        image_handle,
    })
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
        std::fs::create_dir_all(parent)?;
    }
    if path.exists() {
        std::fs::remove_file(path)?;
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
}
