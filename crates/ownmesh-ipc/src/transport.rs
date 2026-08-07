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
            *guard = Some(ServerOptions::new().create(&self.pipe_name)?);
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
