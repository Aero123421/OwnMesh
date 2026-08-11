//! OS-local broker transport.
//!
//! Production order of preference:
//! - Windows: Named Pipe (ACL-backed; see Microsoft Named Pipe Security docs)
//! - Unix: filesystem Unix socket (mode 0600) + optional `SO_PEERCRED` (Linux)
//! - Fallback: loopback TCP (`127.0.0.1` / `::1` only) for portable tests
//!
//! References:
//! - <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>
//! - <https://www.man7.org/linux/man-pages/man7/unix.7.html> (`SO_PEERCRED`)
//! - <https://www.man7.org/linux/man-pages/man7/socket.7.html>

use crate::{
    compute_cancel_intent_mac_v2, operation_facts_digest, BrokerError, BrokerRequest,
    BrokerResponse, BrokerResponseV2, BrokerResult, BrokerSecret, BrokerWireIntentV2,
    CancelIntentV2, ExecuteIntentV2, DEFAULT_BROKER_ENDPOINT, DEFAULT_CAPABILITY_TTL_SECS,
    MAX_BROKER_REQUEST_BYTES,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::watch;
use uuid::Uuid;

#[cfg(any(unix, windows))]
use crate::MAX_BROKER_RESPONSE_BYTES;
#[cfg(any(unix, windows))]
use std::time::Duration;
#[cfg(any(unix, windows))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

/// Timeout phase for the strict v2 Unix-socket client path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum V2TimeoutPhase {
    Connect,
    Write,
    Read,
}

impl std::fmt::Display for V2TimeoutPhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect => f.write_str("connect"),
            Self::Write => f.write_str("write"),
            Self::Read => f.write_str("read"),
        }
    }
}

/// Typed failure surface for a v2 execution attempt.
///
/// [`Self::ExecutionUncertain`] is intentionally non-retriable: after an
/// Execute frame may have reached the broker, submitting it again could run a
/// privileged action twice.  Callers must reconcile through a durable broker
/// receipt rather than automatically re-executing it.
#[derive(Debug, Error)]
pub enum BrokerV2ClientError {
    #[error("v2 execution requires a Unix domain socket endpoint")]
    UnixSocketRequired,
    #[error("v2 {phase} timed out")]
    Timeout { phase: V2TimeoutPhase },
    #[error("v2 request exceeds byte limit")]
    RequestTooLarge,
    #[error("v2 response exceeds byte limit")]
    ResponseTooLarge,
    #[error("malformed strict v2 response: {0}")]
    MalformedResponse(String),
    #[error("v2 response request_id mismatch")]
    RequestIdMismatch,
    #[error("v2 transport failed before execute submission: {0}")]
    Connect(String),
    #[error("v2 Windows broker server identity rejected: {0}")]
    TrustedServer(String),
    #[error("v2 execution outcome uncertain; do not retry: {0}")]
    ExecutionUncertain(String),
}

/// Result type for the production v2 client path.
pub type BrokerV2ClientResult<T> = Result<T, BrokerV2ClientError>;

#[cfg(any(unix, windows))]
const V2_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(unix, windows))]
const V2_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(any(unix, windows))]
const V2_RESPONSE_GRACE: Duration = Duration::from_secs(5);

/// Transport kind selected for a broker endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    NamedPipe,
    UnixSocket,
    LoopbackTcp,
}

/// Fully resolved broker endpoint (always local / networkless).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerEndpoint {
    /// Windows named pipe path (`\\.\pipe\...`).
    NamedPipe(String),
    /// Unix domain socket filesystem path.
    UnixSocket(PathBuf),
    /// Loopback TCP (tests / portable fallback only).
    LoopbackTcp(SocketAddr),
}

impl BrokerEndpoint {
    #[must_use]
    pub fn kind(&self) -> TransportKind {
        match self {
            Self::NamedPipe(_) => TransportKind::NamedPipe,
            Self::UnixSocket(_) => TransportKind::UnixSocket,
            Self::LoopbackTcp(_) => TransportKind::LoopbackTcp,
        }
    }

    /// Ensure TCP endpoints are loopback-only.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Networkless`] for a non-loopback TCP endpoint.
    pub fn enforce_networkless(&self) -> BrokerResult<()> {
        match self {
            Self::LoopbackTcp(addr) => {
                if !addr.ip().is_loopback() {
                    return Err(BrokerError::Networkless(format!(
                        "refusing non-loopback broker listen/connect: {addr}"
                    )));
                }
                Ok(())
            }
            Self::NamedPipe(_) | Self::UnixSocket(_) => Ok(()),
        }
    }
}

/// Fixed production identity that a Windows v2 broker client must verify before
/// it writes an authority-bearing frame.  This cannot be inferred from a pipe
/// name: the exact pipe handle PID, SCM running-service PID, installed image
/// path, process birth, and held image identity must all agree.
#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsBrokerTrust {
    service_name: String,
    broker_image: PathBuf,
}

#[cfg(windows)]
impl WindowsBrokerTrust {
    /// Construct a trust record from the service name and the already-custodied
    /// installed broker image.  The path is canonicalized immediately; a
    /// missing/reparse/replaced record is denied before pipe connection.
    pub fn new(service_name: impl Into<String>, broker_image: &Path) -> BrokerV2ClientResult<Self> {
        let service_name = service_name.into();
        if service_name.is_empty()
            || service_name.len() > 256
            || !service_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(BrokerV2ClientError::TrustedServer(
                "invalid SCM service name".into(),
            ));
        }
        let broker_image = std::fs::canonicalize(broker_image).map_err(|error| {
            BrokerV2ClientError::TrustedServer(format!(
                "canonicalize recorded broker image: {error}"
            ))
        })?;
        if !broker_image.is_file() {
            return Err(BrokerV2ClientError::TrustedServer(
                "recorded broker image is not a regular file".into(),
            ));
        }
        Ok(Self {
            service_name,
            broker_image,
        })
    }

    #[must_use]
    pub fn service_name(&self) -> &str {
        &self.service_name
    }
    #[must_use]
    pub fn broker_image(&self) -> &Path {
        &self.broker_image
    }
}

/// A connected, SCM-and-handle-attested Windows broker pipe.  The retained
/// process facts must be revalidated after the response before a caller treats
/// it as an authoritative execution receipt.
#[cfg(windows)]
pub struct VerifiedWindowsBrokerConnection {
    connection: ownmesh_ipc::ClientConnection,
    process: ownmesh_ipc::WindowsProcessFacts,
}

#[cfg(windows)]
impl VerifiedWindowsBrokerConnection {
    #[must_use]
    pub fn connection_mut(&mut self) -> &mut ownmesh_ipc::ClientConnection {
        &mut self.connection
    }

    /// Revalidate PID birth and held image identity after a request/response.
    pub fn revalidate_server(&self) -> BrokerV2ClientResult<()> {
        self.process
            .revalidate_process_birth()
            .map_err(|error| BrokerV2ClientError::TrustedServer(error.to_string()))?;
        self.process
            .revalidate_image()
            .map_err(|error| BrokerV2ClientError::TrustedServer(error.to_string()))
    }
}

/// Open only the fixed secure broker pipe and verify the server process before
/// any bytes are sent.  Generic NamedPipe endpoints deliberately cannot use
/// this path, preventing same-name/user-pipe substitution.
#[cfg(windows)]
pub async fn connect_verified_windows_broker(
    endpoint: &BrokerEndpoint,
    trust: &WindowsBrokerTrust,
) -> BrokerV2ClientResult<VerifiedWindowsBrokerConnection> {
    let BrokerEndpoint::NamedPipe(pipe_name) = endpoint else {
        return Err(BrokerV2ClientError::TrustedServer(
            "Windows v2 broker requires a named pipe".into(),
        ));
    };
    if pipe_name != ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME {
        return Err(BrokerV2ClientError::TrustedServer(
            "Windows broker pipe name is not the fixed secure endpoint".into(),
        ));
    }
    let connection = ownmesh_ipc::connect(&ownmesh_ipc::Endpoint::NamedPipe(pipe_name.clone()))
        .await
        .map_err(|error| BrokerV2ClientError::Connect(error.to_string()))?;
    let pid = connection
        .windows_pipe_server_pid()
        .map_err(|error| BrokerV2ClientError::TrustedServer(error.to_string()))?;
    let service = ownmesh_ipc::windows_running_service_facts(trust.service_name(), pid)
        .map_err(|error| BrokerV2ClientError::TrustedServer(error.to_string()))?;
    let configured_image = extract_windows_service_image(service.binary_command_line())?;
    let configured_image = std::fs::canonicalize(configured_image).map_err(|error| {
        BrokerV2ClientError::TrustedServer(format!("canonicalize SCM broker image: {error}"))
    })?;
    if configured_image != trust.broker_image {
        return Err(BrokerV2ClientError::TrustedServer(
            "SCM broker image differs from installed trust record".into(),
        ));
    }
    let process = ownmesh_ipc::windows_process_facts(pid)
        .map_err(|error| BrokerV2ClientError::TrustedServer(error.to_string()))?;
    if !process
        .image_path()
        .eq_ignore_ascii_case(trust.broker_image.to_string_lossy().as_ref())
    {
        return Err(BrokerV2ClientError::TrustedServer(
            "pipe server running image differs from SCM/install record".into(),
        ));
    }
    process
        .revalidate_process_birth()
        .map_err(|error| BrokerV2ClientError::TrustedServer(error.to_string()))?;
    process
        .revalidate_image()
        .map_err(|error| BrokerV2ClientError::TrustedServer(error.to_string()))?;
    Ok(VerifiedWindowsBrokerConnection {
        connection,
        process,
    })
}

#[cfg(windows)]
fn extract_windows_service_image(command_line: &str) -> BrokerV2ClientResult<&Path> {
    let command_line = command_line.trim();
    let image = if let Some(rest) = command_line.strip_prefix('"') {
        rest.split_once('"')
            .map(|(image, _)| image)
            .ok_or_else(|| {
                BrokerV2ClientError::TrustedServer(
                    "SCM broker command line has an unterminated image quote".into(),
                )
            })?
    } else {
        command_line.split_whitespace().next().ok_or_else(|| {
            BrokerV2ClientError::TrustedServer("SCM broker command line is empty".into())
        })?
    };
    if image.is_empty() {
        return Err(BrokerV2ClientError::TrustedServer(
            "SCM broker image is empty".into(),
        ));
    }
    Ok(Path::new(image))
}

/// True when `addr` is a loopback IP (IPv4 or IPv6).
#[must_use]
pub fn is_loopback_socket_addr(addr: &SocketAddr) -> bool {
    addr.ip().is_loopback()
}

/// Human-readable endpoint.
#[must_use]
pub fn broker_endpoint_display(ep: &BrokerEndpoint) -> String {
    match ep {
        BrokerEndpoint::NamedPipe(n) => n.clone(),
        BrokerEndpoint::UnixSocket(p) => p.display().to_string(),
        BrokerEndpoint::LoopbackTcp(a) => a.to_string(),
    }
}

/// Default production endpoint under `runtime_dir`.
#[must_use]
pub fn default_broker_endpoint(runtime_dir: &Path) -> BrokerEndpoint {
    #[cfg(windows)]
    {
        let raw = runtime_dir.to_string_lossy();
        let mut key: String = raw
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(40)
            .collect();
        if key.is_empty() {
            let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
            for b in raw.as_bytes() {
                acc = acc
                    .wrapping_mul(0x0100_0000_01b3)
                    .wrapping_add(u64::from(*b));
            }
            key = format!("{acc:016x}");
        }
        BrokerEndpoint::NamedPipe(format!(r"\\.\pipe\{DEFAULT_BROKER_ENDPOINT}-{key}"))
    }
    #[cfg(not(windows))]
    {
        BrokerEndpoint::UnixSocket(runtime_dir.join(format!("{DEFAULT_BROKER_ENDPOINT}.sock")))
    }
}

/// Resolve endpoint from optional override string.
///
/// Accepts:
/// - `tcp:127.0.0.1:PORT` or bare `127.0.0.1:PORT` / `[::1]:PORT`
/// - `pipe:NAME` or `\\.\pipe\...`
/// - `unix:/path` or absolute/relative filesystem path ending in `.sock`
///
/// # Errors
///
/// Returns [`BrokerError::Protocol`] if the endpoint cannot be parsed, or
/// [`BrokerError::Networkless`] if a TCP endpoint is not loopback-only.
pub fn resolve_broker_endpoint(
    runtime_dir: &Path,
    override_spec: Option<&str>,
) -> BrokerResult<BrokerEndpoint> {
    let Some(spec) = override_spec.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(default_broker_endpoint(runtime_dir));
    };

    if let Some(rest) = spec.strip_prefix("tcp:") {
        let addr: SocketAddr = rest
            .parse()
            .map_err(|e| BrokerError::Protocol(format!("invalid tcp endpoint: {e}")))?;
        let ep = BrokerEndpoint::LoopbackTcp(addr);
        ep.enforce_networkless()?;
        return Ok(ep);
    }
    if let Some(rest) = spec.strip_prefix("pipe:") {
        return Ok(BrokerEndpoint::NamedPipe(
            if rest.starts_with(r"\\.\pipe\") {
                rest.to_string()
            } else {
                format!(r"\\.\pipe\{rest}")
            },
        ));
    }
    if let Some(rest) = spec.strip_prefix("unix:") {
        return Ok(BrokerEndpoint::UnixSocket(PathBuf::from(rest)));
    }
    if spec.starts_with(r"\\.\pipe\") {
        return Ok(BrokerEndpoint::NamedPipe(spec.to_string()));
    }
    if spec.eq_ignore_ascii_case(".sock")
        || Path::new(spec)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("sock"))
        || spec.starts_with('/')
    {
        return Ok(BrokerEndpoint::UnixSocket(PathBuf::from(spec)));
    }
    if let Ok(addr) = spec.parse::<SocketAddr>() {
        let ep = BrokerEndpoint::LoopbackTcp(addr);
        ep.enforce_networkless()?;
        return Ok(ep);
    }
    Err(BrokerError::Protocol(format!(
        "unrecognized broker endpoint: {spec}"
    )))
}

/// Connect, write one JSON request line, and read one JSON response line.
///
/// # Errors
///
/// Returns a [`BrokerError`] if endpoint validation, connection, request writing,
/// response reading, or response deserialization fails.
pub async fn connect_and_call(
    endpoint: &BrokerEndpoint,
    req: &BrokerRequest,
) -> BrokerResult<BrokerResponse> {
    endpoint.enforce_networkless()?;
    match endpoint {
        // TCP cannot carry OS peer credentials.  A loopback address is not a
        // production privilege boundary, so callers must never silently fall
        // back to it.  In-process socket tests use the broker's direct helper.
        BrokerEndpoint::LoopbackTcp(addr) => Err(BrokerError::Networkless(format!(
            "refusing LoopbackTcp broker client path at {addr}; production requires a peer-verifiable local IPC endpoint"
        ))),
        #[cfg(windows)]
        BrokerEndpoint::NamedPipe(name) => {
            use tokio::net::windows::named_pipe::ClientOptions;
            let mut last = None;
            for _ in 0..80 {
                match ClientOptions::new().open(name) {
                    Ok(mut client) => return write_req_read_resp(&mut client, req).await,
                    Err(err) => {
                        last = Some(err);
                        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                    }
                }
            }
            Err(BrokerError::Io(format!(
                "named pipe connect failed: {}",
                last.map(|e| e.to_string()).unwrap_or_default()
            )))
        }
        #[cfg(not(windows))]
        BrokerEndpoint::NamedPipe(name) => Err(BrokerError::Protocol(format!(
            "named pipe {name} unsupported on this OS"
        ))),
        #[cfg(unix)]
        BrokerEndpoint::UnixSocket(path) => {
            let mut stream = tokio::net::UnixStream::connect(path)
                .await
                .map_err(|e| BrokerError::Io(format!("unix connect {}: {e}", path.display())))?;
            write_req_read_resp(&mut stream, req).await
        }
        #[cfg(not(unix))]
        BrokerEndpoint::UnixSocket(path) => Err(BrokerError::Protocol(format!(
            "unix socket {} unsupported on this OS",
            path.display()
        ))),
    }
}

/// Build a fresh, exact cancellation intent for one submitted execute intent.
/// The target facts digest and all target identifiers are copied from the
/// original frame; callers cannot turn a local cancel signal into a free-form
/// broker operation.
#[must_use]
pub fn build_cancel_intent_v2(
    secret: &BrokerSecret,
    execute: &ExecuteIntentV2,
    now_unix: i64,
) -> CancelIntentV2 {
    let expires_at_unix = now_unix
        .saturating_add(DEFAULT_CAPABILITY_TTL_SECS)
        .min(execute.expires_at_unix);
    let mut cancel = CancelIntentV2 {
        protocol_version: crate::BROKER_PROTOCOL_V2,
        request_id: format!("cancel_{}", Uuid::new_v4().simple()),
        operation_id: execute.operation_id.clone(),
        nonce: format!("cancel_nonce_{}", Uuid::new_v4().simple()),
        issued_at_unix: now_unix,
        expires_at_unix,
        target_request_id: execute.request_id.clone(),
        target_operation_id: execute.operation_id.clone(),
        target_nonce: execute.nonce.clone(),
        target_facts_digest: operation_facts_digest(&execute.facts),
        mac: String::new(),
    };
    cancel.mac = compute_cancel_intent_mac_v2(secret, &cancel);
    cancel
}

/// Submit one exact v2 Execute intent over a Unix domain socket and keep that
/// socket open until the broker returns the matching response.
///
/// No TCP, loopback, or named-pipe fallback exists on this path: v2 elevation
/// relies on Unix peer credentials and the server treats this connection's EOF
/// as an execution-cancel signal.
pub async fn connect_and_execute_v2(
    endpoint: &BrokerEndpoint,
    execute: &ExecuteIntentV2,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    let (mut stream, request_id) = submit_execute_v2(endpoint, execute).await?;
    read_execute_response_v2(&mut stream, &request_id, execute.facts.timeout_ms).await
}

/// Submit one exact capability-free v2 Execute intent through a Windows pipe
/// only after its server has passed the fixed-pipe, SCM, process-birth, and
/// image-identity checks.  There is no TCP or generic-NamedPipe fallback.
#[cfg(windows)]
pub async fn submit_execute_v2_windows(
    endpoint: &BrokerEndpoint,
    trust: &WindowsBrokerTrust,
    execute: &ExecuteIntentV2,
) -> BrokerV2ClientResult<(VerifiedWindowsBrokerConnection, String)> {
    let frame = serialize_v2_intent(&BrokerWireIntentV2::Execute(execute.clone()))?;
    let request_id = execute.request_id.clone();
    let mut connection = connect_verified_windows_broker(endpoint, trust).await?;
    write_v2_frame(connection.connection_mut(), &frame)
        .await
        .map_err(|error| {
            BrokerV2ClientError::ExecutionUncertain(format!("execute write: {error}"))
        })?;
    Ok((connection, request_id))
}

/// Await an already-submitted exact Windows Execute request. Dropping the
/// retained connection before this future completes is an intentional
/// cancellation fence at the broker boundary, not a retry signal.
#[cfg(windows)]
pub async fn read_submitted_execute_v2_windows(
    connection: &mut VerifiedWindowsBrokerConnection,
    request_id: &str,
    execution_timeout_ms: u64,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    let timeout = Duration::from_millis(execution_timeout_ms).saturating_add(V2_RESPONSE_GRACE);
    let response = read_v2_response(connection.connection_mut(), request_id, timeout)
        .await
        .map_err(|error| match error {
            BrokerV2ClientError::Timeout { .. }
            | BrokerV2ClientError::Connect(_)
            | BrokerV2ClientError::ExecutionUncertain(_) => {
                BrokerV2ClientError::ExecutionUncertain(error.to_string())
            }
            other => other,
        })?;
    connection.revalidate_server()?;
    Ok(response)
}

/// Submit and await one exact Windows v2 Execute intent.
#[cfg(windows)]
pub async fn connect_and_execute_v2_windows(
    endpoint: &BrokerEndpoint,
    trust: &WindowsBrokerTrust,
    execute: &ExecuteIntentV2,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    let (mut connection, request_id) = submit_execute_v2_windows(endpoint, trust, execute).await?;
    read_submitted_execute_v2_windows(&mut connection, &request_id, execute.facts.timeout_ms).await
}

/// Submit a fenced v2 Cancel intent through the same verified Windows service
/// identity boundary.  Cancel is always a new connection and cannot become a
/// free-form command.
#[cfg(windows)]
pub async fn connect_and_cancel_v2_windows(
    endpoint: &BrokerEndpoint,
    trust: &WindowsBrokerTrust,
    cancel: &CancelIntentV2,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    let frame = serialize_v2_intent(&BrokerWireIntentV2::Cancel(cancel.clone()))?;
    let request_id = cancel.request_id.clone();
    let mut connection = connect_verified_windows_broker(endpoint, trust).await?;
    write_v2_frame(connection.connection_mut(), &frame)
        .await
        .map_err(|error| {
            BrokerV2ClientError::ExecutionUncertain(format!("cancel write: {error}"))
        })?;
    let response = read_v2_response(connection.connection_mut(), &request_id, V2_CONNECT_TIMEOUT)
        .await
        .map_err(cancel_response_error)?;
    connection.revalidate_server()?;
    Ok(response)
}

/// Send an already-MACed, exact v2 Cancel intent over a fresh Unix socket.
/// This deliberately does not reuse the execute socket, which is held open by
/// the pending execution and is itself part of the broker's disconnect fence.
pub async fn connect_and_cancel_v2(
    endpoint: &BrokerEndpoint,
    cancel: &CancelIntentV2,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    let request_id = cancel.request_id.clone();
    let frame = serialize_v2_intent(&BrokerWireIntentV2::Cancel(cancel.clone()))?;
    #[cfg(unix)]
    {
        let mut stream = connect_v2_unix(endpoint).await?;
        write_v2_frame(&mut stream, &frame).await.map_err(|error| {
            BrokerV2ClientError::ExecutionUncertain(format!("cancel write: {error}"))
        })?;
        read_v2_response(&mut stream, &request_id, V2_CONNECT_TIMEOUT)
            .await
            .map_err(cancel_response_error)
    }
    #[cfg(not(unix))]
    {
        let _ = (endpoint, frame, request_id);
        Err(BrokerV2ClientError::UnixSocketRequired)
    }
}

/// Execute while watching a local cancellation signal.  Once signaled, this
/// submits one freshly MACed exact Cancel intent on a separate socket while
/// continuing to await the original Execute response.  It never retries or
/// re-executes the privileged operation.
pub async fn connect_and_execute_v2_cancellable(
    endpoint: &BrokerEndpoint,
    secret: &BrokerSecret,
    execute: &ExecuteIntentV2,
    cancel_signal: &mut watch::Receiver<bool>,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    let (mut stream, request_id) = submit_execute_v2(endpoint, execute).await?;
    let mut cancel_sent = false;
    let mut response = Box::pin(read_execute_response_v2(
        &mut stream,
        &request_id,
        execute.facts.timeout_ms,
    ));

    loop {
        tokio::select! {
            result = &mut response => return result,
            changed = cancel_signal.changed(), if !cancel_sent => {
                if changed.is_err() || *cancel_signal.borrow() {
                    cancel_sent = true;
                    let cancel = build_cancel_intent_v2(secret, execute, now_unix());
                    // A cancel transport failure does not justify abandoning a
                    // still-live execute connection; its final response is the
                    // only authoritative outcome. If that connection becomes
                    // uncertain, read_execute_response_v2 returns the explicit
                    // non-retriable ExecutionUncertain outcome.
                    let _ = connect_and_cancel_v2(endpoint, &cancel).await;
                }
            }
        }
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn serialize_v2_intent(intent: &BrokerWireIntentV2) -> BrokerV2ClientResult<Vec<u8>> {
    let frame = serde_json::to_vec(intent)
        .map_err(|error| BrokerV2ClientError::MalformedResponse(error.to_string()))?;
    if frame.len() > MAX_BROKER_REQUEST_BYTES {
        return Err(BrokerV2ClientError::RequestTooLarge);
    }
    Ok(frame)
}

#[allow(clippy::unused_async)]
async fn submit_execute_v2(
    endpoint: &BrokerEndpoint,
    execute: &ExecuteIntentV2,
) -> BrokerV2ClientResult<(V2ExecuteStream, String)> {
    let request_id = execute.request_id.clone();
    let frame = serialize_v2_intent(&BrokerWireIntentV2::Execute(execute.clone()))?;
    #[cfg(unix)]
    {
        let mut stream = connect_v2_unix(endpoint).await?;
        write_v2_frame(&mut stream, &frame).await.map_err(|error| {
            BrokerV2ClientError::ExecutionUncertain(format!("execute write: {error}"))
        })?;
        Ok((stream, request_id))
    }
    #[cfg(not(unix))]
    {
        let _ = (endpoint, frame, request_id);
        Err(BrokerV2ClientError::UnixSocketRequired)
    }
}

#[cfg(unix)]
type V2ExecuteStream = tokio::net::UnixStream;

#[cfg(not(unix))]
type V2ExecuteStream = ();

#[cfg(unix)]
async fn connect_v2_unix(
    endpoint: &BrokerEndpoint,
) -> BrokerV2ClientResult<tokio::net::UnixStream> {
    let BrokerEndpoint::UnixSocket(path) = endpoint else {
        return Err(BrokerV2ClientError::UnixSocketRequired);
    };
    tokio::time::timeout(V2_CONNECT_TIMEOUT, tokio::net::UnixStream::connect(path))
        .await
        .map_err(|_| BrokerV2ClientError::Timeout {
            phase: V2TimeoutPhase::Connect,
        })?
        .map_err(|error| BrokerV2ClientError::Connect(format!("{}: {error}", path.display())))
}

#[cfg(any(unix, windows))]
async fn write_v2_frame<S>(stream: &mut S, frame: &[u8]) -> Result<(), String>
where
    S: AsyncWrite + Unpin,
{
    let mut line = Vec::with_capacity(frame.len() + 1);
    line.extend_from_slice(frame);
    line.push(b'\n');
    tokio::time::timeout(V2_WRITE_TIMEOUT, async {
        stream.write_all(&line).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| "write timed out".to_string())?
    .map_err(|error| error.to_string())
}

#[cfg(unix)]
#[allow(clippy::unused_async)]
async fn read_execute_response_v2(
    stream: &mut tokio::net::UnixStream,
    request_id: &str,
    execution_timeout_ms: u64,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    let timeout = Duration::from_millis(execution_timeout_ms).saturating_add(V2_RESPONSE_GRACE);
    read_v2_response(stream, request_id, timeout)
        .await
        .map_err(|error| match error {
            BrokerV2ClientError::Timeout { .. }
            | BrokerV2ClientError::Connect(_)
            | BrokerV2ClientError::ExecutionUncertain(_) => {
                BrokerV2ClientError::ExecutionUncertain(error.to_string())
            }
            other => other,
        })
}

#[cfg(not(unix))]
#[allow(clippy::unused_async)]
async fn read_execute_response_v2(
    _stream: &mut V2ExecuteStream,
    _request_id: &str,
    _execution_timeout_ms: u64,
) -> BrokerV2ClientResult<BrokerResponseV2> {
    Err(BrokerV2ClientError::UnixSocketRequired)
}

#[cfg(any(unix, windows))]
async fn read_v2_response<S>(
    stream: &mut S,
    request_id: &str,
    timeout: Duration,
) -> BrokerV2ClientResult<BrokerResponseV2>
where
    S: AsyncRead + Unpin,
{
    let line = tokio::time::timeout(timeout, read_bounded_v2_line(stream))
        .await
        .map_err(|_| BrokerV2ClientError::Timeout {
            phase: V2TimeoutPhase::Read,
        })??;
    let response: BrokerResponseV2 = serde_json::from_slice(&line)
        .map_err(|error| BrokerV2ClientError::MalformedResponse(error.to_string()))?;
    if response.request_id != request_id {
        return Err(BrokerV2ClientError::RequestIdMismatch);
    }
    if response.stdout.len() > crate::MAX_BROKER_OUTPUT_BYTES
        || response.stderr.len() > crate::MAX_BROKER_OUTPUT_BYTES
        || response
            .error
            .as_ref()
            .is_some_and(|error| error.len() > crate::MAX_BROKER_OUTPUT_BYTES)
    {
        return Err(BrokerV2ClientError::ResponseTooLarge);
    }
    Ok(response)
}

#[cfg(any(unix, windows))]
async fn read_bounded_v2_line<S>(stream: &mut S) -> BrokerV2ClientResult<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::with_capacity(1024);
    let mut byte = [0_u8; 1];
    loop {
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| BrokerV2ClientError::ExecutionUncertain(error.to_string()))?;
        if read == 0 {
            return Err(BrokerV2ClientError::ExecutionUncertain(
                "broker closed before a response".into(),
            ));
        }
        if byte[0] == b'\n' {
            return Ok(line);
        }
        if line.len() >= MAX_BROKER_RESPONSE_BYTES {
            return Err(BrokerV2ClientError::ResponseTooLarge);
        }
        line.push(byte[0]);
    }
}

#[cfg(any(unix, windows))]
fn cancel_response_error(error: BrokerV2ClientError) -> BrokerV2ClientError {
    match error {
        BrokerV2ClientError::Timeout { .. }
        | BrokerV2ClientError::Connect(_)
        | BrokerV2ClientError::ExecutionUncertain(_) => {
            BrokerV2ClientError::ExecutionUncertain(format!("cancel outcome uncertain: {error}"))
        }
        other => other,
    }
}

async fn write_req_read_resp<S>(stream: &mut S, req: &BrokerRequest) -> BrokerResult<BrokerResponse>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut line = serde_json::to_string(req).map_err(|e| BrokerError::Protocol(e.to_string()))?;
    line.push('\n');
    stream
        .write_all(line.as_bytes())
        .await
        .map_err(|e| BrokerError::Io(e.to_string()))?;
    stream
        .flush()
        .await
        .map_err(|e| BrokerError::Io(e.to_string()))?;
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    let n = reader
        .read_line(&mut resp_line)
        .await
        .map_err(|e| BrokerError::Io(e.to_string()))?;
    if n == 0 {
        return Err(BrokerError::Io("broker closed connection".into()));
    }
    serde_json::from_str(resp_line.trim())
        .map_err(|e| BrokerError::Protocol(format!("malformed response: {e}")))
}

/// Linux `SO_PEERCRED` peer identity (uid/gid/pid).
/// Populated by the broker server on accept (see ownmesh-broker peer module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    pub pid: i32,
    pub uid: u32,
    pub gid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_rejects_non_loopback_tcp() {
        let err = resolve_broker_endpoint(Path::new("/tmp"), Some("0.0.0.0:9")).unwrap_err();
        assert!(matches!(err, BrokerError::Networkless(_)));
        let err = resolve_broker_endpoint(Path::new("/tmp"), Some("tcp:8.8.8.8:53")).unwrap_err();
        assert!(matches!(err, BrokerError::Networkless(_)));
    }

    #[test]
    fn resolve_accepts_dotfile_unix_socket() {
        let ep = resolve_broker_endpoint(Path::new("/tmp/om"), Some(".sock")).unwrap();
        assert_eq!(ep, BrokerEndpoint::UnixSocket(PathBuf::from(".sock")));
    }

    #[test]
    fn resolve_accepts_loopback_and_default() {
        let ep = resolve_broker_endpoint(Path::new("/tmp/om"), Some("127.0.0.1:0")).unwrap();
        assert!(matches!(ep, BrokerEndpoint::LoopbackTcp(_)));
        let ep = resolve_broker_endpoint(Path::new("/tmp/om"), None).unwrap();
        match ep {
            #[cfg(windows)]
            BrokerEndpoint::NamedPipe(n) => assert!(n.contains("ownmesh-privileged")),
            #[cfg(not(windows))]
            BrokerEndpoint::UnixSocket(p) => {
                assert!(p.to_string_lossy().contains("ownmesh-privileged"));
            }
            other => panic!("unexpected default: {other:?}"),
        }
    }

    #[cfg(windows)]
    #[test]
    fn windows_service_image_parser_rejects_ambiguous_or_unterminated_command_lines() {
        assert_eq!(
            extract_windows_service_image(
                r#""C:\Program Files\OwnMesh\ownmesh-broker.exe" run --config C:\x"#
            )
            .unwrap(),
            Path::new(r"C:\Program Files\OwnMesh\ownmesh-broker.exe")
        );
        assert!(extract_windows_service_image(r#""C:\Program Files\broken.exe"#).is_err());
        assert!(extract_windows_service_image(" ").is_err());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn verified_windows_client_refuses_nonfixed_pipe_before_connecting() {
        let file = tempfile::NamedTempFile::new().unwrap();
        let trust = WindowsBrokerTrust::new("OwnMeshBroker", file.path()).unwrap();
        let Err(err) = connect_verified_windows_broker(
            &BrokerEndpoint::NamedPipe(r"\\.\pipe\attacker".into()),
            &trust,
        )
        .await
        else {
            panic!("non-fixed pipe must be denied before connecting");
        };
        assert!(matches!(err, BrokerV2ClientError::TrustedServer(_)));
    }
}
