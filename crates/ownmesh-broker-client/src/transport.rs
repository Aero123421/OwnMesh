//! OS-local broker transport.
//!
//! Production order of preference:
//! - Windows: Named Pipe (ACL-backed; see Microsoft Named Pipe Security docs)
//! - Unix: filesystem Unix socket (mode 0600) + optional `SO_PEERCRED` (Linux)
//! - Fallback: loopback TCP (127.0.0.1 / ::1 only) for portable tests
//!
//! References:
//! - https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
//! - https://www.man7.org/linux/man-pages/man7/unix.7.html (SO_PEERCRED)
//! - https://www.man7.org/linux/man-pages/man7/socket.7.html

use crate::{BrokerError, BrokerRequest, BrokerResponse, BrokerResult, DEFAULT_BROKER_ENDPOINT};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
            .filter(|c| c.is_ascii_alphanumeric())
            .take(40)
            .collect();
        if key.is_empty() {
            let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
            for b in raw.as_bytes() {
                acc = acc.wrapping_mul(0x0100_0000_01b3).wrapping_add(u64::from(*b));
            }
            key = format!("{acc:016x}");
        }
        BrokerEndpoint::NamedPipe(format!(
            r"\\.\pipe\{DEFAULT_BROKER_ENDPOINT}-{key}"
        ))
    }
    #[cfg(not(windows))]
    {
        BrokerEndpoint::UnixSocket(
            runtime_dir.join(format!("{DEFAULT_BROKER_ENDPOINT}.sock")),
        )
    }
}

/// Resolve endpoint from optional override string.
///
/// Accepts:
/// - `tcp:127.0.0.1:PORT` or bare `127.0.0.1:PORT` / `[::1]:PORT`
/// - `pipe:NAME` or `\\.\pipe\...`
/// - `unix:/path` or absolute/relative filesystem path ending in `.sock`
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
        return Ok(BrokerEndpoint::NamedPipe(if rest.starts_with(r"\\.\pipe\") {
            rest.to_string()
        } else {
            format!(r"\\.\pipe\{rest}")
        }));
    }
    if let Some(rest) = spec.strip_prefix("unix:") {
        return Ok(BrokerEndpoint::UnixSocket(PathBuf::from(rest)));
    }
    if spec.starts_with(r"\\.\pipe\") {
        return Ok(BrokerEndpoint::NamedPipe(spec.to_string()));
    }
    if spec.ends_with(".sock") || spec.starts_with('/') {
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

/// Connect, write one JSON request line, read one JSON response line.
pub async fn connect_and_call(
    endpoint: &BrokerEndpoint,
    req: &BrokerRequest,
) -> BrokerResult<BrokerResponse> {
    endpoint.enforce_networkless()?;
    match endpoint {
        BrokerEndpoint::LoopbackTcp(addr) => {
            let mut stream = tokio::net::TcpStream::connect(addr)
                .await
                .map_err(|e| BrokerError::Io(e.to_string()))?;
            write_req_read_resp(&mut stream, req).await
        }
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
}
