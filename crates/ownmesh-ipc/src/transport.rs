//! OS-specific local stream transport (Named Pipe / Unix socket).

use crate::endpoint::Endpoint;
use crate::error::{IpcError, IpcResult};
use tokio::io::{AsyncRead, AsyncWrite};

#[cfg(windows)]
use tokio::net::windows::named_pipe::{
    ClientOptions, NamedPipeClient, NamedPipeServer, ServerOptions,
};
#[cfg(windows)]
use tokio::sync::Mutex;

#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};

/// Accepted server-side connection.
pub struct ServerConnection {
    inner: ConnInner,
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

/// Listening socket / named-pipe factory.
pub struct LocalListener {
    endpoint: Endpoint,
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    pending: Mutex<Option<NamedPipeServer>>,
    #[cfg(unix)]
    listener: UnixListener,
}

impl LocalListener {
    /// Bind a new listener on `endpoint`.
    ///
    /// # Errors
    ///
    /// Returns transport IO errors.
    pub fn bind(endpoint: Endpoint) -> IpcResult<Self> {
        match &endpoint {
            #[cfg(windows)]
            Endpoint::NamedPipe(name) => {
                let first = ServerOptions::new()
                    .first_pipe_instance(true)
                    .create(name)?;
                Ok(Self {
                    pipe_name: name.clone(),
                    pending: Mutex::new(Some(first)),
                    endpoint,
                })
            }
            #[cfg(unix)]
            Endpoint::UnixSocket(path) => {
                prepare_unix_path(path)?;
                let listener = UnixListener::bind(path)?;
                restrict_unix_socket(path)?;
                Ok(Self { listener, endpoint })
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

    /// Accept the next client connection.
    ///
    /// # Errors
    ///
    /// Returns transport IO errors.
    pub async fn accept(&self) -> IpcResult<ServerConnection> {
        #[cfg(windows)]
        {
            let mut guard = self.pending.lock().await;
            let server = match guard.take() {
                Some(s) => s,
                None => ServerOptions::new().create(&self.pipe_name)?,
            };
            // Wait for a client. While waiting, no replacement instance is published yet.
            server.connect().await?;
            // Immediately create the next pending instance so another client can connect.
            *guard = Some(ServerOptions::new().create(&self.pipe_name)?);
            Ok(ServerConnection {
                inner: ConnInner::PipeServer(server),
            })
        }
        #[cfg(unix)]
        {
            let (stream, _addr) = self.listener.accept().await?;
            Ok(ServerConnection {
                inner: ConnInner::Unix(stream),
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
                last_err.map_or_else(|| "unknown".into(), |e| e.to_string())
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
fn restrict_unix_socket(path: &Path) -> IpcResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}
