//! Loopback HTTP callback server for Authorization Code + PKCE (RFC 8252 §7.3).

use anyhow::{anyhow, Context, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::time::timeout;
use url::Url;

/// Result captured from the browser redirect.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct CallbackResult {
    pub code: String,
    pub state: Option<String>,
}

/// Bound loopback listener waiting for a single OAuth redirect.
pub struct CallbackServer {
    listener: TcpListener,
    pub redirect_uri: String,
    pub bind_addr: SocketAddr,
}

impl CallbackServer {
    /// Bind `127.0.0.1:preferred` or fall back to an ephemeral port.
    pub async fn bind(preferred_port: u16) -> Result<Self> {
        let preferred = SocketAddr::from(([127, 0, 0, 1], preferred_port));
        let listener = match TcpListener::bind(preferred).await {
            Ok(l) => l,
            Err(_) => TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .context("bind loopback callback listener")?,
        };
        let bind_addr = listener.local_addr()?;
        let redirect_uri = format!("http://127.0.0.1:{}/callback", bind_addr.port());
        Ok(Self {
            listener,
            redirect_uri,
            bind_addr,
        })
    }

    /// Wait for one successful callback matching `expected_state` (when set).
    pub async fn wait_for_code(
        self,
        expected_state: Option<&str>,
        idle_timeout: Duration,
    ) -> Result<CallbackResult> {
        let (tx, rx) = oneshot::channel::<Result<CallbackResult>>();
        let expected = expected_state.map(str::to_owned);
        tokio::spawn(async move {
            let result = accept_once(self.listener, expected.as_deref()).await;
            let _ = tx.send(result);
        });
        match timeout(idle_timeout, rx).await {
            Ok(Ok(inner)) => inner,
            Ok(Err(_)) => Err(anyhow!("callback listener closed unexpectedly")),
            Err(_) => Err(anyhow!(
                "timed out waiting for browser OAuth callback on {}",
                self.bind_addr
            )),
        }
    }
}

async fn accept_once(
    listener: TcpListener,
    expected_state: Option<&str>,
) -> Result<CallbackResult> {
    loop {
        let (mut stream, _) = listener
            .accept()
            .await
            .context("accept OAuth callback connection")?;
        match handle_connection(&mut stream, expected_state).await {
            Ok(Some(result)) => {
                let body = "<!doctype html><html><body style=\"font-family:system-ui;margin:2rem\">\
                    <h1>OwnMesh</h1><p>Login complete. You can close this window and return to the CLI.</p>\
                    </body></html>";
                write_http(
                    &mut stream,
                    200,
                    "text/html; charset=utf-8",
                    body.as_bytes(),
                )
                .await?;
                return Ok(result);
            }
            Ok(None) => {
                // favicon or other noise — keep waiting
                let _ = write_http(&mut stream, 404, "text/plain", b"not found").await;
            }
            Err(err) => {
                let msg = format!("oauth callback error: {err}");
                let body = format!(
                    "<!doctype html><html><body style=\"font-family:system-ui;margin:2rem\">\
                    <h1>OwnMesh login failed</h1><pre>{}</pre></body></html>",
                    html_escape(&msg)
                );
                let _ = write_http(
                    &mut stream,
                    400,
                    "text/html; charset=utf-8",
                    body.as_bytes(),
                )
                .await;
                return Err(err);
            }
        }
    }
}

async fn handle_connection(
    stream: &mut TcpStream,
    expected_state: Option<&str>,
) -> Result<Option<CallbackResult>> {
    let mut buf = vec![0_u8; 16 * 1024];
    let n = stream
        .read(&mut buf)
        .await
        .context("read callback request")?;
    if n == 0 {
        return Ok(None);
    }
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if method != "GET" {
        return Err(anyhow!("unsupported callback method {method}"));
    }
    let path_only = path.split('?').next().unwrap_or(path);
    if path_only != "/callback" && path_only != "/callback/" {
        return Ok(None);
    }
    let url = Url::parse(&format!("http://127.0.0.1{path}"))
        .context("parse callback URL")?;
    let params: HashMap<String, String> = url.query_pairs().into_owned().collect();
    if let Some(err) = params.get("error") {
        let desc = params
            .get("error_description")
            .map(String::as_str)
            .unwrap_or("");
        return Err(anyhow!("authorization server error: {err} {desc}"));
    }
    let code = params
        .get("code")
        .cloned()
        .ok_or_else(|| anyhow!("callback missing code"))?;
    let state = params.get("state").cloned();
    if let Some(expected) = expected_state {
        match &state {
            Some(got) if got == expected => {}
            Some(_) => return Err(anyhow!("OAuth state mismatch")),
            None => return Err(anyhow!("OAuth state missing")),
        }
    }
    Ok(Some(CallbackResult { code, state }))
}

async fn write_http(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
