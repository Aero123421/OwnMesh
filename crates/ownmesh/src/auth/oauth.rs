//! Control-plane OAuth client (authorization code + device code + refresh).
//!
//! Endpoint paths match cp-04 / `packages/control-plane/src/oauth.ts`:
//! - `POST /oauth/register`
//! - `GET  /oauth/authorize`
//! - `POST /oauth/token`
//! - `POST /oauth/revoke`
//! - `POST /oauth/device_authorization`

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::json;
use std::time::Duration;
use tracing::{debug, info};
use url::Url;

use super::callback::CallbackServer;
use super::pkce::{generate_pkce, generate_state};
use super::session::{DEFAULT_CLIENT_ID, PREFERRED_CALLBACK_PORT};

/// Default scopes requested by the OwnMesh CLI.
pub const DEFAULT_SCOPES: &str = "ownmesh.read ownmesh.write ownmesh.exec ownmesh.session ownmesh.device offline_access";

/// Token response subset used by the CLI.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TokenSet {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
    pub scope: Option<String>,
    pub client_id: String,
    pub token_type: String,
}

/// Device-code start payload (RFC 8628).
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    #[serde(default = "default_interval")]
    pub interval: u64,
}

fn default_interval() -> u64 {
    5
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    token_type: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    interval: Option<u64>,
}

/// Options for browser PKCE login.
pub struct BrowserLoginOpts {
    /// When true, skip `webbrowser::open` (tests drive the authorize URL themselves).
    pub skip_browser_open: bool,
    /// Append `auto=1` so the control plane skips the HTML consent page.
    pub auto_approve: bool,
    /// Callback wait timeout.
    pub callback_timeout: Duration,
    /// Optional hook invoked with the authorize URL (tests).
    pub on_authorize_url: Option<Box<dyn FnOnce(String) + Send>>,
}

impl Default for BrowserLoginOpts {
    fn default() -> Self {
        Self {
            skip_browser_open: false,
            auto_approve: false,
            callback_timeout: Duration::from_secs(300),
            on_authorize_url: None,
        }
    }
}

/// Perform Authorization Code + PKCE login against `issuer`.
pub async fn login_browser_pkce(
    http: &reqwest::Client,
    issuer: &str,
    opts: BrowserLoginOpts,
) -> Result<TokenSet> {
    let issuer = issuer.trim().trim_end_matches('/');
    let callback = CallbackServer::bind(PREFERRED_CALLBACK_PORT).await?;
    let redirect_uri = callback.redirect_uri.clone();

    // Prefer bootstrap client when using the registered loopback port; otherwise DCR.
    let client_id = if callback.bind_addr.port() == PREFERRED_CALLBACK_PORT {
        DEFAULT_CLIENT_ID.to_owned()
    } else {
        register_public_client(http, issuer, &redirect_uri).await?
    };

    let pkce = generate_pkce();
    let state = generate_state();
    let mut auth = Url::parse(&format!("{issuer}/oauth/authorize"))
        .context("build authorize URL")?;
    {
        let mut q = auth.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("client_id", &client_id);
        q.append_pair("redirect_uri", &redirect_uri);
        q.append_pair("scope", DEFAULT_SCOPES);
        q.append_pair("code_challenge", &pkce.challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("state", &state);
        if opts.auto_approve {
            q.append_pair("auto", "1");
        }
    }
    let auth_url = auth.to_string();
    info!(%redirect_uri, "starting browser PKCE login");
    debug!(%auth_url, "authorize URL ready");

    if let Some(hook) = opts.on_authorize_url {
        hook(auth_url.clone());
    }
    if !opts.skip_browser_open {
        if let Err(err) = webbrowser::open(&auth_url) {
            eprintln!("could not open browser automatically ({err}); open this URL:\n{auth_url}");
        } else {
            eprintln!("Opened browser for OwnMesh login.");
            eprintln!("If nothing opens, visit:\n{auth_url}");
        }
    }

    let cb = callback
        .wait_for_code(Some(&state), opts.callback_timeout)
        .await?;
    exchange_authorization_code(
        http,
        issuer,
        &client_id,
        &cb.code,
        &pkce.verifier,
        &redirect_uri,
    )
    .await
}

/// Exchange an authorization code for tokens (PKCE).
pub async fn exchange_authorization_code(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
    code: &str,
    code_verifier: &str,
    redirect_uri: &str,
) -> Result<TokenSet> {
    let issuer = issuer.trim().trim_end_matches('/');
    let resp = http
        .post(format!("{issuer}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", client_id),
            ("code_verifier", code_verifier),
        ]))
        .send()
        .await
        .context("token endpoint (authorization_code)")?;
    parse_token_response(resp, client_id).await
}

/// Start + poll RFC 8628 device authorization grant.
pub async fn login_device_code(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
    poll_hook: Option<&dyn Fn(&DeviceCodeStart)>,
) -> Result<TokenSet> {
    let issuer = issuer.trim().trim_end_matches('/');
    let client_id = if client_id.is_empty() {
        DEFAULT_CLIENT_ID
    } else {
        client_id
    };

    let start_resp = http
        .post(format!("{issuer}/oauth/device_authorization"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("client_id", client_id),
            ("scope", DEFAULT_SCOPES),
        ]))
        .send()
        .await
        .context("device_authorization endpoint")?;
    if !start_resp.status().is_success() {
        let status = start_resp.status();
        let body = start_resp.text().await.unwrap_or_default();
        bail!("device_authorization failed ({status}): {body}");
    }
    let start: DeviceCodeStart = start_resp
        .json()
        .await
        .context("parse device_authorization response")?;

    if let Some(hook) = poll_hook {
        hook(&start);
    } else {
        eprintln!("OwnMesh device login");
        eprintln!("  Visit: {}", start.verification_uri);
        if let Some(complete) = &start.verification_uri_complete {
            eprintln!("  Or open: {complete}");
        }
        eprintln!("  Enter code: {}", start.user_code);
        eprintln!("Waiting for approval…");
    }

    poll_device_token(http, issuer, client_id, &start).await
}

async fn poll_device_token(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
    start: &DeviceCodeStart,
) -> Result<TokenSet> {
    let mut interval = Duration::from_secs(start.interval.max(1));
    let deadline = tokio::time::Instant::now() + Duration::from_secs(start.expires_in.max(1));

    loop {
        if tokio::time::Instant::now() >= deadline {
            bail!("device code expired before authorization completed");
        }
        tokio::time::sleep(interval).await;

        let resp = http
            .post(format!("{issuer}/oauth/token"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form(&[
                (
                    "grant_type",
                    "urn:ietf:params:oauth:grant-type:device_code",
                ),
                ("device_code", &start.device_code),
                ("client_id", client_id),
            ]))
            .send()
            .await
            .context("token endpoint (device_code)")?;

        let status = resp.status();
        let body: TokenResponse = resp.json().await.context("parse device token response")?;
        if let Some(err) = body.error.as_deref() {
            match err {
                "authorization_pending" => continue,
                "slow_down" => {
                    let extra = body.interval.unwrap_or(start.interval + 5);
                    interval = Duration::from_secs(extra.max(1));
                    continue;
                }
                "expired_token" => bail!("device code expired"),
                "access_denied" => bail!("device authorization denied"),
                other => {
                    let desc = body.error_description.unwrap_or_default();
                    bail!("device token error ({status}): {other} {desc}");
                }
            }
        }
        if body.access_token.is_empty() {
            bail!("device token response missing access_token");
        }
        return Ok(TokenSet {
            access_token: body.access_token,
            refresh_token: body.refresh_token,
            expires_in: body.expires_in,
            scope: body.scope,
            client_id: client_id.to_owned(),
            token_type: body.token_type.unwrap_or_else(|| "bearer".into()),
        });
    }
}

/// Refresh an access token (rotation may return a new refresh token).
pub async fn refresh_access_token(
    http: &reqwest::Client,
    issuer: &str,
    client_id: &str,
    refresh_token: &str,
) -> Result<TokenSet> {
    let issuer = issuer.trim().trim_end_matches('/');
    let resp = http
        .post(format!("{issuer}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", client_id),
        ]))
        .send()
        .await
        .context("token endpoint (refresh_token)")?;
    parse_token_response(resp, client_id).await
}

/// Best-effort token revocation (RFC 7009).
pub async fn revoke_token(
    http: &reqwest::Client,
    issuer: &str,
    token: &str,
) -> Result<()> {
    let issuer = issuer.trim().trim_end_matches('/');
    let resp = http
        .post(format!("{issuer}/oauth/revoke"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[("token", token)]))
        .send()
        .await
        .context("revoke endpoint")?;
    if !(resp.status().is_success() || resp.status().as_u16() == 200) {
        // RFC 7009: endpoint should return 200 even for unknown tokens; still tolerate.
        debug!(status = %resp.status(), "revoke returned non-success");
    }
    Ok(())
}

/// Dynamic Client Registration for a public (PKCE) loopback client.
pub async fn register_public_client(
    http: &reqwest::Client,
    issuer: &str,
    redirect_uri: &str,
) -> Result<String> {
    let issuer = issuer.trim().trim_end_matches('/');
    let resp = http
        .post(format!("{issuer}/oauth/register"))
        .json(&json!({
            "client_name": "ownmesh-cli",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "none",
        }))
        .send()
        .await
        .context("DCR register")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("DCR failed ({status}): {body}");
    }
    #[derive(Deserialize)]
    struct Reg {
        client_id: String,
    }
    let reg: Reg = resp.json().await.context("parse DCR response")?;
    if reg.client_id.is_empty() {
        return Err(anyhow!("DCR response missing client_id"));
    }
    Ok(reg.client_id)
}

async fn parse_token_response(resp: reqwest::Response, client_id: &str) -> Result<TokenSet> {
    let status = resp.status();
    let body: TokenResponse = resp.json().await.context("parse token JSON")?;
    if let Some(err) = body.error {
        let desc = body.error_description.unwrap_or_default();
        bail!("token error ({status}): {err} {desc}");
    }
    if !status.is_success() {
        bail!("token endpoint HTTP {status}");
    }
    if body.access_token.is_empty() {
        bail!("token response missing access_token");
    }
    Ok(TokenSet {
        access_token: body.access_token,
        refresh_token: body.refresh_token,
        expires_in: body.expires_in,
        scope: body.scope,
        client_id: client_id.to_owned(),
        token_type: body.token_type.unwrap_or_else(|| "bearer".into()),
    })
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding_encode(k), urlencoding_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

fn urlencoding_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
