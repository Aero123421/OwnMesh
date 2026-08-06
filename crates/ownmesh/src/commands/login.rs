//! `ownmesh login` / `ownmesh logout`.

use crate::auth::{
    clear_session_secrets, login_browser_pkce, login_device_code, open_secret_store,
    resolve_issuer, revoke_token, save_token_set, BrowserLoginOpts, SessionPaths,
    DEFAULT_CLIENT_ID, DEFAULT_SCOPES,
};
use crate::cli::{Cli, LoginArgs};
use ownmesh_domain::ExitCode;
use serde_json::json;
use std::time::Duration;
use tracing::{debug, warn};

/// Run `ownmesh login` (browser PKCE) or `ownmesh login --device`.
pub fn run_login(cli: &Cli, args: &LoginArgs) -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            eprintln!("failed to start async runtime: {err}");
            ExitCode::Internal
        })?;
    rt.block_on(async { login_async(cli, args).await })
}

async fn login_async(cli: &Cli, args: &LoginArgs) -> Result<(), ExitCode> {
    let session_paths = SessionPaths::discover().map_err(|err| {
        eprintln!("path error: {err}");
        ExitCode::UsageConfig
    })?;
    let store = open_secret_store(&session_paths.paths).map_err(|err| {
        eprintln!("keychain error: {err}");
        ExitCode::Internal
    })?;
    let prior = session_paths.load_session().unwrap_or_default();
    let issuer = resolve_issuer(&prior).map_err(|err| {
        eprintln!("{err}");
        eprintln!("hint: set OWNMESH_ISSUER=https://your-control-plane or configure an instance");
        ExitCode::UsageConfig
    })?;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| {
            eprintln!("http client error: {err}");
            ExitCode::Internal
        })?;

    let tokens = if args.device {
        login_device_code(&http, &issuer, DEFAULT_CLIENT_ID, None)
            .await
            .map_err(|err| {
                eprintln!("device login failed: {err}");
                ExitCode::Authentication
            })?
    } else {
        login_browser_pkce(
            &http,
            &issuer,
            BrowserLoginOpts {
                skip_browser_open: std::env::var_os("OWNMESH_LOGIN_NO_BROWSER").is_some(),
                auto_approve: std::env::var_os("OWNMESH_LOGIN_AUTO").is_some(),
                callback_timeout: Duration::from_secs(
                    std::env::var("OWNMESH_LOGIN_TIMEOUT_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(300),
                ),
                on_authorize_url: None,
            },
        )
        .await
        .map_err(|err| {
            eprintln!("login failed: {err}");
            ExitCode::Authentication
        })?
    };

    // Never print token values.
    debug!(
        has_refresh = tokens.refresh_token.is_some(),
        scope = tokens.scope.as_deref().unwrap_or(DEFAULT_SCOPES),
        "login token exchange ok"
    );

    let session = save_token_set(&session_paths, &store, &issuer, &tokens).map_err(|err| {
        eprintln!("failed to store credentials: {err}");
        ExitCode::Internal
    })?;

    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": true,
                "flow": if args.device { "device_code" } else { "authorization_code_pkce" },
                "issuer": session.issuer,
                "client_id": session.client_id,
                "scope": session.scope,
                "has_refresh_token": session.has_refresh_token,
                // Explicitly omit access_token / refresh_token.
            })
        );
    } else {
        println!("Logged in to {}", session.issuer);
        println!("  client:  {}", session.client_id);
        if let Some(scope) = &session.scope {
            println!("  scope:   {scope}");
        }
        println!("  refresh: stored in OS keychain (not printed)");
    }
    Ok(())
}

/// Run `ownmesh logout`.
pub fn run_logout(cli: &Cli) -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            eprintln!("failed to start async runtime: {err}");
            ExitCode::Internal
        })?;
    rt.block_on(async { logout_async(cli).await })
}

async fn logout_async(cli: &Cli) -> Result<(), ExitCode> {
    let session_paths = SessionPaths::discover().map_err(|err| {
        eprintln!("path error: {err}");
        ExitCode::UsageConfig
    })?;
    let store = open_secret_store(&session_paths.paths).map_err(|err| {
        eprintln!("keychain error: {err}");
        ExitCode::Internal
    })?;
    let session = session_paths.load_session().unwrap_or_default();

    // Best-effort remote revoke of refresh token.
    // Never follow HTTP redirects: the refresh token must not be forwarded to a
    // Location target. Revoke failure must not block local secret deletion.
    if !session.issuer.is_empty() {
        if let Ok(Some(rt)) = ownmesh_identity::load_human_refresh_token(&store) {
            match reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()
            {
                Ok(http) => {
                    if let Err(err) = revoke_token(&http, &session.issuer, rt.expose()).await {
                        warn!(error = %err, "remote token revoke failed; continuing local logout");
                        eprintln!(
                            "warning: remote token revoke failed (local logout continues): {err}"
                        );
                    }
                }
                Err(err) => {
                    warn!(error = %err, "revoke HTTP client build failed; continuing local logout");
                    eprintln!(
                        "warning: could not build revoke HTTP client (local logout continues): {err}"
                    );
                }
            }
        }
    }

    clear_session_secrets(&session_paths, &store).map_err(|err| {
        eprintln!("logout failed: {err}");
        ExitCode::Internal
    })?;

    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": true,
                "logged_out": true,
            })
        );
    } else {
        println!("Logged out. Refresh token removed from keychain.");
    }
    Ok(())
}
