//! Local session metadata + keychain-backed credential helpers.

use anyhow::{anyhow, Context, Result};
use ownmesh_config::{load_config, save_config, InstanceConfig, OwnMeshConfig, OwnMeshPaths};
use ownmesh_identity::{
    load_human_refresh_token, store_human_refresh_token, PreferredSecretStore, SecretPurpose,
    SecretStore, SecretString, DEFAULT_KEYCHAIN_SERVICE,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use url::Url;

use super::oauth::{refresh_access_token, TokenSet};

/// Default bootstrap OAuth client id (control-plane ensureBootstrap).
pub const DEFAULT_CLIENT_ID: &str = "client_ownmesh_cli";

/// Preferred loopback callback port (registered on the bootstrap client).
pub const PREFERRED_CALLBACK_PORT: u16 = 8750;

/// Non-secret session metadata written under the state directory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuthSession {
    /// Control-plane issuer / base URL.
    pub issuer: String,
    /// OAuth client_id used for token operations.
    pub client_id: String,
    /// Last enrolled device id, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// ISO-ish marker that a human refresh token is present in the keychain.
    #[serde(default)]
    pub has_refresh_token: bool,
    /// Optional scope string from the last token response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// Resolved filesystem + keychain handles for auth.
pub struct SessionPaths {
    pub paths: OwnMeshPaths,
    pub session_file: PathBuf,
}

impl SessionPaths {
    /// Discover OS paths.
    pub fn discover() -> Result<Self> {
        let paths = OwnMeshPaths::discover().context("resolve OwnMesh paths")?;
        paths.ensure_layout().context("ensure OwnMesh layout")?;
        Ok(Self::from_paths(paths))
    }

    /// Build from an already-resolved path set (tests).
    #[must_use]
    pub fn from_paths(paths: OwnMeshPaths) -> Self {
        let session_file = paths.state_dir.join("auth_session.json");
        Self {
            paths,
            session_file,
        }
    }

    /// Load session metadata (empty default when missing).
    pub fn load_session(&self) -> Result<AuthSession> {
        if !self.session_file.exists() {
            return Ok(AuthSession::default());
        }
        let raw = std::fs::read_to_string(&self.session_file)
            .with_context(|| format!("read {}", self.session_file.display()))?;
        // Defense: session file must never carry raw tokens.
        assert_no_plaintext_tokens(&raw)?;
        let session: AuthSession = serde_json::from_str(&raw).context("parse auth_session.json")?;
        Ok(session)
    }

    /// Persist session metadata.
    pub fn save_session(&self, session: &AuthSession) -> Result<()> {
        if let Some(parent) = self.session_file.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(session)?;
        assert_no_plaintext_tokens(&raw)?;
        atomic_write(&self.session_file, raw.as_bytes())?;
        Ok(())
    }
}

/// Open the preferred secret store (OS keychain with encrypted file fallback).
pub fn open_secret_store(paths: &OwnMeshPaths) -> Result<PreferredSecretStore> {
    paths.ensure_layout()?;
    PreferredSecretStore::open(DEFAULT_KEYCHAIN_SERVICE, paths.keystore_dir())
        .map_err(|err| anyhow!("open secret store: {err}"))
}

/// Validate a control-plane issuer / base URL.
///
/// Rules:
/// - `https://` is accepted when a non-empty host is present.
/// - `http://` is accepted **only** when the host is loopback
///   (`127.0.0.0/8`, `::1`, or the name `localhost`) — required for local mock servers.
/// - Non-loopback `http://` issuers are rejected with an explicit error.
/// - Other schemes are rejected.
///
/// Returns the trimmed issuer (no trailing `/`).
pub fn validate_issuer(raw: &str) -> Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(anyhow!("issuer URL must not be empty"));
    }
    let parsed = Url::parse(trimmed).map_err(|err| anyhow!("invalid issuer URL: {err}"))?;
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| anyhow!("issuer URL must include a host"))?;

    match parsed.scheme() {
        "https" => Ok(trimmed.to_owned()),
        "http" => {
            if is_loopback_host(host) {
                Ok(trimmed.to_owned())
            } else {
                Err(anyhow!(
                    "refusing non-loopback http:// issuer `{trimmed}`; use https:// or a loopback host (127.0.0.1, ::1, localhost)"
                ))
            }
        }
        other => Err(anyhow!(
            "unsupported issuer URL scheme `{other}`; expected https (or http on loopback only)"
        )),
    }
}

/// True when `host` is a loopback IP or the conventional `localhost` name.
fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // `url` may yield IPv6 with brackets (`[::1]`) via `host_str()`.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match host.parse::<IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Resolve the control-plane issuer URL.
///
/// Order: `OWNMESH_ISSUER` env → active instance `base_url` → session.issuer.
/// Every source is passed through [`validate_issuer`] (non-loopback http is rejected).
pub fn resolve_issuer(session: &AuthSession) -> Result<String> {
    if let Ok(env) = std::env::var("OWNMESH_ISSUER") {
        let t = env.trim().trim_end_matches('/').to_owned();
        if !t.is_empty() {
            return validate_issuer(&t);
        }
    }
    if let Ok(paths) = OwnMeshPaths::discover() {
        if let Ok(cfg) = load_config(&paths) {
            if let Some(url) = active_instance_url(&cfg) {
                return validate_issuer(&url);
            }
        }
    }
    let from_session = session.issuer.trim().trim_end_matches('/');
    if !from_session.is_empty() {
        return validate_issuer(from_session);
    }
    Err(anyhow!(
        "no control-plane issuer configured; set OWNMESH_ISSUER or `ownmesh instance add/use`"
    ))
}

fn active_instance_url(cfg: &OwnMeshConfig) -> Option<String> {
    let id = cfg.active_instance.as_deref()?;
    cfg.instances
        .iter()
        .find(|i| i.id == id)
        .map(|i| i.base_url.trim().trim_end_matches('/').to_owned())
}

/// Ensure an instance alias exists and is active (best-effort after login).
pub fn ensure_instance_alias(paths: &OwnMeshPaths, issuer: &str) -> Result<()> {
    let issuer = validate_issuer(issuer)?;
    let mut cfg = load_config(paths).unwrap_or_default();
    let id = "default".to_owned();
    if let Some(existing) = cfg.instances.iter_mut().find(|i| i.id == id) {
        existing.base_url = issuer.clone();
    } else {
        cfg.instances.push(InstanceConfig {
            id: id.clone(),
            base_url: issuer,
            display_name: Some("Default".into()),
        });
    }
    cfg.active_instance = Some(id);
    // save_config re-validates (incl. non-loopback http rejection).
    save_config(paths, &cfg).map_err(|err| anyhow!("save instance config: {err}"))?;
    Ok(())
}

/// Save a token set: refresh → keychain; metadata → session file. Never logs secrets.
pub fn save_token_set(
    session_paths: &SessionPaths,
    store: &dyn SecretStore,
    issuer: &str,
    tokens: &TokenSet,
) -> Result<AuthSession> {
    if let Some(refresh) = &tokens.refresh_token {
        store_human_refresh_token(store, &SecretString::new(refresh.clone()))
            .map_err(|err| anyhow!("store refresh token: {err}"))?;
    }
    let mut session = session_paths.load_session().unwrap_or_default();
    session.issuer = validate_issuer(issuer)?;
    session.client_id = if tokens.client_id.is_empty() {
        DEFAULT_CLIENT_ID.to_owned()
    } else {
        tokens.client_id.clone()
    };
    session.has_refresh_token = tokens.refresh_token.is_some();
    if let Some(scope) = &tokens.scope {
        session.scope = Some(scope.clone());
    }
    session_paths.save_session(&session)?;
    let _ = ensure_instance_alias(&session_paths.paths, &session.issuer);
    Ok(session)
}

/// Load a usable access token, refreshing via keychain-stored refresh token when needed.
pub async fn load_access_token(
    session_paths: &SessionPaths,
    store: &dyn SecretStore,
    http: &reqwest::Client,
) -> Result<(String, AuthSession)> {
    let session = session_paths.load_session()?;
    if session.issuer.is_empty() {
        return Err(anyhow!("not logged in (missing auth session)"));
    }
    let refresh = load_human_refresh_token(store)
        .map_err(|err| anyhow!("load refresh token: {err}"))?
        .ok_or_else(|| anyhow!("not logged in (no refresh token in keychain)"))?;

    // Validate persisted metadata before sending the refresh token anywhere. This
    // protects upgrades from legacy/tampered auth_session.json values.
    let issuer = validate_issuer(&session.issuer)?;
    let tokens = refresh_access_token(http, &issuer, &session.client_id, refresh.expose()).await?;
    // Persist rotated refresh token when the server rotates it.
    if let Some(new_rt) = &tokens.refresh_token {
        if new_rt != refresh.expose() {
            store_human_refresh_token(store, &SecretString::new(new_rt.clone()))
                .map_err(|err| anyhow!("store rotated refresh token: {err}"))?;
        }
    }
    let mut session = save_token_set(session_paths, store, &issuer, &tokens)?;
    // Keep prior device_id.
    let prior = session_paths.load_session().unwrap_or_default();
    if session.device_id.is_none() {
        session.device_id = prior.device_id;
        session_paths.save_session(&session)?;
    }
    Ok((tokens.access_token, session))
}

/// Clear human credentials from keychain + session file.
pub fn clear_session_secrets(session_paths: &SessionPaths, store: &dyn SecretStore) -> Result<()> {
    store
        .delete(SecretPurpose::HumanRefreshToken)
        .map_err(|err| anyhow!("delete refresh token from all secret backends: {err}"))?;
    let mut session = session_paths.load_session().unwrap_or_default();
    session.has_refresh_token = false;
    // Keep issuer/client_id/device_id for convenience; tokens are gone.
    session_paths.save_session(&session)?;
    Ok(())
}

fn assert_no_plaintext_tokens(text: &str) -> Result<()> {
    let lower = text.to_ascii_lowercase();
    for needle in [
        "refresh_token",
        "access_token",
        "\"rt_",
        "\"at_",
        "private_key",
        "client_secret",
    ] {
        // Allow the boolean flag name has_refresh_token and field docs — block assignment shapes.
        if needle == "refresh_token" && lower.contains("has_refresh_token") {
            // still reject `"refresh_token": "secret"` shapes
            if lower.contains("\"refresh_token\"") || lower.contains("refresh_token =") {
                return Err(anyhow!(
                    "refusing to write plaintext secret material to session/config"
                ));
            }
            continue;
        }
        if lower.contains(&format!("\"{needle}\""))
            || lower.contains(&format!("{needle} ="))
            || lower.contains(&format!("{needle}="))
        {
            return Err(anyhow!(
                "refusing to write plaintext secret material to session/config"
            ));
        }
    }
    Ok(())
}

fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("session path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("auth_session")
    ));
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn session_roundtrip_rejects_token_fields() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let sp = SessionPaths::from_paths(paths);
        let session = AuthSession {
            issuer: "http://127.0.0.1:9".into(),
            client_id: DEFAULT_CLIENT_ID.into(),
            device_id: Some("dev_x".into()),
            has_refresh_token: true,
            scope: Some("ownmesh.read".into()),
        };
        sp.save_session(&session).unwrap();
        let loaded = sp.load_session().unwrap();
        assert_eq!(loaded.device_id.as_deref(), Some("dev_x"));
        let raw = std::fs::read_to_string(&sp.session_file).unwrap();
        assert!(!raw.contains("rt_"));
        assert!(!raw.to_ascii_lowercase().contains("\"refresh_token\""));
    }

    #[test]
    fn validate_issuer_allows_loopback_http_and_https() {
        // mock_server / local CP compatibility
        assert_eq!(
            validate_issuer("http://127.0.0.1:9").unwrap(),
            "http://127.0.0.1:9"
        );
        assert!(validate_issuer("http://127.0.0.1").is_ok());
        assert!(validate_issuer("http://127.0.0.1:8750/").is_ok());
        assert!(validate_issuer("http://[::1]:8080").is_ok());
        assert!(validate_issuer("http://localhost:8750").is_ok());
        assert!(validate_issuer("https://cp.example.test").is_ok());
        assert!(validate_issuer("https://example.test/").is_ok());
    }

    #[test]
    fn validate_issuer_rejects_non_loopback_http() {
        let err = validate_issuer("http://example.test")
            .expect_err("non-loopback http must fail")
            .to_string();
        assert!(
            err.contains("non-loopback"),
            "expected explicit non-loopback error, got: {err}"
        );

        assert!(validate_issuer("http://example.test/oauth").is_err());
        assert!(validate_issuer("http://192.168.1.10").is_err());
        assert!(validate_issuer("http://10.0.0.1:443").is_err());
        assert!(validate_issuer("http://[fe80::1]").is_err());
        assert!(validate_issuer("ftp://127.0.0.1").is_err());
        assert!(validate_issuer("").is_err());
    }

    #[test]
    fn resolve_issuer_validates_session_value() {
        let bad = AuthSession {
            issuer: "http://example.test".into(),
            ..AuthSession::default()
        };
        // Only exercises the session fallback when env/config are absent or empty.
        // If OWNMESH_ISSUER is set in the ambient environment it is also validated.
        match resolve_issuer(&bad) {
            Ok(url) => {
                // Ambient env overrode session — still must be a valid issuer.
                validate_issuer(&url).expect("resolve_issuer must only return validated URLs");
            }
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("non-loopback")
                        || msg.contains("no control-plane issuer")
                        || msg.contains("invalid issuer"),
                    "unexpected error: {msg}"
                );
            }
        }

        let good = AuthSession {
            issuer: "http://127.0.0.1:9".into(),
            ..AuthSession::default()
        };
        // When session is the source (or env is also valid), must not reject loopback http.
        if std::env::var("OWNMESH_ISSUER")
            .ok()
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
        {
            // May still pick up a user config active instance; only assert when we get a result
            // from session or when error is "not configured".
            match resolve_issuer(&good) {
                Ok(url) => assert!(
                    validate_issuer(&url).is_ok(),
                    "resolved issuer must pass validate_issuer: {url}"
                ),
                Err(err) => {
                    let msg = err.to_string();
                    assert!(
                        !msg.contains("127.0.0.1"),
                        "loopback http must not be rejected: {msg}"
                    );
                }
            }
        }
    }
}
