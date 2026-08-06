//! Local session metadata + keychain-backed credential helpers.

use anyhow::{anyhow, Context, Result};
use ownmesh_config::{load_config, save_config, InstanceConfig, OwnMeshConfig, OwnMeshPaths};
use ownmesh_identity::{
    load_human_refresh_token, store_human_refresh_token, PreferredSecretStore, SecretPurpose,
    SecretStore, SecretString, DEFAULT_KEYCHAIN_SERVICE,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

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
        let session: AuthSession =
            serde_json::from_str(&raw).context("parse auth_session.json")?;
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

/// Resolve the control-plane issuer URL.
///
/// Order: `OWNMESH_ISSUER` env → active instance `base_url` → session.issuer.
pub fn resolve_issuer(session: &AuthSession) -> Result<String> {
    if let Ok(env) = std::env::var("OWNMESH_ISSUER") {
        let t = env.trim().trim_end_matches('/').to_owned();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    if let Ok(paths) = OwnMeshPaths::discover() {
        if let Ok(cfg) = load_config(&paths) {
            if let Some(url) = active_instance_url(&cfg) {
                return Ok(url);
            }
        }
    }
    let from_session = session.issuer.trim().trim_end_matches('/');
    if !from_session.is_empty() {
        return Ok(from_session.to_owned());
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
    let mut cfg = load_config(paths).unwrap_or_default();
    let id = "default".to_owned();
    if let Some(existing) = cfg.instances.iter_mut().find(|i| i.id == id) {
        existing.base_url = issuer.to_owned();
    } else {
        cfg.instances.push(InstanceConfig {
            id: id.clone(),
            base_url: issuer.to_owned(),
            display_name: Some("Default".into()),
        });
    }
    cfg.active_instance = Some(id);
    // Ignore validation failures for http:// in odd environments — save_config validates.
    let _ = save_config(paths, &cfg);
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
    session.issuer = issuer.trim().trim_end_matches('/').to_owned();
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

    let tokens = refresh_access_token(
        http,
        &session.issuer,
        &session.client_id,
        refresh.expose(),
    )
    .await?;
    // Persist rotated refresh token when the server rotates it.
    if let Some(new_rt) = &tokens.refresh_token {
        if new_rt != refresh.expose() {
            store_human_refresh_token(store, &SecretString::new(new_rt.clone()))
                .map_err(|err| anyhow!("store rotated refresh token: {err}"))?;
        }
    }
    let mut session = save_token_set(session_paths, store, &session.issuer, &tokens)?;
    // Keep prior device_id.
    let prior = session_paths.load_session().unwrap_or_default();
    if session.device_id.is_none() {
        session.device_id = prior.device_id;
        session_paths.save_session(&session)?;
    }
    Ok((tokens.access_token, session))
}

/// Clear human credentials from keychain + session file.
pub fn clear_session_secrets(
    session_paths: &SessionPaths,
    store: &dyn SecretStore,
) -> Result<()> {
    let _ = store.delete(SecretPurpose::HumanRefreshToken);
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
}
