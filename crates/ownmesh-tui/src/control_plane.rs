//! Explicit, user-initiated Control Plane device inventory for the TUI.
//!
//! Network is opt-in: this module is only called from a documented refresh
//! action. Tokens never enter TUI status/log strings.

use anyhow::{anyhow, bail, Context, Result};
use ownmesh_config::{validate_control_plane_base_url, OwnMeshPaths};
use ownmesh_diagnostics::redact_text;
use ownmesh_identity::{load_human_refresh_token, PreferredSecretStore, DEFAULT_KEYCHAIN_SERVICE};
use serde::Deserialize;
use std::fmt::Write as _;
use std::time::Duration;

pub const MAX_INVENTORY_DEVICES: usize = 64;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// One bounded Control Plane device row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryDevice {
    pub id: String,
    pub name: Option<String>,
    pub enrollment_status: Option<String>,
    pub connection_status: Option<String>,
    pub agent_version: Option<String>,
    pub last_seen_at: Option<String>,
}

/// User-visible inventory state. Failed refresh keeps the last loaded snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DeviceInventory {
    #[default]
    Idle,
    NotConfigured,
    AuthRequired,
    Empty,
    Loaded {
        devices: Vec<InventoryDevice>,
        truncated: bool,
    },
    Unreachable {
        message: String,
        previous: Option<Box<DeviceInventory>>,
    },
}

impl DeviceInventory {
    #[must_use]
    pub fn loaded_snapshot(&self) -> Option<&DeviceInventory> {
        match self {
            Self::Loaded { .. } => Some(self),
            Self::Unreachable { previous, .. } => {
                previous.as_deref().and_then(Self::loaded_snapshot)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct SessionFile {
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    client_id: String,
    #[serde(default)]
    has_refresh_token: bool,
}

#[derive(Debug, Deserialize)]
struct DeviceRecord {
    id: String,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    enrollment_status: Option<String>,
    #[serde(default)]
    connection_status: Option<String>,
    #[serde(default)]
    agent_version: Option<String>,
    #[serde(default)]
    last_seen_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    devices: Vec<DeviceRecord>,
}

/// Classify local config before opening the keychain or making a request.
pub fn classify_local_inventory(
    paths: &OwnMeshPaths,
    server_url: Option<&str>,
    account_present: bool,
) -> DeviceInventory {
    if server_url.map(str::trim).is_none_or(str::is_empty) {
        return DeviceInventory::NotConfigured;
    }
    if !account_present || !paths.state_dir.join("auth_session.json").is_file() {
        return DeviceInventory::AuthRequired;
    }
    DeviceInventory::Idle
}

/// Fetch the authenticated device list. Call only from an explicit user action.
pub async fn fetch_device_inventory(paths: &OwnMeshPaths) -> Result<DeviceInventory> {
    let session_path = paths.state_dir.join("auth_session.json");
    if !session_path.is_file() {
        return Ok(DeviceInventory::AuthRequired);
    }
    let raw = std::fs::read_to_string(&session_path).context("read auth session")?;
    let session: SessionFile = serde_json::from_str(&raw).context("parse auth session")?;
    if !session.has_refresh_token {
        return Ok(DeviceInventory::AuthRequired);
    }
    let issuer =
        validate_control_plane_base_url(session.issuer.trim()).map_err(|err| anyhow!("{err}"))?;
    let client_id = if session.client_id.trim().is_empty() {
        "client_ownmesh_cli"
    } else {
        session.client_id.trim()
    };

    let store = PreferredSecretStore::open(DEFAULT_KEYCHAIN_SERVICE, paths.keystore_dir())
        .map_err(|err| anyhow!("open secret store: {err}"))?;
    let refresh = load_human_refresh_token(&store)
        .map_err(|err| anyhow!("load refresh token: {err}"))?
        .ok_or_else(|| anyhow!("not logged in"))?;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("build device inventory HTTP client")?;

    let token_resp = http
        .post(format!("{issuer}/oauth/token"))
        .header("content-type", "application/x-www-form-urlencoded")
        .body(form(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh.expose()),
            ("client_id", client_id),
        ]))
        .send()
        .await
        .context("refresh access token")?;
    if token_resp.status().is_redirection() {
        bail!("token endpoint refused an HTTP redirect");
    }
    let token_bytes = read_bounded(token_resp).await?;
    let token_json: serde_json::Value =
        serde_json::from_slice(&token_bytes).context("parse token response")?;
    let access = token_json
        .get("access_token")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("authentication required"))?;

    let list_resp = http
        .get(format!("{issuer}/v1/devices"))
        .bearer_auth(access)
        .send()
        .await
        .context("GET /v1/devices")?;
    if list_resp.status().is_redirection() {
        bail!("device list refused an HTTP redirect");
    }
    if !list_resp.status().is_success() {
        bail!("control plane device list is unreachable");
    }
    let list_bytes = read_bounded(list_resp).await?;
    let list: ListResponse = serde_json::from_slice(&list_bytes).context("parse device list")?;
    if list.devices.is_empty() {
        return Ok(DeviceInventory::Empty);
    }
    let truncated = list.devices.len() > MAX_INVENTORY_DEVICES;
    let devices = list
        .devices
        .into_iter()
        .take(MAX_INVENTORY_DEVICES)
        .map(|device| InventoryDevice {
            id: device.id,
            name: device.name,
            enrollment_status: device.enrollment_status,
            connection_status: device.connection_status,
            agent_version: device.agent_version,
            last_seen_at: device.last_seen_at,
        })
        .collect();
    Ok(DeviceInventory::Loaded { devices, truncated })
}

#[must_use]
pub fn redacted_error(err: &anyhow::Error) -> String {
    redact_text(&err.to_string())
}

#[must_use]
pub fn format_device_row(device: &InventoryDevice, local_device_id: Option<&str>) -> String {
    let name = device
        .name
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let enroll = device
        .enrollment_status
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let route = device
        .connection_status
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let version = device
        .agent_version
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let seen = device
        .last_seen_at
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("-");
    let local = if local_device_id == Some(device.id.as_str()) {
        " local"
    } else {
        ""
    };
    format!(
        "{id}  {name}  enroll={enroll}  route={route}  agent={version}  seen={seen}{local}",
        id = device.id,
        name = name,
        enroll = enroll,
        route = route,
        version = version,
        seen = seen,
        local = local
    )
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
            _ => write!(out, "%{b:02X}").expect("write urlencoded byte"),
        }
    }
    out
}

async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        bail!("control plane response exceeded {MAX_RESPONSE_BYTES} bytes");
    }
    let mut buf = Vec::new();
    while let Some(chunk) = response.chunk().await.context("read control plane body")? {
        if buf.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            bail!("control plane response exceeded {MAX_RESPONSE_BYTES} bytes");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_row_marks_local_device_and_bounds_fields() {
        let row = format_device_row(
            &InventoryDevice {
                id: "dev_a".into(),
                name: Some("Laptop".into()),
                enrollment_status: Some("active".into()),
                connection_status: Some("connected".into()),
                agent_version: Some("1.2.11".into()),
                last_seen_at: Some("2026-08-14T00:00:00Z".into()),
            },
            Some("dev_a"),
        );
        assert!(row.contains("dev_a"));
        assert!(row.contains("Laptop"));
        assert!(row.contains("enroll=active"));
        assert!(row.contains("route=connected"));
        assert!(row.contains("agent=1.2.11"));
        assert!(row.contains(" local"));
        assert!(!row.contains("atk_"));
        assert!(!row.contains("Bearer"));
    }

    #[test]
    fn redacted_error_strips_bearer_material() {
        let err = anyhow!("list failed: Bearer atk_secret refresh_token=rt_secret");
        let out = redacted_error(&err);
        assert!(!out.to_ascii_lowercase().contains("atk_secret"));
        assert!(!out.to_ascii_lowercase().contains("rt_secret"));
    }
}
