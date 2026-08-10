//! Device enrollment / list / revoke client (cp-04 `/v1/devices/*` contract).

use anyhow::{anyhow, bail, Context, Result};
use ownmesh_identity::{
    load_or_create_device_key, rotate_device_key, store_device_credential, DevicePublicIdentity,
    SecretStore, SecretString,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::time::Duration;

const MAX_DEVICE_API_RESPONSE_BYTES: usize = 64 * 1024;

use super::session::{validate_issuer, SessionPaths};

/// Public device record returned by the control plane.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub arch: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub revoked: Option<bool>,
    #[serde(default)]
    pub status: Option<String>,
}

/// Result of a successful enroll + proof exchange.
#[derive(Debug, Clone)]
pub struct EnrollResult {
    pub device_id: String,
    pub status: String,
    pub public: DevicePublicIdentity,
    pub connect_path: String,
}

#[derive(Debug, Deserialize)]
struct EnrollResponse {
    device_id: String,
    #[serde(default)]
    enrollment_token: Option<String>,
    challenge: Challenge,
    #[serde(default)]
    connect_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Challenge {
    id: String,
    #[serde(default)]
    nonce: Option<String>,
    message: String,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProofResponse {
    ok: bool,
    device_credential: String,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    connect_path: Option<String>,
}

/// Enroll this machine: challenge → Ed25519 proof → active device.
pub async fn enroll_device(
    http: &reqwest::Client,
    issuer: &str,
    access_token: &str,
    store: &dyn SecretStore,
    session_paths: &SessionPaths,
    name: Option<&str>,
) -> Result<EnrollResult> {
    let issuer = validate_issuer(issuer)?;
    let key =
        load_or_create_device_key(store).map_err(|err| anyhow!("load/create device key: {err}"))?;
    let public = key.public_identity();

    let hostname = hostname_string();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let display = name.map(str::to_owned).unwrap_or_else(|| hostname.clone());

    let enroll_resp = http
        .post(format!("{issuer}/v1/devices/enroll"))
        .bearer_auth(access_token)
        .json(&json!({
            "name": display,
            "hostname": hostname,
            "os": os,
            "arch": arch,
            "agent_version": env!("CARGO_PKG_VERSION"),
            "protocol_version": "ownmesh.device/1.0",
            "public_key": public.public_key_hex,
        }))
        .send()
        .await
        .context("POST /v1/devices/enroll")?;

    if enroll_resp.status().as_u16() != 201 && !enroll_resp.status().is_success() {
        let status = enroll_resp.status();
        let body = enroll_resp.text().await.unwrap_or_default();
        bail!("enroll failed ({status}): {body}");
    }

    let enroll: EnrollResponse = enroll_resp.json().await.context("parse enroll response")?;
    // Sign challenge.message with the device private key (hex 64-byte sig).
    let sig = key.sign(enroll.challenge.message.as_bytes());
    let signature_hex = hex_encode(sig.expose());

    let proof_token = enroll.enrollment_token.as_deref().unwrap_or(access_token);

    let proof_resp = http
        .post(format!("{issuer}/v1/devices/enroll/proof"))
        .bearer_auth(proof_token)
        .json(&json!({
            "device_id": enroll.device_id,
            "challenge_id": enroll.challenge.id,
            "signature": signature_hex,
        }))
        .send()
        .await
        .context("POST /v1/devices/enroll/proof")?;

    if !proof_resp.status().is_success() {
        let status = proof_resp.status();
        let body = proof_resp.text().await.unwrap_or_default();
        bail!("enroll proof failed ({status}): {body}");
    }
    let proof: ProofResponse = proof_resp.json().await.context("parse proof response")?;
    if !proof.ok || proof.device_credential.is_empty() {
        bail!("enroll proof rejected or missing device credential");
    }
    // Long-lived connect credential is bound to issuer + device_id under DeviceCredential.
    // Never park it under DeviceEnrollmentProof (legacy purpose only).
    store_device_credential(
        store,
        issuer.as_str(),
        &enroll.device_id,
        &SecretString::new(proof.device_credential),
    )
    .map_err(|err| anyhow!("store device credential: {err}"))?;

    let mut session = session_paths.load_session().unwrap_or_default();
    session.device_id = Some(enroll.device_id.clone());
    if session.issuer.is_empty() {
        session.issuer = issuer.to_owned();
    }
    session_paths.save_session(&session)?;

    let _ = (enroll.challenge.nonce, enroll.challenge.expires_at);
    Ok(EnrollResult {
        device_id: enroll.device_id,
        status: proof.status.unwrap_or_else(|| "active".into()),
        public,
        connect_path: proof
            .connect_path
            .or(enroll.connect_path)
            .unwrap_or_else(|| "/agent/connect".into()),
    })
}

/// List devices for the authenticated principal.
pub async fn list_devices(
    http: &reqwest::Client,
    issuer: &str,
    access_token: &str,
) -> Result<Vec<DeviceInfo>> {
    let issuer = validate_issuer(issuer)?;
    let resp = http
        .get(format!("{issuer}/v1/devices"))
        .bearer_auth(access_token)
        .send()
        .await
        .context("GET /v1/devices")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("list devices failed ({status}): {body}");
    }
    #[derive(Deserialize)]
    struct List {
        devices: Vec<DeviceInfo>,
    }
    let list: List = resp.json().await.context("parse devices list")?;
    Ok(list.devices)
}

/// Replace the supplied display metadata for one owned device.
///
/// This security-sensitive bearer request always disables redirects, applies a
/// total timeout, bounds the response before parsing, and never includes a raw
/// response body in errors. The caller's authenticated session/token is reused;
/// no second login or token copy is created.
pub async fn update_device_metadata(
    _http: &reqwest::Client,
    issuer: &str,
    access_token: &str,
    device_id: &str,
    name: Option<&str>,
    labels: Option<&[String]>,
) -> Result<DeviceInfo> {
    let issuer = validate_issuer(issuer)?;
    let mut endpoint = url::Url::parse(&issuer).context("build device metadata URL")?;
    endpoint
        .path_segments_mut()
        .map_err(|()| anyhow!("control-plane issuer cannot be a base URL"))?
        .clear()
        .extend(["v1", "devices", device_id]);

    let mut patch = Map::new();
    if let Some(name) = name {
        patch.insert("name".into(), Value::String(name.to_owned()));
    }
    if let Some(labels) = labels {
        patch.insert("labels".into(), json!(labels));
    }
    if patch.is_empty() {
        bail!("device metadata update requires name and/or labels");
    }

    let secure_http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .context("build device metadata HTTP client")?;
    let response = secure_http
        .patch(endpoint)
        .bearer_auth(access_token)
        .json(&patch)
        .send()
        .await
        .context("PATCH /v1/devices/:id")?;
    let status = response.status();
    if status.is_redirection() {
        bail!("device metadata update refused an HTTP redirect ({status})");
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let bytes = read_response_bounded(response).await?;
    if content_type != "application/json" {
        bail!("device metadata update returned a non-JSON response ({status})");
    }
    if !status.is_success() {
        bail!(
            "device metadata update failed ({status}): {}",
            safe_api_error(&bytes)
        );
    }

    #[derive(Deserialize)]
    struct UpdateResponse {
        ok: bool,
        device: DeviceInfo,
    }
    let updated: UpdateResponse =
        serde_json::from_slice(&bytes).context("parse device metadata response")?;
    if !updated.ok || updated.device.id != device_id {
        bail!("device metadata response did not match the requested device");
    }
    Ok(updated.device)
}

/// Revoke a device on the control plane (immediate invalidation server-side).
pub async fn revoke_device(
    http: &reqwest::Client,
    issuer: &str,
    access_token: &str,
    device_id: &str,
    session_paths: &SessionPaths,
) -> Result<bool> {
    let issuer = validate_issuer(issuer)?;
    let resp = http
        .post(format!("{issuer}/v1/devices/revoke"))
        .bearer_auth(access_token)
        .json(&json!({ "id": device_id }))
        .send()
        .await
        .context("POST /v1/devices/revoke")?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("revoke failed ({status}): {body}");
    }
    #[derive(Deserialize)]
    struct Rev {
        ok: bool,
    }
    let rev: Rev = resp.json().await.context("parse revoke response")?;
    let mut session = session_paths.load_session().unwrap_or_default();
    if session.device_id.as_deref() == Some(device_id) {
        session.device_id = None;
        session_paths.save_session(&session)?;
    }
    Ok(rev.ok)
}

/// Rotate the local device key in the keychain store.
pub fn rotate_local_device_key(
    store: &dyn SecretStore,
) -> Result<(DevicePublicIdentity, Option<DevicePublicIdentity>)> {
    let (new_key, old) =
        rotate_device_key(store).map_err(|err| anyhow!("rotate device key: {err}"))?;
    Ok((new_key.public_identity(), old))
}

fn hostname_string() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown-host".into())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn read_response_bounded(mut response: reqwest::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_DEVICE_API_RESPONSE_BYTES as u64)
    {
        bail!("control-plane response exceeds the {MAX_DEVICE_API_RESPONSE_BYTES}-byte limit");
    }
    let mut bytes = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_DEVICE_API_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .context("read device metadata response")?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_DEVICE_API_RESPONSE_BYTES {
            bail!("control-plane response exceeds the {MAX_DEVICE_API_RESPONSE_BYTES}-byte limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn safe_api_error(bytes: &[u8]) -> String {
    #[derive(Deserialize)]
    struct ApiError {
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        field: Option<String>,
    }
    let Ok(error) = serde_json::from_slice::<ApiError>(bytes) else {
        return "invalid control-plane error response".into();
    };
    let code =
        ownmesh_diagnostics::redact_text(&error.error.unwrap_or_else(|| "request_failed".into()));
    let field = error
        .field
        .map(|value| ownmesh_diagnostics::redact_text(&value))
        .map(|value| format!(" (field: {value})"));
    format!("{code}{}", field.as_deref().unwrap_or(""))
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}

#[cfg(test)]
mod device_metadata_tests {
    use super::*;

    #[test]
    fn api_error_is_structured_bounded_and_redacted() {
        let secret = br#"{"error":"failed atk_super_secret","field":"labels"}"#;
        let rendered = safe_api_error(secret);
        assert!(!rendered.contains("atk_super_secret"));
        assert!(rendered.contains("labels"));
        assert!(rendered.len() <= 512);
    }
}
