//! Device enrollment / list / revoke client (cp-04 `/v1/devices/*` contract).

use anyhow::{anyhow, bail, Context, Result};
use ownmesh_identity::{
    load_or_create_device_key, rotate_device_key, DevicePublicIdentity, SecretStore,
};
use serde::Deserialize;
use serde_json::json;

use super::session::SessionPaths;

/// Public device record returned by the control plane.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceInfo {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
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
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    connect_path: Option<String>,
}

#[derive(Deserialize)]
struct DeviceListResponse {
    devices: Vec<DeviceInfo>,
}

#[derive(Deserialize)]
struct RevokeResponse {
    ok: bool,
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
    let issuer = issuer.trim().trim_end_matches('/');
    let key =
        load_or_create_device_key(store).map_err(|err| anyhow!("load/create device key: {err}"))?;
    let public = key.public_identity();

    let hostname = hostname_string();
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let display = name.map_or_else(|| hostname.clone(), str::to_owned);

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
    if !proof.ok {
        bail!("enroll proof rejected");
    }

    let mut session = session_paths.load_session().unwrap_or_default();
    session.device_id = Some(enroll.device_id.clone());
    if session.issuer.is_empty() {
        issuer.clone_into(&mut session.issuer);
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
    let issuer = issuer.trim().trim_end_matches('/');
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
    let list: DeviceListResponse = resp.json().await.context("parse devices list")?;
    Ok(list.devices)
}

/// Revoke a device on the control plane (immediate invalidation server-side).
pub async fn revoke_device(
    http: &reqwest::Client,
    issuer: &str,
    access_token: &str,
    device_id: &str,
    session_paths: &SessionPaths,
) -> Result<bool> {
    let issuer = issuer.trim().trim_end_matches('/');
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
    let rev: RevokeResponse = resp.json().await.context("parse revoke response")?;
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
