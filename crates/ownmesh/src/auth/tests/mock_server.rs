//! Minimal HTTP mock implementing the cp-04 OAuth + device contract.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

#[derive(Clone)]
pub struct MockControlPlane {
    inner: Arc<Inner>,
    base_url: String,
    shutdown: Arc<AtomicBool>,
}

struct Inner {
    next_id: AtomicU64,
    auth_codes: Mutex<HashMap<String, AuthCode>>,
    refresh_tokens: Mutex<HashMap<String, TokenRec>>,
    access_tokens: Mutex<HashMap<String, TokenRec>>,
    device_codes: Mutex<HashMap<String, DeviceCode>>,
    devices: Mutex<HashMap<String, DeviceRec>>,
    challenges: Mutex<HashMap<String, ChallengeRec>>,
    clients: Mutex<HashMap<String, Vec<String>>>,
    auto_approve_device: AtomicBool,
}

#[derive(Clone)]
struct AuthCode {
    client_id: String,
    redirect_uri: String,
    scope: String,
    challenge: String,
    used: bool,
}

#[derive(Clone)]
#[allow(dead_code)]
struct TokenRec {
    principal: String,
    client_id: String,
    scope: String,
    family: String,
    revoked: bool,
}

#[derive(Clone)]
#[allow(dead_code)]
struct DeviceCode {
    user_code: String,
    client_id: String,
    scope: String,
    status: String, // pending | approved | denied | expired
    principal_id: Option<String>,
    interval_sec: u64,
    last_polled_at: Option<u64>,
}

#[derive(Clone)]
struct DeviceRec {
    id: String,
    principal_id: String,
    name: String,
    public_key: String,
    revoked: bool,
}

#[derive(Clone)]
#[allow(dead_code)]
struct ChallengeRec {
    id: String,
    device_id: String,
    message: String,
    consumed: bool,
}

impl MockControlPlane {
    pub async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind mock");
        let addr = listener.local_addr().unwrap();
        let base_url = format!("http://{addr}");
        let shutdown = Arc::new(AtomicBool::new(false));
        let inner = Arc::new(Inner {
            next_id: AtomicU64::new(1),
            auth_codes: Mutex::new(HashMap::new()),
            refresh_tokens: Mutex::new(HashMap::new()),
            access_tokens: Mutex::new(HashMap::new()),
            device_codes: Mutex::new(HashMap::new()),
            devices: Mutex::new(HashMap::new()),
            challenges: Mutex::new(HashMap::new()),
            clients: Mutex::new({
                let mut m = HashMap::new();
                m.insert(
                    "client_ownmesh_cli".into(),
                    vec![
                        "http://127.0.0.1:8750/callback".into(),
                        "http://localhost:8750/callback".into(),
                    ],
                );
                m
            }),
            auto_approve_device: AtomicBool::new(false),
        });

        let inner_clone = inner.clone();
        let shutdown_clone = shutdown.clone();
        tokio::spawn(async move {
            loop {
                if shutdown_clone.load(Ordering::SeqCst) {
                    break;
                }
                let accept = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    listener.accept(),
                )
                .await;
                let Ok(Ok((stream, _))) = accept else {
                    continue;
                };
                let inner = inner_clone.clone();
                let base = format!("http://{addr}");
                tokio::spawn(async move {
                    let _ = handle_client(stream, inner, &base).await;
                });
            }
        });

        Self {
            inner,
            base_url,
            shutdown,
        }
    }

    pub fn base_url(&self) -> String {
        self.base_url.clone()
    }

    pub fn set_auto_approve_device(&self, on: bool) {
        self.inner
            .auto_approve_device
            .store(on, Ordering::SeqCst);
    }

    pub async fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Tiny delay so the accept loop notices.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    fn alloc(inner: &Inner, prefix: &str) -> String {
        let n = inner.next_id.fetch_add(1, Ordering::SeqCst);
        format!("{prefix}{n:x}")
    }
}

async fn handle_client(mut stream: TcpStream, inner: Arc<Inner>, base: &str) -> anyhow::Result<()> {
    let mut buf = vec![0_u8; 64 * 1024];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let raw = String::from_utf8_lossy(&buf[..n]);
    let (method, path_q, headers, body) = parse_http(&raw);
    let url = format!("{base}{path_q}");
    let path = path_q.split('?').next().unwrap_or(path_q.as_str());

    let response = match (method.as_str(), path) {
        ("POST", "/oauth/register") => handle_register(&inner, &body).await,
        ("GET", "/oauth/authorize") => handle_authorize(&inner, &url).await,
        ("POST", "/oauth/token") => handle_token(&inner, &headers, &body).await,
        ("POST", "/oauth/revoke") => handle_revoke(&inner, &body).await,
        ("POST", "/oauth/device_authorization") => {
            handle_device_authorization(&inner, base, &body).await
        }
        ("GET", "/oauth/device") | ("POST", "/oauth/device") => {
            handle_device_verify(&inner, method.as_str(), &body, &url).await
        }
        ("POST", "/v1/devices/enroll") => handle_enroll(&inner, &headers, &body).await,
        ("POST", "/v1/devices/enroll/proof") => handle_proof(&inner, &headers, &body).await,
        ("GET", "/v1/devices") => handle_list_devices(&inner, &headers).await,
        ("POST", "/v1/devices/revoke") => handle_revoke_device(&inner, &headers, &body).await,
        _ => json_response(404, json!({"error":"not_found","path": path})),
    };

    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

fn parse_http(raw: &str) -> (String, String, HashMap<String, String>, String) {
    let mut parts = raw.split("\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_owned();
    let mut lines = head.lines();
    let req = lines.next().unwrap_or("");
    let mut rp = req.split_whitespace();
    let method = rp.next().unwrap_or("GET").to_owned();
    let path = rp.next().unwrap_or("/").to_owned();
    let mut headers = HashMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_owned());
        }
    }
    (method, path, headers, body)
}

async fn handle_register(inner: &Inner, body: &str) -> Vec<u8> {
    let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
    let redirect_uris = v
        .get("redirect_uris")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let client_id = MockControlPlane::alloc(inner, "client_");
    inner
        .clients
        .lock()
        .await
        .insert(client_id.clone(), redirect_uris.clone());
    json_response(
        201,
        json!({
            "client_id": client_id,
            "client_name": v.get("client_name").and_then(|x| x.as_str()).unwrap_or("ownmesh-cli"),
            "redirect_uris": redirect_uris,
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"],
            "response_types": ["code"],
        }),
    )
}

async fn handle_authorize(inner: &Inner, url: &str) -> Vec<u8> {
    let parsed = url::Url::parse(url).expect("url");
    let q: HashMap<_, _> = parsed.query_pairs().into_owned().collect();
    let redirect = q.get("redirect_uri").cloned().unwrap_or_default();
    let client_id = q.get("client_id").cloned().unwrap_or_default();
    let challenge = q.get("code_challenge").cloned().unwrap_or_default();
    let method = q
        .get("code_challenge_method")
        .cloned()
        .unwrap_or_else(|| "S256".into());
    let state = q.get("state").cloned().unwrap_or_default();
    let scope = q
        .get("scope")
        .cloned()
        .unwrap_or_else(|| super::super::oauth::DEFAULT_SCOPES.to_owned());
    let auto = q.get("auto").map(|s| s == "1").unwrap_or(false);

    if redirect.is_empty() || client_id.is_empty() || challenge.is_empty() || method != "S256" {
        return json_response(400, json!({"error":"invalid_request"}));
    }

    {
        let mut clients = inner.clients.lock().await;
        let entry = clients.entry(client_id.clone()).or_default();
        if !entry.contains(&redirect) {
            // Dev convenience: allow exact redirect registration on the fly.
            entry.push(redirect.clone());
        }
    }

    let code = MockControlPlane::alloc(inner, "ac_");
    inner.auth_codes.lock().await.insert(
        code.clone(),
        AuthCode {
            client_id,
            redirect_uri: redirect.clone(),
            scope,
            challenge,
            used: false,
        },
    );

    if !auto {
        // HTML consent page — tests always pass auto=1.
        let html = format!(
            "<html><body>approve <a href=\"{}&auto=1\">ok</a></body></html>",
            url
        );
        return html_response(200, &html);
    }

    let mut dest = url::Url::parse(&redirect).expect("redirect");
    dest.query_pairs_mut().append_pair("code", &code);
    if !state.is_empty() {
        dest.query_pairs_mut().append_pair("state", &state);
    }
    redirect_response(dest.as_str())
}

async fn handle_token(inner: &Inner, _headers: &HashMap<String, String>, body: &str) -> Vec<u8> {
    let form = parse_form(body);
    let grant = form.get("grant_type").map(String::as_str).unwrap_or("");

    match grant {
        "authorization_code" => {
            let code = form.get("code").cloned().unwrap_or_default();
            let verifier = form.get("code_verifier").cloned().unwrap_or_default();
            let redirect = form.get("redirect_uri").cloned().unwrap_or_default();
            let client_id = form.get("client_id").cloned().unwrap_or_default();
            let mut codes = inner.auth_codes.lock().await;
            let Some(auth) = codes.get_mut(&code) else {
                return json_response(400, json!({"error":"invalid_grant"}));
            };
            if auth.used || auth.redirect_uri != redirect {
                return json_response(400, json!({"error":"invalid_grant"}));
            }
            if !client_id.is_empty() && client_id != auth.client_id {
                return json_response(400, json!({"error":"invalid_grant"}));
            }
            if !verify_pkce_s256(&verifier, &auth.challenge) {
                return json_response(
                    400,
                    json!({"error":"invalid_grant","error_description":"pkce verification failed"}),
                );
            }
            auth.used = true;
            let client_id = auth.client_id.clone();
            let scope = auth.scope.clone();
            drop(codes);
            let tokens = issue_tokens(inner, &client_id, "prin_dev", &scope).await;
            json_response(200, tokens)
        }
        "refresh_token" => {
            let rt = form.get("refresh_token").cloned().unwrap_or_default();
            let mut refresh = inner.refresh_tokens.lock().await;
            let Some(rec) = refresh.remove(&rt) else {
                return json_response(400, json!({"error":"invalid_grant"}));
            };
            if rec.revoked {
                return json_response(400, json!({"error":"invalid_grant"}));
            }
            // rotate
            let tokens = issue_tokens(inner, &rec.client_id, &rec.principal, &rec.scope).await;
            json_response(200, tokens)
        }
        "urn:ietf:params:oauth:grant-type:device_code" => {
            let dc = form.get("device_code").cloned().unwrap_or_default();
            let mut map = inner.device_codes.lock().await;
            let Some(rec) = map.get_mut(&dc) else {
                return json_response(400, json!({"error":"invalid_grant"}));
            };
            if rec.status == "pending" {
                // auto-approve path for tests
                if inner.auto_approve_device.load(Ordering::SeqCst) {
                    rec.status = "approved".into();
                    rec.principal_id = Some("prin_dev".into());
                } else {
                    return json_response(400, json!({"error":"authorization_pending"}));
                }
            }
            if rec.status == "expired" {
                return json_response(400, json!({"error":"expired_token"}));
            }
            if rec.status == "denied" {
                return json_response(400, json!({"error":"access_denied"}));
            }
            let client_id = rec.client_id.clone();
            let scope = rec.scope.clone();
            let principal = rec
                .principal_id
                .clone()
                .unwrap_or_else(|| "prin_dev".into());
            drop(map);
            let tokens = issue_tokens(inner, &client_id, &principal, &scope).await;
            json_response(200, tokens)
        }
        _ => json_response(400, json!({"error":"unsupported_grant_type"})),
    }
}

async fn handle_revoke(inner: &Inner, body: &str) -> Vec<u8> {
    let form = parse_form(body);
    if let Some(token) = form.get("token") {
        inner.access_tokens.lock().await.remove(token);
        inner.refresh_tokens.lock().await.remove(token);
    }
    // RFC 7009 empty 200
    http_raw(200, "text/plain", b"")
}

async fn handle_device_authorization(inner: &Inner, base: &str, body: &str) -> Vec<u8> {
    let form = parse_form(body);
    let client_id = form
        .get("client_id")
        .cloned()
        .unwrap_or_else(|| "client_ownmesh_cli".into());
    let scope = form
        .get("scope")
        .cloned()
        .unwrap_or_else(|| super::super::oauth::DEFAULT_SCOPES.to_owned());
    let device_code = MockControlPlane::alloc(inner, "dcode_");
    let user_code = format!("ABCD-{:04}", inner.next_id.load(Ordering::SeqCst) % 10000);
    let verification_uri = format!("{base}/oauth/device");
    inner.device_codes.lock().await.insert(
        device_code.clone(),
        DeviceCode {
            user_code: user_code.clone(),
            client_id,
            scope,
            status: "pending".into(),
            principal_id: None,
            interval_sec: 1,
            last_polled_at: None,
        },
    );
    json_response(
        200,
        json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": format!("{verification_uri}?user_code={user_code}"),
            "expires_in": 900,
            "interval": 1
        }),
    )
}

async fn handle_device_verify(
    inner: &Inner,
    method: &str,
    body: &str,
    url: &str,
) -> Vec<u8> {
    if method == "GET" {
        return html_response(200, "<html><body>device login</body></html>");
    }
    let form = parse_form(body);
    let mut user_code = form.get("user_code").cloned().unwrap_or_default();
    if user_code.is_empty() {
        let parsed = url::Url::parse(url).ok();
        if let Some(u) = parsed {
            user_code = u
                .query_pairs()
                .find(|(k, _)| k == "user_code")
                .map(|(_, v)| v.into_owned())
                .unwrap_or_default();
        }
    }
    let user_code = user_code.trim().to_ascii_uppercase();
    let principal = form
        .get("principal_id")
        .cloned()
        .unwrap_or_else(|| "prin_dev".into());
    let mut map = inner.device_codes.lock().await;
    for rec in map.values_mut() {
        if rec.user_code.to_ascii_uppercase() == user_code && rec.status == "pending" {
            rec.status = "approved".into();
            rec.principal_id = Some(principal);
            return html_response(200, "<html><body>Approved</body></html>");
        }
    }
    json_response(400, json!({"error":"invalid_request"}))
}

async fn handle_enroll(inner: &Inner, headers: &HashMap<String, String>, body: &str) -> Vec<u8> {
    let Some(tok) = bearer(headers) else {
        return json_response(401, json!({"error":"unauthorized"}));
    };
    let access = inner.access_tokens.lock().await;
    let Some(rec) = access.get(&tok).cloned() else {
        return json_response(401, json!({"error":"invalid_token"}));
    };
    drop(access);
    if !rec.scope.contains("ownmesh.device") && !rec.scope.contains("ownmesh.write") {
        return json_response(403, json!({"error":"insufficient_scope"}));
    }
    let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
    let public_key = v
        .get("public_key")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_owned();
    if public_key.is_empty() {
        return json_response(400, json!({"error":"invalid_request","field":"public_key"}));
    }
    let device_id = MockControlPlane::alloc(inner, "dev_");
    let name = v
        .get("name")
        .and_then(|x| x.as_str())
        .unwrap_or(&device_id)
        .to_owned();
    inner.devices.lock().await.insert(
        device_id.clone(),
        DeviceRec {
            id: device_id.clone(),
            principal_id: rec.principal.clone(),
            name: name.clone(),
            public_key: public_key.clone(),
            revoked: false,
        },
    );
    let nonce = MockControlPlane::alloc(inner, "n_");
    let challenge_id = MockControlPlane::alloc(inner, "ech_");
    let message = format!("ownmesh-device-challenge:{nonce}:{device_id}");
    inner.challenges.lock().await.insert(
        challenge_id.clone(),
        ChallengeRec {
            id: challenge_id.clone(),
            device_id: device_id.clone(),
            message: message.clone(),
            consumed: false,
        },
    );
    // enrollment token = scoped access
    let enr = issue_tokens(inner, &rec.client_id, &rec.principal, "ownmesh.device").await;
    let enr_access = enr
        .get("access_token")
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_owned();
    json_response(
        201,
        json!({
            "device_id": device_id,
            "enrollment_token": enr_access,
            "expires_in": 300,
            "challenge": {
                "id": challenge_id,
                "nonce": nonce,
                "message": message,
                "expires_at": "2099-01-01T00:00:00.000Z"
            },
            "connect_path": "/agent/connect",
            "device": {
                "id": device_id,
                "name": name,
                "public_key": public_key,
                "revoked": false
            }
        }),
    )
}

async fn handle_proof(inner: &Inner, headers: &HashMap<String, String>, body: &str) -> Vec<u8> {
    let Some(tok) = bearer(headers) else {
        return json_response(401, json!({"error":"unauthorized"}));
    };
    let access = inner.access_tokens.lock().await;
    let Some(rec) = access.get(&tok).cloned() else {
        return json_response(401, json!({"error":"invalid_token"}));
    };
    drop(access);
    let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
    let device_id = v
        .get("device_id")
        .and_then(|x| x.as_str())
        .unwrap_or_default();
    let challenge_id = v
        .get("challenge_id")
        .and_then(|x| x.as_str())
        .unwrap_or_default();
    let signature = v
        .get("signature")
        .and_then(|x| x.as_str())
        .unwrap_or_default();
    if device_id.is_empty() || challenge_id.is_empty() || signature.is_empty() {
        return json_response(400, json!({"error":"invalid_request"}));
    }
    let devices = inner.devices.lock().await;
    let Some(device) = devices.get(device_id).cloned() else {
        return json_response(404, json!({"error":"not_found"}));
    };
    if device.principal_id != rec.principal {
        return json_response(404, json!({"error":"not_found"}));
    }
    if device.revoked {
        return json_response(403, json!({"error":"device_revoked"}));
    }
    drop(devices);
    // Require well-formed 64-byte ed25519 hex (cp-04 contract).
    if signature.len() != 128 || !signature.chars().all(|c| c.is_ascii_hexdigit()) {
        return json_response(400, json!({"error":"invalid_proof"}));
    }
    let mut ch = inner.challenges.lock().await;
    let Some(challenge) = ch.get_mut(challenge_id) else {
        return json_response(400, json!({"error":"invalid_challenge"}));
    };
    if challenge.device_id != device_id || challenge.consumed {
        return json_response(400, json!({"error":"challenge_consumed_or_expired"}));
    }
    challenge.consumed = true;
    json_response(
        200,
        json!({
            "ok": true,
            "status": "active",
            "device": {
                "id": device.id,
                "name": device.name,
                "public_key": device.public_key,
                "revoked": false
            },
            "connect_path": "/agent/connect"
        }),
    )
}

async fn handle_list_devices(inner: &Inner, headers: &HashMap<String, String>) -> Vec<u8> {
    let Some(tok) = bearer(headers) else {
        return json_response(401, json!({"error":"unauthorized"}));
    };
    let access = inner.access_tokens.lock().await;
    let Some(rec) = access.get(&tok).cloned() else {
        return json_response(401, json!({"error":"invalid_token"}));
    };
    drop(access);
    let devices = inner.devices.lock().await;
    let list: Vec<Value> = devices
        .values()
        .filter(|d| d.principal_id == rec.principal && !d.revoked)
        .map(|d| {
            json!({
                "id": d.id,
                "name": d.name,
                "public_key": d.public_key,
                "revoked": d.revoked
            })
        })
        .collect();
    json_response(200, json!({"devices": list}))
}

async fn handle_revoke_device(
    inner: &Inner,
    headers: &HashMap<String, String>,
    body: &str,
) -> Vec<u8> {
    let Some(tok) = bearer(headers) else {
        return json_response(401, json!({"error":"unauthorized"}));
    };
    let access = inner.access_tokens.lock().await;
    let Some(rec) = access.get(&tok).cloned() else {
        return json_response(401, json!({"error":"invalid_token"}));
    };
    drop(access);
    let v: Value = serde_json::from_str(body).unwrap_or(json!({}));
    let id = v.get("id").and_then(|x| x.as_str()).unwrap_or_default();
    let mut devices = inner.devices.lock().await;
    let ok = if let Some(d) = devices.get_mut(id) {
        if d.principal_id == rec.principal {
            d.revoked = true;
            // cp-04 list filters revoked out (listDevices returns non-revoked)
            devices.remove(id);
            true
        } else {
            false
        }
    } else {
        false
    };
    json_response(200, json!({"ok": ok}))
}

async fn issue_tokens(inner: &Inner, client_id: &str, principal: &str, scope: &str) -> Value {
    let family = MockControlPlane::alloc(inner, "fam_");
    let access = MockControlPlane::alloc(inner, "at_");
    let refresh = MockControlPlane::alloc(inner, "rt_");
    let rec = TokenRec {
        principal: principal.to_owned(),
        client_id: client_id.to_owned(),
        scope: scope.to_owned(),
        family,
        revoked: false,
    };
    inner
        .access_tokens
        .lock()
        .await
        .insert(access.clone(), rec.clone());
    inner
        .refresh_tokens
        .lock()
        .await
        .insert(refresh.clone(), rec);
    json!({
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
        "expires_in": 900,
        "scope": scope,
    })
}

fn verify_pkce_s256(verifier: &str, challenge: &str) -> bool {
    let digest = Sha256::digest(verifier.as_bytes());
    let encoded = URL_SAFE_NO_PAD.encode(digest);
    encoded == challenge
}

fn bearer(headers: &HashMap<String, String>) -> Option<String> {
    let h = headers.get("authorization")?;
    let rest = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer "))?;
    Some(rest.trim().to_owned())
}

fn parse_form(body: &str) -> HashMap<String, String> {
    // JSON body support (control plane readBody accepts both).
    if body.trim_start().starts_with('{') {
        if let Ok(v) = serde_json::from_str::<Value>(body) {
            let mut out = HashMap::new();
            if let Some(obj) = v.as_object() {
                for (k, val) in obj {
                    let s = match val {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    out.insert(k.clone(), s);
                }
            }
            return out;
        }
    }
    let mut out = HashMap::new();
    for pair in body.split('&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        let v = it.next().unwrap_or("");
        out.insert(url_decode(k), url_decode(v));
    }
    out
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hex = &s[i + 1..i + 3];
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn json_response(status: u16, body: Value) -> Vec<u8> {
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    http_raw(status, "application/json; charset=utf-8", &bytes)
}

fn html_response(status: u16, html: &str) -> Vec<u8> {
    http_raw(status, "text/html; charset=utf-8", html.as_bytes())
}

fn redirect_response(location: &str) -> Vec<u8> {
    let reason = "Found";
    let header = format!(
        "HTTP/1.1 302 {reason}\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    header.into_bytes()
}

fn http_raw(status: u16, content_type: &str, body: &[u8]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        201 => "Created",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        _ => "Error",
    };
    let mut out = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}


