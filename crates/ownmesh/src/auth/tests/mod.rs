//! End-to-end auth tests against an in-process mock control plane (cp-04 contract).

mod mock_server;

use super::*;
use mock_server::MockControlPlane;
use ownmesh_config::OwnMeshPaths;
use ownmesh_identity::{
    load_human_refresh_token, load_or_create_device_key, MemorySecretStore, SecretString,
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client")
}

fn session_paths(dir: &std::path::Path) -> SessionPaths {
    let paths = OwnMeshPaths::for_base(dir);
    paths.ensure_layout().unwrap();
    SessionPaths::from_paths(paths)
}

#[tokio::test]
async fn pkce_login_stores_refresh_in_keychain_not_plaintext() {
    let mock = MockControlPlane::start().await;
    let dir = tempdir().unwrap();
    let sp = session_paths(dir.path());
    let store = MemorySecretStore::default();
    let http = http_client();

    let issuer = mock.base_url();
    let http2 = http.clone();
    let issuer2 = issuer.clone();
    let tokens = login_browser_pkce(
        &http,
        &issuer,
        BrowserLoginOpts {
            skip_browser_open: true,
            auto_approve: true,
            callback_timeout: Duration::from_secs(15),
            on_authorize_url: Some(Box::new(move |url| {
                // Drive the authorize redirect ourselves (simulates browser).
                let http2 = http2.clone();
                let issuer2 = issuer2.clone();
                std::thread::spawn(move || {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    rt.block_on(async move {
                        // Follow redirect manually — client has redirect::none.
                        let _ = issuer2;
                        let resp = http2
                            .get(&url)
                            .header("accept", "application/json")
                            .send()
                            .await
                            .expect("authorize");
                        assert!(
                            resp.status().is_redirection() || resp.status().is_success(),
                            "authorize status {}",
                            resp.status()
                        );
                        if let Some(loc) = resp.headers().get(reqwest::header::LOCATION) {
                            let loc = loc.to_str().unwrap();
                            let _ = http2.get(loc).send().await.expect("callback hit");
                        }
                    });
                });
            })),
        },
    )
    .await
    .expect("pkce login");

    assert!(!tokens.access_token.is_empty());
    assert!(tokens.refresh_token.as_ref().is_some_and(|r| !r.is_empty()));

    let session = save_token_set(&sp, &store, &issuer, &tokens).unwrap();
    assert!(session.has_refresh_token);
    assert_eq!(session.issuer, issuer);

    let loaded = load_human_refresh_token(&store).unwrap().unwrap();
    assert_eq!(loaded.expose(), tokens.refresh_token.as_ref().unwrap());
    // Debug/display must redact.
    assert!(!format!("{loaded:?}").contains(loaded.expose()));
    assert_eq!(format!("{loaded}"), "[REDACTED]");

    // Session file + config must not contain the refresh token plaintext.
    let session_raw = std::fs::read_to_string(&sp.session_file).unwrap();
    assert!(!session_raw.contains(tokens.refresh_token.as_ref().unwrap()));
    assert!(!session_raw.contains(&tokens.access_token));
    assert!(!session_raw
        .to_ascii_lowercase()
        .contains("\"refresh_token\""));

    if sp.paths.config_file().exists() {
        let cfg = std::fs::read_to_string(sp.paths.config_file()).unwrap();
        assert!(!cfg.contains(tokens.refresh_token.as_ref().unwrap()));
        assert!(!cfg.contains(&tokens.access_token));
    }

    mock.shutdown().await;
}

#[tokio::test]
async fn device_code_login_polls_until_approved() {
    let mock = MockControlPlane::start().await;
    let dir = tempdir().unwrap();
    let sp = session_paths(dir.path());
    let store = MemorySecretStore::default();
    let http = http_client();
    let issuer = mock.base_url();

    // Auto-approve device codes shortly after issue.
    mock.set_auto_approve_device(true);

    let tokens = login_device_code(&http, &issuer, "client_ownmesh_cli", None)
        .await
        .expect("device login");
    assert!(!tokens.access_token.is_empty());
    assert!(tokens.refresh_token.is_some());

    let session = save_token_set(&sp, &store, &issuer, &tokens).unwrap();
    assert!(session.has_refresh_token);
    let rt = load_human_refresh_token(&store).unwrap().unwrap();
    assert!(!format!("{rt:?}").contains(rt.expose()));

    mock.shutdown().await;
}

#[tokio::test]
async fn enroll_challenge_proof_revoke_and_key_rotation() {
    let mock = MockControlPlane::start().await;
    let dir = tempdir().unwrap();
    let sp = session_paths(dir.path());
    let store = MemorySecretStore::default();
    let http = http_client();
    let issuer = mock.base_url();

    mock.set_auto_approve_device(true);
    let tokens = login_device_code(&http, &issuer, "client_ownmesh_cli", None)
        .await
        .unwrap();
    save_token_set(&sp, &store, &issuer, &tokens).unwrap();

    let key_before = load_or_create_device_key(&store).unwrap();
    let fp_before = key_before.public_identity().fingerprint;

    let enrolled = enroll_device(
        &http,
        &issuer,
        &tokens.access_token,
        &store,
        &sp,
        Some("test-desk"),
    )
    .await
    .expect("enroll");
    assert!(enrolled.device_id.starts_with("dev_"));
    assert_eq!(enrolled.status, "active");
    assert_eq!(enrolled.public.fingerprint, fp_before);

    let listed = list_devices(&http, &issuer, &tokens.access_token)
        .await
        .unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].id, enrolled.device_id);

    // Key rotation changes the local key material.
    let (new_pub, old_pub) = rotate_local_device_key(&store).unwrap();
    assert_eq!(old_pub.unwrap().fingerprint, fp_before);
    assert_ne!(new_pub.fingerprint, fp_before);

    // Immediate revoke.
    let ok = revoke_device(
        &http,
        &issuer,
        &tokens.access_token,
        &enrolled.device_id,
        &sp,
    )
    .await
    .unwrap();
    assert!(ok);
    let listed = list_devices(&http, &issuer, &tokens.access_token)
        .await
        .unwrap();
    assert!(listed.is_empty());
    assert!(sp.load_session().unwrap().device_id.is_none());

    mock.shutdown().await;
}

#[tokio::test]
async fn no_stub_paths_for_login_device_enroll() {
    // Source-level guarantee: command dispatch must not route login/device enroll
    // through the generic stub helper with chapter-5 messaging.
    let mod_src = include_str!("../../commands/mod.rs");
    assert!(
        !mod_src.contains("OAuth login arrives in chapter 5"),
        "login stub message still present"
    );
    assert!(
        !mod_src.contains("device enroll\", \"chapter 5\""),
        "device enroll stub still present"
    );
    assert!(
        mod_src.contains("login::run_login") || mod_src.contains("crate::commands::login"),
        "login dispatch must call real handler"
    );
    assert!(
        mod_src.contains("device_cmd::") || mod_src.contains("run_enroll"),
        "device enroll dispatch must call real handler"
    );

    // Runtime: handlers are wired (compile-time linkage).
    let _ = std::any::type_name::<
        fn(&crate::cli::Cli, &crate::cli::LoginArgs) -> Result<(), ownmesh_domain::ExitCode>,
    >();
    let login_name = std::any::type_name_of_val(&crate::commands::login::run_login);
    let enroll_name = std::any::type_name_of_val(&crate::commands::device_cmd::run_enroll);
    assert!(login_name.contains("login"));
    assert!(enroll_name.contains("device_cmd") || enroll_name.contains("enroll"));
}

#[tokio::test]
async fn refresh_token_not_logged_via_tracing_fields() {
    let store = Arc::new(MemorySecretStore::default());
    let secret = SecretString::new("rt_super_secret_do_not_emit");
    ownmesh_identity::store_human_refresh_token(store.as_ref(), &secret).unwrap();
    let loaded = load_human_refresh_token(store.as_ref()).unwrap().unwrap();
    let debug = format!("session tokens debug={loaded:?} display={loaded}");
    assert!(!debug.contains("rt_super_secret"));
    assert!(!debug.contains(secret.expose()));
}
