//! `ownmesh device` enrollment and lifecycle commands.

use crate::auth::{
    enroll_device, list_devices, load_access_token, open_secret_store, resolve_issuer,
    revoke_device, rotate_local_device_key, update_device_metadata, AuthSession, DeviceInfo,
    SessionPaths,
};
use crate::cli::{Cli, DeviceCmd};
use ownmesh_domain::ExitCode;
use ownmesh_identity::PreferredSecretStore;
use serde_json::json;
use std::time::Duration;

/// Dispatch device subcommands that are implemented for §5-CLI.
pub fn dispatch_device(cli: &Cli, cmd: &DeviceCmd) -> Result<(), ExitCode> {
    match cmd {
        DeviceCmd::Enroll => run_enroll(cli),
        DeviceCmd::List => run_list(cli),
        DeviceCmd::Show { id } => run_show(cli, id),
        DeviceCmd::Rename { id, name } => run_metadata_update(cli, id, Some(name), None),
        DeviceCmd::Labels { id, labels } => run_metadata_update(cli, id, None, Some(labels)),
        DeviceCmd::RotateKey => run_rotate_key(cli),
        DeviceCmd::Revoke { id } => run_revoke(cli, id),
    }
}

/// `ownmesh device enroll`
pub fn run_enroll(cli: &Cli) -> Result<(), ExitCode> {
    let rt = runtime()?;
    rt.block_on(async {
        let ctx = authed_context().await?;
        let issuer = if ctx.session.issuer.is_empty() {
            resolve_issuer(&ctx.session).map_err(|err| {
                eprintln!("{err}");
                ExitCode::UsageConfig
            })?
        } else {
            ctx.session.issuer.clone()
        };

        let result = enroll_device(
            &ctx.http,
            &issuer,
            &ctx.access,
            &ctx.store,
            &ctx.session_paths,
            None,
        )
        .await
        .map_err(|err| {
            eprintln!("device enroll failed: {err}");
            ExitCode::Authentication
        })?;

        if cli.json {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "ok": true,
                    "device_id": result.device_id,
                    "status": result.status,
                    "fingerprint": result.public.fingerprint,
                    "public_key": result.public.public_key_hex,
                    "connect_path": result.connect_path,
                })
            );
        } else {
            println!("Device enrolled: {}", result.device_id);
            println!("  status:      {}", result.status);
            println!("  fingerprint: {}", result.public.fingerprint);
            println!("  connect:     {}", result.connect_path);
            println!("  device key:  stored in OS keychain (private key never printed)");
        }
        Ok(())
    })
}

fn run_list(cli: &Cli) -> Result<(), ExitCode> {
    let rt = runtime()?;
    rt.block_on(async {
        let ctx = authed_context().await?;
        let devices = list_devices(&ctx.http, &ctx.session.issuer, &ctx.access)
            .await
            .map_err(|err| {
                eprintln!("device list failed: {err}");
                ExitCode::DeviceOffline
            })?;
        if cli.json {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "devices": devices.iter().map(|d| json!({
                        "id": d.id,
                        "name": d.name,
                        "labels": d.labels,
                        "hostname": d.hostname,
                        "os": d.os,
                        "arch": d.arch,
                        "public_key": d.public_key,
                        "revoked": d.revoked,
                    })).collect::<Vec<_>>(),
                })
            );
        } else if devices.is_empty() {
            println!("(no devices)");
        } else {
            for d in devices {
                println!("{}  {}", d.id, d.name.as_deref().unwrap_or("-"));
            }
        }
        Ok(())
    })
}

fn run_show(cli: &Cli, id: &str) -> Result<(), ExitCode> {
    let rt = runtime()?;
    rt.block_on(async {
        let ctx = authed_context().await?;
        let devices = list_devices(&ctx.http, &ctx.session.issuer, &ctx.access)
            .await
            .map_err(|err| {
                eprintln!("device show failed: {err}");
                ExitCode::DeviceOffline
            })?;
        let Some(d) = devices.into_iter().find(|d| d.id == id) else {
            eprintln!("device not found: {id}");
            return Err(ExitCode::UsageConfig);
        };
        if cli.json {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "device": {
                        "id": d.id,
                        "name": d.name,
                        "labels": d.labels,
                        "hostname": d.hostname,
                        "os": d.os,
                        "arch": d.arch,
                        "public_key": d.public_key,
                        "revoked": d.revoked,
                    }
                })
            );
        } else {
            println!("id:         {}", d.id);
            println!("name:       {}", d.name.as_deref().unwrap_or("-"));
            println!(
                "labels:     {}",
                if d.labels.is_empty() {
                    "-".to_owned()
                } else {
                    d.labels.join(", ")
                }
            );
            println!("hostname:   {}", d.hostname.as_deref().unwrap_or("-"));
            println!(
                "os/arch:    {} / {}",
                d.os.as_deref().unwrap_or("-"),
                d.arch.as_deref().unwrap_or("-")
            );
            println!("public_key: {}", d.public_key.as_deref().unwrap_or("-"));
        }
        Ok(())
    })
}

fn run_metadata_update(
    cli: &Cli,
    id: &str,
    name: Option<&str>,
    labels: Option<&[String]>,
) -> Result<(), ExitCode> {
    let rt = runtime()?;
    rt.block_on(async {
        let ctx = authed_context().await?;
        let device = update_device_metadata(
            &ctx.http,
            &ctx.session.issuer,
            &ctx.access,
            id,
            name,
            labels,
        )
        .await
        .map_err(|error| emit_metadata_error(cli, id, &error))?;

        if cli.json {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "ok": true,
                    "device": device_json(&device),
                })
            );
        } else if name.is_some() {
            println!(
                "Device renamed: {} -> {}",
                device.id,
                device.name.as_deref().unwrap_or("-")
            );
        } else if device.labels.is_empty() {
            println!("Device labels cleared: {}", device.id);
        } else {
            println!(
                "Device labels updated: {}  {}",
                device.id,
                device.labels.join(", ")
            );
        }
        Ok(())
    })
}

fn device_json(device: &DeviceInfo) -> serde_json::Value {
    json!({
        "id": device.id,
        "name": device.name,
        "labels": device.labels,
        "hostname": device.hostname,
        "os": device.os,
        "arch": device.arch,
        "public_key": device.public_key,
        "revoked": device.revoked,
        "status": device.status,
    })
}

fn metadata_error_payload(id: &str, error: &anyhow::Error) -> serde_json::Value {
    json!({
        "schema_version": 1,
        "ok": false,
        "error": {
            "code": "device_metadata_update_failed",
            "message": ownmesh_diagnostics::redact_text(&error.to_string()),
            "device_id": ownmesh_diagnostics::redact_text(id),
        }
    })
}

fn emit_metadata_error(cli: &Cli, id: &str, error: &anyhow::Error) -> ExitCode {
    let payload = metadata_error_payload(id, error);
    if cli.json {
        println!("{payload}");
    } else {
        eprintln!(
            "device update failed: {}",
            payload["error"]["message"]
                .as_str()
                .unwrap_or("request failed")
        );
    }
    ExitCode::Conflict
}

fn run_revoke(cli: &Cli, id: &str) -> Result<(), ExitCode> {
    let rt = runtime()?;
    rt.block_on(async {
        let ctx = authed_context().await?;
        let ok = revoke_device(
            &ctx.http,
            &ctx.session.issuer,
            &ctx.access,
            id,
            &ctx.session_paths,
        )
        .await
        .map_err(|err| {
            eprintln!("device revoke failed: {err}");
            ExitCode::DeviceOffline
        })?;
        if cli.json {
            println!("{}", json!({"schema_version": 1, "ok": ok, "id": id}));
        } else if ok {
            println!("Device revoked: {id}");
        } else {
            println!("Device revoke returned ok=false for {id}");
        }
        if ok {
            Ok(())
        } else {
            Err(ExitCode::Conflict)
        }
    })
}

fn run_rotate_key(cli: &Cli) -> Result<(), ExitCode> {
    let session_paths = SessionPaths::discover().map_err(|err| {
        eprintln!("path error: {err}");
        ExitCode::UsageConfig
    })?;
    let store = open_secret_store(&session_paths.paths).map_err(|err| {
        eprintln!("keychain error: {err}");
        ExitCode::Internal
    })?;

    let (new_pub, old_pub) = rotate_local_device_key(&store).map_err(|err| {
        eprintln!("rotate-key failed: {err}");
        ExitCode::Internal
    })?;

    // Best-effort re-enroll so the control plane learns the new public key.
    let reenrolled = try_reenroll_after_rotate();

    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": true,
                "fingerprint": new_pub.fingerprint,
                "public_key": new_pub.public_key_hex,
                "previous_fingerprint": old_pub.as_ref().map(|p| &p.fingerprint),
                "reenrolled_device_id": reenrolled,
            })
        );
    } else {
        println!("Device key rotated");
        println!("  fingerprint: {}", new_pub.fingerprint);
        if let Some(old) = old_pub {
            println!("  previous:    {}", old.fingerprint);
        }
        if let Some(id) = reenrolled {
            println!("  re-enrolled: {id}");
        } else {
            println!("  note: run `ownmesh device enroll` to register the new public key");
        }
    }
    Ok(())
}

fn try_reenroll_after_rotate() -> Option<String> {
    let rt = runtime().ok()?;
    rt.block_on(async {
        let ctx = authed_context().await.ok()?;
        if ctx.session.issuer.is_empty() {
            return None;
        }
        match enroll_device(
            &ctx.http,
            &ctx.session.issuer,
            &ctx.access,
            &ctx.store,
            &ctx.session_paths,
            None,
        )
        .await
        {
            Ok(r) => Some(r.device_id),
            Err(err) => {
                eprintln!("warning: re-enroll after rotate failed: {err}");
                None
            }
        }
    })
}

struct AuthCtx {
    http: reqwest::Client,
    session_paths: SessionPaths,
    store: PreferredSecretStore,
    access: String,
    session: AuthSession,
}

async fn authed_context() -> Result<AuthCtx, ExitCode> {
    let session_paths = SessionPaths::discover().map_err(|err| {
        eprintln!("path error: {err}");
        ExitCode::UsageConfig
    })?;
    let store = open_secret_store(&session_paths.paths).map_err(|err| {
        eprintln!("keychain error: {err}");
        ExitCode::Internal
    })?;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|err| {
            eprintln!("http client error: {err}");
            ExitCode::Internal
        })?;
    let (access, session) = load_access_token(&session_paths, &store, &http)
        .await
        .map_err(|err| {
            eprintln!("{err}");
            eprintln!("hint: run `ownmesh login` first");
            ExitCode::Authentication
        })?;
    Ok(AuthCtx {
        http,
        session_paths,
        store,
        access,
        session,
    })
}

fn runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            eprintln!("failed to start async runtime: {err}");
            ExitCode::Internal
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_update_errors_are_redacted() {
        let error = anyhow::anyhow!("request failed with Bearer atk_super_secret");
        let payload = metadata_error_payload("dev_test", &error).to_string();
        assert!(!payload.contains("atk_super_secret"));
        assert!(payload.contains("device_metadata_update_failed"));
    }
}
