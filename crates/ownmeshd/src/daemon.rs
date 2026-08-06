//! Foreground daemon loop: local IPC + status responder.

use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_identity::{
    load_or_create_device_key, PreferredSecretStore, DEFAULT_KEYCHAIN_SERVICE,
};
use ownmesh_ipc::{
    generate_token, reject_unknown_handler, write_token_file, AuthGate, ClientIdentity,
    ClientOptions, Endpoint, IpcBus, IpcClient, IpcServer, ServerConfig,
};
use std::sync::Arc;
use std::time::Duration;

/// Run ownmeshd until Ctrl-C / shutdown signal.
pub fn run_foreground() -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            tracing::error!(error = %err, "runtime build failed");
            ExitCode::Internal
        })?;
    rt.block_on(run_async())
}

async fn run_async() -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        tracing::error!(error = %err, "path discovery failed");
        ExitCode::UsageConfig
    })?;
    paths.ensure_layout().map_err(|err| {
        tracing::error!(error = %err, "failed to create data directories");
        ExitCode::UsageConfig
    })?;

    let cfg = load_config(&paths).map_err(|err| {
        tracing::error!(error = %err, "config load failed");
        ExitCode::UsageConfig
    })?;
    tracing::info!(lang = %cfg.lang, "config loaded");

    let public = ensure_device_identity(&paths).map_err(|err| {
        tracing::error!(error = %err, "device identity bootstrap failed");
        ExitCode::Internal
    })?;
    // Public fingerprint only — never log key material.
    tracing::info!(fingerprint = %public.fingerprint, "device identity ready");

    let token = generate_token();
    write_token_file(&paths.runtime_dir, &token).map_err(|err| {
        tracing::error!(error = %err, "failed to write daemon token");
        ExitCode::Internal
    })?;

    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let server = Arc::new(IpcServer::new(
        ServerConfig {
            endpoint: endpoint.clone(),
            auth: AuthGate::new(token),
            server_name: env!("CARGO_PKG_NAME").into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
        },
        reject_unknown_handler(),
    ));

    tracing::info!(endpoint = %endpoint.display(), "ownmeshd starting");

    let serve = Arc::clone(&server);
    let serve_task = tokio::spawn(async move {
        if let Err(err) = serve.serve().await {
            tracing::error!(error = %err, "ipc server terminated with error");
        }
    });

    wait_for_shutdown().await?;

    server.request_shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), serve_task).await;
    tracing::info!("ownmeshd stopped");
    Ok(())
}

fn ensure_device_identity(
    paths: &OwnMeshPaths,
) -> Result<ownmesh_identity::DevicePublicIdentity, String> {
    let store = PreferredSecretStore::open(DEFAULT_KEYCHAIN_SERVICE, paths.keystore_dir())
        .map_err(|e| e.to_string())?;
    let key = load_or_create_device_key(&store).map_err(|e| e.to_string())?;
    Ok(key.public_identity())
}

async fn wait_for_shutdown() -> Result<(), ExitCode> {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|err| {
                tracing::error!(error = %err, "signal hook failed");
                ExitCode::Internal
            })?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|err| {
                    tracing::error!(error = %err, "ctrl-c hook failed");
                    ExitCode::Internal
                })?;
                tracing::info!("ctrl-c received");
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received");
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map_err(|err| {
            tracing::error!(error = %err, "ctrl-c hook failed");
            ExitCode::Internal
        })?;
        tracing::info!("ctrl-c received");
        Ok(())
    }
}

/// Probe a running daemon and print status.
pub fn probe_status() -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ExitCode::Internal)?;
    rt.block_on(async {
        let paths = OwnMeshPaths::discover().map_err(|_| ExitCode::UsageConfig)?;
        let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
        let client = IpcClient::new(
            endpoint,
            paths.runtime_dir,
            ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            ClientOptions {
                request_timeout: Duration::from_secs(2),
                max_reconnect_attempts: 1,
                reconnect_base_delay: Duration::from_millis(50),
            },
        );
        match client.status().await {
            Ok(status) => {
                println!(
                    "ownmeshd {version} state={state} pid={pid}",
                    version = status.version,
                    state = status.state,
                    pid = status.pid
                );
                Ok(())
            }
            Err(err) => {
                eprintln!("ownmeshd not reachable: {err}");
                Err(ExitCode::DeviceOffline)
            }
        }
    })
}

/// Test helper: start an in-process daemon server for the given paths.
#[cfg(test)]
pub async fn start_test_daemon(
    paths: &OwnMeshPaths,
) -> (Arc<IpcServer>, tokio::task::JoinHandle<()>, Endpoint) {
    paths.ensure_layout().unwrap();
    let token = generate_token();
    write_token_file(&paths.runtime_dir, &token).unwrap();
    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let server = Arc::new(IpcServer::new(
        ServerConfig {
            endpoint: endpoint.clone(),
            auth: AuthGate::new(token),
            server_name: "ownmeshd".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
        },
        reject_unknown_handler(),
    ));
    let serve = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        let _ = serve.serve().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (server, handle, endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_ipc::{ClientIdentity, ClientOptions, IpcClient, IpcError};
    use tempfile::tempdir;

    #[tokio::test]
    async fn cli_and_tui_clients_get_status() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint) = start_test_daemon(&paths).await;

        let cli = IpcClient::new(
            endpoint.clone(),
            paths.runtime_dir.clone(),
            ClientIdentity::new("ownmesh", "0.1.0"),
            ClientOptions::default(),
        );
        let tui = IpcClient::new(
            endpoint,
            paths.runtime_dir.clone(),
            ClientIdentity::new("ownmesh-tui", "0.1.0"),
            ClientOptions::default(),
        );

        let s1 = cli.status().await.expect("cli status");
        let s2 = tui.status().await.expect("tui status");
        assert_eq!(s1.state, "running");
        assert_eq!(s2.state, "running");
        assert_eq!(s1.version, s2.version);

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn unauthenticated_process_is_rejected() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint) = start_test_daemon(&paths).await;

        let evil = IpcClient::new(
            endpoint,
            paths.runtime_dir,
            ClientIdentity::new("untrusted", "0.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        )
        .with_token("not-a-valid-token");

        let err = evil.status().await.expect_err("must fail");
        assert!(
            matches!(
                err,
                IpcError::Unauthorized(_) | IpcError::Remote { .. } | IpcError::Disconnected(_)
            ),
            "{err:?}"
        );

        server.request_shutdown();
        let _ = handle.await;
    }
}
