//! `ownmesh update` — signed GitHub Release check/download/apply.

use crate::cli::{Cli, UpdateCmd};
use ownmesh_config::{load_config, save_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_update::{
    looks_secret, redact_json, redact_url, CheckReport, FetchKind, FetchRequest, FetchResponse,
    HttpTransport, UpdateChannel, UpdateEngine, UpdateError, UpdateMode, UpdateSettings,
    ALLOWED_HOSTS,
};
use serde_json::json;
use std::time::Duration;

/// Dispatch `ownmesh update …`.
pub fn dispatch_update(cli: &Cli, cmd: &UpdateCmd) -> Result<(), ExitCode> {
    match cmd {
        UpdateCmd::Check => run_check(cli),
        UpdateCmd::Download => run_download(cli),
        UpdateCmd::Apply => run_apply(cli),
        UpdateCmd::Channel { name } => run_channel(cli, name.as_deref()),
    }
}

fn run_check(cli: &Cli) -> Result<(), ExitCode> {
    let (settings, _) = load_settings()?;
    let engine = UpdateEngine {
        current_version: env!("CARGO_PKG_VERSION").to_owned(),
        ..UpdateEngine::default()
    };
    let transport = ReqwestTransport::new()?;
    // Explicit user command may use the network even when mode is off.
    match engine.check(&transport, settings.channel, None) {
        Ok(report) => {
            emit_check(cli, &report);
            Ok(())
        }
        Err(err) => fail(cli, err),
    }
}

fn run_download(cli: &Cli) -> Result<(), ExitCode> {
    let (settings, _) = load_settings()?;
    let engine = UpdateEngine {
        current_version: env!("CARGO_PKG_VERSION").to_owned(),
        ..UpdateEngine::default()
    };
    let transport = ReqwestTransport::new()?;
    match engine.download(&transport, settings.channel) {
        Ok(artifacts) => {
            let cache = update_cache_dir()?;
            std::fs::create_dir_all(&cache).map_err(|err| {
                eprintln!("ownmesh update download: cache dir: {err}");
                ExitCode::Internal
            })?;
            let archive_path = cache.join(&artifacts.release.asset_name);
            let meta_path = cache.join("ownmesh-release-meta.json");
            let sums_path = cache.join("SHA256SUMS");
            std::fs::write(&archive_path, &artifacts.archive_bytes).map_err(|err| {
                eprintln!("ownmesh update download: write archive: {err}");
                ExitCode::Internal
            })?;
            std::fs::write(
                &meta_path,
                serde_json::to_vec_pretty(&artifacts.meta).unwrap_or_default(),
            )
            .map_err(|_| ExitCode::Internal)?;
            let mut sums_text = String::new();
            for (name, digest) in &artifacts.checksums {
                sums_text.push_str(&format!("{digest}  {name}\n"));
            }
            std::fs::write(&sums_path, sums_text).map_err(|_| ExitCode::Internal)?;
            // Marker used by apply.
            let marker = json!({
                "schema_version": 1,
                "version": artifacts.release.version,
                "tag_name": artifacts.release.tag_name,
                "asset_name": artifacts.release.asset_name,
                "channel": settings.channel.as_str(),
            });
            std::fs::write(cache.join("download.json"), marker.to_string())
                .map_err(|_| ExitCode::Internal)?;
            if cli.json {
                println!(
                    "{}",
                    redact_json(&json!({
                        "schema_version": 1,
                        "status": "downloaded",
                        "version": artifacts.release.version,
                        "asset_name": artifacts.release.asset_name,
                        "path": archive_path,
                    }))
                );
            } else {
                println!(
                    "downloaded {} ({}) → {}",
                    artifacts.release.version,
                    artifacts.release.asset_name,
                    archive_path.display()
                );
            }
            Ok(())
        }
        Err(err) => fail(cli, err),
    }
}

fn run_apply(cli: &Cli) -> Result<(), ExitCode> {
    let (settings, _) = load_settings()?;
    let engine = UpdateEngine {
        current_version: env!("CARGO_PKG_VERSION").to_owned(),
        ..UpdateEngine::default()
    };
    let transport = ReqwestTransport::new()?;
    // Prefer freshly verified download+apply so signature path always runs.
    match engine.download_and_apply(&transport, settings.channel) {
        Ok(report) => {
            if cli.json {
                println!(
                    "{}",
                    redact_json(&json!({
                        "schema_version": 1,
                        "status": "applied",
                        "install_dir": report.install_dir,
                        "backup_dir": report.backup_dir,
                        "written": report.written,
                        "pending_windows_replace": report.pending_windows_replace,
                    }))
                );
            } else {
                println!(
                    "applied update to {} ({} binaries)",
                    report.install_dir.display(),
                    report.written.len()
                );
                if report.pending_windows_replace {
                    println!(
                        "note: Windows pending replace helper written; restart ownmesh to finish"
                    );
                }
                if let Some(backup) = report.backup_dir {
                    println!("previous binaries backed up under {}", backup.display());
                }
            }
            Ok(())
        }
        Err(UpdateError::HomebrewManaged) => {
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "status": "homebrew_managed",
                        "message": "run `brew upgrade ownmesh`",
                    })
                );
            } else {
                eprintln!(
                    "ownmesh update apply: this install is managed by Homebrew; run `brew upgrade ownmesh`"
                );
            }
            Err(ExitCode::UsageConfig)
        }
        Err(err) => fail(cli, err),
    }
}

fn run_channel(cli: &Cli, name: Option<&str>) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        eprintln!("config error: {err}");
        ExitCode::UsageConfig
    })?;
    let mut cfg = load_config(&paths).map_err(|err| {
        eprintln!("config error: {err}");
        ExitCode::UsageConfig
    })?;
    if let Some(raw) = name {
        let channel = UpdateChannel::parse(raw).map_err(|err| {
            eprintln!("ownmesh update channel: {err}");
            ExitCode::UsageConfig
        })?;
        cfg.update.channel = channel.as_str().to_owned();
        cfg.validate().map_err(|err| {
            eprintln!("config invalid: {err}");
            ExitCode::UsageConfig
        })?;
        save_config(&paths, &cfg).map_err(|err| {
            eprintln!("config save failed: {err}");
            ExitCode::Internal
        })?;
    }
    let channel = cfg.update.channel.clone();
    let mode = cfg.update.mode.clone();
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "channel": channel,
                "mode": mode,
                "network_default": "off",
            })
        );
    } else if name.is_some() {
        println!("update channel set to {channel} (mode={mode})");
    } else {
        println!("update channel: {channel}");
        println!("update mode:    {mode} (network off unless mode != off or explicit check/download/apply)");
    }
    Ok(())
}

fn load_settings() -> Result<(UpdateSettings, OwnMeshPaths), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        eprintln!("config error: {err}");
        ExitCode::UsageConfig
    })?;
    let cfg = load_config(&paths).map_err(|err| {
        eprintln!("config error: {err}");
        ExitCode::UsageConfig
    })?;
    let mode = UpdateMode::parse(&cfg.update.mode).unwrap_or(UpdateMode::Off);
    let channel = match UpdateChannel::parse(&cfg.update.channel) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("ownmesh update: {err}");
            return Err(ExitCode::UsageConfig);
        }
    };
    Ok((
        UpdateSettings {
            mode,
            channel,
            telemetry_enabled: false,
            crash_reports_opt_in: false,
        },
        paths,
    ))
}

fn update_cache_dir() -> Result<std::path::PathBuf, ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|_| ExitCode::UsageConfig)?;
    Ok(paths.cache_dir.join("updates"))
}

fn emit_check(cli: &Cli, report: &CheckReport) {
    if cli.json {
        println!(
            "{}",
            redact_json(&json!({
                "schema_version": 1,
                "status": "ok",
                "current_version": report.current_version,
                "available_version": report.available_version,
                "update_available": report.update_available,
                "channel": report.channel,
                "asset_name": report.asset_name,
                "tag_name": report.tag_name,
            }))
        );
    } else if report.update_available {
        println!(
            "update available: {} → {} ({})",
            report.current_version,
            report.available_version.as_deref().unwrap_or("?"),
            report.channel
        );
    } else {
        println!(
            "ownmesh {} is up to date on channel {}",
            report.current_version, report.channel
        );
    }
}

fn fail(cli: &Cli, err: UpdateError) -> Result<(), ExitCode> {
    let message = err.to_string();
    let code = match &err {
        UpdateError::Disabled
        | UpdateError::UnknownChannel(_)
        | UpdateError::InvalidArgument(_)
        | UpdateError::HomebrewManaged => ExitCode::UsageConfig,
        UpdateError::AlreadyCurrent(_) => ExitCode::Success,
        UpdateError::DowngradeRefused(_)
        | UpdateError::BadSignature
        | UpdateError::BadChecksum
        | UpdateError::RedirectHostRefused(_)
        | UpdateError::ProtocolIncompatible(_)
        | UpdateError::UnsafeArchive(_) => ExitCode::Authorization,
        UpdateError::UnsupportedPlatform(_) | UpdateError::MissingMetadata(_) => {
            ExitCode::ProfileUnavailable
        }
        UpdateError::LimitExceeded(_) | UpdateError::Transport(_) | UpdateError::Install(_) => {
            ExitCode::Internal
        }
    };
    if matches!(err, UpdateError::AlreadyCurrent(_)) {
        if cli.json {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "status": "current",
                    "message": message,
                })
            );
        } else {
            println!("{message}");
        }
        return Ok(());
    }
    if cli.json {
        println!(
            "{}",
            redact_json(&json!({
                "schema_version": 1,
                "status": "error",
                "error": message,
            }))
        );
    } else {
        eprintln!("ownmesh update: {message}");
    }
    Err(code)
}

/// reqwest-backed transport with hard host allow-list and size limits.
struct ReqwestTransport {
    client: reqwest::blocking::Client,
}

impl ReqwestTransport {
    fn new() -> Result<Self, ExitCode> {
        // blocking client keeps the update crate free of async while reusing rustls.
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                let scheme_ok = attempt.url().scheme() == "https";
                let host = attempt.url().host_str().map(str::to_owned);
                if !scheme_ok {
                    return attempt.error(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "non-https redirect refused",
                    ));
                }
                match host.as_deref() {
                    Some(host) if host_is_allowed(host) => attempt.follow(),
                    Some(host) => attempt.error(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!("redirect host refused: {host}"),
                    )),
                    None => attempt.error(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "redirect missing host",
                    )),
                }
            }))
            .timeout(Duration::from_secs(600))
            .https_only(true)
            .build()
            .map_err(|err| {
                eprintln!("ownmesh update: http client: {err}");
                ExitCode::Internal
            })?;
        Ok(Self { client })
    }
}

fn host_is_allowed(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    ALLOWED_HOSTS
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

impl HttpTransport for ReqwestTransport {
    fn fetch(&self, request: &FetchRequest) -> ownmesh_update::UpdateResult<FetchResponse> {
        ownmesh_update::validate_url_host(&request.url)?;
        let mut builder = self
            .client
            .get(&request.url)
            .timeout(request.kind.timeout());
        for (k, v) in &request.headers {
            if looks_secret(k) || looks_secret(v) {
                continue;
            }
            builder = builder.header(k, v);
        }
        let response = builder.send().map_err(|err| {
            UpdateError::Transport(format!("{}: {err}", redact_url(&request.url)))
        })?;
        let final_url = response.url().to_string();
        ownmesh_update::validate_url_host(&final_url)?;
        if !response.status().is_success() {
            return Err(UpdateError::Transport(format!(
                "HTTP {} for {}",
                response.status(),
                redact_url(&final_url)
            )));
        }
        if let Some(len) = response.content_length() {
            if len > request.kind.max_bytes() {
                return Err(UpdateError::LimitExceeded(format!(
                    "{} content-length {len} exceeds {}",
                    redact_url(&final_url),
                    request.kind.max_bytes()
                )));
            }
        }
        let mut body = Vec::new();
        let mut response = response;
        copy_with_limit(&mut response, &mut body, request.kind.max_bytes()).map_err(|err| {
            UpdateError::LimitExceeded(format!("{}: {err}", redact_url(&final_url)))
        })?;
        let _ = FetchKind::Metadata; // keep import meaningful for match sites
        Ok(FetchResponse { final_url, body })
    }
}

fn copy_with_limit(
    response: &mut reqwest::blocking::Response,
    out: &mut Vec<u8>,
    max: u64,
) -> Result<(), String> {
    use std::io::Read;
    let mut buf = vec![0_u8; 64 * 1024];
    loop {
        let n = response.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        if (out.len() as u64) + (n as u64) > max {
            return Err(format!("body exceeded {max} bytes"));
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use ownmesh_update::network_check_allowed;
    use serde_json::Value;

    #[test]
    fn channel_parse_roundtrip_samples() {
        let cli = Cli::try_parse_from(["ownmesh", "update", "channel", "beta"]).unwrap();
        match cli.command {
            Some(crate::cli::Commands::Update(UpdateCmd::Channel { name })) => {
                assert_eq!(name.as_deref(), Some("beta"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn network_off_default_settings() {
        let s = UpdateSettings::default();
        assert!(!network_check_allowed(&s));
    }

    #[test]
    fn json_redaction_hides_secrets() {
        let v = json!({"token": "abc", "ok": true});
        let red = redact_json(&v);
        assert_eq!(red["token"], Value::String("[REDACTED]".into()));
        assert_eq!(red["ok"], Value::Bool(true));
    }
}
