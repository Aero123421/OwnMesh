//! Native macOS lifecycle for the networkless privileged broker.
//!
//! The broker is a root launch daemon.  `ownmeshd` remains unprivileged and
//! reaches it only through a daemon-owned mode-0600 Unix socket.  Every static
//! artifact lives at a fixed root-controlled path and is hash-bound by the
//! install record.

use crate::install::{BrokerInstallConfig, InstallRecord, InstallStatus, INSTALL_FILE};
use crate::serve::{
    BrokerServeConfig, UnixSocketSecurity, CAPABILITY_SIGNING_FILE, CAPABILITY_VERIFY_FILE,
};
use ownmesh_broker_client::BrokerEndpoint;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

const LABEL: &str = "dev.ownmesh.privileged-broker";
const APP_DIR: &str = "/Library/Application Support/OwnMesh";
const BIN_DIR: &str = "/Library/Application Support/OwnMesh/bin";
const BROKER: &str = "/Library/PrivilegedHelperTools/dev.ownmesh.privileged-broker";
const DAEMON: &str = "/Library/Application Support/OwnMesh/bin/ownmeshd";
const STATE: &str = "/Library/Application Support/OwnMesh/broker";
const RUNTIME: &str = "/private/var/run/ownmesh";
const SOCKET: &str = "/private/var/run/ownmesh/broker.sock";
const CONFIG: &str = "/Library/Application Support/OwnMesh/broker/ownmesh-broker.json";
const PLIST: &str = "/Library/LaunchDaemons/dev.ownmesh.privileged-broker.plist";
const MAX_STATIC_IMAGE_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacRunConfig {
    endpoint: String,
    secret_file: String,
    signing_key_file: String,
    trusted_executable: String,
    socket_owner_uid: u32,
    socket_group_gid: u32,
    socket_mode: u32,
    allowed_uids: Vec<u32>,
    daemon_uid: u32,
    daemon_gid: u32,
}

fn record_path() -> PathBuf {
    Path::new(STATE).join(INSTALL_FILE)
}

pub(crate) fn install_macos_broker(
    broker_source: &Path,
    config: &BrokerInstallConfig,
) -> Result<InstallRecord, String> {
    require_root()?;
    validate_requested_policy(config)?;
    verify_source(broker_source)?;
    verify_source(&config.trusted_executable)?;

    ensure_existing_root_dir(Path::new("/Library/PrivilegedHelperTools"))?;
    ensure_existing_root_dir(Path::new("/Library/LaunchDaemons"))?;
    ensure_dir(Path::new(APP_DIR), 0o711)?;
    ensure_dir(Path::new(BIN_DIR), 0o755)?;
    ensure_dir(Path::new(STATE), 0o711)?;
    ensure_dir(Path::new(RUNTIME), 0o711)?;

    let record_path = record_path();
    if record_path.exists() {
        let record = read_record(&record_path)?;
        validate_record(&record)?;
        if sha256_file(broker_source)? != record.broker_sha256
            || sha256_file(&config.trusted_executable)? != record.trusted_executable_sha256
            || config.daemon_uid != record.daemon_uid
            || config.daemon_gid != record.daemon_gid
        {
            return Err(
                "idempotent macOS reinstall differs from the recorded images or daemon identity"
                    .into(),
            );
        }
        start_service()?;
        wait_ready(&record)?;
        return Ok(record);
    }

    // A missing record never grants permission to adopt runtime material from
    // an interrupted or foreign install.
    require_directory_entries(Path::new(APP_DIR), &["bin", "broker"])?;
    require_directory_entries(Path::new(BIN_DIR), &[])?;
    require_directory_entries(Path::new(STATE), &[])?;
    require_directory_entries(Path::new(RUNTIME), &[])?;

    for path in [BROKER, DAEMON, CONFIG, PLIST] {
        if std::fs::symlink_metadata(path).is_ok() {
            return Err(format!("refusing unrecorded macOS broker artifact {path}"));
        }
    }

    let mut created = Vec::new();
    let outcome = (|| {
        copy_new_root_file(broker_source, Path::new(BROKER), 0o755)?;
        created.push(PathBuf::from(BROKER));
        copy_new_root_file(&config.trusted_executable, Path::new(DAEMON), 0o755)?;
        created.push(PathBuf::from(DAEMON));

        let run = MacRunConfig {
            endpoint: format!("unix:{SOCKET}"),
            secret_file: format!("{STATE}/broker.secret"),
            signing_key_file: format!("{STATE}/private/{CAPABILITY_SIGNING_FILE}"),
            trusted_executable: DAEMON.into(),
            socket_owner_uid: config.daemon_uid,
            socket_group_gid: config.daemon_gid,
            socket_mode: 0o600,
            allowed_uids: vec![config.daemon_uid],
            daemon_uid: config.daemon_uid,
            daemon_gid: config.daemon_gid,
        };
        let config_bytes = serde_json::to_vec_pretty(&run)
            .map_err(|error| format!("serialize macOS broker config: {error}"))?;
        write_new_root_file(Path::new(CONFIG), &config_bytes, 0o600)?;
        created.push(PathBuf::from(CONFIG));
        write_new_root_file(Path::new(PLIST), &launchd_plist(), 0o644)?;
        created.push(PathBuf::from(PLIST));

        let record = InstallRecord {
            installed: true,
            installed_at_unix: crate::now_unix(),
            endpoint: SOCKET.into(),
            endpoint_kind: "unix_socket".into(),
            unit_path: Some(PLIST.into()),
            secret_file: run.secret_file,
            signing_key_file: run.signing_key_file,
            verify_key_file: format!("{STATE}/{CAPABILITY_VERIFY_FILE}"),
            trusted_executable: DAEMON.into(),
            socket_owner_uid: config.daemon_uid,
            socket_group_gid: config.daemon_gid,
            socket_mode: 0o600,
            allowed_uids: vec![config.daemon_uid],
            daemon_uid: config.daemon_uid,
            daemon_gid: config.daemon_gid,
            broker_binary: BROKER.into(),
            config_path: CONFIG.into(),
            broker_sha256: sha256_file(Path::new(BROKER))?,
            trusted_executable_sha256: sha256_file(Path::new(DAEMON))?,
            config_sha256: sha256_file(Path::new(CONFIG))?,
            unit_sha256: sha256_file(Path::new(PLIST))?,
            notes: vec![
                "macOS root LaunchDaemon; fixed Unix socket; audit-token peer identity".into(),
            ],
            support: "supported".into(),
        };
        let record_bytes = serde_json::to_vec_pretty(&record)
            .map_err(|error| format!("serialize macOS install record: {error}"))?;
        write_new_root_file(&record_path, &record_bytes, 0o600)?;
        created.push(record_path.clone());
        start_service()?;
        wait_ready(&record)?;
        Ok(record)
    })();
    match outcome {
        Ok(record) => Ok(record),
        Err(error) => {
            let rollback = stop_service()
                .and_then(|()| wait_stopped())
                .and_then(|()| {
                    require_only_directory_entries(
                        Path::new(STATE),
                        &["ownmesh-broker.json", INSTALL_FILE],
                    )
                })
                .and_then(|()| rollback_created(&created));
            match rollback {
                Ok(()) => Err(error),
                Err(rollback_error) => Err(format!(
                    "macOS broker install failed: {error}; safe rollback failed: {rollback_error}; preserving remaining artifacts"
                )),
            }
        }
    }
}

pub(crate) fn uninstall_macos_broker() -> Result<(), String> {
    require_root()?;
    let record_path = record_path();
    if !record_path.exists() {
        if [BROKER, DAEMON, CONFIG, PLIST]
            .iter()
            .any(|path| std::fs::symlink_metadata(path).is_ok())
        {
            return Err("macOS broker record is absent but fixed artifacts remain; refusing foreign cleanup".into());
        }
        return Ok(());
    }
    let record = read_record(&record_path)?;
    validate_record(&record)?;
    stop_service()?;
    wait_stopped()?;
    validate_runtime_tree(&record)?;
    for (path, hash, mode) in [
        (PLIST, record.unit_sha256.as_str(), 0o644),
        (CONFIG, record.config_sha256.as_str(), 0o600),
        (BROKER, record.broker_sha256.as_str(), 0o755),
        (DAEMON, record.trusted_executable_sha256.as_str(), 0o755),
    ] {
        verify_root_hash(Path::new(path), mode, hash)?;
    }
    for path in [PLIST, CONFIG, BROKER, DAEMON] {
        std::fs::remove_file(path).map_err(|error| format!("remove {path}: {error}"))?;
    }
    for path in [
        record.secret_file.as_str(),
        record.verify_key_file.as_str(),
        &format!("{STATE}/private/replay-ledger.json"),
        record.signing_key_file.as_str(),
    ] {
        std::fs::remove_file(path).map_err(|error| format!("remove {path}: {error}"))?;
    }
    for path in [
        format!("{STATE}/private/staged"),
        format!("{STATE}/private"),
    ] {
        std::fs::remove_dir(&path).map_err(|error| format!("remove {path}: {error}"))?;
    }
    verify_regular_root(&record_path, 0o600)?;
    std::fs::remove_file(&record_path)
        .map_err(|error| format!("remove {}: {error}", record_path.display()))?;
    for path in [STATE, BIN_DIR, APP_DIR, RUNTIME] {
        std::fs::remove_dir(path).map_err(|error| format!("remove {path}: {error}"))?;
    }
    Ok(())
}

pub(crate) fn broker_status_macos() -> Result<InstallStatus, String> {
    let path = record_path();
    if !path.exists() {
        return Ok(absent_status("no native macOS broker install record"));
    }
    let record = match read_record(&path).and_then(|record| {
        validate_record(&record)?;
        Ok(record)
    }) {
        Ok(record) => record,
        Err(error) => {
            return Ok(absent_status(&format!(
                "invalid macOS broker install: {error}"
            )))
        }
    };
    let socket_ok = endpoint_socket_valid(
        Path::new(SOCKET),
        record.daemon_uid,
        record.daemon_gid,
        0o600,
    );
    let installed = service_loaded() && socket_ok;
    Ok(InstallStatus {
        installed,
        network: "disabled",
        endpoint: Some(record.endpoint),
        endpoint_kind: record.endpoint_kind,
        secret_present: regular_owned_mode(
            Path::new(&record.secret_file),
            record.daemon_uid,
            record.daemon_gid,
            0o600,
        ),
        signing_key_present: verify_regular_root(Path::new(&record.signing_key_file), 0o600)
            .is_ok(),
        verify_key_present: verify_regular_root(Path::new(&record.verify_key_file), 0o644).is_ok(),
        unit_path: record.unit_path,
        notes: if installed {
            record.notes
        } else {
            vec!["launchd service inactive or Unix socket custody validation failed".into()]
        },
        support: if installed {
            "supported"
        } else {
            "unsupported"
        }
        .into(),
    })
}

pub fn load_macos_run_config(path: &Path) -> Result<BrokerServeConfig, String> {
    require_root()?;
    if path != Path::new(CONFIG) {
        return Err(format!("macOS broker config path is fixed at {CONFIG}"));
    }
    verify_regular_root(path, 0o600)?;
    let raw = std::fs::read(path)
        .map_err(|error| format!("read macOS broker config {}: {error}", path.display()))?;
    let config: MacRunConfig = serde_json::from_slice(&raw)
        .map_err(|error| format!("parse macOS broker config: {error}"))?;
    if config.endpoint != format!("unix:{SOCKET}")
        || config.secret_file != format!("{STATE}/broker.secret")
        || config.signing_key_file != format!("{STATE}/private/{CAPABILITY_SIGNING_FILE}")
        || config.trusted_executable != DAEMON
        || config.daemon_uid == 0
        || config.daemon_gid == 0
        || config.socket_owner_uid != config.daemon_uid
        || config.socket_group_gid != config.daemon_gid
        || config.socket_mode != 0o600
        || config.allowed_uids != [config.daemon_uid]
    {
        return Err("macOS broker config differs from the fixed native policy".into());
    }
    Ok(BrokerServeConfig {
        endpoint: BrokerEndpoint::UnixSocket(PathBuf::from(SOCKET)),
        secret_file: PathBuf::from(config.secret_file),
        signing_key_file: PathBuf::from(config.signing_key_file),
        trusted_executable: PathBuf::from(config.trusted_executable),
        allowed_uids: config.allowed_uids,
        socket_security: UnixSocketSecurity {
            owner_uid: config.daemon_uid,
            group_gid: config.daemon_gid,
            mode: 0o600,
        },
        addr_file: None,
    })
}

fn validate_requested_policy(config: &BrokerInstallConfig) -> Result<(), String> {
    match config.endpoint.as_ref() {
        None => {}
        Some(BrokerEndpoint::UnixSocket(path)) if path == Path::new(SOCKET) => {}
        Some(_) => return Err(format!("macOS broker endpoint is fixed at {SOCKET}")),
    }
    if config.daemon_uid == 0
        || config.daemon_gid == 0
        || config.socket_security
            != (UnixSocketSecurity {
                owner_uid: config.daemon_uid,
                group_gid: config.daemon_gid,
                mode: 0o600,
            })
        || config.allowed_uids != [config.daemon_uid]
    {
        return Err("macOS broker requires one explicit non-root ownmeshd UID/GID and an exact owner-only socket policy".into());
    }
    Ok(())
}

fn launchd_plist() -> Vec<u8> {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n  <key>Label</key><string>{LABEL}</string>\n  <key>ProgramArguments</key>\n  <array><string>{BROKER}</string><string>run</string><string>--config</string><string>{CONFIG}</string></array>\n  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>ProcessType</key><string>Background</string>\n  <key>Umask</key><integer>63</integer>\n</dict>\n</plist>\n"
    )
    .into_bytes()
}

fn start_service() -> Result<(), String> {
    if !service_loaded() {
        launchctl(&["bootstrap", "system", PLIST])?;
    }
    launchctl(&["kickstart", "-k", &format!("system/{LABEL}")])
}

fn stop_service() -> Result<(), String> {
    if service_loaded() {
        launchctl(&["bootout", &format!("system/{LABEL}")])?;
    }
    Ok(())
}

fn service_loaded() -> bool {
    Command::new("/bin/launchctl")
        .args(["print", &format!("system/{LABEL}")])
        .output()
        .is_ok_and(|output| output.status.success())
}

fn launchctl(args: &[&str]) -> Result<(), String> {
    let output = Command::new("/bin/launchctl")
        .args(args)
        .output()
        .map_err(|error| format!("execute launchctl: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "launchctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn wait_ready(record: &InstallRecord) -> Result<(), String> {
    for _ in 0..50 {
        if service_loaded()
            && endpoint_socket_valid(
                Path::new(SOCKET),
                record.daemon_uid,
                record.daemon_gid,
                0o600,
            )
        {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("macOS broker did not become ready with a custody-valid Unix socket".into())
}

fn wait_stopped() -> Result<(), String> {
    for _ in 0..50 {
        if !service_loaded() && !Path::new(SOCKET).exists() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err("macOS broker remained active after launchd bootout".into())
}

fn validate_record(record: &InstallRecord) -> Result<(), String> {
    if !record.installed
        || record.support != "supported"
        || record.endpoint != SOCKET
        || record.endpoint_kind != "unix_socket"
        || record.unit_path.as_deref() != Some(PLIST)
        || record.broker_binary != BROKER
        || record.config_path != CONFIG
        || record.trusted_executable != DAEMON
        || record.secret_file != format!("{STATE}/broker.secret")
        || record.signing_key_file != format!("{STATE}/private/{CAPABILITY_SIGNING_FILE}")
        || record.verify_key_file != format!("{STATE}/{CAPABILITY_VERIFY_FILE}")
        || record.daemon_uid == 0
        || record.daemon_gid == 0
        || record.allowed_uids != [record.daemon_uid]
        || record.socket_owner_uid != record.daemon_uid
        || record.socket_group_gid != record.daemon_gid
        || record.socket_mode != 0o600
    {
        return Err("install record is not an exact native macOS broker record".into());
    }
    verify_root_hash(Path::new(BROKER), 0o755, &record.broker_sha256)?;
    verify_root_hash(Path::new(DAEMON), 0o755, &record.trusted_executable_sha256)?;
    verify_root_hash(Path::new(CONFIG), 0o600, &record.config_sha256)?;
    verify_root_hash(Path::new(PLIST), 0o644, &record.unit_sha256)?;
    let _ = load_macos_run_config(Path::new(CONFIG))?;
    Ok(())
}

fn validate_runtime_tree(record: &InstallRecord) -> Result<(), String> {
    let private = Path::new(STATE).join("private");
    let staging = private.join("staged");
    let ledger = private.join("replay-ledger.json");
    verify_root_dir(Path::new(APP_DIR), 0o711)?;
    verify_root_dir(Path::new(BIN_DIR), 0o755)?;
    verify_root_dir(Path::new(STATE), 0o711)?;
    verify_root_dir(Path::new(RUNTIME), 0o711)?;
    verify_root_dir(&private, 0o700)?;
    verify_root_dir(&staging, 0o700)?;
    require_directory_entries(Path::new(APP_DIR), &["bin", "broker"])?;
    require_directory_entries(Path::new(BIN_DIR), &["ownmeshd"])?;
    require_directory_entries(
        Path::new(STATE),
        &[
            "ownmesh-broker.json",
            INSTALL_FILE,
            "broker.secret",
            "private",
            CAPABILITY_VERIFY_FILE,
        ],
    )?;
    require_directory_entries(
        &private,
        &[CAPABILITY_SIGNING_FILE, "replay-ledger.json", "staged"],
    )?;
    require_directory_entries(&staging, &[])?;
    require_directory_entries(Path::new(RUNTIME), &[])?;
    verify_daemon_file(
        Path::new(&record.secret_file),
        record.daemon_uid,
        record.daemon_gid,
        0o600,
    )?;
    verify_regular_root(Path::new(&record.signing_key_file), 0o600)?;
    verify_regular_root(Path::new(&record.verify_key_file), 0o644)?;
    verify_regular_root(&ledger, 0o600)
}

fn require_directory_entries(path: &Path, expected: &[&str]) -> Result<(), String> {
    let mut actual = std::fs::read_dir(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?
        .map(|entry| {
            entry
                .map_err(|error| error.to_string())?
                .file_name()
                .into_string()
                .map_err(|_| format!("{} contains a non-UTF-8 entry", path.display()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    actual.sort();
    let mut expected = expected.iter().map(ToString::to_string).collect::<Vec<_>>();
    expected.sort();
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{} contains unexpected or missing artifacts",
            path.display()
        ))
    }
}

fn require_only_directory_entries(path: &Path, allowed: &[&str]) -> Result<(), String> {
    for entry in
        std::fs::read_dir(path).map_err(|error| format!("inspect {}: {error}", path.display()))?
    {
        let name = entry
            .map_err(|error| error.to_string())?
            .file_name()
            .into_string()
            .map_err(|_| format!("{} contains a non-UTF-8 entry", path.display()))?;
        if !allowed.contains(&name.as_str()) {
            return Err(format!(
                "{} contains runtime artifacts; preserving the recoverable install record",
                path.display()
            ));
        }
    }
    Ok(())
}

fn read_record(path: &Path) -> Result<InstallRecord, String> {
    verify_regular_root(path, 0o600)?;
    serde_json::from_slice(&std::fs::read(path).map_err(|error| error.to_string())?)
        .map_err(|error| format!("parse macOS broker install record: {error}"))
}

fn require_root() -> Result<(), String> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err("macOS privileged broker lifecycle requires effective UID 0; run with sudo".into())
    }
}

fn ensure_existing_root_dir(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "{} is not a root-controlled directory",
            path.display()
        ));
    }
    ensure_no_acl(path)
}

fn ensure_dir(path: &Path, mode: u32) -> Result<(), String> {
    if !path.exists() {
        std::fs::create_dir(path).map_err(|error| format!("create {}: {error}", path.display()))?;
        set_root_mode(path, mode)?;
    }
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(format!(
            "{} has unexpected directory custody",
            path.display()
        ));
    }
    ensure_no_acl(path)
}

fn verify_source(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect source {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || metadata.len() > MAX_STATIC_IMAGE_BYTES
    {
        return Err(format!(
            "{} is not a bounded non-writable regular executable",
            path.display()
        ));
    }
    Ok(())
}

fn write_new_root_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|error| format!("create {}: {error}", path.display()))?;
    file.write_all(bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))?;
    file.sync_all()
        .map_err(|error| format!("sync {}: {error}", path.display()))?;
    set_root_mode(path, mode)
}

fn copy_new_root_file(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    let mut input = std::fs::File::open(source)
        .map_err(|error| format!("open source {}: {error}", source.display()))?;
    let before = input.metadata().map_err(|error| error.to_string())?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(destination)
        .map_err(|error| format!("create {}: {error}", destination.display()))?;
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = input.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(u64::try_from(count).map_err(|_| "copy length overflow")?)
            .ok_or_else(|| "copy length overflow".to_string())?;
        if total > MAX_STATIC_IMAGE_BYTES {
            return Err("macOS broker image exceeds bounded install size".into());
        }
        hasher.update(&buffer[..count]);
        output
            .write_all(&buffer[..count])
            .map_err(|error| error.to_string())?;
    }
    output.sync_all().map_err(|error| error.to_string())?;
    let after = input.metadata().map_err(|error| error.to_string())?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || total != before.len()
    {
        return Err("macOS install source changed while being copied".into());
    }
    drop(output);
    set_root_mode(destination, mode)?;
    if hex::encode(hasher.finalize()) != sha256_file(destination)? {
        return Err("macOS installed image hash verification failed".into());
    }
    Ok(())
}

fn set_root_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    rustix::fs::chown(
        path.as_os_str().as_bytes(),
        Some(rustix::process::Uid::from_raw(0)),
        Some(rustix::process::Gid::from_raw(0)),
    )
    .map_err(|error| format!("chown root:wheel {}: {error}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|error| format!("chmod {}: {error}", path.display()))?;
    let status = Command::new("/bin/chmod")
        .arg("-N")
        .arg(path)
        .status()
        .map_err(|error| format!("clear ACL {}: {error}", path.display()))?;
    if !status.success() {
        return Err(format!("could not clear ACL on {}", path.display()));
    }
    ensure_no_acl(path)
}

fn ensure_no_acl(path: &Path) -> Result<(), String> {
    let output = Command::new("/bin/ls")
        .arg("-lde")
        .arg(path)
        .output()
        .map_err(|error| format!("inspect ACL {}: {error}", path.display()))?;
    if !output.status.success() {
        return Err(format!("inspect ACL {} failed", path.display()));
    }
    let mode = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    if mode.contains('+') {
        return Err(format!("extended ACL on {} is forbidden", path.display()));
    }
    Ok(())
}

fn verify_regular_root(path: &Path, mode: u32) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(format!(
            "{} has unexpected root file custody",
            path.display()
        ));
    }
    ensure_no_acl(path)
}

fn verify_root_dir(path: &Path, mode: u32) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(format!(
            "{} has unexpected root directory custody",
            path.display()
        ));
    }
    ensure_no_acl(path)
}

fn verify_daemon_file(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != mode
    {
        return Err(format!(
            "{} has unexpected daemon file custody",
            path.display()
        ));
    }
    ensure_no_acl(path)
}

fn verify_root_hash(path: &Path, mode: u32, expected: &str) -> Result<(), String> {
    verify_regular_root(path, mode)?;
    if expected.len() != 64 || sha256_file(path)? != expected {
        return Err(format!(
            "{} differs from the recorded SHA-256",
            path.display()
        ));
    }
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        std::fs::File::open(path).map_err(|error| format!("hash {}: {error}", path.display()))?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if metadata.len() > MAX_STATIC_IMAGE_BYTES {
        return Err(format!("{} exceeds bounded hash size", path.display()));
    }
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if count == 0 {
            break;
        }
        total += u64::try_from(count).map_err(|_| "hash length overflow")?;
        hasher.update(&buffer[..count]);
    }
    if total != metadata.len() {
        return Err(format!("{} changed while hashing", path.display()));
    }
    Ok(hex::encode(hasher.finalize()))
}

fn regular_owned_mode(path: &Path, uid: u32, gid: u32, mode: u32) -> bool {
    std::fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| {
            metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.gid() == gid
                && metadata.mode() & 0o777 == mode
                && ensure_no_acl(path).is_ok()
        })
}

fn endpoint_socket_valid(path: &Path, uid: u32, gid: u32, mode: u32) -> bool {
    std::fs::symlink_metadata(path)
        .ok()
        .is_some_and(|metadata| {
            metadata.file_type().is_socket()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == uid
                && metadata.gid() == gid
                && metadata.mode() & 0o777 == mode
                && std::os::unix::net::UnixStream::connect(path).is_ok()
        })
}

fn rollback_created(paths: &[PathBuf]) -> Result<(), String> {
    for path in paths.iter().rev() {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|error| format!("inspect rollback artifact {}: {error}", path.display()))?;
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
        {
            return Err(format!(
                "refusing unsafe rollback artifact {}",
                path.display()
            ));
        }
        std::fs::remove_file(path)
            .map_err(|error| format!("remove rollback artifact {}: {error}", path.display()))?;
    }
    Ok(())
}

fn absent_status(note: &str) -> InstallStatus {
    InstallStatus {
        installed: false,
        network: "disabled",
        endpoint: None,
        endpoint_kind: String::new(),
        secret_present: false,
        signing_key_present: false,
        verify_key_present: false,
        unit_path: None,
        notes: vec![note.into()],
        support: "unsupported".into(),
    }
}
