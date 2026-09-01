//! `ownmesh update` — signed GitHub Release check/download/apply.

use crate::cli::{Cli, UpdateArgs, UpdateCmd, UpdateWorkerArgs};
use ownmesh_config::{load_config, save_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_update::{
    current_install_dir, finalize_apply, finalize_interrupted_commit, interrupted_apply_pending,
    is_homebrew_install, looks_secret, recover_interrupted_apply, redact_json, redact_url,
    rollback_apply, verify_applied_binaries, ApplyReport, CheckReport, FetchKind, FetchRequest,
    FetchResponse, HttpTransport, UpdateChannel, UpdateEngine, UpdateError, UpdateMode,
    UpdateSettings, ALLOWED_HOSTS,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const UPDATE_STATE_SCHEMA: u32 = 1;
const UPDATE_DAEMON_READY_TIMEOUT: Duration = Duration::from_secs(20);

/// Dispatch `ownmesh update …`.
pub fn dispatch_update(cli: &Cli, args: &UpdateArgs) -> Result<(), ExitCode> {
    match args.command.as_ref() {
        None | Some(UpdateCmd::Apply) => run_apply(cli),
        Some(UpdateCmd::Check) => run_check(cli),
        Some(UpdateCmd::Download) => run_download(cli),
        Some(UpdateCmd::Status) => run_update_status(cli),
        Some(UpdateCmd::Channel { name }) => run_channel(cli, name.as_deref()),
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
    let (settings, paths) = load_settings()?;
    paths.ensure_layout().map_err(|error| {
        eprintln!("ownmesh update: create local state: {error}");
        ExitCode::Internal
    })?;
    let install_dir = current_install_dir().map_err(|error| {
        eprintln!("ownmesh update: {error}");
        ExitCode::Internal
    })?;
    if is_homebrew_install(&install_dir) {
        return fail(cli, UpdateError::HomebrewManaged);
    }
    let transaction = begin_transaction(&paths, &install_dir, settings.channel)?;

    #[cfg(windows)]
    {
        launch_detached_worker(cli, &paths, &transaction)?;
        emit_started(cli, &paths, &transaction);
        Ok(())
    }

    #[cfg(not(windows))]
    {
        let worker_args = UpdateWorkerArgs {
            transaction_id: transaction.id.clone(),
        };
        run_worker(cli, &worker_args)
    }
}

fn run_update_status(cli: &Cli) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|error| {
        eprintln!("ownmesh update status: {error}");
        ExitCode::UsageConfig
    })?;
    let Some(transaction) = read_transaction(&paths).map_err(|error| {
        eprintln!("ownmesh update status: {error}");
        ExitCode::Internal
    })?
    else {
        if cli.json {
            println!("{}", json!({"schema_version": 1, "status": "none"}));
        } else {
            println!("no update transaction has been recorded");
        }
        return Ok(());
    };
    emit_transaction(cli, &transaction);
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateTransaction {
    schema_version: u32,
    id: String,
    phase: String,
    from_version: String,
    target_version: Option<String>,
    channel: String,
    install_dir: String,
    worker_path: Option<String>,
    service_was_running: Option<bool>,
    owner_pid: u32,
    owner_birth_id: u64,
    started_at_unix: i64,
    updated_at_unix: i64,
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpdateLock {
    schema_version: u32,
    transaction_id: String,
    owner_pid: u32,
    owner_birth_id: u64,
}

impl UpdateTransaction {
    fn terminal(&self) -> bool {
        matches!(
            self.phase.as_str(),
            "completed" | "current" | "failed" | "rolled_back"
        )
    }
}

#[derive(Debug, Clone, Copy)]
struct ServiceUpdateState {
    was_running: bool,
    stopped: bool,
}

fn update_dir(paths: &OwnMeshPaths) -> PathBuf {
    paths.state_dir.join("update")
}

fn transaction_path(paths: &OwnMeshPaths) -> PathBuf {
    update_dir(paths).join("transaction.json")
}

fn transaction_lock_path(paths: &OwnMeshPaths) -> PathBuf {
    update_dir(paths).join("transaction.lock")
}

fn ensure_update_dir(paths: &OwnMeshPaths) -> Result<PathBuf, String> {
    let dir = update_dir(paths);
    ownmesh_ipc::prepare_owner_only_state_dir(&dir)
        .map_err(|error| format!("prepare private update state {}: {error}", dir.display()))?;
    Ok(dir)
}

fn read_transaction(paths: &OwnMeshPaths) -> Result<Option<UpdateTransaction>, String> {
    let path = transaction_path(paths);
    let raw = match fs::read(&path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("read {}: {error}", path.display())),
    };
    let transaction: UpdateTransaction = serde_json::from_slice(&raw)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if transaction.schema_version != UPDATE_STATE_SCHEMA {
        return Err(format!(
            "unsupported update transaction schema {}",
            transaction.schema_version
        ));
    }
    Ok(Some(transaction))
}

fn write_transaction(paths: &OwnMeshPaths, transaction: &UpdateTransaction) -> Result<(), String> {
    let path = transaction_path(paths);
    let bytes = serde_json::to_vec_pretty(transaction)
        .map_err(|error| format!("serialize update transaction: {error}"))?;
    ownmesh_persist::write_atomically(&path, &bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

fn set_phase(
    paths: &OwnMeshPaths,
    transaction: &mut UpdateTransaction,
    phase: &str,
) -> Result<(), String> {
    transaction.phase = phase.to_owned();
    transaction.updated_at_unix = now_unix();
    write_transaction(paths, transaction)?;
    refresh_transaction_lock(paths, transaction)
}

fn refresh_transaction_lock(
    paths: &OwnMeshPaths,
    transaction: &UpdateTransaction,
) -> Result<(), String> {
    let path = transaction_lock_path(paths);
    let lock = UpdateLock {
        schema_version: UPDATE_STATE_SCHEMA,
        transaction_id: transaction.id.clone(),
        owner_pid: transaction.owner_pid,
        owner_birth_id: transaction.owner_birth_id,
    };
    let bytes =
        serde_json::to_vec(&lock).map_err(|error| format!("serialize update lock: {error}"))?;
    ownmesh_persist::write_atomically(&path, &bytes)
        .map_err(|error| format!("write {}: {error}", path.display()))
}

fn read_transaction_lock(paths: &OwnMeshPaths) -> Result<UpdateLock, String> {
    let path = transaction_lock_path(paths);
    let raw = fs::read(&path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let lock: UpdateLock = serde_json::from_slice(&raw)
        .map_err(|error| format!("parse {}: {error}", path.display()))?;
    if lock.schema_version != UPDATE_STATE_SCHEMA
        || lock.transaction_id.len() != 36
        || !lock.transaction_id.starts_with("upd_")
        || !lock
            .transaction_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || lock.owner_pid == 0
        || lock.owner_birth_id == 0
    {
        return Err("unsafe update transaction lock refused".into());
    }
    Ok(lock)
}

fn process_identity_alive(pid: u32, birth_id: u64) -> Result<bool, String> {
    match ownmesh_ipc::process_birth_id(pid) {
        Ok(Some(actual)) => Ok(actual == birth_id),
        Ok(None) => Ok(false),
        Err(error) => Err(format!("inspect update worker identity: {error}")),
    }
}

fn transaction_owner_alive(transaction: &UpdateTransaction) -> Result<bool, String> {
    process_identity_alive(transaction.owner_pid, transaction.owner_birth_id)
}

fn recover_recorded_transaction(
    transaction: &UpdateTransaction,
    install_dir: &Path,
) -> Result<(), ExitCode> {
    let recorded_install = fs::canonicalize(&transaction.install_dir).map_err(|error| {
        eprintln!("ownmesh update: resolve interrupted install directory: {error}");
        ExitCode::Authorization
    })?;
    if recorded_install != install_dir {
        eprintln!("ownmesh update: interrupted transaction install binding refused");
        return Err(ExitCode::Authorization);
    }
    if transaction.phase == "commit_decided" {
        finalize_interrupted_commit(install_dir).map_err(|error| {
            eprintln!("ownmesh update: finish interrupted committed update: {error}");
            ExitCode::Internal
        })?;
        restore_committed_service(transaction, install_dir).map_err(|error| {
            eprintln!("ownmesh update: restore committed service state: {error}");
            ExitCode::Internal
        })?;
    } else {
        quiesce_interrupted_service(transaction, install_dir).map_err(|error| {
            eprintln!("ownmesh update: quiesce interrupted service: {error}");
            ExitCode::Internal
        })?;
        recover_interrupted_apply(install_dir).map_err(|error| {
            eprintln!("ownmesh update: recover interrupted update: {error}");
            ExitCode::Internal
        })?;
        restore_abandoned_service(transaction, install_dir).map_err(|error| {
            eprintln!("ownmesh update: recover interrupted service state: {error}");
            ExitCode::Internal
        })?;
    }
    Ok(())
}

fn begin_transaction(
    paths: &OwnMeshPaths,
    install_dir: &Path,
    channel: UpdateChannel,
) -> Result<UpdateTransaction, ExitCode> {
    let dir = ensure_update_dir(paths).map_err(|error| {
        eprintln!("ownmesh update: {error}");
        ExitCode::Internal
    })?;
    let lock_path = transaction_lock_path(paths);
    if lock_path.exists() {
        let lock = read_transaction_lock(paths).map_err(|error| {
            eprintln!("ownmesh update: {error}");
            ExitCode::Authorization
        })?;
        let existing = read_transaction(paths).map_err(|error| {
            eprintln!("ownmesh update: {error}");
            ExitCode::Internal
        })?;
        let matching = existing
            .as_ref()
            .is_some_and(|transaction| transaction.id == lock.transaction_id);
        let owner_alive =
            process_identity_alive(lock.owner_pid, lock.owner_birth_id).map_err(|error| {
                eprintln!("ownmesh update: {error}");
                ExitCode::Internal
            })?;
        if owner_alive {
            let phase = existing
                .as_ref()
                .map_or("unknown", |transaction| transaction.phase.as_str());
            eprintln!(
                "ownmesh update: another update transaction is active (phase={phase}); run `ownmesh update status`"
            );
            return Err(ExitCode::UsageConfig);
        }
        if let Some(transaction) = &existing {
            let pending = interrupted_apply_pending(install_dir).map_err(|error| {
                eprintln!("ownmesh update: inspect interrupted update: {error}");
                ExitCode::Internal
            })?;
            if matching
                && (!transaction.terminal()
                    || (pending && matches!(transaction.phase.as_str(), "failed" | "rolled_back")))
            {
                recover_recorded_transaction(transaction, install_dir)?;
            } else if matching
                && pending
                && matches!(transaction.phase.as_str(), "completed" | "current")
            {
                eprintln!(
                    "ownmesh update: committed transaction has unexpected rollback evidence; recovery refused"
                );
                return Err(ExitCode::Authorization);
            }
        }
        fs::remove_file(&lock_path).map_err(|error| {
            eprintln!("ownmesh update: clear inactive transaction lock: {error}");
            ExitCode::Internal
        })?;
    } else {
        let pending = interrupted_apply_pending(install_dir).map_err(|error| {
            eprintln!("ownmesh update: inspect retained update journal: {error}");
            ExitCode::Internal
        })?;
        if pending {
            let transaction = read_transaction(paths)
                .map_err(|error| {
                    eprintln!("ownmesh update: {error}");
                    ExitCode::Internal
                })?
                .ok_or_else(|| {
                    eprintln!(
                        "ownmesh update: orphaned apply journal has no bound transaction; recovery refused"
                    );
                    ExitCode::Authorization
                })?;
            if transaction_owner_alive(&transaction).map_err(|error| {
                eprintln!("ownmesh update: {error}");
                ExitCode::Internal
            })? {
                eprintln!(
                    "ownmesh update: retained apply journal is still owned by a live updater"
                );
                return Err(ExitCode::UsageConfig);
            }
            if matches!(transaction.phase.as_str(), "completed" | "current") {
                eprintln!(
                    "ownmesh update: committed transaction has unexpected rollback evidence; recovery refused"
                );
                return Err(ExitCode::Authorization);
            }
            recover_recorded_transaction(&transaction, install_dir)?;
        }
    }

    // Only collect stale private workers after proving that no live
    // transaction owns one. This prevents filename-based GC from deleting
    // the executable of an active updater.
    gc_old_workers(&dir);

    let id = format!("upd_{}", uuid::Uuid::new_v4().simple());
    let owner_pid = std::process::id();
    let owner_birth_id = ownmesh_ipc::process_birth_id(owner_pid)
        .map_err(|error| {
            eprintln!("ownmesh update: inspect updater process identity: {error}");
            ExitCode::Internal
        })?
        .ok_or_else(|| {
            eprintln!("ownmesh update: updater process identity is unavailable");
            ExitCode::Internal
        })?;
    let mut lock_file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&lock_path)
        .map_err(|error| {
            eprintln!("ownmesh update: acquire transaction lock: {error}");
            ExitCode::Internal
        })?;
    let lock = UpdateLock {
        schema_version: UPDATE_STATE_SCHEMA,
        transaction_id: id.clone(),
        owner_pid,
        owner_birth_id,
    };
    let lock_bytes = serde_json::to_vec(&lock).map_err(|error| {
        eprintln!("ownmesh update: serialize transaction lock: {error}");
        ExitCode::Internal
    })?;
    lock_file.write_all(&lock_bytes).map_err(|error| {
        eprintln!("ownmesh update: write transaction lock: {error}");
        ExitCode::Internal
    })?;
    lock_file.sync_all().map_err(|error| {
        eprintln!("ownmesh update: flush transaction lock: {error}");
        ExitCode::Internal
    })?;
    drop(lock_file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600));
    }

    let now = now_unix();
    let transaction = UpdateTransaction {
        schema_version: UPDATE_STATE_SCHEMA,
        id,
        phase: "prepared".into(),
        from_version: env!("CARGO_PKG_VERSION").into(),
        target_version: None,
        channel: channel.as_str().into(),
        install_dir: install_dir.display().to_string(),
        worker_path: None,
        service_was_running: None,
        owner_pid,
        owner_birth_id,
        started_at_unix: now,
        updated_at_unix: now,
        error: None,
    };
    if let Err(error) = write_transaction(paths, &transaction)
        .and_then(|()| refresh_transaction_lock(paths, &transaction))
    {
        let _ = fs::remove_file(&lock_path);
        eprintln!("ownmesh update: {error}");
        return Err(ExitCode::Internal);
    }
    Ok(transaction)
}

fn quiesce_interrupted_service(
    transaction: &UpdateTransaction,
    install_dir: &Path,
) -> Result<(), String> {
    // `restarting` is written only after all five signed binaries were swapped.
    // A crash after the new daemon starts but before journal finalization leaves
    // that image running. Stop it before restoring the old tree; earlier phases
    // have not restarted the service and must not execute a partial install.
    if transaction.phase != "restarting" || transaction.service_was_running != Some(true) {
        return Ok(());
    }
    let cli = install_dir.join(format!("ownmesh{}", std::env::consts::EXE_SUFFIX));
    let _ = run_child(&cli, &["--json", "service", "stop"]);
    wait_for_daemon_offline(&cli, Duration::from_secs(15))
}

fn restore_abandoned_service(
    transaction: &UpdateTransaction,
    install_dir: &Path,
) -> Result<(), String> {
    if transaction.service_was_running != Some(true) {
        return Ok(());
    }
    let cli = install_dir.join(format!("ownmesh{}", std::env::consts::EXE_SUFFIX));
    run_child(&cli, &["--json", "service", "start"])
        .map_err(|_| "previously running user service could not be restored".to_owned())?;
    wait_for_daemon_version(
        &cli,
        Some(&transaction.from_version),
        UPDATE_DAEMON_READY_TIMEOUT,
    )
}

fn restore_committed_service(
    transaction: &UpdateTransaction,
    install_dir: &Path,
) -> Result<(), String> {
    if transaction.service_was_running != Some(true) {
        return Ok(());
    }
    let expected = transaction
        .target_version
        .as_deref()
        .ok_or_else(|| "committed update is missing target version".to_owned())?;
    let cli = install_dir.join(format!("ownmesh{}", std::env::consts::EXE_SUFFIX));
    if daemon_status(&cli)
        .and_then(|status| {
            status
                .pointer("/daemon/version")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .as_deref()
        == Some(expected)
    {
        return Ok(());
    }
    run_child(&cli, &["--json", "service", "start"])
        .map_err(|_| "committed user service could not be restored".to_owned())?;
    wait_for_daemon_version(&cli, Some(expected), UPDATE_DAEMON_READY_TIMEOUT)
}

fn finish_transaction(paths: &OwnMeshPaths) {
    let _ = fs::remove_file(transaction_lock_path(paths));
}

fn gc_old_workers(dir: &Path) {
    let current = std::env::current_exe()
        .ok()
        .and_then(|path| fs::canonicalize(path).ok());
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("ownmesh-update-worker-") {
            continue;
        }
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            continue;
        }
        if current.as_ref().is_some_and(|active| *active == path) {
            continue;
        }
        let _ = fs::remove_file(path);
    }
}

#[cfg(windows)]
fn create_private_worker(source: &Path, worker: &Path) -> std::io::Result<()> {
    let mut input = fs::File::open(source)?;
    let expected_len = input.metadata()?.len();
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(worker)?;
    let copied = std::io::copy(&mut input, &mut output)?;
    if copied != expected_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "private update worker copy length mismatch",
        ));
    }
    output.sync_all()?;
    drop(output);
    drop(input);
    Ok(())
}

#[cfg(windows)]
fn fail_worker_bootstrap(
    paths: &OwnMeshPaths,
    transaction: &UpdateTransaction,
    worker: Option<&Path>,
    child: Option<&mut std::process::Child>,
    message: String,
) -> ExitCode {
    if let Some(child) = child {
        let _ = child.kill();
        let _ = child.wait();
    }
    let mut recorded = transaction.clone();
    recorded.error = Some(message.clone());
    if let Err(error) = set_phase(paths, &mut recorded, "failed") {
        eprintln!("ownmesh update: persist worker bootstrap failure: {error}");
    }
    finish_transaction(paths);
    if let Some(worker) = worker {
        if let Err(error) = fs::remove_file(worker) {
            if error.kind() != std::io::ErrorKind::NotFound {
                eprintln!("ownmesh update: remove failed private worker: {error}");
            }
        }
    }
    eprintln!("ownmesh update: {message}");
    ExitCode::Internal
}

#[cfg(windows)]
fn launch_detached_worker(
    cli: &Cli,
    paths: &OwnMeshPaths,
    transaction: &UpdateTransaction,
) -> Result<(), ExitCode> {
    use std::os::windows::process::CommandExt;

    let source = std::env::current_exe().map_err(|error| {
        fail_worker_bootstrap(
            paths,
            transaction,
            None,
            None,
            format!("locate current executable: {error}"),
        )
    })?;
    let worker = update_dir(paths).join(format!(
        "ownmesh-update-worker-{}{}",
        transaction.id,
        std::env::consts::EXE_SUFFIX
    ));
    create_private_worker(&source, &worker).map_err(|error| {
        let raw = error
            .raw_os_error()
            .map_or_else(|| "none".to_owned(), |code| code.to_string());
        fail_worker_bootstrap(
            paths,
            transaction,
            Some(&worker),
            None,
            format!("create/flush private update worker (os_error={raw}): {error}"),
        )
    })?;

    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let mut spawn_cmd = Command::new(&worker);
    spawn_cmd
        .arg("__update-worker")
        .arg("--transaction-id")
        .arg(&transaction.id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    apply_ownmesh_path_env(&mut spawn_cmd, paths);
    spawn_cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW);
    let mut child = spawn_cmd.spawn().map_err(|error| {
        fail_worker_bootstrap(
            paths,
            transaction,
            Some(&worker),
            None,
            format!("start private worker: {error}"),
        )
    })?;
    let child_pid = child.id();
    let child_birth_id = match wait_for_process_birth_id(child_pid) {
        Ok(value) => value,
        Err(error) => {
            return Err(fail_worker_bootstrap(
                paths,
                transaction,
                Some(&worker),
                Some(&mut child),
                format!("bind private worker identity: {error}"),
            ));
        }
    };
    let mut recorded = transaction.clone();
    recorded.worker_path = Some(worker.display().to_string());
    recorded.owner_pid = child_pid;
    recorded.owner_birth_id = child_birth_id;
    if let Err(error) = set_phase(paths, &mut recorded, "worker_started") {
        return Err(fail_worker_bootstrap(
            paths,
            transaction,
            Some(&worker),
            Some(&mut child),
            format!("record private worker identity: {error}"),
        ));
    }
    let _ = cli;
    Ok(())
}

#[cfg(windows)]
fn wait_for_process_birth_id(pid: u32) -> Result<u64, String> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match ownmesh_ipc::process_birth_id(pid)? {
            Some(birth_id) => return Ok(birth_id),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            None => return Err("private worker exited before identity binding".into()),
        }
    }
}

#[cfg(windows)]
fn emit_started(cli: &Cli, paths: &OwnMeshPaths, transaction: &UpdateTransaction) {
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "status": "started",
                "transaction_id": transaction.id,
                "status_file": transaction_path(paths),
            })
        );
    } else {
        println!("OwnMesh update started ({})", transaction.id);
        println!("  sessions and the user service will be drained automatically");
        println!("  check progress: ownmesh update status");
    }
}

fn emit_transaction(cli: &Cli, transaction: &UpdateTransaction) {
    if cli.json {
        println!(
            "{}",
            redact_json(&serde_json::to_value(transaction).unwrap_or_else(|_| json!({})))
        );
    } else {
        println!("OwnMesh update {}", transaction.id);
        println!("  phase:   {}", transaction.phase);
        println!("  from:    {}", transaction.from_version);
        if let Some(target) = &transaction.target_version {
            println!("  target:  {target}");
        }
        if let Some(error) = &transaction.error {
            println!("  error:   {error}");
        }
    }
}

/// Execute the private self-update worker. The public command starts this from
/// a copy outside the install directory on Windows, so all five installed
/// images can be replaced without a shell helper or a reboot-time move.
pub(crate) fn run_worker(cli: &Cli, args: &UpdateWorkerArgs) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|error| {
        eprintln!("ownmesh update worker: {error}");
        ExitCode::UsageConfig
    })?;
    let mut transaction = wait_for_worker_binding(&paths, &args.transaction_id)?;
    if transaction.id != args.transaction_id
        || transaction.schema_version != UPDATE_STATE_SCHEMA
        || transaction.terminal()
    {
        eprintln!("ownmesh update worker: transaction binding refused");
        return Err(ExitCode::Authorization);
    }
    if !transaction_owner_alive(&transaction).map_err(|error| {
        eprintln!("ownmesh update worker: {error}");
        ExitCode::Authorization
    })? {
        eprintln!("ownmesh update worker: process identity binding refused");
        return Err(ExitCode::Authorization);
    }
    #[cfg(windows)]
    verify_private_worker_path(&transaction)?;
    let install_dir = PathBuf::from(&transaction.install_dir);
    let canonical_install = fs::canonicalize(&install_dir).map_err(|error| {
        eprintln!("ownmesh update worker: canonicalize install directory: {error}");
        ExitCode::Authorization
    })?;
    if canonical_install != install_dir {
        eprintln!("ownmesh update worker: non-canonical install directory refused");
        return Err(ExitCode::Authorization);
    }

    match perform_worker_update(&paths, &mut transaction, &install_dir) {
        Ok(Some(report)) => {
            set_phase(&paths, &mut transaction, "completed").map_err(|error| {
                eprintln!("ownmesh update worker: {error}");
                ExitCode::Internal
            })?;
            finish_transaction(&paths);
            if !cfg!(windows) {
                emit_applied(
                    cli,
                    &report,
                    transaction.target_version.as_deref(),
                    transaction.service_was_running == Some(true),
                );
            }
            Ok(())
        }
        Ok(None) => {
            transaction.error = None;
            set_phase(&paths, &mut transaction, "current").map_err(|error| {
                eprintln!("ownmesh update worker: {error}");
                ExitCode::Internal
            })?;
            finish_transaction(&paths);
            if !cfg!(windows) {
                println!("ownmesh {} is already current", transaction.from_version);
            }
            Ok(())
        }
        Err(message) => {
            transaction.error = Some(message);
            if matches!(
                transaction.phase.as_str(),
                "commit_decided" | "recovery_required"
            ) {
                // Keep the lock and committed phase durable. The worker is
                // about to exit, so the next invocation will finish journal/
                // backup cleanup without ever restoring the old binaries.
                let _ = write_transaction(&paths, &transaction);
            } else if transaction.phase == "rolled_back" {
                let _ = write_transaction(&paths, &transaction);
                finish_transaction(&paths);
            } else {
                let _ = set_phase(&paths, &mut transaction, "failed");
                finish_transaction(&paths);
            }
            if cfg!(windows) {
                Err(ExitCode::Internal)
            } else {
                emit_transaction(cli, &transaction);
                Err(ExitCode::Internal)
            }
        }
    }
}

fn wait_for_worker_binding(
    paths: &OwnMeshPaths,
    transaction_id: &str,
) -> Result<UpdateTransaction, ExitCode> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let transaction = read_transaction(paths)
            .map_err(|error| {
                eprintln!("ownmesh update worker: {error}");
                ExitCode::Internal
            })?
            .ok_or_else(|| {
                eprintln!("ownmesh update worker: transaction is missing");
                ExitCode::UsageConfig
            })?;
        if transaction.id != transaction_id {
            eprintln!("ownmesh update worker: transaction binding refused");
            return Err(ExitCode::Authorization);
        }
        if transaction.owner_pid == std::process::id() {
            return Ok(transaction);
        }
        if Instant::now() >= deadline {
            eprintln!("ownmesh update worker: parent did not bind the private worker");
            return Err(ExitCode::Authorization);
        }
        thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(windows)]
fn verify_private_worker_path(transaction: &UpdateTransaction) -> Result<(), ExitCode> {
    let expected = transaction.worker_path.as_ref().ok_or_else(|| {
        eprintln!("ownmesh update worker: private worker path is missing");
        ExitCode::Authorization
    })?;
    let actual = std::env::current_exe()
        .and_then(fs::canonicalize)
        .map_err(|error| {
            eprintln!("ownmesh update worker: resolve private worker: {error}");
            ExitCode::Authorization
        })?;
    let expected = fs::canonicalize(expected).map_err(|error| {
        eprintln!("ownmesh update worker: resolve bound worker: {error}");
        ExitCode::Authorization
    })?;
    if actual != expected {
        eprintln!("ownmesh update worker: private worker path binding refused");
        return Err(ExitCode::Authorization);
    }
    Ok(())
}

fn perform_worker_update(
    paths: &OwnMeshPaths,
    transaction: &mut UpdateTransaction,
    install_dir: &Path,
) -> Result<Option<ApplyReport>, String> {
    let channel = UpdateChannel::parse(&transaction.channel).map_err(|error| error.to_string())?;
    set_phase(paths, transaction, "downloading")?;
    let transport = ReqwestTransport::new().map_err(|_| "create update HTTP client".to_owned())?;
    let engine = UpdateEngine {
        current_version: transaction.from_version.clone(),
        install_dir_override: Some(install_dir.to_path_buf()),
        ..UpdateEngine::default()
    };
    let artifacts = match engine.download(&transport, channel) {
        Ok(artifacts) => artifacts,
        Err(UpdateError::AlreadyCurrent(_)) => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    transaction.target_version = Some(artifacts.release.version.clone());
    set_phase(paths, transaction, "verified")?;

    let command_exe = std::env::current_exe()
        .map_err(|error| format!("locate update worker executable: {error}"))?;
    let lifecycle = prepare_service_for_update(paths, transaction, &command_exe)?;

    let installed_cli = install_dir.join(format!("ownmesh{}", std::env::consts::EXE_SUFFIX));
    set_phase(paths, transaction, "applying")?;
    let mut report = match engine.apply_verified(&artifacts) {
        Ok(report) => report,
        Err(error) => {
            let message = error.to_string();
            let pending = interrupted_apply_pending(install_dir)
                .map_err(|inspect| format!("{message}; inspect recovery evidence: {inspect}"))?;
            if pending {
                match recover_interrupted_apply(install_dir) {
                    Ok(_) => {
                        restore_service_after_failed_update(lifecycle, &installed_cli)?;
                        transaction.error = Some(message.clone());
                        set_phase(paths, transaction, "rolled_back")?;
                        return Err(format!("{message}; previous binaries restored"));
                    }
                    Err(recovery_error) => {
                        transaction.error =
                            Some(format!("{message}; recovery required: {recovery_error}"));
                        set_phase(paths, transaction, "recovery_required")?;
                        return Err(format!(
                            "{message}; rollback failed and durable recovery evidence was retained: {recovery_error}"
                        ));
                    }
                }
            }
            restore_service_after_failed_update(lifecycle, &installed_cli)?;
            return Err(message);
        }
    };

    set_phase(paths, transaction, "restarting")?;
    let post_result = verify_and_restart(
        &installed_cli,
        artifacts.release.version.as_str(),
        lifecycle.was_running,
    );
    if let Err(error) = post_result {
        rollback_uncommitted_update(
            paths,
            transaction,
            &report,
            lifecycle,
            &command_exe,
            &installed_cli,
            &error,
        )?;
        return Err(format!("{error}; previous binaries restored"));
    }
    if let Err(error) = verify_applied_binaries(&report) {
        let message = format!("verify installed binary set before commit: {error}");
        rollback_uncommitted_update(
            paths,
            transaction,
            &report,
            lifecycle,
            &command_exe,
            &installed_cli,
            &message,
        )?;
        return Err(format!("{message}; previous binaries restored"));
    }
    // Durable outer commit decision precedes removal of rollback evidence.
    // Recovery at/after this phase completes the new set and never restores old binaries.
    set_phase(paths, transaction, "commit_decided")?;
    report.backup_cleanup_pending =
        !finalize_apply(&report).map_err(|error| format!("finalize committed update: {error}"))?;
    Ok(Some(report))
}

fn prepare_service_for_update(
    paths: &OwnMeshPaths,
    transaction: &mut UpdateTransaction,
    command_exe: &Path,
) -> Result<ServiceUpdateState, String> {
    let service = run_child(command_exe, &["--json", "service", "status"])
        .ok()
        .and_then(|output| serde_json::from_slice::<serde_json::Value>(&output.stdout).ok());
    let installed = service
        .as_ref()
        .and_then(|value| value.get("installed"))
        .and_then(serde_json::Value::as_bool)
        .or_else(|| super::service::read_service_record(paths).map(|record| record.installed))
        .unwrap_or(false);
    let os_running = service
        .as_ref()
        .and_then(|value| value.get("running"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    let daemon_online = daemon_status(command_exe).is_some();
    let was_running = daemon_online || os_running;
    transaction.service_was_running = Some(was_running);
    set_phase(paths, transaction, "draining")?;
    if daemon_online {
        run_child(command_exe, &["--json", "session", "terminate", "--all"])
            .map_err(|_| "could not drain active OwnMesh sessions".to_owned())?;
    }
    set_phase(paths, transaction, "stopping_service")?;
    let should_stop = installed || daemon_online || os_running;
    if should_stop {
        run_child(command_exe, &["--json", "service", "stop"])
            .map_err(|_| "could not stop the OwnMesh user service".to_owned())?;
        wait_for_daemon_offline(command_exe, Duration::from_secs(15))?;
    }
    set_phase(paths, transaction, "service_stopped")?;
    Ok(ServiceUpdateState {
        was_running,
        stopped: should_stop,
    })
}

fn rollback_uncommitted_update(
    paths: &OwnMeshPaths,
    transaction: &mut UpdateTransaction,
    report: &ApplyReport,
    state: ServiceUpdateState,
    command_exe: &Path,
    installed_cli: &Path,
    reason: &str,
) -> Result<(), String> {
    if state.was_running {
        let _ = run_child(command_exe, &["--json", "service", "stop"]);
        let _ = wait_for_daemon_offline(command_exe, Duration::from_secs(15));
    }
    if let Err(rollback_error) = rollback_apply(report) {
        transaction.error = Some(format!(
            "{reason}; rollback failed and recovery is required: {rollback_error}"
        ));
        set_phase(paths, transaction, "recovery_required")?;
        return Err(format!(
            "{reason}; rollback failed and durable recovery evidence was retained: {rollback_error}"
        ));
    }
    restore_service_after_failed_update(state, installed_cli)?;
    if state.was_running {
        wait_for_daemon_version(
            installed_cli,
            Some(&transaction.from_version),
            UPDATE_DAEMON_READY_TIMEOUT,
        )
        .map_err(|rollback_health| {
            format!("{reason}; binaries restored but old daemon health failed: {rollback_health}")
        })?;
    }
    transaction.error = Some(reason.to_owned());
    set_phase(paths, transaction, "rolled_back")
}

fn restore_service_after_failed_update(
    state: ServiceUpdateState,
    command_exe: &Path,
) -> Result<(), String> {
    if state.was_running && state.stopped {
        run_child(command_exe, &["--json", "service", "start"])
            .map_err(|error| format!("restore user service after failed update: {error}"))?;
    }
    Ok(())
}

fn verify_and_restart(
    installed_cli: &Path,
    target_version: &str,
    restart_service: bool,
) -> Result<(), String> {
    let version = run_child(installed_cli, &["--version"])?;
    let stdout = String::from_utf8_lossy(&version.stdout);
    if stdout.split_whitespace().last() != Some(target_version) {
        return Err("installed CLI version does not match the verified release".into());
    }
    if restart_service {
        run_child(installed_cli, &["--json", "service", "start"])
            .map_err(|_| "updated user service did not start".to_owned())?;
        wait_for_daemon_version(
            installed_cli,
            Some(target_version),
            UPDATE_DAEMON_READY_TIMEOUT,
        )?;
    }
    Ok(())
}

fn apply_ownmesh_path_env(command: &mut Command, paths: &OwnMeshPaths) {
    command.env("OWNMESH_CONFIG_DIR", &paths.config_dir);
    command.env("OWNMESH_STATE_DIR", &paths.state_dir);
    command.env("OWNMESH_RUNTIME_DIR", &paths.runtime_dir);
}

fn run_child(program: &Path, args: &[&str]) -> Result<std::process::Output, String> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    if let Ok(paths) = OwnMeshPaths::discover() {
        apply_ownmesh_path_env(&mut command, &paths);
    }
    let output = command
        .output()
        .map_err(|error| format!("start {}: {error}", program.display()))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!("{} exited unsuccessfully", program.display()))
    }
}

fn daemon_status(program: &Path) -> Option<serde_json::Value> {
    let output = run_child(program, &["--json", "status"]).ok()?;
    serde_json::from_slice(&output.stdout).ok()
}

fn wait_for_daemon_version(
    program: &Path,
    expected_version: Option<&str>,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = daemon_status(program) {
            let version = status
                .pointer("/daemon/version")
                .and_then(serde_json::Value::as_str);
            if expected_version.is_none() || version == expected_version {
                return Ok(());
            }
        }
        if Instant::now() >= deadline {
            return Err("OwnMesh daemon did not become ready with the expected version".into());
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn service_running(program: &Path) -> Option<bool> {
    let output = run_child(program, &["--json", "service", "status"]).ok()?;
    serde_json::from_slice::<serde_json::Value>(&output.stdout)
        .ok()?
        .get("running")
        .and_then(serde_json::Value::as_bool)
}

fn wait_for_daemon_offline(program: &Path, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    loop {
        let ipc_offline = daemon_status(program).is_none();
        let service_active = service_running(program) == Some(true);
        if ipc_offline && !service_active {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "OwnMesh daemon could not be proven stopped (IPC/service observations disagree)"
                    .into(),
            );
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn emit_applied(
    cli: &Cli,
    report: &ApplyReport,
    target_version: Option<&str>,
    daemon_verified: bool,
) {
    if cli.json {
        println!(
            "{}",
            redact_json(&json!({
                "schema_version": 1,
                "status": "applied",
                "version": target_version,
                "install_dir": report.install_dir,
                "written": report.written,
                "verification": {
                    "binary_hashes": "passed",
                    "cli_version": "passed",
                    "daemon_version": if daemon_verified { "passed" } else { "skipped_not_running" },
                    "backup_cleanup": if report.backup_cleanup_pending { "pending" } else { "passed" }
                }
            }))
        );
    } else {
        println!(
            "updated OwnMesh to {} ({} binaries)",
            target_version.unwrap_or("?"),
            report.written.len()
        );
        if daemon_verified {
            println!("  binary hashes, CLI version, and daemon version checks passed");
        } else {
            println!("  binary hashes and CLI version checks passed; daemon check skipped (service was not running)");
        }
        if report.backup_cleanup_pending {
            println!(
                "  backup cleanup is pending and will be retried on the next update invocation"
            );
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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
            ExitCode::DependencyUnavailable
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
        crate::commands::fail::note_envelope_emitted();
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
    fn apply_ownmesh_path_env_pins_all_three_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut command = Command::new("ownmesh");
        apply_ownmesh_path_env(&mut command, &paths);
        let env = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.to_owned())))
            .collect::<std::collections::BTreeMap<_, _>>();
        assert_eq!(
            env.get(std::ffi::OsStr::new("OWNMESH_CONFIG_DIR"))
                .map(std::ffi::OsString::as_os_str),
            Some(paths.config_dir.as_os_str())
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("OWNMESH_STATE_DIR"))
                .map(std::ffi::OsString::as_os_str),
            Some(paths.state_dir.as_os_str())
        );
        assert_eq!(
            env.get(std::ffi::OsStr::new("OWNMESH_RUNTIME_DIR"))
                .map(std::ffi::OsString::as_os_str),
            Some(paths.runtime_dir.as_os_str())
        );
    }

    #[test]
    fn channel_parse_roundtrip_samples() {
        let cli = Cli::try_parse_from(["ownmesh", "update", "channel", "beta"]).unwrap();
        match cli.command {
            Some(crate::cli::Commands::Update(UpdateArgs {
                command: Some(UpdateCmd::Channel { name }),
            })) => {
                assert_eq!(name.as_deref(), Some("beta"));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn update_without_subcommand_selects_secure_apply_and_status_is_public() {
        let cli = Cli::try_parse_from(["ownmesh", "update"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(crate::cli::Commands::Update(UpdateArgs { command: None }))
        ));

        let cli = Cli::try_parse_from(["ownmesh", "update", "status"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(crate::cli::Commands::Update(UpdateArgs {
                command: Some(UpdateCmd::Status)
            }))
        ));
    }

    #[test]
    fn transaction_owner_binding_uses_process_birth_identity() {
        let pid = std::process::id();
        let birth_id = ownmesh_ipc::process_birth_id(pid)
            .unwrap()
            .expect("test process has a birth identity");
        assert!(process_identity_alive(pid, birth_id).unwrap());
        assert!(!process_identity_alive(pid, birth_id.saturating_add(1)).unwrap());
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
