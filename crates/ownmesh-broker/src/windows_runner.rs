//! Windows broker runner built entirely on the audited IPC Job Object façade.
//!
//! This module contains no Win32 FFI and no `Command` fallback. A production
//! service can instantiate it only after its installer has custody-validated
//! `staging_dir`; it is deliberately not wired into `run_broker` until that
//! service lifecycle proof exists.

use crate::windows::WindowsBrokerRunner;
use ownmesh_broker_client::{BrokerRequestV2, BrokerResponseV2, MAX_BROKER_OUTPUT_BYTES};
use ownmesh_domain::MAX_STRUCTURED_EXECUTABLE_BYTES;
use ownmesh_ipc::spawn_suspended_windows_job;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const MAX_STAGE_BYTES: u64 = MAX_STRUCTURED_EXECUTABLE_BYTES;
const KILL_WAIT: Duration = Duration::from_secs(2);
const POLL_WAIT: Duration = Duration::from_millis(20);

/// Explicit owner for the current Windows broker process tree.  Cancellation
/// is a fail-closed fence: it kills the active private Job and is reset only at
/// the beginning of a new execution.
#[derive(Clone)]
pub struct WindowsJobRunner {
    staging_dir: PathBuf,
    active: Arc<Mutex<BTreeMap<String, ActiveExecution>>>,
    stopping: Arc<AtomicBool>,
    #[cfg(test)]
    before_resume: Arc<Mutex<Option<TestBeforeResumeGate>>>,
}

struct ActiveExecution {
    request_id: String,
    cancelled: Arc<AtomicBool>,
    /// Serializes the one-way transition from a suspended, contained child to
    /// `ResumeThread` with cancellation.  A Cancel which linearizes first
    /// must never allow that child to begin executing.
    launch_gate: Arc<Mutex<()>>,
}

#[cfg(test)]
#[derive(Clone)]
struct TestBeforeResumeGate {
    reached: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

impl WindowsJobRunner {
    /// `staging_dir` must be an Administrator-custodied, non-reparse private
    /// directory created and ACL-verified by the future elevated installer.
    /// This constructor only does structural checks; it never claims lifecycle
    /// custody and therefore cannot promote Windows to supported by itself.
    pub fn new(staging_dir: &Path) -> Result<Self, String> {
        let metadata = std::fs::symlink_metadata(staging_dir).map_err(|error| {
            format!(
                "Windows broker staging directory {} is unavailable: {error}",
                staging_dir.display()
            )
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err("Windows broker staging directory must be a non-reparse directory".into());
        }
        let canonical = std::fs::canonicalize(staging_dir)
            .map_err(|error| format!("canonicalize Windows broker staging directory: {error}"))?;
        Ok(Self {
            staging_dir: canonical,
            active: Arc::new(Mutex::new(BTreeMap::new())),
            stopping: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            before_resume: Arc::new(Mutex::new(None)),
        })
    }

    #[cfg(test)]
    fn set_before_resume_gate(&self, gate: TestBeforeResumeGate) {
        *self.before_resume.lock().unwrap() = Some(gate);
    }
}

impl WindowsBrokerRunner for WindowsJobRunner {
    fn run(&self, request: &BrokerRequestV2) -> BrokerResponseV2 {
        if self.stopping.load(Ordering::Acquire) {
            return response_error(
                &request.request_id,
                "Windows broker is stopping; refusing new Job execution".into(),
            );
        }
        let cancellation = Arc::new(AtomicBool::new(false));
        let launch_gate = Arc::new(Mutex::new(()));
        let registered = self.active.lock().map(|mut active| {
            active.insert(
                request.nonce.clone(),
                ActiveExecution {
                    request_id: request.request_id.clone(),
                    cancelled: Arc::clone(&cancellation),
                    launch_gate: Arc::clone(&launch_gate),
                },
            );
            // Close the tiny race between the first stop fence and this
            // insertion. A runner which registers after shutdown starts must
            // enter its polling loop already cancelled.
            if self.stopping.load(Ordering::Acquire) {
                cancellation.store(true, Ordering::Release);
            }
        });
        if registered.is_err() {
            return response_error(
                &request.request_id,
                "Windows active execution lock poisoned".into(),
            );
        }
        let result = self.run_checked(request, &cancellation, &launch_gate);
        if let Ok(mut active) = self.active.lock() {
            active.remove(&request.nonce);
        }
        match result {
            Ok(response) => response,
            Err(error) => response_error(&request.request_id, error),
        }
    }

    fn cancel(&self, request_id: &str, nonce: &str) -> bool {
        let Ok(active) = self.active.lock() else {
            return false;
        };
        let Some(execution) = active.get(nonce) else {
            return false;
        };
        if execution.request_id != request_id {
            return false;
        }
        let cancellation = Arc::clone(&execution.cancelled);
        let launch_gate = Arc::clone(&execution.launch_gate);
        drop(active);
        // This establishes an exact linearization point with `resume`: if the
        // child has not yet started, it remains suspended and its private Job
        // is dropped instead of executing even one instruction.
        let _launch = launch_gate
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        cancellation.store(true, Ordering::Release);
        true
    }

    fn cancel_all(&self) -> usize {
        self.stopping.store(true, Ordering::Release);
        let Ok(active) = self.active.lock() else {
            return 0;
        };
        let executions = active
            .values()
            .map(|execution| {
                (
                    Arc::clone(&execution.cancelled),
                    Arc::clone(&execution.launch_gate),
                )
            })
            .collect::<Vec<_>>();
        drop(active);
        for (cancellation, launch_gate) in &executions {
            let _launch = launch_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cancellation.store(true, Ordering::Release);
        }
        executions.len()
    }
}

impl WindowsJobRunner {
    fn run_checked(
        &self,
        request: &BrokerRequestV2,
        cancellation: &Arc<AtomicBool>,
        launch_gate: &Arc<Mutex<()>>,
    ) -> Result<BrokerResponseV2, String> {
        let facts = &request.facts;
        if facts.canonical_cwd.is_some() || !facts.sanitized_env.is_empty() || facts.argv.is_empty()
        {
            return Err("Windows runner rejects caller cwd, environment, or empty argv".into());
        }
        reject_shell(&facts.argv[0])?;
        if facts.max_output_bytes == 0 || facts.max_output_bytes > MAX_BROKER_OUTPUT_BYTES {
            return Err("Windows runner output bound is invalid".into());
        }
        if cancellation.load(Ordering::Acquire) {
            return Ok(cancelled_before_launch_response(&request.request_id));
        }
        let staged = stage_pinned_executable(request, &self.staging_dir)?;
        let staged_path = staged.path.clone();
        let result = if cancellation.load(Ordering::Acquire) {
            Ok(cancelled_before_launch_response(&request.request_id))
        } else {
            self.run_staged(request, &staged, cancellation, launch_gate)
        };
        // The broker created this exact unique path. Best-effort cleanup occurs
        // after the retained stage handle and Job have been dropped.
        drop(staged);
        if let Err(error) = std::fs::remove_file(staged_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                return Err(format!("remove Windows staged executable: {error}"));
            }
        }
        result
    }

    fn run_staged(
        &self,
        request: &BrokerRequestV2,
        staged: &StagedWindowsExecutable,
        cancellation: &Arc<AtomicBool>,
        launch_gate: &Arc<Mutex<()>>,
    ) -> Result<BrokerResponseV2, String> {
        if cancellation.load(Ordering::Acquire) {
            return Ok(cancelled_before_launch_response(&request.request_id));
        }
        let facts = &request.facts;
        recheck_retained_stage(
            staged,
            &facts.executable.image_sha256,
            facts.executable.image_len,
        )?;
        let mut process =
            spawn_suspended_windows_job(&staged.path, &facts.argv[1..], &self.staging_dir)
                .map_err(|error| format!("CreateProcessW/Job Object setup: {error}"))?;
        let output_limit = facts.max_output_bytes;
        let exceeded = Arc::new(AtomicBool::new(false));
        let stdout = process
            .take_stdout()
            .ok_or("Windows Job stdout pipe unexpectedly absent")?;
        let stderr = process
            .take_stderr()
            .ok_or("Windows Job stderr pipe unexpectedly absent")?;
        let stdout_signal = Arc::clone(&exceeded);
        let stderr_signal = Arc::clone(&exceeded);
        let stdout_reader =
            std::thread::spawn(move || drain_pipe_bounded(stdout, output_limit, &stdout_signal));
        let stderr_reader =
            std::thread::spawn(move || drain_pipe_bounded(stderr, output_limit, &stderr_signal));
        #[cfg(test)]
        if let Some(gate) = self.before_resume.lock().unwrap().clone() {
            gate.reached.wait();
            gate.release.wait();
        }
        let resumed = {
            // Hold this gate across the final cancellation check and
            // `ResumeThread`. `cancel`/`cancel_all` take the same gate, so a
            // cancellation which arrives first cannot race a suspended child
            // into execution.
            let _launch = launch_gate
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if cancellation.load(Ordering::Acquire) {
                false
            } else {
                process
                    .resume()
                    .map_err(|error| format!("resume contained Windows child: {error}"))?;
                true
            }
        };
        if !resumed {
            // The child was never resumed. Dropping its private kill-on-close
            // Job closes the inherited writers so the already-started drains
            // terminate before this runner returns.
            process
                .terminate_and_wait(KILL_WAIT)
                .map_err(|error| format!("terminate unresumed Windows Job: {error}"))?;
            drop(process);
            let _ = stdout_reader
                .join()
                .map_err(|_| "Windows stdout drain thread panicked")?;
            let _ = stderr_reader
                .join()
                .map_err(|_| "Windows stderr drain thread panicked")?;
            return Ok(cancelled_before_launch_response(&request.request_id));
        }
        let started = Instant::now();
        let mut timed_out = false;
        let mut cancelled = false;
        loop {
            if process
                .wait_timeout(POLL_WAIT)
                .map_err(|error| format!("wait Windows Job child: {error}"))?
            {
                break;
            }
            if cancellation.load(Ordering::Acquire) {
                cancelled = true;
                break;
            }
            if exceeded.load(Ordering::Acquire) {
                break;
            }
            if started.elapsed() >= Duration::from_millis(facts.timeout_ms) {
                timed_out = true;
                break;
            }
        }
        let truncated = exceeded.load(Ordering::Acquire);
        if timed_out || cancelled || truncated {
            process
                .terminate_and_wait(KILL_WAIT)
                .map_err(|error| format!("terminate contained Windows Job: {error}"))?;
        }
        let exit_code = if timed_out || cancelled || truncated {
            None
        } else {
            Some(
                process
                    .exit_code()
                    .map_err(|error| format!("read Windows child exit code: {error}"))?,
            )
        };
        drop(process); // closes the private Job: final descendant-kill fence.
        let stdout = stdout_reader
            .join()
            .map_err(|_| "Windows stdout drain thread panicked")?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| "Windows stderr drain thread panicked")?;
        let truncated = truncated || stdout.truncated || stderr.truncated;
        let error = if timed_out {
            Some("broker execution timed out; Windows Job process tree killed".into())
        } else if cancelled {
            Some("broker execution cancelled; Windows Job process tree killed".into())
        } else if truncated {
            Some("broker execution output limit reached; Windows Job process tree killed".into())
        } else {
            None
        };
        Ok(BrokerResponseV2 {
            request_id: request.request_id.clone(),
            ok: exit_code == Some(0) && error.is_none(),
            exit_code,
            stdout: String::from_utf8_lossy(&stdout.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&stderr.bytes).into_owned(),
            error,
            timed_out,
            cancelled,
            truncated,
            duration_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
}

struct StagedWindowsExecutable {
    path: PathBuf,
    // Holding this open keeps the exact staged file identity stable through the
    // second hash check and CreateProcessW. The private installer-owned parent
    // ACL prevents replacement through the pathname used by CreateProcessW.
    retained: File,
}

fn stage_pinned_executable(
    request: &BrokerRequestV2,
    staging_dir: &Path,
) -> Result<StagedWindowsExecutable, String> {
    let facts = &request.facts;
    let source = Path::new(&facts.executable.canonical_path);
    if !source.is_absolute() {
        return Err("Windows source executable must be absolute".into());
    }
    let source = std::fs::canonicalize(source)
        .map_err(|error| format!("canonicalize Windows source executable: {error}"))?;
    let before = std::fs::symlink_metadata(&source).map_err(|error| error.to_string())?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() != facts.executable.image_len
        || before.len() > MAX_STAGE_BYTES
    {
        return Err("Windows source executable type or length changed".into());
    }
    let path = staging_dir.join(format!("exec-{}.exe", uuid::Uuid::new_v4().simple()));
    let mut source_file = File::open(&source).map_err(|error| error.to_string())?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|error| format!("create Windows private stage: {error}"))?;
    let copied = (|| -> Result<(), String> {
        let mut hash = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = source_file
                .read(&mut buffer)
                .map_err(|error| error.to_string())?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(read).unwrap())
                .ok_or("Windows staged executable length overflow")?;
            if total > MAX_STAGE_BYTES {
                return Err("Windows source executable exceeds staging bound".into());
            }
            hash.update(&buffer[..read]);
            output
                .write_all(&buffer[..read])
                .map_err(|error| error.to_string())?;
        }
        output.sync_all().map_err(|error| error.to_string())?;
        let after = std::fs::symlink_metadata(&source).map_err(|error| error.to_string())?;
        if !after.file_type().is_file()
            || after.file_type().is_symlink()
            || after.len() != before.len()
            || total != facts.executable.image_len
            || hex::encode(hash.finalize()) != facts.executable.image_sha256
        {
            return Err("Windows pinned source executable identity/hash mismatch".into());
        }
        Ok(())
    })();
    drop(output);
    drop(source_file);
    if let Err(error) = copied {
        let _ = std::fs::remove_file(&path);
        return Err(error);
    }
    let retained = File::open(&path).map_err(|error| {
        let _ = std::fs::remove_file(&path);
        format!("open retained Windows stage: {error}")
    })?;
    Ok(StagedWindowsExecutable { path, retained })
}

fn recheck_retained_stage(
    staged: &StagedWindowsExecutable,
    expected_hash: &str,
    expected_len: u64,
) -> Result<(), String> {
    let metadata = staged
        .retained
        .metadata()
        .map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() != expected_len || expected_len > MAX_STAGE_BYTES {
        return Err("retained Windows stage type or length changed".into());
    }
    let mut file = staged
        .retained
        .try_clone()
        .map_err(|error| error.to_string())?;
    let mut hash = Sha256::new();
    let mut total = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        total += u64::try_from(read).unwrap();
        if total > MAX_STAGE_BYTES {
            return Err("retained Windows stage exceeds size bound".into());
        }
        hash.update(&buffer[..read]);
    }
    if total != expected_len || hex::encode(hash.finalize()) != expected_hash {
        return Err("retained Windows stage hash mismatch".into());
    }
    Ok(())
}

fn reject_shell(argv0: &str) -> Result<(), String> {
    let base = argv0.rsplit(['\\', '/']).next().unwrap_or(argv0);
    let base = base.strip_suffix(".exe").unwrap_or(base);
    if ["cmd", "powershell", "pwsh", "sh", "bash"]
        .iter()
        .any(|shell| base.eq_ignore_ascii_case(shell))
    {
        return Err("Windows broker runner rejects shell execution".into());
    }
    Ok(())
}

struct CapturedPipe {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain_pipe_bounded(mut pipe: File, maximum: usize, exceeded: &AtomicBool) -> CapturedPipe {
    let mut bytes = Vec::with_capacity(maximum.min(8192));
    let mut buffer = [0_u8; 8192];
    let mut truncated = false;
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let room = maximum.saturating_sub(bytes.len());
                let kept = room.min(read);
                bytes.extend_from_slice(&buffer[..kept]);
                if kept != read {
                    truncated = true;
                    exceeded.store(true, Ordering::Release);
                    break;
                }
            }
            Err(_) => {
                truncated = true;
                exceeded.store(true, Ordering::Release);
                break;
            }
        }
    }
    CapturedPipe { bytes, truncated }
}

fn response_error(request_id: &str, error: String) -> BrokerResponseV2 {
    BrokerResponseV2 {
        request_id: request_id.into(),
        ok: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        error: Some(error),
        timed_out: false,
        cancelled: false,
        truncated: false,
        duration_ms: 0,
    }
}

fn cancelled_before_launch_response(request_id: &str) -> BrokerResponseV2 {
    BrokerResponseV2 {
        request_id: request_id.into(),
        ok: false,
        exit_code: None,
        stdout: String::new(),
        stderr: String::new(),
        error: Some("broker execution cancelled before Windows Job launch".into()),
        timed_out: false,
        cancelled: true,
        truncated: false,
        duration_ms: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_broker_client::{ExecutablePinV2, OperationFactsV2};

    fn long_running_ping_request(nonce: &str) -> Option<BrokerRequestV2> {
        let system_root = std::env::var_os("SystemRoot")?;
        let executable = PathBuf::from(system_root).join("System32").join("PING.EXE");
        let bytes = std::fs::read(&executable).ok()?;
        let metadata = std::fs::metadata(&executable).ok()?;
        Some(BrokerRequestV2 {
            protocol_version: 2,
            request_id: "windows-job-cancel-test".into(),
            operation_id: "windows-job-cancel-test".into(),
            nonce: nonce.into(),
            issued_at_unix: 1,
            expires_at_unix: i64::MAX,
            facts: OperationFactsV2 {
                operation: "windows-job-cancel-test".into(),
                remote_payload_sha256: "a".repeat(64),
                principal_id: "test".into(),
                tenant_id: "test".into(),
                principal_credential_generation: 1,
                timeout_ms: 30_000,
                max_output_bytes: 4 * 1024,
                device_id: "test".into(),
                workspace_id: "test".into(),
                // `ping -n 20` is a real Windows child which remains alive
                // long enough to prove that the Job cancellation signal
                // reaches a running contained process, not merely a mock.
                argv: vec![
                    executable.display().to_string(),
                    "-n".into(),
                    "20".into(),
                    "127.0.0.1".into(),
                ],
                canonical_cwd: None,
                sanitized_env: BTreeMap::new(),
                executable: ExecutablePinV2 {
                    canonical_path: executable.display().to_string(),
                    image_sha256: hex::encode(Sha256::digest(bytes)),
                    image_len: metadata.len(),
                },
            },
            capability: None,
            mac: "test".into(),
        })
    }

    fn wait_until_cancelable(runner: &WindowsJobRunner, request: &BrokerRequestV2) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if runner.cancel(&request.request_id, &request.nonce) {
                return;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        panic!("real Windows Job did not become cancelable before deadline");
    }

    #[test]
    fn explicit_cancel_terminates_a_real_windows_job() {
        let Some(request) = long_running_ping_request("explicit-cancel") else {
            // Windows Server Core images without ping.exe cannot provide this
            // opt-in process receipt. Production behavior stays fail-closed.
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let runner = WindowsJobRunner::new(dir.path()).unwrap();
        let executing = runner.clone();
        let request_for_thread = request.clone();
        let task = std::thread::spawn(move || executing.run(&request_for_thread));
        wait_until_cancelable(&runner, &request);
        let response = task.join().unwrap();
        assert!(response.cancelled, "{response:?}");
        assert!(!response.ok, "{response:?}");
    }

    #[test]
    fn cancel_before_resume_never_starts_the_contained_child() {
        let Some(request) = long_running_ping_request("cancel-before-resume") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let runner = WindowsJobRunner::new(dir.path()).unwrap();
        let gate = TestBeforeResumeGate {
            reached: Arc::new(std::sync::Barrier::new(2)),
            release: Arc::new(std::sync::Barrier::new(2)),
        };
        runner.set_before_resume_gate(gate.clone());
        let executing = runner.clone();
        let request_for_thread = request.clone();
        let task = std::thread::spawn(move || executing.run(&request_for_thread));
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if runner.active.lock().is_ok_and(|active| !active.is_empty()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(runner.active.lock().is_ok_and(|active| !active.is_empty()));
        gate.reached.wait();
        assert!(runner.cancel(&request.request_id, &request.nonce));
        gate.release.wait();
        let response = task.join().unwrap();
        assert!(response.cancelled, "{response:?}");
        assert_eq!(
            response.error.as_deref(),
            Some("broker execution cancelled before Windows Job launch")
        );
        assert!(runner.active.lock().unwrap().is_empty());
    }

    #[test]
    fn shutdown_fence_terminates_a_real_windows_job() {
        let Some(request) = long_running_ping_request("shutdown-cancel") else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let runner = WindowsJobRunner::new(dir.path()).unwrap();
        let executing = runner.clone();
        let request_for_thread = request.clone();
        let task = std::thread::spawn(move || executing.run(&request_for_thread));
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if runner.active.lock().is_ok_and(|active| !active.is_empty()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            runner.active.lock().is_ok_and(|active| !active.is_empty()),
            "real Windows Job did not register before stop"
        );
        let cancelled = runner.cancel_all();
        assert_eq!(
            cancelled, 1,
            "real Windows Job did not register before stop"
        );
        let response = task.join().unwrap();
        assert!(response.cancelled, "{response:?}");
        assert!(!response.ok, "{response:?}");
    }
}
