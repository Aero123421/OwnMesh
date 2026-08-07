//! Provider registry and builtin wiring.

use crate::docker::DockerLogProvider;
use crate::file::FileLogProvider;
use crate::journald::JournaldLogProvider;
use crate::process::ProcessLogProvider;
use crate::windows_event::WindowsEventLogProvider;
use crate::{LogError, LogProvider, LogResult};
use std::path::PathBuf;

/// Registry of providers.
#[derive(Default)]
pub struct LogRegistry {
    providers: Vec<Box<dyn LogProvider>>,
}

impl LogRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self {
            providers: Vec::new(),
        }
    }

    pub fn register(&mut self, provider: Box<dyn LogProvider>) {
        self.providers.push(provider);
    }

    /// Returns the provider registered under `id`.
    ///
    /// # Errors
    ///
    /// Returns [`LogError::ProviderNotFound`] when no provider has that id.
    pub fn get(&self, id: &str) -> LogResult<&dyn LogProvider> {
        self.providers
            .iter()
            .find(|p| p.id() == id)
            .map(std::convert::AsRef::as_ref)
            .ok_or_else(|| LogError::ProviderNotFound(id.to_string()))
    }

    #[must_use]
    pub fn list_ids(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.id().to_string()).collect()
    }
}

/// Configuration for [`register_builtin_providers`].
#[derive(Debug, Clone)]
pub struct BuiltinProviderConfig {
    pub file_id: String,
    pub file_path: PathBuf,
    pub windows_channel: String,
    pub journald_unit: Option<String>,
    pub docker_container: Option<String>,
    pub process_id: String,
    pub process_log_path: Option<PathBuf>,
}

impl Default for BuiltinProviderConfig {
    fn default() -> Self {
        Self {
            file_id: "audit".into(),
            file_path: PathBuf::from("audit.log"),
            windows_channel: "Application".into(),
            journald_unit: None,
            docker_container: None,
            process_id: "process".into(),
            process_log_path: None,
        }
    }
}

/// Register file + OS + docker/process providers into `reg`.
///
/// - `windows_event` is registered on Windows only.
/// - `journald` is always registered (native on Linux, Unavailable stub elsewhere).
/// - `docker` / `process` always registered; query may return Unavailable.
pub fn register_builtin_providers(reg: &mut LogRegistry, cfg: &BuiltinProviderConfig) {
    reg.register(Box::new(FileLogProvider::new(
        cfg.file_id.clone(),
        cfg.file_path.clone(),
    )));

    #[cfg(windows)]
    {
        reg.register(Box::new(WindowsEventLogProvider::new(
            "windows_event",
            cfg.windows_channel.clone(),
        )));
    }

    reg.register(Box::new(JournaldLogProvider::new(
        "journald",
        cfg.journald_unit.clone(),
    )));

    reg.register(Box::new(DockerLogProvider::new(
        "docker",
        cfg.docker_container.clone(),
    )));

    if let Some(path) = &cfg.process_log_path {
        reg.register(Box::new(ProcessLogProvider::new(
            cfg.process_id.clone(),
            path.clone(),
        )));
    } else {
        // Still wire the id so list/get stays stable; empty path → exhausted pages.
        reg.register(Box::new(ProcessLogProvider::new(
            cfg.process_id.clone(),
            PathBuf::from("process.log"),
        )));
    }
}
