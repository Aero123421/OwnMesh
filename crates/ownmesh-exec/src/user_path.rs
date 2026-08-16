//! Explicit user execution PATH for daemons that inherit a minimal service PATH.
//!
//! OwnMesh never sources interactive shell rc files. Common per-user tool
//! directories are discovered from well-known locations, optional
//! `OWNMESH_EXEC_PATH`, and optional config extras.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Environment variable listing extra execution directories (OS path separator).
pub const EXEC_PATH_ENV: &str = "OWNMESH_EXEC_PATH";

/// Directories that should be searched for user-installed CLIs.
#[must_use]
pub fn discover_user_exec_dirs() -> Vec<PathBuf> {
    merge_exec_dirs(&[], &configured_exec_dirs_from_env())
}

/// Merge configured extras with discovered user tool dirs, extras first.
#[must_use]
pub fn merge_exec_dirs(configured: &[PathBuf], env_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for path in env_dirs
        .iter()
        .chain(configured)
        .chain(discovered_user_exec_dirs().iter())
    {
        let Some(canonical) = normalize_dir(path) else {
            continue;
        };
        if !canonical.is_dir() {
            continue;
        }
        if seen.insert(canonical.clone()) {
            out.push(canonical);
        }
    }
    out
}

/// Directories from `OWNMESH_EXEC_PATH`.
#[must_use]
pub fn configured_exec_dirs_from_env() -> Vec<PathBuf> {
    let Some(raw) = std::env::var_os(EXEC_PATH_ENV) else {
        return Vec::new();
    };
    std::env::split_paths(&raw)
        .filter(|path| !path.as_os_str().is_empty())
        .collect()
}

/// Prepend user execution directories onto `PATH`.
pub fn apply_user_execution_path(configured: &[PathBuf]) {
    let extras = merge_exec_dirs(configured, &configured_exec_dirs_from_env());
    if extras.is_empty() {
        return;
    }
    let mut ordered = extras;
    let mut seen: HashSet<PathBuf> = ordered.iter().cloned().collect();
    if let Some(current) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&current) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            if seen.insert(dir.clone()) {
                ordered.push(dir);
            }
        }
    }
    if let Ok(joined) = std::env::join_paths(ordered.iter()) {
        if !joined.is_empty() {
            std::env::set_var("PATH", joined);
        }
    }
}

/// Snapshot used by doctor / diagnose (paths only).
#[must_use]
pub fn execution_path_report(configured: &[PathBuf]) -> ExecutionPathReport {
    let discovered = discovered_user_exec_dirs();
    let merged = merge_exec_dirs(configured, &configured_exec_dirs_from_env());
    let process_path = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect())
        .unwrap_or_default();
    ExecutionPathReport {
        process_path,
        discovered,
        configured: configured.to_vec(),
        env_dirs: configured_exec_dirs_from_env(),
        effective_prefixes: merged,
    }
}

/// Doctor-facing PATH contract.
#[derive(Debug, Clone, Default)]
pub struct ExecutionPathReport {
    pub process_path: Vec<PathBuf>,
    pub discovered: Vec<PathBuf>,
    pub configured: Vec<PathBuf>,
    pub env_dirs: Vec<PathBuf>,
    pub effective_prefixes: Vec<PathBuf>,
}

fn discovered_user_exec_dirs() -> Vec<PathBuf> {
    let Some(home) = home_dir() else {
        return Vec::new();
    };
    let mut dirs = vec![
        home.join(".local/bin"),
        home.join(".cargo/bin"),
        home.join(".nix-profile/bin"),
        PathBuf::from("/nix/var/nix/profiles/default/bin"),
        PathBuf::from("/opt/homebrew/bin"),
        PathBuf::from("/usr/local/bin"),
        home.join("bin"),
        home.join(".volta/bin"),
        home.join(".local/share/mise/shims"),
        home.join(".local/share/fnm/aliases/default/bin"),
    ];
    dirs.extend(nvm_active_bins(&home));
    dirs
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn nvm_active_bins(home: &Path) -> Vec<PathBuf> {
    let nvm = home.join(".nvm");
    let alias = nvm.join("alias/default");
    if let Ok(name) = std::fs::read_to_string(&alias) {
        let name = name.trim();
        if !name.is_empty() && !name.contains(['/', '\\', '\0']) {
            let candidate = nvm.join("versions/node").join(name).join("bin");
            if candidate.is_dir() {
                return vec![candidate];
            }
        }
    }
    newest_version_bin(nvm.join("versions/node"))
        .into_iter()
        .collect()
}

fn newest_version_bin(versions: PathBuf) -> Option<PathBuf> {
    let mut bins: Vec<PathBuf> = std::fs::read_dir(&versions)
        .ok()?
        .flatten()
        .map(|entry| entry.path().join("bin"))
        .filter(|path| path.is_dir())
        .collect();
    bins.sort();
    bins.pop()
}

fn normalize_dir(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        None
    } else {
        Some(path.to_path_buf())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn merge_prefers_configured_existing_dirs() {
        let dir = tempdir().unwrap();
        let extra = dir.path().join("extra");
        fs::create_dir_all(&extra).unwrap();
        let missing = dir.path().join("missing");
        let merged = merge_exec_dirs(&[extra.clone(), missing.clone()], &[]);
        assert_eq!(merged.first(), Some(&extra));
        assert!(!merged.contains(&missing));
    }

    #[test]
    fn discover_includes_local_bin_when_present() {
        let dir = tempdir().unwrap();
        let local = dir.path().join(".local/bin");
        fs::create_dir_all(&local).unwrap();
        let previous = std::env::var_os("HOME");
        std::env::set_var("HOME", dir.path());
        let found = discovered_user_exec_dirs();
        match previous {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        assert!(found.iter().any(|path| path == &local));
    }
}
