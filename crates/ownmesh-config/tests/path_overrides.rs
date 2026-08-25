//! Layout-binding precedence for typed service-descriptor arguments (#148).
//!
//! Overrides are installed once per process, so this lives in its own
//! integration-test binary: a `OnceLock` set by one test would otherwise decide
//! the layout for every other test in the same process.

use ownmesh_config::{install_path_overrides, path_overrides, OwnMeshPaths, PathOverrides};
use std::path::PathBuf;

fn absolute(name: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!(r"C:\ownmesh-test\{name}"))
    } else {
        PathBuf::from(format!("/ownmesh-test/{name}"))
    }
}

#[test]
fn typed_arguments_outrank_the_environment_and_the_platform_default() {
    // A Scheduled Task action carries no environment, so the descriptor binds
    // the layout through arguments. A stray OWNMESH_* variable in the launched
    // context must not silently split one installation into two state trees.
    // SAFETY-equivalent note: this is the only test in this binary, and it sets
    // the variables before installing overrides, so no other test observes them.
    std::env::set_var("OWNMESH_CONFIG_DIR", absolute("env-config"));
    std::env::set_var("OWNMESH_STATE_DIR", absolute("env-state"));
    std::env::set_var("OWNMESH_RUNTIME_DIR", absolute("env-runtime"));

    let overrides = PathOverrides {
        config_dir: Some(absolute("arg-config")),
        state_dir: Some(absolute("arg-state")),
        runtime_dir: Some(absolute("arg-runtime")),
    };
    assert!(!overrides.is_empty());
    install_path_overrides(&overrides).expect("absolute overrides install");
    assert_eq!(path_overrides(), Some(&overrides));

    let paths = OwnMeshPaths::discover().expect("discover with overrides");
    assert_eq!(paths.config_dir, absolute("arg-config"));
    assert_eq!(paths.state_dir, absolute("arg-state"));
    assert_eq!(paths.runtime_dir, absolute("arg-runtime"));

    // Installing the same binding again is idempotent — a service manager may
    // relaunch the same action — while a conflicting one is refused rather than
    // silently ignored.
    install_path_overrides(&overrides).expect("identical re-install is idempotent");
    let conflicting = PathOverrides {
        config_dir: Some(absolute("other-config")),
        ..PathOverrides::default()
    };
    assert!(
        install_path_overrides(&conflicting).is_err(),
        "a conflicting layout binding must be refused"
    );

    // The unbound directory still falls through to the environment.
    std::env::set_var("OWNMESH_CACHE_DIR", absolute("env-cache"));
    let paths = OwnMeshPaths::discover().expect("discover after cache override");
    assert_eq!(paths.cache_dir, absolute("env-cache"));

    for key in [
        "OWNMESH_CONFIG_DIR",
        "OWNMESH_STATE_DIR",
        "OWNMESH_RUNTIME_DIR",
        "OWNMESH_CACHE_DIR",
    ] {
        std::env::remove_var(key);
    }
    // With the environment gone the typed binding still holds.
    let paths = OwnMeshPaths::discover().expect("discover without environment");
    assert_eq!(paths.config_dir, absolute("arg-config"));
    assert_eq!(paths.state_dir, absolute("arg-state"));
    assert_eq!(paths.runtime_dir, absolute("arg-runtime"));
}
