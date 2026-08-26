//! Rejected layout bindings (#148). Kept in its own binary so a refused
//! override never installs the process-wide `OnceLock` the other test needs.

use ownmesh_config::{install_path_overrides, path_overrides, PathOverrides};
use std::path::PathBuf;

#[test]
fn relative_and_empty_overrides_are_refused_without_installing() {
    let relative = PathOverrides {
        state_dir: Some(PathBuf::from("relative/state")),
        ..PathOverrides::default()
    };
    let error = install_path_overrides(&relative).unwrap_err().to_string();
    assert!(error.contains("--state-dir"), "{error}");
    assert!(error.contains("absolute"), "{error}");

    let empty_value = PathOverrides {
        runtime_dir: Some(PathBuf::new()),
        ..PathOverrides::default()
    };
    let error = install_path_overrides(&empty_value)
        .unwrap_err()
        .to_string();
    assert!(error.contains("--runtime-dir"), "{error}");

    // A refused binding must leave the process unbound, so the daemon still
    // resolves its layout from the environment/platform default rather than
    // from a half-applied override.
    assert_eq!(path_overrides(), None);

    // No arguments at all is a valid, empty binding.
    let none = PathOverrides::default();
    assert!(none.is_empty());
    install_path_overrides(&none).expect("an empty binding installs");
}
