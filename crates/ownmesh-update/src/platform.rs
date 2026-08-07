//! OS / architecture asset selection.

use crate::error::{UpdateError, UpdateResult};

/// Portable archive kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveKind {
    /// `.tar.gz` (macOS / Linux).
    TarGz,
    /// `.zip` (Windows).
    Zip,
}

/// Selected release asset for the running host (or an explicit override).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformAsset {
    /// Asset file name, e.g. `ownmesh-linux-x64.tar.gz`.
    pub asset_name: String,
    /// Archive format.
    pub kind: ArchiveKind,
    /// Target triple label used in diagnostics (`linux-x64`, …).
    pub target_label: String,
}

/// Required shipped binary basenames (no extension).
pub const REQUIRED_BINARIES: &[&str] = &[
    "ownmesh",
    "ownmesh-tui",
    "ownmeshd",
    "ownmesh-session-host",
    "ownmesh-broker",
];

/// Select the portable archive for the current process target.
///
/// # Errors
///
/// Returns [`UpdateError::UnsupportedPlatform`] when OS/arch is not published.
pub fn select_platform_asset() -> UpdateResult<PlatformAsset> {
    select_platform_asset_for(std::env::consts::OS, std::env::consts::ARCH)
}

/// Select the portable archive for an explicit OS/arch pair.
///
/// # Errors
///
/// Returns [`UpdateError::UnsupportedPlatform`] when OS/arch is not published.
pub fn select_platform_asset_for(os: &str, arch: &str) -> UpdateResult<PlatformAsset> {
    let arch_label = match arch {
        "x86_64" | "amd64" => "x64",
        "aarch64" | "arm64" => "arm64",
        other => {
            return Err(UpdateError::UnsupportedPlatform(format!(
                "unsupported CPU architecture '{other}'"
            )));
        }
    };

    match os {
        "windows" => {
            if arch_label != "x64" {
                return Err(UpdateError::UnsupportedPlatform(format!(
                    "Windows {arch_label} is not published; only windows-x64 is supported"
                )));
            }
            Ok(PlatformAsset {
                asset_name: "ownmesh-windows-x64.zip".into(),
                kind: ArchiveKind::Zip,
                target_label: "windows-x64".into(),
            })
        }
        "macos" => Ok(PlatformAsset {
            asset_name: format!("ownmesh-macos-{arch_label}.tar.gz"),
            kind: ArchiveKind::TarGz,
            target_label: format!("macos-{arch_label}"),
        }),
        "linux" => Ok(PlatformAsset {
            asset_name: format!("ownmesh-linux-{arch_label}.tar.gz"),
            kind: ArchiveKind::TarGz,
            target_label: format!("linux-{arch_label}"),
        }),
        other => Err(UpdateError::UnsupportedPlatform(format!(
            "unsupported operating system '{other}'"
        ))),
    }
}

/// Binary file name including platform extension.
#[must_use]
pub fn binary_file_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}

/// Binary file name for an explicit OS.
#[must_use]
pub fn binary_file_name_for(base: &str, os: &str) -> String {
    if os == "windows" {
        format!("{base}.exe")
    } else {
        base.to_owned()
    }
}
