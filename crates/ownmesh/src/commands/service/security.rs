//! Path canonicalization, quoting, and injection rejection for user services.

use std::fs;
use std::path::{Path, PathBuf};

/// A path that has passed service-install security checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPath {
    pub canonical: PathBuf,
    pub original: PathBuf,
}

/// Characters that must never appear in service descriptor path fields.
const FORBIDDEN_CHARS: &[char] = &[
    '\n', '\r', '\0', '"', '`', '|', ';', '&', '$', '<', '>', '\t',
];

/// Reject strings that look like shell/unit injection payloads.
pub fn reject_injection(value: &str) -> Result<(), String> {
    if value.chars().any(|c| FORBIDDEN_CHARS.contains(&c)) {
        return Err("path/value contains characters forbidden in service descriptors".into());
    }
    // Disallow unbalanced percent sequences that systemd would expand unexpectedly
    // beyond our intentional `%%` escaping path — bare `%` followed by a letter.
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 1 < bytes.len() && bytes[i + 1] == b'%' {
                i += 2;
                continue;
            }
            // Allow only if we will escape later; still reject control-like forms.
            if i + 1 < bytes.len() && bytes[i + 1].is_ascii_alphabetic() {
                return Err(
                    "path contains systemd-style percent specifier; refused (fail-closed)".into(),
                );
            }
        }
        i += 1;
    }
    Ok(())
}

/// Validate a path for use in service descriptors.
///
/// - Rejects empty paths and injection characters
/// - Canonicalizes when the path exists
/// - Rejects symlinks at the leaf (and refuses non-canonical symlink targets)
/// - On Unix, rejects world-writable paths and group/other-writable executables
pub fn validate_service_path(
    path: &Path,
    label: &str,
    must_exist: bool,
) -> Result<ValidatedPath, String> {
    let raw = path.as_os_str();
    if raw.is_empty() {
        return Err(format!("{label} path is empty"));
    }
    let display = path.display().to_string();
    reject_injection(&display)?;

    if must_exist && !path.exists() {
        // Create directories for config/state/runtime when missing is OK for parents,
        // but validate_service_path is called after ensure_layout for those.
        return Err(format!("{label} path does not exist: {display}"));
    }

    if path.exists() {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("stat {label} {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{label} path is a symlink ({}); refused (fail-closed)",
                path.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // World-writable anything is refused.
            if meta.mode() & 0o002 != 0 {
                return Err(format!(
                    "{label} path is world-writable ({}); refused",
                    path.display()
                ));
            }
            // Executable should not be group/other writable.
            if meta.is_file() && meta.mode() & 0o022 != 0 {
                return Err(format!(
                    "{label} file is group/other-writable ({}); refused",
                    path.display()
                ));
            }
        }
    }

    let canonical = if path.exists() {
        fs::canonicalize(path).map_err(|e| format!("canonicalize {label}: {e}"))?
    } else {
        path.to_path_buf()
    };
    let canon_display = canonical.display().to_string();
    reject_injection(&canon_display)?;

    // Re-check symlink after canonicalize parent components by ensuring the
    // canonical path's leaf is still not a symlink.
    if canonical.exists() {
        let meta =
            fs::symlink_metadata(&canonical).map_err(|e| format!("stat canonical {label}: {e}"))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "{label} canonical path is a symlink; refused (fail-closed)"
            ));
        }
    }

    Ok(ValidatedPath {
        canonical,
        original: path.to_path_buf(),
    })
}

/// Canonicalize and validate an `ownmeshd` executable path.
pub fn canonicalize_executable(path: &Path) -> Result<ValidatedPath, String> {
    let validated = validate_service_path(path, "executable", true)?;
    let meta = fs::metadata(&validated.canonical).map_err(|e| format!("stat executable: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "executable is not a regular file: {}",
            validated.canonical.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o111 == 0 {
            return Err(format!(
                "executable is not executable: {}",
                validated.canonical.display()
            ));
        }
    }
    Ok(validated)
}

/// Quote a Windows command-line argument per Microsoft CommandLineToArgvW rules
/// (wrap in double quotes; double embedded quotes; escape trailing backslashes
/// before the closing quote).
///
/// Reference: https://learn.microsoft.com/en-us/windows/win32/api/shellapi/nf-shellapi-commandlinetoargvw
#[must_use]
pub fn quote_windows_arg(arg: &str) -> String {
    if arg.is_empty() {
        return "\"\"".to_string();
    }
    let needs_quotes = arg.chars().any(|c| c == ' ' || c == '\t' || c == '"');
    if !needs_quotes {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                // Escape each pending backslash, then escape the quote.
                for _ in 0..(backslashes * 2) {
                    out.push('\\');
                }
                backslashes = 0;
                out.push('\\');
                out.push('"');
            }
            c => {
                for _ in 0..backslashes {
                    out.push('\\');
                }
                backslashes = 0;
                out.push(c);
            }
        }
    }
    // Trailing backslashes before closing quote must be doubled.
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
}

/// Escape a value for systemd unit files (backslash, quotes, percent).
///
/// Reference: https://www.freedesktop.org/software/systemd/man/latest/systemd.syntax.html
#[must_use]
pub fn systemd_escape_arg(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
}

/// Escape text for use inside an XML/plist text node.
#[must_use]
pub fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_injection_characters() {
        for s in ["a\nb", "a;b", "a|b", "a&b", "a`b", "a$b", "a\"b", "%i"] {
            assert!(reject_injection(s).is_err(), "{s}");
        }
        assert!(reject_injection(r"C:\Users\me\ownmeshd.exe").is_ok());
        assert!(reject_injection("/home/me/bin/ownmeshd").is_ok());
    }

    #[test]
    fn windows_quoting_spaces_and_quotes() {
        assert_eq!(quote_windows_arg("simple"), "simple");
        assert_eq!(quote_windows_arg("a b"), "\"a b\"");
        assert_eq!(quote_windows_arg("a\"b"), "\"a\\\"b\"");
        // No spaces → no quotes (even with trailing backslash).
        assert_eq!(quote_windows_arg(r"C:\path\"), r"C:\path\");
        // Spaces + trailing backslash: double trailing backslashes before close quote.
        assert_eq!(quote_windows_arg(r"C:\path with\"), "\"C:\\path with\\\\\"");
    }

    #[test]
    fn systemd_and_xml_escape() {
        assert_eq!(systemd_escape_arg(r#"a"b%c"#), r#"a\"b%%c"#);
        assert_eq!(xml_escape(r#"a<b>&"c"#), "a&lt;b&gt;&amp;&quot;c");
    }

    #[test]
    fn rejects_symlink_executable() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("real");
        fs::write(&target, b"x").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&target).unwrap().permissions();
            p.set_mode(0o755);
            fs::set_permissions(&target, p).unwrap();
            let link = dir.path().join("link");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let err = canonicalize_executable(&link).unwrap_err();
            assert!(err.contains("symlink"), "{err}");
        }
        #[cfg(windows)]
        {
            // On Windows without symlink privilege, just validate regular file.
            let _ = canonicalize_executable(&target);
        }
    }

    #[test]
    fn accepts_regular_file() {
        let dir = tempdir().unwrap();
        let exe = dir.path().join(if cfg!(windows) {
            "ownmeshd.exe"
        } else {
            "ownmeshd"
        });
        fs::write(&exe, b"binary").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut p = fs::metadata(&exe).unwrap().permissions();
            p.set_mode(0o755);
            fs::set_permissions(&exe, p).unwrap();
        }
        let v = canonicalize_executable(&exe).unwrap();
        assert!(v.canonical.is_absolute() || cfg!(windows));
    }
}
