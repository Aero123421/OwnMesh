//! Deterministic argv0-dispatch fixture for executable-binding security tests.

use std::path::Path;

fn main() {
    let mut argv = std::env::args_os();
    let argv0 = argv.next().unwrap_or_default();
    let basename = Path::new(&argv0)
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default();
    let args: Vec<String> = argv.map(|value| value.to_string_lossy().into_owned()).collect();

    if basename.eq_ignore_ascii_case("echo") || basename.eq_ignore_ascii_case("echo.exe") {
        println!("{}", args.join(" "));
        return;
    }
    match args.first().map(String::as_str) {
        Some("argv0") => println!("{}", argv0.to_string_lossy()),
        Some("shell") => {
            let canary = args.get(1).expect("shell selector requires canary path");
            std::fs::write(canary, b"unapproved multicall branch ran")
                .expect("write multicall canary");
        }
        _ => std::process::exit(2),
    }
}
