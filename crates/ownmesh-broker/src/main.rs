//! OwnMesh privileged broker entrypoint (chapter 0 argument-parsing skeleton).

use std::env;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

fn run(args: &[String]) -> Result<(), u8> {
    match args.first().map(String::as_str) {
        None | Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some("version") | Some("--version") | Some("-V") => {
            print_version();
            Ok(())
        }
        Some(other) => {
            eprintln!(
                "error: unknown command `{other}`\n\nRun `{name} --help` for usage.",
                name = env!("CARGO_PKG_NAME")
            );
            Err(2)
        }
    }
}

fn print_version() {
    println!(
        "{name} {version}",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION")
    );
}

fn print_help() {
    println!(
        "{name} {version}

OwnMesh privileged broker — networkless elevation helper.

Usage:
  {name} <command> [options]

Commands:
  help       Show this help
  version    Show version

Install/run/status commands arrive in later chapters. This process must not open
network listeners.
",
        name = env!("CARGO_PKG_NAME"),
        version = env!("CARGO_PKG_VERSION")
    );
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn help_succeeds() {
        assert!(run(&["help".to_owned()]).is_ok());
    }

    #[test]
    fn version_succeeds() {
        assert!(run(&["version".to_owned()]).is_ok());
    }

    #[test]
    fn unknown_command_fails() {
        assert_eq!(run(&["not-a-command".to_owned()]), Err(2));
    }
}
