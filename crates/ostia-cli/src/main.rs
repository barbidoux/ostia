//! The `ostia` command line. Shape and exit codes: `docs/contracts/cli.md`.
//!
//! Built so far: `policy verify` (WP-1.2). `scan` and `version` exit with code 3 ("not implemented") until
//! WP-1.10.

mod flags;
mod policy_verify;

use std::ffi::OsString;
use std::process::ExitCode;

#[cfg(all(feature = "dev", not(debug_assertions)))]
compile_error!("the `dev` feature adds development flags and is refused in release builds");

/// Exit code 2: the command line is not valid.
const USAGE_ERROR: u8 = 2;
/// Exit code 3: the subcommand exists in the contract but is not built yet.
const NOT_IMPLEMENTED: u8 = 3;
/// Exit code 4: an input was refused.
const INPUT_REFUSED: u8 = 4;

const USAGE: &str = "usage: ostia scan --image <path> --report <out.json> --policy <file> --policy-sig <file> --trust <key> [options]
       ostia policy verify --policy <file> --policy-sig <file> --trust <key>
       ostia version";

/// Print a one-line reason, then the usage text, and exit 2.
fn usage_error(reason: &str) -> ExitCode {
    eprintln!("ostia: {reason}");
    eprintln!("{USAGE}");
    ExitCode::from(USAGE_ERROR)
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let words: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("")).collect();
    match words.as_slice() {
        ["policy", "verify", ..] => policy_verify::run(args.get(2..).unwrap_or_default()),
        [name @ ("scan" | "version"), ..] => {
            eprintln!("ostia: not implemented: {name}");
            ExitCode::from(NOT_IMPLEMENTED)
        }
        [] => usage_error("missing subcommand"),
        [..] => {
            let unknown = args
                .first()
                .map(|a| a.to_string_lossy())
                .unwrap_or_default();
            usage_error(&format!("unknown subcommand: {unknown}"))
        }
    }
}
