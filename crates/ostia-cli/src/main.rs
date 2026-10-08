//! The `ostia` command line. Shape and exit codes: `docs/contracts/cli.md`.
//!
//! WP-0.12 lands the contract only: every subcommand exits with code 3 ("not implemented") until the
//! work package that builds it (policy verify: WP-1.2; scan and version: WP-1.10).

use std::process::ExitCode;

#[cfg(all(feature = "dev", not(debug_assertions)))]
compile_error!("the `dev` feature adds development flags and is refused in release builds");

/// Exit code 2: the command line is not valid.
const USAGE_ERROR: u8 = 2;
/// Exit code 3: the subcommand exists in the contract but is not built yet.
const NOT_IMPLEMENTED: u8 = 3;

const USAGE: &str = "usage: ostia scan --image <path> --report <out.json> --policy <file> --policy-sig <file> --trust <key> [options]
       ostia policy verify --policy <file> --policy-sig <file> --trust <key>
       ostia version";

/// The subcommand named by the arguments, if the contract has it.
fn subcommand(args: &[String]) -> Option<&'static str> {
    match args {
        [first, ..] if first == "scan" => Some("scan"),
        [first, second, ..] if first == "policy" && second == "verify" => Some("policy verify"),
        [first, ..] if first == "version" => Some("version"),
        _ => None,
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(name) = subcommand(&args) {
        eprintln!("ostia: not implemented: {name}");
        ExitCode::from(NOT_IMPLEMENTED)
    } else {
        match args.first() {
            Some(unknown) => eprintln!("ostia: unknown subcommand: {unknown}"),
            None => eprintln!("ostia: missing subcommand"),
        }
        eprintln!("{USAGE}");
        ExitCode::from(USAGE_ERROR)
    }
}
