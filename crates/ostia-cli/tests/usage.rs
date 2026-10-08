//! Command-line usage of the `ostia` binary (docs/contracts/cli.md, "Exit codes").

use std::process::{Command, Output};

use ostia_traceability::req;

fn ostia(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ostia"))
        .args(args)
        .output()
        .expect("the ostia binary runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[req("TOOLING")]
#[test]
fn no_subcommand_is_a_usage_error() {
    let output = ostia(&[]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
}

#[req("TOOLING")]
#[test]
fn unknown_subcommand_is_a_usage_error() {
    let output = ostia(&["unpack"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(output.stdout, b"");
}

#[req("TOOLING")]
#[test]
fn usage_error_reason_is_one_line_prefixed_with_ostia() {
    let message = stderr(&ostia(&["unpack"]));
    assert!(message.starts_with("ostia: "), "stderr: {message:?}");
    assert!(message.contains("unpack"), "stderr: {message:?}");
}

#[req("TOOLING")]
#[test]
fn every_contract_subcommand_is_recognised() {
    // Whatever the subcommand does once it is built (a missing flag is a usage error too), it is never
    // reported as unknown.
    for args in [&["scan"][..], &["policy", "verify"][..], &["version"][..]] {
        let message = stderr(&ostia(args));
        assert!(
            !message.contains("unknown subcommand"),
            "ostia {args:?}: {message:?}"
        );
    }
}
