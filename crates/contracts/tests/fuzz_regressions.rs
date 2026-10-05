//! Inputs kept in `fuzz/regressions/` (crashes and hangs the fuzzer found, plus seeds of known hard
//! cases) replay through the fuzz targets' own exercise (`fuzz/src/lib.rs`, both caps and every property
//! it checks) on every `just test`, on stable, without the fuzzer (NFR-06). Each input is a `.hex` file:
//! hex digits and whitespace, `#` starts a comment line, so a diff shows the bytes. The list below is
//! literal: a new input fails this test until it is added with its expected outcome. The planted inputs
//! of the harness self-test (`fuzz/regressions/selftest/`) only trip the self-test target.

#[path = "../../../fuzz/src/lib.rs"]
mod harness;

use std::fs;
use std::path::PathBuf;

use ostia_contracts::{DEFAULT_MAX_FRAME, decode_frame, decode_response};
use ostia_traceability::req;

fn unhex(name: &str, text: &str) -> Vec<u8> {
    let digits: Vec<u8> = text
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .flat_map(str::bytes)
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    assert!(
        digits.len().is_multiple_of(2),
        "{name}: odd number of hex digits"
    );
    digits
        .chunks(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap_or_else(|_| panic!("{name}: bad hex {pair:?}"))
        })
        .collect()
}

fn regressions() -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/regressions");
    let mut inputs: Vec<(String, Vec<u8>)> = fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "hex"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let bytes = unhex(&name, &fs::read_to_string(&path).unwrap());
            (name, bytes)
        })
        .collect();
    inputs.sort();
    inputs
}

/// The outcome of decoding the input as a framed response: `None` when accepted, else the error kind.
fn outcome(data: &[u8]) -> Option<&'static str> {
    match decode_frame(data, DEFAULT_MAX_FRAME) {
        Ok(body) => decode_response(body).err().map(|error| error.kind()),
        Err(error) => Some(error.kind()),
    }
}

#[req("NFR-06", "CTR-02")]
#[test]
fn every_regression_input_replays_through_the_fuzz_exercise() {
    let inputs = regressions();
    let names: Vec<&str> = inputs.iter().map(|(name, _)| name.as_str()).collect();
    assert_eq!(
        names,
        [
            "group_storm.hex",
            "oversized_header.hex",
            "varint_overflow.hex"
        ]
    );
    for (name, data) in &inputs {
        harness::exercise(data);
        let expected = match name.as_str() {
            "oversized_header.hex" => Some("oversized"),
            "varint_overflow.hex" => Some("malformed"),
            _ => None,
        };
        assert_eq!(outcome(data), expected, "{name}");
    }
}
