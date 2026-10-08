//! `ostia policy verify --policy <file> --policy-sig <file> --trust <key>` (docs/contracts/cli.md).

use std::ffi::OsString;
use std::process::ExitCode;

use ostia_core_domain::policy::{KEY_BYTES, MAX_POLICY_BYTES, SIGNATURE_BYTES, load};
use serde_json::json;

use crate::flags::{Flags, read_capped};
use crate::{INPUT_REFUSED, usage_error};

const POLICY: &str = "--policy";
const SIGNATURE: &str = "--policy-sig";
const TRUST: &str = "--trust";

/// Verify a signed policy: exit 0 with `{"version", "sha256"}` on stdout, 4 when refused, 2 on a usage
/// error.
pub fn run(args: &[OsString]) -> ExitCode {
    match read_inputs(args) {
        Ok(inputs) => match load(&inputs.policy, &inputs.signature, &inputs.trust) {
            Ok(policy) => {
                let printed = json!({"version": policy.version, "sha256": hex(&policy.sha256)});
                println!("{printed}");
                ExitCode::SUCCESS
            }
            Err(refused) => {
                eprintln!("ostia: input refused: {refused}");
                ExitCode::from(INPUT_REFUSED)
            }
        },
        Err(reason) => usage_error(&reason),
    }
}

/// The bytes of the three files.
struct Inputs {
    policy: Vec<u8>,
    signature: Vec<u8>,
    trust: Vec<u8>,
}

/// The three files, each read with a cap one byte above what the contract allows.
fn read_inputs(args: &[OsString]) -> Result<Inputs, String> {
    let flags = Flags::parse(args, &[POLICY, SIGNATURE, TRUST])?;
    let read = |name: &'static str, cap: usize| -> Result<Vec<u8>, String> {
        let path = flags.required(name)?;
        read_capped(path, cap).map_err(|error| format!("cannot read {name}: {error}"))
    };
    Ok(Inputs {
        policy: read(POLICY, MAX_POLICY_BYTES)?,
        signature: read(SIGNATURE, SIGNATURE_BYTES)?,
        trust: read(TRUST, KEY_BYTES)?,
    })
}

/// Lower-case hexadecimal.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [DIGITS[usize::from(b >> 4)], DIGITS[usize::from(b & 0x0f)]])
        .map(char::from)
        .collect()
}
