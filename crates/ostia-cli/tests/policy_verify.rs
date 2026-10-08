//! `ostia policy verify` (docs/contracts/cli.md): exit 0 with exactly `{version, sha256}`; a refused policy
//! exits 4 with `ostia: input refused: <code>: <detail>` and nothing on stdout; a missing flag or an unreadable
//! file is a usage error (exit 2).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use ed25519_dalek::{Signer, SigningKey};
use ostia_traceability::req;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const POLICY: &str = r#"{
  "schema": "ostia.policy.v1",
  "version": "cli-1",
  "engines": {"fake-av": {"role": "detector", "trusted_alone": false}},
  "rules": {
    "R1": {"risky_types": ["pe"]},
    "R2": {"k": 2, "critical_severity": 4},
    "R6": {"double_extension": true, "extension_mismatch": true, "single_detection": true, "suspicious_hint": true}
  },
  "limits": {"max_depth": 8, "max_ratio": 200, "max_total_bytes": 1048576, "max_entries": 100,
             "max_path_length": 1024, "engine_timeout_seconds": 30}
}
"#;

/// A directory of its own for each test, under the target directory.
fn workdir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("policy-verify-{name}"));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clean the work directory");
    }
    std::fs::create_dir_all(&dir).expect("work directory");
    dir
}

struct Files {
    policy: PathBuf,
    signature: PathBuf,
    trust: PathBuf,
}

/// Write `policy`, its signature by the test key, and the trusted key.
fn signed(dir: &Path, policy: &[u8]) -> Files {
    let key = SigningKey::from_bytes(&[7; 32]);
    let files = Files {
        policy: dir.join("policy.json"),
        signature: dir.join("policy.sig"),
        trust: dir.join("trusted.pub"),
    };
    std::fs::write(&files.policy, policy).expect("policy");
    std::fs::write(&files.signature, key.sign(policy).to_bytes()).expect("signature");
    std::fs::write(&files.trust, key.verifying_key().to_bytes()).expect("key");
    files
}

fn verify(args: &[&Path]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ostia"));
    command.args(["policy", "verify"]);
    for pair in args.chunks(2) {
        command.arg(pair[0]).arg(pair[1]);
    }
    command.output().expect("the ostia binary runs")
}

fn flags(files: &Files) -> Vec<PathBuf> {
    vec![
        "--policy".into(),
        files.policy.clone(),
        "--policy-sig".into(),
        files.signature.clone(),
        "--trust".into(),
        files.trust.clone(),
    ]
}

fn run(args: &[PathBuf]) -> Output {
    let refs: Vec<&Path> = args.iter().map(PathBuf::as_path).collect();
    verify(&refs)
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[req("FR-09")]
#[test]
fn valid_policy_prints_exactly_its_version_and_hash() {
    let dir = workdir("valid");
    let files = signed(&dir, POLICY.as_bytes());
    let output = run(&flags(&files));
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    let printed: Value = serde_json::from_slice(&output.stdout).expect("one JSON object");
    let mut sha256 = String::new();
    for byte in Sha256::digest(POLICY.as_bytes()) {
        write!(sha256, "{byte:02x}").expect("writing to a String");
    }
    assert_eq!(printed, json!({"version": "cli-1", "sha256": sha256}));
}

#[req("FR-09")]
#[test]
fn flags_may_come_in_any_order() {
    let dir = workdir("order");
    let files = signed(&dir, POLICY.as_bytes());
    let mut args = flags(&files);
    args.rotate_left(2);
    assert_eq!(run(&args).status.code(), Some(0));
}

fn assert_refused(output: &Output, code: &str) {
    assert_eq!(output.status.code(), Some(4), "{}", stderr(output));
    assert_eq!(output.stdout, b"");
    let message = stderr(output);
    assert!(
        message.starts_with(&format!("ostia: input refused: {code}: ")),
        "{message:?}"
    );
    assert_eq!(message.trim_end().lines().count(), 1, "{message:?}");
}

#[req("FR-09")]
#[test]
fn altered_policy_is_refused_on_its_signature() {
    let dir = workdir("altered");
    let files = signed(&dir, POLICY.as_bytes());
    std::fs::write(&files.policy, POLICY.replace("cli-1", "cli-2")).expect("alter");
    assert_refused(&run(&flags(&files)), "policy_signature_invalid");
}

#[req("FR-09")]
#[test]
fn malformed_signature_or_key_is_refused_on_the_signature() {
    for (name, signature, key) in [
        ("short-signature", Some(vec![0_u8; 63]), None),
        ("long-signature", Some(vec![0_u8; 65]), None),
        ("short-key", None, Some(vec![1_u8; 31])),
        ("empty-key", None, Some(Vec::new())),
    ] {
        let dir = workdir(name);
        let files = signed(&dir, POLICY.as_bytes());
        if let Some(bytes) = signature {
            std::fs::write(&files.signature, bytes).expect("signature");
        }
        if let Some(bytes) = key {
            std::fs::write(&files.trust, bytes).expect("key");
        }
        assert_refused(&run(&flags(&files)), "policy_signature_invalid");
    }
}

#[req("FR-09")]
#[test]
fn signed_but_invalid_policy_is_refused_on_its_content() {
    let dir = workdir("invalid");
    let files = signed(&dir, POLICY.replace("\"k\": 2", "\"k\": 1").as_bytes());
    assert_refused(&run(&flags(&files)), "policy_invalid");
}

#[req("FR-09")]
#[test]
fn policy_larger_than_1_mib_is_refused_on_its_content() {
    let dir = workdir("oversize");
    let mut policy = POLICY.as_bytes().to_vec();
    policy.resize((1 << 20) + 1, b' ');
    let files = signed(&dir, &policy);
    assert_refused(&run(&flags(&files)), "policy_invalid");
}

#[req("FR-09")]
#[test]
fn missing_flag_is_a_usage_error_naming_it() {
    let dir = workdir("missing");
    let files = signed(&dir, POLICY.as_bytes());
    for (index, flag) in [(0, "--policy"), (2, "--policy-sig"), (4, "--trust")] {
        let mut args = flags(&files);
        args.drain(index..index + 2);
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{flag}");
        assert_eq!(output.stdout, b"", "{flag}");
        let message = stderr(&output);
        assert!(message.starts_with("ostia: "), "{message:?}");
        assert!(message.contains(flag), "{flag}: {message:?}");
    }
}

#[req("FR-09")]
#[test]
fn unreadable_file_or_unknown_flag_is_a_usage_error() {
    let dir = workdir("unreadable");
    let files = signed(&dir, POLICY.as_bytes());
    let mut absent = flags(&files);
    absent[1] = dir.join("absent.json");
    let mut unknown = flags(&files);
    unknown.extend(["--colour".into(), "red".into()]);
    for args in [absent, unknown] {
        let output = run(&args);
        assert_eq!(output.status.code(), Some(2), "{}", stderr(&output));
        assert_eq!(output.stdout, b"");
        assert!(stderr(&output).starts_with("ostia: "));
    }
}
