//! Loading the signed policy (ADR-09, `docs/contracts/policy.md`): the Ed25519 signature is checked over the
//! exact bytes before anything is parsed, and every document the contract does not allow is refused.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signer, SigningKey};
use ostia_core_domain::policy::{
    EngineRole, Indicator, Limits, MAX_POLICY_BYTES, Policy, PolicyError, Refusal, load,
};
use ostia_traceability::req;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn other_key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn document() -> Value {
    json!({
        "schema": "ostia.policy.v1",
        "version": "test-1",
        "engines": {
            "rep": {"role": "reputation"},
            "av-trusted": {"role": "detector", "trusted_alone": true},
            "av-a": {"role": "detector", "trusted_alone": false},
            "ember": {"role": "scorer", "thresholds": {"low": 0.5, "high": 0.9}},
            "heur": {"role": "heuristic"}
        },
        "rules": {
            "R1": {"risky_types": ["pe", "elf"]},
            "R2": {"k": 2, "critical_severity": 4},
            "R6": {
                "double_extension": true,
                "extension_mismatch": true,
                "single_detection": true,
                "suspicious_hint": true
            }
        },
        "limits": {
            "max_depth": 8,
            "max_ratio": 200,
            "max_total_bytes": 268_435_456,
            "max_entries": 10_000,
            "max_path_length": 1024,
            "engine_timeout_seconds": 30
        }
    })
}

fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(value).expect("serialisable")
}

/// Sign `data` with the test key and load it with the test key trusted.
fn load_signed(data: &[u8]) -> Result<Policy, PolicyError> {
    let signature = key().sign(data).to_bytes();
    load(data, &signature, &key().verifying_key().to_bytes())
}

fn refusal_of(result: Result<Policy, PolicyError>) -> Refusal {
    match result {
        Ok(policy) => panic!("loaded: {policy:?}"),
        Err(error) => error.refusal,
    }
}

/// The document with `value` at `path` (a missing key is created).
fn set(path: &[&str], value: Value) -> Vec<u8> {
    let mut document = document();
    let mut target = &mut document;
    for key in path {
        target = &mut target[*key];
    }
    *target = value;
    bytes(&document)
}

/// The document without the key at `path`.
fn without(path: &[&str]) -> Vec<u8> {
    let mut document = document();
    let (last, parents) = path.split_last().expect("non-empty path");
    let mut target = &mut document;
    for key in parents {
        target = &mut target[*key];
    }
    target
        .as_object_mut()
        .expect("an object")
        .remove(*last)
        .expect("the key exists");
    bytes(&document)
}

fn assert_invalid(cases: Vec<(&str, Vec<u8>)>) {
    for (name, data) in cases {
        assert_eq!(refusal_of(load_signed(&data)), Refusal::Invalid, "{name}");
    }
}

#[req("FR-09")]
#[test]
fn signed_valid_policy_loads_as_written() {
    let data = bytes(&document());
    let policy = load_signed(&data).expect("valid policy");
    assert_eq!(policy.version, "test-1");
    assert_eq!(policy.sha256.as_slice(), Sha256::digest(&data).as_slice());
    let engines = BTreeMap::from([
        (
            "av-a".to_owned(),
            EngineRole::Detector {
                trusted_alone: false,
            },
        ),
        (
            "av-trusted".to_owned(),
            EngineRole::Detector {
                trusted_alone: true,
            },
        ),
        (
            "ember".to_owned(),
            EngineRole::Scorer {
                low: 0.5,
                high: 0.9,
            },
        ),
        ("heur".to_owned(), EngineRole::Heuristic),
        ("rep".to_owned(), EngineRole::Reputation),
    ]);
    assert_eq!(policy.engines, engines);
    assert_eq!(
        policy.risky_types,
        BTreeSet::from(["elf".to_owned(), "pe".to_owned()])
    );
    assert_eq!((policy.k, policy.critical_severity), (2, 4));
    assert_eq!(
        policy.r6,
        BTreeSet::from([
            Indicator::DoubleExtension,
            Indicator::ExtensionMismatch,
            Indicator::SingleDetection,
            Indicator::SuspiciousHint,
        ])
    );
    assert_eq!(
        policy.limits,
        Limits {
            max_depth: 8,
            max_ratio: 200,
            max_total_bytes: 268_435_456,
            max_entries: 10_000,
            max_path_length: 1024,
            engine_timeout_seconds: 30,
        }
    );
}

#[req("FR-09")]
#[test]
fn disabled_r6_indicators_are_not_enabled() {
    let mut value = document();
    value["rules"]["R6"]["double_extension"] = json!(false);
    value["rules"]["R6"]["suspicious_hint"] = json!(false);
    let policy = load_signed(&bytes(&value)).expect("valid policy");
    assert_eq!(
        policy.r6,
        BTreeSet::from([Indicator::ExtensionMismatch, Indicator::SingleDetection])
    );
}

#[req("FR-09")]
#[test]
fn refusal_codes_are_those_of_the_report_contract() {
    assert_eq!(Refusal::SignatureInvalid.code(), "policy_signature_invalid");
    assert_eq!(Refusal::Invalid.code(), "policy_invalid");
    let error = PolicyError {
        refusal: Refusal::Invalid,
        detail: "unknown key".to_owned(),
    };
    assert_eq!(error.to_string(), "policy_invalid: unknown key");
}

#[req("FR-09")]
#[test]
fn altered_policy_is_refused_on_the_signature_even_when_still_valid() {
    let data = bytes(&document());
    let signature = key().sign(&data).to_bytes();
    let altered = String::from_utf8(data)
        .expect("utf-8")
        .replace("test-1", "test-2")
        .into_bytes();
    assert_eq!(
        refusal_of(load(
            &altered,
            &signature,
            &key().verifying_key().to_bytes()
        )),
        Refusal::SignatureInvalid
    );
}

#[req("FR-09")]
#[test]
fn signature_problems_are_refused_before_parsing() {
    // The content is not JSON at all: a signature problem must be reported first.
    let data = b"not json".to_vec();
    let good = key().sign(&data).to_bytes();
    let trusted = key().verifying_key().to_bytes();
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        (
            "signed by another key",
            other_key().sign(&data).to_bytes().to_vec(),
            trusted.to_vec(),
        ),
        (
            "signature of other bytes",
            key().sign(b"other").to_bytes().to_vec(),
            trusted.to_vec(),
        ),
        (
            "signature of 63 bytes",
            good[..63].to_vec(),
            trusted.to_vec(),
        ),
        (
            "signature of 65 bytes",
            [good.as_slice(), &[0]].concat(),
            trusted.to_vec(),
        ),
        ("empty signature", Vec::new(), trusted.to_vec()),
        ("key of 31 bytes", good.to_vec(), trusted[..31].to_vec()),
        (
            "key of 33 bytes",
            good.to_vec(),
            [trusted.as_slice(), &[0]].concat(),
        ),
        ("all-zero key", good.to_vec(), vec![0; 32]),
    ];
    for (name, signature, trusted_key) in cases {
        assert_eq!(
            refusal_of(load(&data, &signature, &trusted_key)),
            Refusal::SignatureInvalid,
            "{name}"
        );
    }
}

#[req("FR-09")]
#[test]
fn signed_document_that_is_not_json_is_invalid() {
    assert_eq!(
        refusal_of(load_signed(b"version = 'x'\n")),
        Refusal::Invalid
    );
    assert_eq!(
        refusal_of(load_signed(&[0xff, 0xfe, 0x00])),
        Refusal::Invalid
    );
}

#[req("FR-09")]
#[test]
fn policy_larger_than_1_mib_is_refused() {
    let mut data = bytes(&document());
    data.resize(MAX_POLICY_BYTES + 1, b' ');
    assert_eq!(refusal_of(load_signed(&data)), Refusal::Invalid);
    let mut at_limit = bytes(&document());
    at_limit.resize(MAX_POLICY_BYTES, b' ');
    assert!(load_signed(&at_limit).is_ok(), "exactly 1 MiB is accepted");
}

#[req("FR-09")]
#[test]
fn unknown_or_missing_keys_are_invalid() {
    assert_invalid(vec![
        ("unknown top-level key", set(&["extra"], json!(1))),
        (
            "unknown key in rules.R6",
            set(&["rules", "R6", "extra"], json!(true)),
        ),
        ("unknown key in limits", set(&["limits", "extra"], json!(1))),
        (
            "unknown key in an engine",
            set(&["engines", "rep", "extra"], json!(1)),
        ),
        ("unknown rule", set(&["rules", "R9"], json!({}))),
        ("missing limits", without(&["limits"])),
        ("missing engines", without(&["engines"])),
        (
            "missing rules.R6.single_detection",
            without(&["rules", "R6", "single_detection"]),
        ),
        ("missing rules.R2.k", without(&["rules", "R2", "k"])),
        ("missing rules.R1", without(&["rules", "R1"])),
        ("missing version", without(&["version"])),
        ("missing schema", without(&["schema"])),
        ("other schema", set(&["schema"], json!("ostia.policy.v2"))),
        ("not an object", b"[1, 2]".to_vec()),
    ]);
}

#[req("FR-09")]
#[test]
fn values_out_of_range_are_invalid() {
    assert_invalid(vec![
        ("empty version", set(&["version"], json!(""))),
        (
            "version of 65 characters",
            set(&["version"], json!("v".repeat(65))),
        ),
        ("k of 1", set(&["rules", "R2", "k"], json!(1))),
        (
            "critical severity 0",
            set(&["rules", "R2", "critical_severity"], json!(0)),
        ),
        (
            "critical severity 5",
            set(&["rules", "R2", "critical_severity"], json!(5)),
        ),
        ("max depth 0", set(&["limits", "max_depth"], json!(0))),
        ("max depth 65", set(&["limits", "max_depth"], json!(65))),
        ("max ratio 0", set(&["limits", "max_ratio"], json!(0))),
        (
            "max total bytes 0",
            set(&["limits", "max_total_bytes"], json!(0)),
        ),
        ("max entries 0", set(&["limits", "max_entries"], json!(0))),
        (
            "max path length 0",
            set(&["limits", "max_path_length"], json!(0)),
        ),
        (
            "max path length 65536",
            set(&["limits", "max_path_length"], json!(65_536)),
        ),
        (
            "engine timeout 0",
            set(&["limits", "engine_timeout_seconds"], json!(0)),
        ),
        (
            "engine timeout 3601",
            set(&["limits", "engine_timeout_seconds"], json!(3601)),
        ),
        ("negative limit", set(&["limits", "max_entries"], json!(-1))),
        (
            "upper-case risky type",
            set(&["rules", "R1", "risky_types"], json!(["PE"])),
        ),
        (
            "duplicate risky type",
            set(&["rules", "R1", "risky_types"], json!(["pe", "pe"])),
        ),
        (
            "risky types not a list",
            set(&["rules", "R1", "risky_types"], json!("pe")),
        ),
        (
            "flag not a boolean",
            set(&["rules", "R6", "double_extension"], json!(1)),
        ),
    ]);
}

#[req("FR-09")]
#[test]
fn engine_entries_the_contract_refuses_are_invalid() {
    let thresholds = |low: f64, high: f64| json!({"low": low, "high": high});
    let scorer = |t: Value| json!({"role": "scorer", "thresholds": t});
    assert_invalid(vec![
        (
            "thresholds low = high",
            set(&["engines", "ember"], scorer(thresholds(0.7, 0.7))),
        ),
        (
            "thresholds low > high",
            set(&["engines", "ember"], scorer(thresholds(0.9, 0.5))),
        ),
        (
            "threshold low 0",
            set(&["engines", "ember"], scorer(thresholds(0.0, 0.5))),
        ),
        (
            "threshold high above 1",
            set(&["engines", "ember"], scorer(thresholds(0.5, 1.5))),
        ),
        (
            "scorer without thresholds",
            set(&["engines", "ember"], json!({"role": "scorer"})),
        ),
        (
            "scorer trusted alone",
            set(&["engines", "ember", "trusted_alone"], json!(true)),
        ),
        (
            "detector without trusted_alone",
            set(&["engines", "av-a"], json!({"role": "detector"})),
        ),
        (
            "detector with thresholds",
            set(&["engines", "av-a", "thresholds"], thresholds(0.5, 0.9)),
        ),
        (
            "reputation with thresholds",
            set(&["engines", "rep", "thresholds"], thresholds(0.5, 0.9)),
        ),
        (
            "heuristic trusted alone",
            set(&["engines", "heur", "trusted_alone"], json!(true)),
        ),
        (
            "unknown role",
            set(&["engines", "rep", "role"], json!("oracle")),
        ),
        (
            "engine id with a space",
            set(&["engines", "bad id"], json!({"role": "heuristic"})),
        ),
        (
            "engine id of 65 characters",
            set(&["engines", &"e".repeat(65)], json!({"role": "heuristic"})),
        ),
    ]);
}

#[req("FR-09")]
#[test]
fn json_text_the_contract_refuses_is_invalid() {
    let compact = serde_json::to_string(&document()).expect("serialisable");
    let replaced = |from: &str, to: &str| compact.replacen(from, to, 1).into_bytes();
    assert_invalid(vec![
        (
            "duplicate key",
            replaced(
                "\"version\":\"test-1\"",
                "\"version\":\"test-1\",\"version\":\"test-2\"",
            ),
        ),
        (
            "duplicate nested key",
            replaced("\"k\":2", "\"k\":2,\"k\":3"),
        ),
        ("integer written 2.0", replaced("\"k\":2", "\"k\":2.0")),
        ("integer written 2e0", replaced("\"k\":2", "\"k\":2e0")),
        ("trailing data", [compact.as_bytes(), b" {}"].concat()),
    ]);
}

#[req("FR-09")]
#[test]
fn every_role_without_its_optional_keys_loads() {
    // A policy may declare a single engine of any role.
    for role in [
        json!({"role": "reputation"}),
        json!({"role": "heuristic"}),
        json!({"role": "detector", "trusted_alone": true}),
        json!({"role": "scorer", "thresholds": {"low": 0.000_001, "high": 1.0}}),
    ] {
        let data = set(&["engines"], json!({"only": role.clone()}));
        assert!(load_signed(&data).is_ok(), "{role}");
    }
}
