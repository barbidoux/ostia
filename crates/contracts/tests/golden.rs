//! Golden vectors shared with the Python framing (`proto/testdata/`, written once by
//! `tools/contracts/gen_vectors.py` with the Python encoder). Rust must encode each valid message to the
//! same bytes, decode it back, and refuse each invalid frame with the same error kind (CTR-01 to CTR-04).

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use ostia_contracts::v1::{AnalyzeRequest, AnalyzeResponse, ContractVersion, Finding, Limits};
use ostia_contracts::{
    ContractError, DEFAULT_MAX_FRAME, decode_frame, decode_request, decode_response, encode_frame,
};
use ostia_traceability::req;

fn testdata() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../proto/testdata")
}

fn vector(name: &str) -> Vec<u8> {
    let path = testdata().join(format!("{name}.bin"));
    fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn request_pdf() -> AnalyzeRequest {
    AnalyzeRequest {
        session_id: "session-0001".into(),
        object_id: "object-0001".into(),
        sha256: vec![
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ],
        detected_type: "application/pdf".into(),
        size: 0,
        origin: 1,
        limits: Some(Limits {
            memory_bytes: 268_435_456,
            duration_ms: 30_000,
            write_bytes: 0,
        }),
        version: Some(ContractVersion { major: 1, minor: 0 }),
    }
}

fn response_clean(minor: u32) -> AnalyzeResponse {
    AnalyzeResponse {
        engine_id: "clamav".into(),
        engine_version: "1.4.3".into(),
        content_version: "daily-27500".into(),
        status: 1,
        hint: 2,
        score: None,
        findings: vec![],
        duration_ms: 12,
        version: Some(ContractVersion { major: 1, minor }),
    }
}

fn response_scored() -> AnalyzeResponse {
    AnalyzeResponse {
        engine_id: "ember".into(),
        engine_version: "2024.1".into(),
        content_version: "model-2024-09".into(),
        status: 1,
        hint: 3,
        score: Some(0.875),
        findings: vec![Finding {
            id: "EMBER-SCORE".into(),
            title: "PE model score above threshold".into(),
            severity: 3,
            evidence: "score=0.875 threshold=0.8".into(),
            attack_ids: vec!["T1204.002".into()],
        }],
        duration_ms: 840,
        version: Some(ContractVersion { major: 1, minor: 0 }),
    }
}

/// Invalid vectors: name, message type, expected error kind.
const INVALID: [(&str, &str, &str); 24] = [
    ("frame_empty", "response", "empty"),
    ("frame_oversized", "response", "oversized"),
    ("frame_truncated_header", "response", "truncated_header"),
    ("frame_truncated_body", "response", "truncated_body"),
    ("frame_trailing_bytes", "response", "trailing_bytes"),
    ("response_malformed", "response", "malformed"),
    ("response_major_2", "response", "unsupported_major"),
    ("response_no_version", "response", "unsupported_major"),
    (
        "response_no_engine_id",
        "response",
        "missing_engine_identity",
    ),
    (
        "response_no_engine_version",
        "response",
        "missing_engine_identity",
    ),
    (
        "response_no_content_version",
        "response",
        "missing_engine_identity",
    ),
    ("response_score_above_one", "response", "invalid_score"),
    ("response_score_nan", "response", "invalid_score"),
    (
        "response_status_unspecified",
        "response",
        "invalid_response",
    ),
    ("request_major_2", "request", "unsupported_major"),
    ("request_short_sha256", "request", "invalid_request"),
    ("response_wrong_wire_type", "response", "malformed"),
    ("response_version_as_varint", "response", "malformed"),
    ("response_finding_id_as_varint", "response", "malformed"),
    ("response_varint_overflow", "response", "malformed"),
    ("response_engine_id_bad_utf8", "response", "malformed"),
    ("response_hint_unknown", "response", "invalid_response"),
    ("response_severity_5", "response", "invalid_response"),
    ("response_two_faults", "response", "unsupported_major"),
];

const VALID: [&str; 5] = [
    "request_pdf",
    "response_clean",
    "response_scored",
    "response_newer_minor",
    "response_minor_1_extra_field",
];

fn decode(name: &str, message: &str) -> Result<(), ContractError> {
    let frame = vector(name);
    let body = decode_frame(&frame, DEFAULT_MAX_FRAME)?;
    match message {
        "request" => decode_request(body).map(|_| ()),
        _ => decode_response(body).map(|_| ()),
    }
}

#[req("CTR-01", "CTR-03")]
#[test]
fn rust_encodes_the_valid_vectors_to_the_python_bytes() {
    let request = encode_frame(&request_pdf(), DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(request, vector("request_pdf"));
    let cases = [
        ("response_clean", response_clean(0)),
        ("response_scored", response_scored()),
        ("response_newer_minor", response_clean(7)),
    ];
    for (name, message) in cases {
        assert_eq!(
            encode_frame(&message, DEFAULT_MAX_FRAME).unwrap(),
            vector(name),
            "{name}"
        );
    }
}

#[req("CTR-01", "CTR-03", "CTR-04")]
#[test]
fn rust_decodes_the_python_bytes_of_the_valid_vectors() {
    let frame = vector("request_pdf");
    let body = decode_frame(&frame, DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(decode_request(body).unwrap(), request_pdf());
    let cases = [
        ("response_clean", response_clean(0)),
        ("response_scored", response_scored()),
        ("response_newer_minor", response_clean(7)),
        // Minor 1 with a field this decoder does not know (field 9): ignored, not refused.
        ("response_minor_1_extra_field", response_clean(1)),
    ];
    for (name, message) in cases {
        let frame = vector(name);
        let body = decode_frame(&frame, DEFAULT_MAX_FRAME).unwrap();
        assert_eq!(decode_response(body).unwrap(), message, "{name}");
    }
}

#[req("CTR-01")]
#[test]
fn response_clean_is_the_hand_decoded_frame() {
    // Written out field by field from engine.proto, independently of both encoders.
    let expected: Vec<u8> = [
        &[0x00, 0x00, 0x00, 0x26][..],
        &[0x0a, 0x06, b'c', b'l', b'a', b'm', b'a', b'v'],
        &[0x12, 0x05, b'1', b'.', b'4', b'.', b'3'],
        &[
            0x1a, 0x0b, b'd', b'a', b'i', b'l', b'y', b'-', b'2', b'7', b'5', b'0', b'0',
        ],
        &[0x20, 0x01, 0x28, 0x02, 0x40, 0x0c],
        &[0x7a, 0x02, 0x08, 0x01],
    ]
    .concat();
    assert_eq!(vector("response_clean"), expected);
    assert_eq!(
        encode_frame(&response_clean(0), DEFAULT_MAX_FRAME).unwrap(),
        expected
    );
}

#[req("CTR-02", "CTR-03", "CTR-04")]
#[test]
fn rust_refuses_the_invalid_vectors_with_the_same_kind() {
    for (name, message, kind) in INVALID {
        let refused = decode(name, message).expect_err(name);
        assert_eq!(refused.kind(), kind, "{name}");
    }
}

#[req("TOOLING")]
#[test]
fn every_committed_vector_is_checked_here() {
    let committed: BTreeSet<String> = fs::read_dir(testdata())
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".bin").map(str::to_owned)
        })
        .collect();
    let checked: BTreeSet<String> = VALID
        .iter()
        .copied()
        .chain(INVALID.iter().map(|(name, _, _)| *name))
        .map(str::to_owned)
        .collect();
    assert_eq!(committed, checked);
}
