//! Framing and validated decoding of `ostia.engine.v1` messages (CTR-01 to CTR-04).

use std::io::{Cursor, Read};

use ostia_contracts::v1::{AnalyzeRequest, AnalyzeResponse, ContractVersion, Finding, Limits};
use ostia_contracts::{
    ContractError, DEFAULT_MAX_FRAME, MAJOR, MINOR, current_version, decode_frame, decode_request,
    decode_response, encode_frame, read_frame, write_frame,
};
use ostia_traceability::req;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

fn version(major: u32, minor: u32) -> ContractVersion {
    ContractVersion { major, minor }
}

fn request() -> AnalyzeRequest {
    AnalyzeRequest {
        session_id: "session-0001".into(),
        object_id: "object-0001".into(),
        sha256: SHA256_EMPTY.to_vec(),
        detected_type: "application/pdf".into(),
        size: 0,
        origin: 1,
        limits: Some(Limits {
            memory_bytes: 268_435_456,
            duration_ms: 30_000,
            write_bytes: 0,
        }),
        version: Some(version(1, 0)),
    }
}

fn response() -> AnalyzeResponse {
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
        version: Some(version(1, 0)),
    }
}

fn response_frame(response: &AnalyzeResponse) -> Vec<u8> {
    encode_frame(response, DEFAULT_MAX_FRAME).expect("a valid response encodes")
}

fn decode_response_frame(frame: &[u8]) -> Result<AnalyzeResponse, ContractError> {
    decode_response(decode_frame(frame, DEFAULT_MAX_FRAME)?)
}

#[req("CTR-04")]
#[test]
fn messages_carry_contract_version_one_zero() {
    assert_eq!((MAJOR, MINOR), (1, 0));
    assert_eq!(current_version(), ContractVersion { major: 1, minor: 0 });
}

#[req("CTR-01")]
#[test]
fn frame_is_a_big_endian_length_then_the_message() {
    // ContractVersion { major: 1, minor: 0 } encodes as field 1, varint 1: 0x08 0x01.
    let frame = encode_frame(&ContractVersion { major: 1, minor: 0 }, DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(frame, [0x00, 0x00, 0x00, 0x02, 0x08, 0x01]);
    let big = ContractVersion {
        major: 1,
        minor: 300,
    };
    let frame = encode_frame(&big, DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(
        frame,
        [0x00, 0x00, 0x00, 0x05, 0x08, 0x01, 0x10, 0xac, 0x02]
    );
}

#[req("CTR-01")]
#[test]
fn request_round_trips_through_a_frame() {
    let frame = encode_frame(&request(), DEFAULT_MAX_FRAME).unwrap();
    let body = decode_frame(&frame, DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(decode_request(body).unwrap(), request());
}

#[req("CTR-01", "CTR-03")]
#[test]
fn response_round_trips_through_a_frame() {
    assert_eq!(
        decode_response_frame(&response_frame(&response())).unwrap(),
        response()
    );
}

#[req("CTR-01")]
#[test]
fn frames_round_trip_through_a_stream() {
    let mut stream = Vec::new();
    write_frame(&mut stream, &request(), DEFAULT_MAX_FRAME).unwrap();
    write_frame(&mut stream, &response(), DEFAULT_MAX_FRAME).unwrap();
    let mut reader = Cursor::new(stream);
    let first = read_frame(&mut reader, DEFAULT_MAX_FRAME).unwrap();
    let second = read_frame(&mut reader, DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(decode_request(&first).unwrap(), request());
    assert_eq!(decode_response(&second).unwrap(), response());
    assert_eq!(
        read_frame(&mut reader, DEFAULT_MAX_FRAME),
        Err(ContractError::TruncatedHeader)
    );
}

#[req("CTR-02")]
#[test]
fn malformed_frames_are_rejected_with_their_kind() {
    let cases: [(&[u8], ContractError, &str); 7] = [
        (&[0, 0, 0, 0], ContractError::Empty, "empty"),
        (&[], ContractError::TruncatedHeader, "truncated_header"),
        (
            &[0, 0, 1],
            ContractError::TruncatedHeader,
            "truncated_header",
        ),
        (
            &[0, 0, 0, 4, 1, 2, 3],
            ContractError::TruncatedBody,
            "truncated_body",
        ),
        (
            &[0, 0, 0, 1, 1, 2],
            ContractError::TrailingBytes,
            "trailing_bytes",
        ),
        (
            &[0x01, 0x00, 0x00, 0x01],
            ContractError::Oversized {
                len: 16_777_217,
                cap: 16_777_216,
            },
            "oversized",
        ),
        (
            &[0xff, 0xff, 0xff, 0xff],
            ContractError::Oversized {
                len: 4_294_967_295,
                cap: 16_777_216,
            },
            "oversized",
        ),
    ];
    for (frame, error, kind) in cases {
        let refused = decode_frame(frame, DEFAULT_MAX_FRAME).unwrap_err();
        assert_eq!(refused, error, "frame {frame:?}");
        assert_eq!(refused.kind(), kind);
    }
}

#[req("CTR-02")]
#[test]
fn the_cap_is_configurable() {
    assert_eq!(DEFAULT_MAX_FRAME, 16 * 1024 * 1024);
    let frame = [0, 0, 0, 5, 1, 2, 3, 4, 5];
    assert_eq!(decode_frame(&frame, 5), Ok(&frame[4..]));
    assert_eq!(
        decode_frame(&frame, 4),
        Err(ContractError::Oversized { len: 5, cap: 4 })
    );
    let refused = encode_frame(&response(), 16).unwrap_err();
    assert!(
        matches!(refused, ContractError::Oversized { cap: 16, .. }),
        "{refused:?}"
    );
}

/// A reader that announces a 4 GiB frame and counts the bytes it is asked for.
struct Announcing {
    header: Cursor<[u8; 4]>,
    requested_after_header: usize,
}

impl Read for Announcing {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.header.read(buf)?;
        if n == 0 {
            self.requested_after_header += buf.len();
            buf.fill(0);
            return Ok(buf.len());
        }
        Ok(n)
    }
}

#[req("CTR-02")]
#[test]
fn the_cap_is_checked_before_reading_the_body() {
    let mut reader = Announcing {
        header: Cursor::new([0xff; 4]),
        requested_after_header: 0,
    };
    let refused = read_frame(&mut reader, DEFAULT_MAX_FRAME).unwrap_err();
    assert_eq!(
        refused,
        ContractError::Oversized {
            len: 4_294_967_295,
            cap: 16_777_216
        }
    );
    assert_eq!(reader.requested_after_header, 0);
}

#[req("CTR-02")]
#[test]
fn a_stream_that_ends_early_is_truncated() {
    let frame = response_frame(&response());
    let mut short_header = Cursor::new(frame[..2].to_vec());
    assert_eq!(
        read_frame(&mut short_header, DEFAULT_MAX_FRAME),
        Err(ContractError::TruncatedHeader)
    );
    let mut short_body = Cursor::new(frame[..frame.len() - 1].to_vec());
    assert_eq!(
        read_frame(&mut short_body, DEFAULT_MAX_FRAME),
        Err(ContractError::TruncatedBody)
    );
    let mut empty = Cursor::new(vec![0, 0, 0, 0]);
    assert_eq!(
        read_frame(&mut empty, DEFAULT_MAX_FRAME),
        Err(ContractError::Empty)
    );
}

#[req("CTR-02")]
#[test]
fn bytes_that_are_not_protobuf_are_malformed() {
    // Field 1 announces 5 bytes and only 2 follow.
    let body = [0x0a, 0x05, b'a', b'b'];
    assert_eq!(decode_response(&body), Err(ContractError::Malformed));
    assert_eq!(decode_request(&body), Err(ContractError::Malformed));
    assert_eq!(ContractError::Malformed.kind(), "malformed");
}

#[req("CTR-02", "CTR-04")]
#[test]
fn other_majors_are_refused_and_newer_minors_accepted() {
    for (version, expected) in [
        (None, Err(ContractError::UnsupportedMajor(0))),
        (Some(version(0, 9)), Err(ContractError::UnsupportedMajor(0))),
        (Some(version(2, 0)), Err(ContractError::UnsupportedMajor(2))),
        (Some(version(1, 7)), Ok(())),
    ] {
        let message = AnalyzeResponse {
            version,
            ..response()
        };
        let decoded = decode_response_frame(&response_frame(&message)).map(|_| ());
        assert_eq!(decoded, expected, "{version:?}");
        let request = AnalyzeRequest {
            version,
            ..request()
        };
        let frame = encode_frame(&request, DEFAULT_MAX_FRAME).unwrap();
        let decoded = decode_request(decode_frame(&frame, DEFAULT_MAX_FRAME).unwrap()).map(|_| ());
        assert_eq!(decoded, expected, "{version:?}");
    }
    assert_eq!(
        ContractError::UnsupportedMajor(2).kind(),
        "unsupported_major"
    );
}

#[req("CTR-03")]
#[test]
fn responses_without_engine_identity_are_refused() {
    let cases = [
        (
            AnalyzeResponse {
                engine_id: String::new(),
                ..response()
            },
            "engine_id",
        ),
        (
            AnalyzeResponse {
                engine_version: String::new(),
                ..response()
            },
            "engine_version",
        ),
        (
            AnalyzeResponse {
                content_version: String::new(),
                ..response()
            },
            "content_version",
        ),
    ];
    for (message, field) in cases {
        let refused = decode_response_frame(&response_frame(&message)).unwrap_err();
        assert_eq!(refused, ContractError::MissingEngineIdentity(field));
        assert_eq!(refused.kind(), "missing_engine_identity");
    }
}

#[req("CTR-02")]
#[test]
fn scores_outside_zero_one_are_refused() {
    for score in [-0.001, 1.5, f64::NAN, f64::INFINITY] {
        let message = AnalyzeResponse {
            score: Some(score),
            ..response()
        };
        let refused = decode_response_frame(&response_frame(&message)).unwrap_err();
        assert_eq!(refused, ContractError::InvalidScore, "score {score}");
        assert_eq!(refused.kind(), "invalid_score");
    }
    for score in [0.0, 1.0] {
        let message = AnalyzeResponse {
            score: Some(score),
            ..response()
        };
        assert!(
            decode_response_frame(&response_frame(&message)).is_ok(),
            "score {score}"
        );
    }
}

#[req("CTR-02")]
#[test]
fn invalid_request_and_response_fields_are_refused() {
    let short_hash = AnalyzeRequest {
        sha256: SHA256_EMPTY[..31].to_vec(),
        ..request()
    };
    let unknown_origin = AnalyzeRequest {
        origin: 0,
        ..request()
    };
    for (message, error) in [
        (short_hash, ContractError::InvalidRequest("sha256")),
        (unknown_origin, ContractError::InvalidRequest("origin")),
        (
            AnalyzeRequest {
                origin: 99,
                ..request()
            },
            ContractError::InvalidRequest("origin"),
        ),
    ] {
        let frame = encode_frame(&message, DEFAULT_MAX_FRAME).unwrap();
        let refused = decode_request(decode_frame(&frame, DEFAULT_MAX_FRAME).unwrap()).unwrap_err();
        assert_eq!(refused, error);
        assert_eq!(refused.kind(), "invalid_request");
    }
    for status in [0, 99] {
        let message = AnalyzeResponse {
            status,
            ..response()
        };
        let refused = decode_response_frame(&response_frame(&message)).unwrap_err();
        assert_eq!(refused, ContractError::InvalidResponse("status"));
        assert_eq!(refused.kind(), "invalid_response");
    }
}

#[req("CTR-02")]
#[test]
fn unknown_hints_and_severities_are_refused() {
    for hint in [-1, 5, 99] {
        let message = AnalyzeResponse { hint, ..response() };
        let refused = decode_response_frame(&response_frame(&message)).unwrap_err();
        assert_eq!(
            refused,
            ContractError::InvalidResponse("hint"),
            "hint {hint}"
        );
    }
    let unspecified = AnalyzeResponse {
        hint: 0,
        ..response()
    };
    assert!(decode_response_frame(&response_frame(&unspecified)).is_ok());
    let mut severe = response();
    severe.findings[0].severity = 5;
    let refused = decode_response_frame(&response_frame(&severe)).unwrap_err();
    assert_eq!(refused, ContractError::InvalidResponse("severity"));
}

#[req("CTR-02")]
#[test]
fn encoding_honours_the_cap_exactly() {
    let message = ContractVersion { major: 1, minor: 0 };
    assert_eq!(
        encode_frame(&message, 2),
        Ok(vec![0x00, 0x00, 0x00, 0x02, 0x08, 0x01])
    );
    assert_eq!(
        encode_frame(&message, 1),
        Err(ContractError::Oversized { len: 2, cap: 1 })
    );
    let empty = ContractVersion { major: 0, minor: 0 };
    assert_eq!(
        encode_frame(&empty, DEFAULT_MAX_FRAME),
        Err(ContractError::Empty)
    );
    // A cap above what 32 bits can announce: the longest announced frame is merely truncated.
    assert_eq!(
        decode_frame(&[0xff, 0xff, 0xff, 0xff], usize::MAX),
        Err(ContractError::TruncatedBody)
    );
}

/// A reader that hands out one byte per call and is interrupted before each byte.
struct Trickle {
    bytes: Cursor<Vec<u8>>,
    interrupt: bool,
}

impl Read for Trickle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.interrupt = !self.interrupt;
        if self.interrupt {
            return Err(std::io::ErrorKind::Interrupted.into());
        }
        let Some(first) = buf.first_mut() else {
            return Ok(0);
        };
        let mut one = [0_u8; 1];
        let n = self.bytes.read(&mut one)?;
        *first = one[0];
        Ok(n)
    }
}

#[req("CTR-01")]
#[test]
fn short_and_interrupted_reads_are_retried() {
    let frame = response_frame(&response());
    let mut reader = Trickle {
        bytes: Cursor::new(frame),
        interrupt: false,
    };
    let body = read_frame(&mut reader, DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(decode_response(&body).unwrap(), response());
}

struct Failing;

impl Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::PermissionDenied.into())
    }
}

impl std::io::Write for Failing {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A writer that accepts one byte per call and counts flushes.
#[derive(Default)]
struct Recording {
    bytes: Vec<u8>,
    flushes: usize,
}

impl std::io::Write for Recording {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(first) = buf.first() else {
            return Ok(0);
        };
        self.bytes.push(*first);
        Ok(1)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flushes += 1;
        Ok(())
    }
}

#[req("CTR-01", "CTR-02")]
#[test]
fn stream_failures_are_io_errors_and_frames_are_flushed() {
    let refused = read_frame(&mut Failing, DEFAULT_MAX_FRAME).unwrap_err();
    assert_eq!(
        refused,
        ContractError::Io(std::io::ErrorKind::PermissionDenied)
    );
    assert_eq!(refused.kind(), "io");
    let refused = write_frame(&mut Failing, &response(), DEFAULT_MAX_FRAME).unwrap_err();
    assert_eq!(refused, ContractError::Io(std::io::ErrorKind::BrokenPipe));
    let mut writer = Recording::default();
    write_frame(&mut writer, &response(), DEFAULT_MAX_FRAME).unwrap();
    assert_eq!(writer.bytes, response_frame(&response()));
    assert_eq!(writer.flushes, 1);
}

fn fixed_seed() -> Config {
    Config {
        cases: 2_000,
        rng_seed: RngSeed::Fixed(0x05_7a_c0_de),
        failure_persistence: None,
        ..Config::default()
    }
}

proptest! {
    #![proptest_config(fixed_seed())]

    #[req("CTR-02")]
    #[test]
    fn decoders_never_panic_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = decode_frame(&bytes, DEFAULT_MAX_FRAME);
        let _ = decode_frame(&bytes, 64);
        let _ = read_frame(&mut Cursor::new(bytes.clone()), DEFAULT_MAX_FRAME);
        let _ = decode_request(&bytes);
        let _ = decode_response(&bytes);
    }

    #[req("CTR-02")]
    #[test]
    fn framed_random_bodies_never_panic(body in prop::collection::vec(any::<u8>(), 1..512)) {
        let mut frame = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&body);
        let decoded = decode_frame(&frame, DEFAULT_MAX_FRAME);
        prop_assert_eq!(decoded, Ok(&body[..]));
        let _ = decode_request(&body);
        let _ = decode_response(&body);
    }
}
