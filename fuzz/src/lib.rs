//! What every fuzz target does with one input: feed it to each decoder of `ostia-contracts`, raw and
//! framed, under two caps, and check properties the decoders must hold. Any panic (a broken property
//! included), abort, sanitizer report, timeout or out-of-memory is a finding (NFR-06, CTR-02).
//!
//! The Rust replay test of `fuzz/regressions/` includes this file (`#[path]`), so it runs exactly this
//! code on stable.

use std::io::{Cursor, ErrorKind, Read};

use ostia_contracts::v1::AnalyzeResponse;
use ostia_contracts::{
    ContractError, DEFAULT_MAX_FRAME, decode_frame, decode_request, decode_response, encode_frame,
    read_frame,
};

/// Small cap so that the length checks around the cap are reached often.
const SMALL_CAP: usize = 64;

/// Runs every decoder on `data` and checks their properties.
///
/// # Panics
/// As [`exercise_with`].
pub fn exercise(data: &[u8]) {
    exercise_with(data, &|_| {});
}

/// As [`exercise`], calling `on_response` with every response the decoders accept (the harness self-test
/// plants its bugs there, after decoding).
///
/// # Panics
/// When a decoder breaks one of the properties checked here: that is what the fuzzer looks for.
pub fn exercise_with(data: &[u8], on_response: &dyn Fn(&AnalyzeResponse)) {
    for cap in [DEFAULT_MAX_FRAME, SMALL_CAP] {
        let framed = decode_frame(data, cap);
        let streamed = read_frame(&mut Cursor::new(data), cap);
        let trickled = read_frame(&mut Trickle::new(data), cap);
        assert_eq!(
            streamed, trickled,
            "short or interrupted reads changed the result"
        );
        match framed {
            Ok(body) => {
                assert!(body.len() <= cap, "a frame above the cap was accepted");
                assert_eq!(
                    streamed.as_deref(),
                    Ok(body),
                    "read_frame disagrees with decode_frame"
                );
                decode_body(body, on_response);
            }
            Err(ContractError::TrailingBytes) => {
                let prefix = streamed.expect("a frame followed by more bytes reads as one frame");
                assert!(prefix.len() <= cap, "a frame above the cap was read");
            }
            Err(error) => assert_eq!(
                streamed,
                Err(error),
                "read_frame disagrees with decode_frame"
            ),
        }
    }
    decode_body(data, on_response);
}

/// Decodes `body` as a request and as a response; an accepted message survives a re-encoding.
fn decode_body(body: &[u8], on_response: &dyn Fn(&AnalyzeResponse)) {
    if let Ok(request) = decode_request(body) {
        let frame = encode_frame(&request, DEFAULT_MAX_FRAME).expect("an accepted request encodes");
        let again = decode_frame(&frame, DEFAULT_MAX_FRAME).and_then(decode_request);
        assert_eq!(
            again,
            Ok(request),
            "a request changed through a re-encoding"
        );
    }
    if let Ok(response) = decode_response(body) {
        on_response(&response);
        let frame =
            encode_frame(&response, DEFAULT_MAX_FRAME).expect("an accepted response encodes");
        let again = decode_frame(&frame, DEFAULT_MAX_FRAME).and_then(decode_response);
        assert_eq!(
            again,
            Ok(response),
            "a response changed through a re-encoding"
        );
    }
}

/// A reader that hands out the input in short pieces (sizes taken from the input itself) and is
/// interrupted every third call, like a pipe under load.
struct Trickle<'a> {
    data: &'a [u8],
    position: usize,
    calls: usize,
}

impl<'a> Trickle<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            position: 0,
            calls: 0,
        }
    }
}

impl Read for Trickle<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.calls += 1;
        if self.calls.is_multiple_of(3) {
            return Err(ErrorKind::Interrupted.into());
        }
        let rest = self.data.get(self.position..).unwrap_or_default();
        let piece = rest
            .first()
            .map_or(1, |byte| usize::from(byte % 7) + 1)
            .min(rest.len())
            .min(buf.len());
        let (Some(target), Some(source)) = (buf.get_mut(..piece), rest.get(..piece)) else {
            return Ok(0);
        };
        target.copy_from_slice(source);
        self.position += piece;
        Ok(piece)
    }
}
