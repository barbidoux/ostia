//! What every fuzz target does with one input: feed it to each decoder of `ostia-contracts`, raw and
//! framed. Any panic, abort, sanitizer report, timeout or out-of-memory is a finding (NFR-06, CTR-02).

use std::io::Cursor;

use ostia_contracts::{
    DEFAULT_MAX_FRAME, decode_frame, decode_request, decode_response, read_frame,
};

/// Small cap so that the length checks around the cap are reached often.
const SMALL_CAP: usize = 64;

/// Runs every decoder on `data`.
pub fn exercise(data: &[u8]) {
    for cap in [DEFAULT_MAX_FRAME, SMALL_CAP] {
        let _ = read_frame(&mut Cursor::new(data), cap);
        if let Ok(body) = decode_frame(data, cap) {
            let _ = decode_request(body);
            let _ = decode_response(body);
        }
    }
    let _ = decode_request(data);
    let _ = decode_response(data);
}
