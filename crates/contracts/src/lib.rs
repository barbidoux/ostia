//! The Ostia engine contract (`ostia.engine.v1`, ADR-03) and its framing.
//!
//! Messages are generated from `proto/ostia/engine/v1/engine.proto` at build time (ADR-15). On a worker's
//! standard input and output every message is one frame: a 4-byte big-endian length, then the encoded
//! message (CTR-01). Decoding never panics: any malformed, oversized, truncated or incompatible input is a
//! [`ContractError`] (CTR-02). A response must name its engine, engine version and content version
//! (CTR-03), and every message carries a [`v1::ContractVersion`] whose major must be [`MAJOR`] (CTR-04).

mod framing;

pub use framing::{
    ContractError, DEFAULT_MAX_FRAME, MAJOR, MINOR, current_version, decode_frame, decode_request,
    decode_response, encode_frame, read_frame, write_frame,
};

/// Messages of the `ostia.engine.v1` contract.
// prost's generated helpers (`as_str_name`, `from_str_name`) lack `#[must_use]` and write "ProtoBuf"
// without backticks; approved by the owner for this generated module only (Q-21).
#[allow(clippy::must_use_candidate, clippy::doc_markdown)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/ostia.engine.v1.rs"));
}
