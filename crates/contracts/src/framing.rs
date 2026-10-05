//! Length-prefixed framing and validated decoding of `ostia.engine.v1` messages.

use std::io::{Read, Write};

use crate::v1::{AnalyzeRequest, AnalyzeResponse, ContractVersion};

/// Default cap on the length of one frame's message: 16 MiB.
pub const DEFAULT_MAX_FRAME: usize = 16 * 1024 * 1024;

/// Contract major version this crate speaks.
pub const MAJOR: u32 = 1;

/// Contract minor version this crate writes.
pub const MINOR: u32 = 0;

/// Why a frame or a message was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ContractError {
    /// The frame announces a zero-length message.
    #[error("empty frame")]
    Empty,
    /// The frame announces more bytes than the cap allows.
    #[error("frame of {len} bytes exceeds the {cap}-byte cap")]
    Oversized {
        /// Announced (or encoded) message length.
        len: u64,
        /// Cap in force.
        cap: usize,
    },
    /// Fewer than 4 bytes of length prefix.
    #[error("truncated frame header")]
    TruncatedHeader,
    /// Fewer message bytes than announced.
    #[error("truncated frame body")]
    TruncatedBody,
    /// Bytes after the announced message.
    #[error("trailing bytes after the frame")]
    TrailingBytes,
    /// The message is not valid Protobuf for its type.
    #[error("malformed message")]
    Malformed,
    /// The message's contract major is not [`MAJOR`] (a missing version reads as major 0).
    #[error("unsupported contract major version {0}")]
    UnsupportedMajor(u32),
    /// A response without its engine id, engine version or content version (CTR-03).
    #[error("response without {0}")]
    MissingEngineIdentity(&'static str),
    /// A score that is not a number in [0, 1].
    #[error("score outside [0, 1]")]
    InvalidScore,
    /// A request field with an invalid value.
    #[error("invalid request: {0}")]
    InvalidRequest(&'static str),
    /// A response field with an invalid value.
    #[error("invalid response: {0}")]
    InvalidResponse(&'static str),
    /// Reading or writing the stream failed.
    #[error("i/o error: {0}")]
    Io(std::io::ErrorKind),
}

impl ContractError {
    /// Stable name of the error kind, shared with the Python framing and the golden vectors.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        todo!()
    }
}

/// The version written into every message: `{MAJOR, MINOR}`.
#[must_use]
pub fn current_version() -> ContractVersion {
    todo!()
}

/// Encodes `message` as one frame.
///
/// # Errors
/// [`ContractError::Empty`] for a message that encodes to no bytes, [`ContractError::Oversized`] above
/// `cap`.
pub fn encode_frame<M: prost::Message>(
    _message: &M,
    _cap: usize,
) -> Result<Vec<u8>, ContractError> {
    todo!()
}

/// The message bytes of `buf`, which must hold exactly one frame.
///
/// # Errors
/// Empty, oversized, truncated frames and trailing bytes.
pub fn decode_frame(_buf: &[u8], _cap: usize) -> Result<&[u8], ContractError> {
    todo!()
}

/// Reads one frame from `reader` and returns its message bytes. The cap is checked before any message
/// byte is read or allocated.
///
/// # Errors
/// Empty, oversized and truncated frames, and read failures.
pub fn read_frame<R: Read>(_reader: &mut R, _cap: usize) -> Result<Vec<u8>, ContractError> {
    todo!()
}

/// Writes `message` to `writer` as one frame.
///
/// # Errors
/// As [`encode_frame`], and write failures.
pub fn write_frame<W: Write, M: prost::Message>(
    _writer: &mut W,
    _message: &M,
    _cap: usize,
) -> Result<(), ContractError> {
    todo!()
}

/// Decodes and validates a request: contract major, a 32-byte SHA-256, a known origin.
///
/// # Errors
/// Malformed message, unsupported major, invalid fields.
pub fn decode_request(_body: &[u8]) -> Result<AnalyzeRequest, ContractError> {
    todo!()
}

/// Decodes and validates a response: contract major, engine identity (CTR-03), a known status, a score
/// in [0, 1] when present.
///
/// # Errors
/// Malformed message, unsupported major, missing engine identity, invalid fields.
pub fn decode_response(_body: &[u8]) -> Result<AnalyzeResponse, ContractError> {
    todo!()
}
