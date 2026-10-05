//! Length-prefixed framing and validated decoding of `ostia.engine.v1` messages.

use std::io::{Read, Write};

use prost::Message;

use crate::v1::{AnalyzeRequest, AnalyzeResponse, ContractVersion, Hint, Origin, Status};

/// Default cap on the length of one frame's message: 16 MiB.
pub const DEFAULT_MAX_FRAME: usize = 16 * 1024 * 1024;

/// Contract major version this crate speaks.
pub const MAJOR: u32 = 1;

/// Contract minor version this crate writes.
pub const MINOR: u32 = 0;

/// Highest finding severity (4, critical).
const MAX_SEVERITY: u32 = 4;

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
        match self {
            Self::Empty => "empty",
            Self::Oversized { .. } => "oversized",
            Self::TruncatedHeader => "truncated_header",
            Self::TruncatedBody => "truncated_body",
            Self::TrailingBytes => "trailing_bytes",
            Self::Malformed => "malformed",
            Self::UnsupportedMajor(_) => "unsupported_major",
            Self::MissingEngineIdentity(_) => "missing_engine_identity",
            Self::InvalidScore => "invalid_score",
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidResponse(_) => "invalid_response",
            Self::Io(_) => "io",
        }
    }
}

/// The version written into every message: `{MAJOR, MINOR}`.
#[must_use]
pub fn current_version() -> ContractVersion {
    ContractVersion {
        major: MAJOR,
        minor: MINOR,
    }
}

/// The largest message length a frame can carry under `cap` (the prefix is 32 bits).
fn effective_cap(cap: usize) -> usize {
    cap.min(usize::try_from(u32::MAX).unwrap_or(usize::MAX))
}

fn oversized(len: usize, cap: usize) -> ContractError {
    ContractError::Oversized {
        len: u64::try_from(len).unwrap_or(u64::MAX),
        cap,
    }
}

/// Checks an announced length against the cap and returns it as a `usize`.
fn announced_length(header: [u8; 4], cap: usize) -> Result<usize, ContractError> {
    let announced = u32::from_be_bytes(header);
    if announced == 0 {
        return Err(ContractError::Empty);
    }
    match usize::try_from(announced) {
        Ok(len) if len <= effective_cap(cap) => Ok(len),
        _ => Err(ContractError::Oversized {
            len: u64::from(announced),
            cap,
        }),
    }
}

/// Encodes `message` as one frame.
///
/// # Errors
/// [`ContractError::Empty`] for a message that encodes to no bytes, [`ContractError::Oversized`] above
/// `cap`.
pub fn encode_frame<M: prost::Message>(message: &M, cap: usize) -> Result<Vec<u8>, ContractError> {
    let len = message.encoded_len();
    if len == 0 {
        return Err(ContractError::Empty);
    }
    if len > effective_cap(cap) {
        return Err(oversized(len, cap));
    }
    let header = u32::try_from(len).map_err(|_| oversized(len, cap))?;
    let mut frame = Vec::with_capacity(len + 4);
    frame.extend_from_slice(&header.to_be_bytes());
    message.encode_raw(&mut frame);
    Ok(frame)
}

/// The message bytes of `buf`, which must hold exactly one frame.
///
/// # Errors
/// Empty, oversized, truncated frames and trailing bytes.
pub fn decode_frame(buf: &[u8], cap: usize) -> Result<&[u8], ContractError> {
    let Some((header, body)) = buf.split_first_chunk::<4>() else {
        return Err(ContractError::TruncatedHeader);
    };
    let len = announced_length(*header, cap)?;
    match body.len().cmp(&len) {
        std::cmp::Ordering::Less => Err(ContractError::TruncatedBody),
        std::cmp::Ordering::Greater => Err(ContractError::TrailingBytes),
        std::cmp::Ordering::Equal => Ok(body),
    }
}

/// Fills `buf` from `reader` until it is full or the stream ends; returns the bytes read.
fn fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize, ContractError> {
    let mut filled = 0;
    while filled < buf.len() {
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        match reader.read(rest) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(ContractError::Io(error.kind())),
        }
    }
    Ok(filled)
}

/// Reads one frame from `reader` and returns its message bytes. The cap is checked before any message
/// byte is read or allocated.
///
/// # Errors
/// Empty, oversized and truncated frames, and read failures.
pub fn read_frame<R: Read>(reader: &mut R, cap: usize) -> Result<Vec<u8>, ContractError> {
    let mut header = [0_u8; 4];
    if fill(reader, &mut header)? < header.len() {
        return Err(ContractError::TruncatedHeader);
    }
    let len = announced_length(header, cap)?;
    let mut body = vec![0_u8; len];
    if fill(reader, &mut body)? < len {
        return Err(ContractError::TruncatedBody);
    }
    Ok(body)
}

/// Writes `message` to `writer` as one frame.
///
/// # Errors
/// As [`encode_frame`], and write failures.
pub fn write_frame<W: Write, M: prost::Message>(
    writer: &mut W,
    message: &M,
    cap: usize,
) -> Result<(), ContractError> {
    let frame = encode_frame(message, cap)?;
    writer
        .write_all(&frame)
        .and_then(|()| writer.flush())
        .map_err(|error| ContractError::Io(error.kind()))
}

/// A missing version reads as major 0; any major other than [`MAJOR`] is refused.
fn check_version(version: Option<&ContractVersion>) -> Result<(), ContractError> {
    let major = version.map_or(0, |version| version.major);
    if major == MAJOR {
        Ok(())
    } else {
        Err(ContractError::UnsupportedMajor(major))
    }
}

/// Decodes and validates a request: contract major, a 32-byte SHA-256, a known origin.
///
/// # Errors
/// Malformed message, unsupported major, invalid fields.
pub fn decode_request(body: &[u8]) -> Result<AnalyzeRequest, ContractError> {
    let request = AnalyzeRequest::decode(body).map_err(|_| ContractError::Malformed)?;
    check_version(request.version.as_ref())?;
    if request.sha256.len() != 32 {
        return Err(ContractError::InvalidRequest("sha256"));
    }
    match Origin::try_from(request.origin) {
        Ok(origin) if origin != Origin::Unspecified => Ok(request),
        _ => Err(ContractError::InvalidRequest("origin")),
    }
}

/// Decodes and validates a response: contract major, engine identity (CTR-03), a known status, a known
/// hint (unspecified allowed), finding severities up to 4, a score in [0, 1] when present.
///
/// # Errors
/// Malformed message, unsupported major, missing engine identity, invalid fields.
pub fn decode_response(body: &[u8]) -> Result<AnalyzeResponse, ContractError> {
    let response = AnalyzeResponse::decode(body).map_err(|_| ContractError::Malformed)?;
    check_version(response.version.as_ref())?;
    for (field, value) in [
        ("engine_id", &response.engine_id),
        ("engine_version", &response.engine_version),
        ("content_version", &response.content_version),
    ] {
        if value.is_empty() {
            return Err(ContractError::MissingEngineIdentity(field));
        }
    }
    match Status::try_from(response.status) {
        Ok(status) if status != Status::Unspecified => {}
        _ => return Err(ContractError::InvalidResponse("status")),
    }
    if Hint::try_from(response.hint).is_err() {
        return Err(ContractError::InvalidResponse("hint"));
    }
    if response
        .findings
        .iter()
        .any(|finding| finding.severity > MAX_SEVERITY)
    {
        return Err(ContractError::InvalidResponse("severity"));
    }
    if let Some(score) = response.score
        && !(0.0..=1.0).contains(&score)
    {
        return Err(ContractError::InvalidScore);
    }
    Ok(response)
}
