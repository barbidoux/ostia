//! The extraction worker's formats (FR-06, ADR-18): zip, tar and gzip (WP-1.8). Entries go to a [`Sink`] as
//! they stream: a header, then the entry's bytes in chunks of at most [`CHUNK`] bytes. The policy's limits
//! are checked while streaming, never after: an extraction stops at the first byte or entry beyond them.

use std::io::{self, Read, Seek};

use ostia_core_domain::types::DetectedType;
use ostia_core_domain::verdict::Limit;

/// Largest chunk of entry bytes handed to the sink at once.
pub const CHUNK: usize = 64 * 1024;

/// A container format this worker extracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// `zip` (stored and deflated entries).
    Zip,
    /// `tar` (ustar, GNU and pax headers).
    Tar,
    /// `gzip` (one entry: every member, concatenated).
    Gzip,
}

impl Format {
    /// The format of a detected type, if this worker extracts it.
    #[must_use]
    pub fn of(detected: DetectedType) -> Option<Self> {
        let _ = detected;
        todo!("WP-1.8: Format::of")
    }
}

/// What the extraction may still produce (the request's `ExtractionBudget`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    /// Largest uncompressed / compressed ratio, per entry and for the whole container.
    pub max_ratio: u64,
    /// Bytes the extraction may still produce.
    pub remaining_bytes: u64,
    /// Entries the extraction may still produce.
    pub remaining_entries: u64,
    /// Largest entry path, in bytes.
    pub max_path_length: u32,
}

/// What an entry is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A regular file: its bytes follow.
    Regular,
    /// A symbolic or hard link: no bytes, never followed.
    Link,
    /// A device, FIFO or socket: no bytes.
    Special,
}

/// One entry, announced before its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Path inside the container, as stored; empty for a gzip file whose member records no name.
    pub path: Vec<u8>,
    /// What the entry is.
    pub kind: Kind,
    /// Bytes that follow (0 for a link or a special entry).
    pub size: u64,
    /// Modification time in seconds since the Unix epoch (UTC), when the container records one.
    pub modified: Option<i64>,
}

/// Where entries go.
pub trait Sink {
    /// The next entry begins.
    ///
    /// # Errors
    /// Any error stops the extraction ([`Stop::Sink`]).
    fn entry(&mut self, header: &Header) -> io::Result<()>;

    /// The next bytes of the current entry.
    ///
    /// # Errors
    /// Any error stops the extraction ([`Stop::Sink`]).
    fn data(&mut self, bytes: &[u8]) -> io::Result<()>;
}

/// Why a container could not be extracted (policy.md R1: UNSCANNABLE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Malformed {
    /// The structure cannot be read: truncated, corrupt, a bad checksum, trailing bytes.
    Archive,
    /// An encrypted entry.
    Encrypted,
    /// An entry compressed with a method this worker does not extract.
    Method,
    /// An entry path that is empty, absolute, has a `..` component or holds a NUL byte.
    Path,
    /// An entry whose bytes do not match its declared size.
    Size,
}

/// Why an extraction stopped before its end.
#[derive(Debug)]
pub enum Stop {
    /// A limit of the budget was reached (`ratio`, `total_size`, `entry_count`, `path_length`).
    Limit(Limit),
    /// The container is malformed.
    Malformed(Malformed),
    /// The sink refused an entry or its bytes.
    Sink(io::Error),
}

/// Extracts `object`, a container of `format`, into `sink` under `budget`.
///
/// # Errors
/// The first limit reached, the first malformation found, or the sink's error.
pub fn extract<R: Read + Seek>(
    format: Format,
    object: &mut R,
    budget: &Budget,
    sink: &mut dyn Sink,
) -> Result<(), Stop> {
    let _ = (format, object, budget, sink);
    todo!("WP-1.8: extract")
}
