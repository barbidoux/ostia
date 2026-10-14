//! The extraction worker's formats (FR-06, ADR-18): zip, tar and gzip (WP-1.8). Entries go to a [`Sink`] as
//! they stream: a header, then the entry's bytes in chunks of at most [`CHUNK`] bytes. The policy's limits
//! are checked while streaming, never after: an extraction stops at the first byte or entry beyond them.

use std::io::{self, BufReader, ErrorKind, Read, Seek, SeekFrom};

use flate2::Crc;
use flate2::bufread::MultiGzDecoder;
use flate2::read::DeflateDecoder;
use ostia_core_domain::types::DetectedType;
use ostia_core_domain::verdict::Limit;
use tar::EntryType;
use zip::{CompressionMethod, ZipArchive};

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
        match detected {
            DetectedType::Zip => Some(Self::Zip),
            DetectedType::Tar => Some(Self::Tar),
            DetectedType::Gzip => Some(Self::Gzip),
            _ => None,
        }
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
    let container = object
        .seek(SeekFrom::End(0))
        .and_then(|end| object.seek(SeekFrom::Start(0)).map(|_| end))
        .map_err(|_| Stop::Malformed(Malformed::Archive))?;
    let mut run = Run {
        budget,
        sink,
        container,
        produced: 0,
        entries: 0,
    };
    match format {
        Format::Zip => zip(object, &mut run),
        Format::Tar => tar(object, &mut run),
        Format::Gzip => gzip(object, &mut run),
    }
}

const ARCHIVE: Stop = Stop::Malformed(Malformed::Archive);

/// One extraction's running totals against its budget.
struct Run<'a> {
    budget: &'a Budget,
    sink: &'a mut dyn Sink,
    /// Size of the container, the denominator of its ratio.
    container: u64,
    /// Bytes produced so far, all entries.
    produced: u64,
    /// Entries begun so far.
    entries: u64,
}

impl Run<'_> {
    /// Checks a path (`unnamed`: an empty path is allowed) against the rules and the length limit.
    fn check_path(&self, path: &[u8], unnamed: bool) -> Result<(), Stop> {
        let leaves = path.first() == Some(&b'/')
            || path.contains(&0)
            || path.split(|&b| b == b'/').any(|part| part == b"..");
        if leaves || (path.is_empty() && !unnamed) {
            return Err(Stop::Malformed(Malformed::Path));
        }
        if path.len() > usize::try_from(self.budget.max_path_length).unwrap_or(usize::MAX) {
            return Err(Stop::Limit(Limit::PathLength));
        }
        Ok(())
    }

    /// Announces an entry once its path, the path length and the entry count allow it.
    fn begin(&mut self, header: &Header, unnamed: bool) -> Result<(), Stop> {
        self.check_path(&header.path, unnamed)?;
        self.entries += 1;
        if self.entries > self.budget.remaining_entries {
            return Err(Stop::Limit(Limit::EntryCount));
        }
        self.sink.entry(header).map_err(Stop::Sink)
    }

    /// Streams an entry's decoded bytes to the sink: exactly `declared` bytes (fewer: `short`; more: a size
    /// mismatch), within the remaining total and the ratio of the entry (`compressed` bytes in the
    /// container) and of the container. A chunk that would breach a limit is never handed over.
    fn stream(
        &mut self,
        reader: &mut dyn Read,
        compressed: u64,
        declared: u64,
        short: Malformed,
    ) -> Result<(), Stop> {
        let mut buffer = vec![0_u8; CHUNK];
        let mut got: u64 = 0;
        loop {
            // One byte past the declared size is enough to see a lie.
            let room = declared.saturating_sub(got).saturating_add(1);
            let want = usize::try_from(room).map_or(CHUNK, |room| room.min(CHUNK));
            let read = match reader.read(buffer.get_mut(..want).unwrap_or_default()) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(ARCHIVE),
            };
            let count = u64::try_from(read).unwrap_or(u64::MAX);
            got = got.saturating_add(count);
            if got > declared {
                return Err(Stop::Malformed(Malformed::Size));
            }
            self.produced = self.produced.saturating_add(count);
            if self.produced > self.budget.remaining_bytes {
                return Err(Stop::Limit(Limit::TotalSize));
            }
            if over_ratio(got, compressed, self.budget.max_ratio)
                || over_ratio(self.produced, self.container, self.budget.max_ratio)
            {
                return Err(Stop::Limit(Limit::Ratio));
            }
            self.sink
                .data(buffer.get(..read).unwrap_or_default())
                .map_err(Stop::Sink)?;
        }
        if got == declared {
            Ok(())
        } else {
            Err(Stop::Malformed(short))
        }
    }
}

/// `produced` bytes from `compressed` ones exceed `max_ratio` (an empty source counts as one byte).
fn over_ratio(produced: u64, compressed: u64, max_ratio: u64) -> bool {
    u128::from(produced) > u128::from(max_ratio) * u128::from(compressed.max(1))
}

fn zip<R: Read + Seek>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let mut archive = ZipArchive::new(object).map_err(|_| ARCHIVE)?;
    for index in 0..archive.len() {
        let (header, compressed, crc, deflated) = {
            let entry = archive.by_index_raw(index).map_err(|_| ARCHIVE)?;
            let path = entry.name_raw().to_vec();
            if entry.is_dir() {
                run.check_path(&path, false)?;
                continue;
            }
            if entry.encrypted() {
                return Err(Stop::Malformed(Malformed::Encrypted));
            }
            let deflated = match entry.compression() {
                CompressionMethod::Stored => false,
                CompressionMethod::Deflated => true,
                _ => return Err(Stop::Malformed(Malformed::Method)),
            };
            let kind = if entry.is_symlink() {
                Kind::Link
            } else {
                Kind::Regular
            };
            let size = if kind == Kind::Regular {
                entry.size()
            } else {
                0
            };
            let modified = entry.last_modified().and_then(|time| {
                epoch_seconds(
                    time.year(),
                    time.month(),
                    time.day(),
                    time.hour(),
                    time.minute(),
                    time.second(),
                )
            });
            let header = Header {
                path,
                kind,
                size,
                modified,
            };
            (header, entry.compressed_size(), entry.crc32(), deflated)
        };
        run.begin(&header, false)?;
        if header.kind == Kind::Regular {
            // The raw bytes, decoded here: the size and the CRC are checked by this code, not the crate.
            let raw = archive.by_index_raw(index).map_err(|_| ARCHIVE)?;
            let decoded: Box<dyn Read + '_> = if deflated {
                Box::new(DeflateDecoder::new(raw))
            } else {
                Box::new(raw)
            };
            let mut checked = Checked {
                inner: decoded,
                crc: Crc::new(),
            };
            run.stream(&mut checked, compressed, header.size, Malformed::Size)?;
            if checked.crc.sum() != crc {
                return Err(ARCHIVE);
            }
        }
    }
    Ok(())
}

/// A reader computing the CRC-32 of the bytes it hands out.
struct Checked<R> {
    inner: R,
    crc: Crc,
}

impl<R: Read> Read for Checked<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buffer)?;
        self.crc.update(buffer.get(..read).unwrap_or_default());
        Ok(read)
    }
}

/// Seconds since the Unix epoch of a calendar time read as UTC (days from civil, H. Hinnant).
fn epoch_seconds(year: u16, month: u8, day: u8, hour: u8, minute: u8, second: u8) -> Option<i64> {
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let month = i64::from(month);
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let day_of_year = (153 * ((month + 9) % 12) + 2) / 5 + i64::from(day) - 1;
    let of_cycle = of_era * 365 + of_era / 4 - of_era / 100 + day_of_year;
    let days = era * 146_097 + of_cycle - 719_468;
    Some(days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))
}

fn tar<R: Read>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let mut archive = tar::Archive::new(object);
    for entry in archive.entries().map_err(|_| ARCHIVE)? {
        let mut entry = entry.map_err(|_| ARCHIVE)?;
        let path = entry.path_bytes().into_owned();
        let kind = match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse => Kind::Regular,
            EntryType::Symlink | EntryType::Link => Kind::Link,
            EntryType::Char | EntryType::Block | EntryType::Fifo => Kind::Special,
            EntryType::Directory => {
                run.check_path(&path, false)?;
                continue;
            }
            EntryType::XGlobalHeader => continue,
            _ => return Err(ARCHIVE),
        };
        let size = if kind == Kind::Regular {
            entry.size()
        } else {
            0
        };
        let compressed = entry.header().entry_size().map_err(|_| ARCHIVE)?;
        let modified = entry
            .header()
            .mtime()
            .ok()
            .and_then(|time| i64::try_from(time).ok());
        let header = Header {
            path,
            kind,
            size,
            modified,
        };
        run.begin(&header, false)?;
        if kind == Kind::Regular {
            // Tar sizes are exact: fewer bytes than announced is a cut archive.
            run.stream(&mut entry, compressed, size, Malformed::Archive)?;
        }
    }
    Ok(())
}

/// A gzip file is one entry: every member, concatenated, as gunzip reads them. Its size is not recorded
/// (ISIZE is modulo 2^32 and per member), so a first pass decodes and counts it under the limits, then a
/// second one streams it.
fn gzip<R: Read + Seek>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let (size, name, mtime) = {
        let mut decoder = MultiGzDecoder::new(BufReader::new(&mut *object));
        let mut buffer = vec![0_u8; CHUNK];
        let mut size: u64 = 0;
        let mut first: Option<(Vec<u8>, u32)> = None;
        loop {
            let read = match decoder.read(&mut buffer) {
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(ARCHIVE),
            };
            if first.is_none()
                && let Some(header) = decoder.header()
            {
                first = Some((
                    header.filename().unwrap_or_default().to_vec(),
                    header.mtime(),
                ));
            }
            if read == 0 {
                break;
            }
            size = size.saturating_add(u64::try_from(read).unwrap_or(u64::MAX));
            if size > run.budget.remaining_bytes {
                return Err(Stop::Limit(Limit::TotalSize));
            }
            if over_ratio(size, run.container, run.budget.max_ratio) {
                return Err(Stop::Limit(Limit::Ratio));
            }
        }
        let (name, mtime) = first.ok_or(ARCHIVE)?;
        (size, name, mtime)
    };
    object.seek(SeekFrom::Start(0)).map_err(|_| ARCHIVE)?;
    let header = Header {
        path: name,
        kind: Kind::Regular,
        size,
        modified: (mtime != 0).then_some(i64::from(mtime)),
    };
    run.begin(&header, true)?;
    let mut decoder = MultiGzDecoder::new(BufReader::new(object));
    run.stream(&mut decoder, run.container, size, Malformed::Archive)
}
