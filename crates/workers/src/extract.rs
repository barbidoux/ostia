//! The extraction worker's formats (FR-06, ADR-18): zip, tar and gzip (WP-1.8); 7z, rar, cab, iso and msi
//! (WP-1.9). Entries go to a [`Sink`] as they stream: a header, then the entry's bytes in chunks of at most
//! [`CHUNK`] bytes. The policy's limits are checked while streaming, never after: an extraction stops at the
//! first byte or entry beyond them.

mod cab;
mod iso;
mod msi;
mod rar;
mod seven_zip;

use std::io::{self, BufReader, ErrorKind, Read, Seek, SeekFrom};

use flate2::Crc;
use flate2::bufread::{DeflateDecoder, MultiGzDecoder};
use ostia_core_domain::entry::{EntryPathError, check_entry_path};
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
    /// `7z` (LZMA, LZMA2, BCJ, delta and copy coders).
    SevenZip,
    /// `rar` (RAR 1.3 to RAR 7, one volume).
    Rar,
    /// `cab` (stored, MSZIP and LZX folders).
    Cab,
    /// `iso9660` (the Joliet tree when there is one, else the primary one).
    Iso,
    /// `msi` (every stream of its compound file).
    Msi,
}

impl Format {
    /// The format of a detected type, if this worker extracts it.
    #[must_use]
    pub fn of(detected: DetectedType) -> Option<Self> {
        match detected {
            DetectedType::Zip => Some(Self::Zip),
            DetectedType::Tar => Some(Self::Tar),
            DetectedType::Gzip => Some(Self::Gzip),
            DetectedType::SevenZip => Some(Self::SevenZip),
            DetectedType::Rar => Some(Self::Rar),
            DetectedType::Cab => Some(Self::Cab),
            DetectedType::Iso9660 => Some(Self::Iso),
            DetectedType::Msi => Some(Self::Msi),
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

/// Extracts `object`, a container of `format`, into `sink` under `budget`. The object is owned: the rar
/// reader keeps its source.
///
/// # Errors
/// The first limit reached, the first malformation found, or the sink's error.
pub fn extract<R: Read + Seek + Send + 'static>(
    format: Format,
    mut object: R,
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
        Format::Zip => zip(&mut object, &mut run),
        Format::Tar => tar(&mut object, &mut run),
        Format::Gzip => gzip(&mut object, &mut run),
        Format::SevenZip => seven_zip::extract(&mut object, &mut run),
        Format::Rar => rar::extract(object, &mut run),
        Format::Cab => cab::extract(&mut object, &mut run),
        Format::Iso => iso::extract(&mut object, &mut run),
        Format::Msi => msi::extract(object, &mut run),
    }
}

const ARCHIVE: Stop = Stop::Malformed(Malformed::Archive);

/// The compressed bytes entries are decoded from, and how much was decoded from them so far: one entry's own
/// (zip, tar, gzip, iso, msi), or one stream several entries share (a 7z folder, a cabinet folder, a solid
/// run of rar members), whose ratio is then the ratio of every entry decoded from it (Q-64).
struct Packed {
    /// Compressed bytes in the container.
    size: u64,
    /// Bytes decoded from them so far.
    decoded: u64,
}

impl Packed {
    fn new(size: u64) -> Self {
        Self { size, decoded: 0 }
    }
}

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
        match check_entry_path(path, self.budget.max_path_length) {
            Ok(()) => Ok(()),
            Err(EntryPathError::Empty) if unnamed => Ok(()),
            Err(EntryPathError::Empty | EntryPathError::Leaves) => {
                Err(Stop::Malformed(Malformed::Path))
            }
            Err(EntryPathError::TooLong) => Err(Stop::Limit(Limit::PathLength)),
        }
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
        self.stream_from(reader, &mut Packed::new(compressed), declared, short)
    }

    /// As [`Run::stream`], the entry's ratio being the ratio of `packed`, which it may share (Q-64).
    fn stream_from(
        &mut self,
        reader: &mut dyn Read,
        packed: &mut Packed,
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
            self.accept(
                packed,
                &mut got,
                declared,
                buffer.get(..read).unwrap_or_default(),
            )?;
        }
        if got == declared {
            Ok(())
        } else {
            Err(Stop::Malformed(short))
        }
    }

    /// Hands `bytes` (at most [`CHUNK`]) of the current entry to the sink once the limits allow them: `got`
    /// bytes of the entry so far, of `declared`, decoded from `packed`.
    fn accept(
        &mut self,
        packed: &mut Packed,
        got: &mut u64,
        declared: u64,
        bytes: &[u8],
    ) -> Result<(), Stop> {
        let count = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        *got = got.saturating_add(count);
        if *got > declared {
            return Err(Stop::Malformed(Malformed::Size));
        }
        self.produced = self.produced.saturating_add(count);
        if self.produced > self.budget.remaining_bytes {
            return Err(Stop::Limit(Limit::TotalSize));
        }
        packed.decoded = packed.decoded.saturating_add(count);
        if over_ratio(packed.decoded, packed.size, self.budget.max_ratio)
            || over_ratio(self.produced, self.container, self.budget.max_ratio)
        {
            return Err(Stop::Limit(Limit::Ratio));
        }
        self.sink.data(bytes).map_err(Stop::Sink)
    }
}

/// `produced` bytes from `compressed` ones exceed `max_ratio` (an empty source counts as one byte).
fn over_ratio(produced: u64, compressed: u64, max_ratio: u64) -> bool {
    u128::from(produced) > u128::from(max_ratio) * u128::from(compressed.max(1))
}

fn zip<R: Read + Seek>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    check_zip_layout(object)?;
    object.seek(SeekFrom::Start(0)).map_err(|_| ARCHIVE)?;
    let mut archive = ZipArchive::new(object).map_err(|_| ARCHIVE)?;
    for index in 0..archive.len() {
        let (header, compressed, crc, deflated) = {
            let entry = archive.by_index_raw(index).map_err(|_| ARCHIVE)?;
            let path = entry.name_raw().to_vec();
            if entry.is_dir() {
                // A directory has no bytes (a deflated empty stream is 2): any more is hidden data.
                if entry.size() > 0 || entry.compressed_size() > 2 {
                    return Err(ARCHIVE);
                }
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
            if !deflated && entry.compressed_size() != entry.size() {
                return Err(Stop::Malformed(Malformed::Size));
            }
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
            // The raw bytes, decoded here: the sizes and the CRC are checked by this code, not the crate.
            let raw = archive.by_index_raw(index).map_err(|_| ARCHIVE)?;
            let sum = if deflated {
                let mut decoder = DeflateDecoder::new(BufReader::new(raw));
                let mut checked = Checked {
                    inner: &mut decoder,
                    crc: Crc::new(),
                };
                run.stream(&mut checked, compressed, header.size, Malformed::Size)?;
                let sum = checked.crc.sum();
                // Every declared compressed byte belongs to the stream.
                let mut rest = decoder.into_inner();
                let mut byte = [0_u8; 1];
                if rest.read(&mut byte).map_err(|_| ARCHIVE)? != 0 {
                    return Err(Stop::Malformed(Malformed::Size));
                }
                sum
            } else {
                let mut checked = Checked {
                    inner: raw,
                    crc: Crc::new(),
                };
                run.stream(&mut checked, compressed, header.size, Malformed::Size)?;
                checked.crc.sum()
            };
            if sum != crc {
                return Err(ARCHIVE);
            }
        }
    }
    Ok(())
}

/// One entry's place in a zip: where its local header starts, where its bytes end, what a data descriptor
/// after them must hold.
struct Placed {
    start: u64,
    /// Where its central directory record starts.
    central: u64,
    end: u64,
    crc: u32,
    compressed: u64,
    size: u64,
}

/// Every byte before the central directory belongs to exactly one entry: its local header, its bytes and an
/// optional data descriptor. A name listed twice (a reader keeps one record per name), an entry listed only by
/// its local header, bytes between entries, entries sharing bytes, a compressed size that lies: malformed.
fn check_zip_layout<R: Read + Seek>(object: &mut R) -> Result<(), Stop> {
    let mut archive = ZipArchive::new(&mut *object).map_err(|_| ARCHIVE)?;
    if archive.offset() != 0 {
        return Err(ARCHIVE);
    }
    let directory = archive.central_directory_start();
    let mut placed = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let entry = archive.by_index_raw(index).map_err(|_| ARCHIVE)?;
        let data = entry.data_start().ok_or(ARCHIVE)?;
        placed.push(Placed {
            start: entry.header_start(),
            central: entry.central_header_start(),
            end: data.checked_add(entry.compressed_size()).ok_or(ARCHIVE)?,
            crc: entry.crc32(),
            compressed: entry.compressed_size(),
            size: entry.size(),
        });
    }
    drop(archive);
    placed.sort_by_key(|entry| entry.start);
    let mut expected = 0;
    for (index, entry) in placed.iter().enumerate() {
        if entry.start != expected || entry.end < entry.start {
            return Err(ARCHIVE);
        }
        check_local_header(object, entry)?;
        let next = placed.get(index + 1).map_or(directory, |next| next.start);
        let gap = next.checked_sub(entry.end).ok_or(ARCHIVE)?;
        if gap != 0 {
            check_descriptor(object, entry, gap)?;
        }
        expected = next;
    }
    if expected != directory {
        return Err(ARCHIVE);
    }
    Ok(())
}

/// The local header says what the central record says: name, flags, method, and CRC and sizes unless a data
/// descriptor carries them (flag bit 3). Streaming extractors read the local header only.
fn check_local_header<R: Read + Seek>(object: &mut R, entry: &Placed) -> Result<(), Stop> {
    let mut read_at = |offset: u64, buffer: &mut [u8]| {
        object
            .seek(SeekFrom::Start(offset))
            .and_then(|_| object.read_exact(buffer))
            .map_err(|_| ARCHIVE)
    };
    let mut local = [0_u8; 30];
    let mut central = [0_u8; 46];
    read_at(entry.start, &mut local)?;
    read_at(entry.central, &mut central)?;
    let field = |bytes: &[u8], at: usize, len: usize| bytes.get(at..at + len).map(<[u8]>::to_vec);
    let same = |local_at: usize, central_at: usize, len: usize| {
        field(&local, local_at, len).is_some()
            && field(&local, local_at, len) == field(&central, central_at, len)
    };
    let descriptor = local.get(6).is_some_and(|flags| flags & 0x08 != 0);
    let consistent = local.starts_with(b"PK\x03\x04")
        && central.starts_with(b"PK\x01\x02")
        // flags, method; name length
        && same(6, 8, 4)
        && same(26, 28, 2)
        // CRC, compressed size, size
        && (descriptor || same(14, 16, 12));
    if !consistent {
        return Err(ARCHIVE);
    }
    let length = usize::from(u16::from_le_bytes([local[26], local[27]]));
    let mut local_name = vec![0_u8; length];
    let mut central_name = vec![0_u8; length];
    read_at(entry.start + 30, &mut local_name)?;
    read_at(entry.central + 46, &mut central_name)?;
    if local_name == central_name {
        Ok(())
    } else {
        Err(ARCHIVE)
    }
}

/// The `gap` bytes after an entry are its data descriptor: an optional signature, its CRC, then its sizes in 32
/// or 64 bits.
fn check_descriptor<R: Read + Seek>(object: &mut R, entry: &Placed, gap: u64) -> Result<(), Stop> {
    if !matches!(gap, 12 | 16 | 20 | 24) {
        return Err(ARCHIVE);
    }
    let mut bytes = [0_u8; 24];
    let bytes = bytes
        .get_mut(..usize::try_from(gap).map_err(|_| ARCHIVE)?)
        .ok_or(ARCHIVE)?;
    object
        .seek(SeekFrom::Start(entry.end))
        .and_then(|_| object.read_exact(bytes))
        .map_err(|_| ARCHIVE)?;
    let body = match bytes.strip_prefix(b"PK\x07\x08") {
        Some(body) if gap == 16 || gap == 24 => body,
        _ if gap == 12 || gap == 20 => &bytes[..],
        _ => return Err(ARCHIVE),
    };
    let field = |at: usize, len: usize| -> Option<u64> {
        let raw = body.get(at..at + len)?;
        Some(
            raw.iter()
                .rev()
                .fold(0_u64, |value, &byte| (value << 8) | u64::from(byte)),
        )
    };
    let width = if body.len() == 12 { 4 } else { 8 };
    let matches = field(0, 4) == Some(u64::from(entry.crc))
        && field(4, width) == Some(entry.compressed)
        && field(4 + width, width) == Some(entry.size);
    if matches { Ok(()) } else { Err(ARCHIVE) }
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

/// Seconds since the Unix epoch of a DOS date and time, read as UTC.
fn dos_time(date: u16, time: u16) -> Option<i64> {
    let field = |value: u16, shift: u16, mask: u16| u8::try_from((value >> shift) & mask).ok();
    epoch_seconds(
        1980 + (date >> 9),
        field(date, 5, 0x0F)?,
        field(date, 0, 0x1F)?,
        field(time, 11, 0x1F)?,
        field(time, 5, 0x3F)?,
        field(time, 0, 0x1F)? * 2,
    )
}

fn tar<R: Read>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let mut archive = tar::Archive::new(&mut *object);
    for entry in archive.entries().map_err(|_| ARCHIVE)? {
        let mut entry = entry.map_err(|_| ARCHIVE)?;
        let path = entry.path_bytes().into_owned();
        let entry_type = entry.header().entry_type();
        // Only a regular member carries bytes: any in a directory, link or special member is hidden data.
        let regular = matches!(
            entry_type,
            EntryType::Regular | EntryType::Continuous | EntryType::GNUSparse
        );
        if !regular && entry_type != EntryType::XGlobalHeader && entry.size() > 0 {
            return Err(ARCHIVE);
        }
        let kind = match entry_type {
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
    // After the end marker, only zeros (the second zero block, record padding).
    let object = archive.into_inner();
    let mut rest = vec![0_u8; CHUNK];
    loop {
        match object.read(&mut rest) {
            Ok(0) => return Ok(()),
            Ok(read) => {
                if rest.get(..read).unwrap_or_default().iter().any(|&b| b != 0) {
                    return Err(ARCHIVE);
                }
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(_) => return Err(ARCHIVE),
        }
    }
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
