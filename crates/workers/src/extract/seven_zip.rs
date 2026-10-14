//! 7z (WP-1.9): each folder is decoded once, front to back, and its entries stream from it; the folder's
//! ratio is the ratio of every entry decoded from it (Q-64). Files without bytes, which belong to no folder,
//! follow. An encrypted folder (AES coder) or header is malformed as encrypted; a coder this build lacks, or
//! an LZMA dictionary over [`DICTIONARY`] (Q-67), is an unsupported method.
//!
//! Checked before anything is decoded: the start header (its checksum present and right, the header ending
//! the object), one packed stream per folder, every one of them used and before the header, and every file
//! with bytes in exactly one folder. The crate pairs a folder's sub-streams with files by position, so the
//! files are put in folder order first: an empty file between two of a folder's files would otherwise take a
//! sub-stream's place and leave the next file unread.

use std::io::{Read, Seek, SeekFrom};

use flate2::Crc;
use sevenz_rust2::{Archive, ArchiveEntry, BlockDecoder, Error, Password};

use super::{ARCHIVE, DICTIONARY, Header, Kind, Malformed, Packed, Run, Stop};

/// The 7zAES coder, the BCJ2 filter (four inputs), LZMA and LZMA2.
const AES: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];
const BCJ2: [u8; 4] = [0x03, 0x03, 0x01, 0x1B];
const LZMA: [u8; 3] = [0x03, 0x01, 0x01];
const LZMA2: [u8; 1] = [0x21];
/// The signature header: signature, version, start header checksum, next header offset, size, checksum.
const START: u64 = 32;

/// 100-nanosecond intervals per second, and seconds from 1601-01-01 (Windows FILETIME) to 1970-01-01.
const TICKS: u64 = 10_000_000;
const FILETIME_TO_UNIX: i64 = 11_644_473_600;

pub(super) fn extract<R: Read + Seek>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let header_at = check_start(object, run.container)?;
    let password = Password::empty();
    let mut archive = Archive::read(object, &password).map_err(|error| refused(&error))?;
    check_coders(&archive)?;
    // One packed stream per folder, in folder order, all of them before the header.
    let sizes = archive.pack_sizes();
    if sizes.len() != archive.blocks.len()
        || archive
            .stream_map
            .block_first_pack_stream_index()
            .iter()
            .enumerate()
            .any(|(index, &first)| index != first)
    {
        return Err(ARCHIVE);
    }
    let packed_end = sizes
        .iter()
        .try_fold(START + archive.pack_pos(), |end, size| {
            end.checked_add(*size)
        })
        .ok_or(ARCHIVE)?;
    if packed_end > header_at {
        return Err(ARCHIVE);
    }
    for entry in archive
        .files
        .iter()
        .filter(|e| e.is_directory() || e.is_anti_item())
    {
        if entry.has_stream() || entry.size() > 0 {
            return Err(ARCHIVE);
        }
        run.check_path(entry.name().as_bytes(), false)?;
    }
    let counts: Vec<usize> = (0..archive.blocks.len())
        .map(|index| BlockDecoder::new(1, index, &archive, &password, object).entry_count())
        .collect();
    regroup(&mut archive, &counts)?;
    for index in 0..archive.blocks.len() {
        let mut packed = Packed::new(*archive.pack_sizes().get(index).ok_or(ARCHIVE)?);
        let mut stopped = None;
        let decoded = BlockDecoder::new(1, index, &archive, &password, object).for_each_entries(
            &mut |entry: &ArchiveEntry, reader: &mut dyn Read| match one(
                run,
                &mut packed,
                entry,
                reader,
            ) {
                Ok(()) => Ok(true),
                Err(stop) => {
                    stopped = Some(stop);
                    Err(Error::Other("extraction stopped".into()))
                }
            },
        );
        if let Some(stop) = stopped {
            return Err(stop);
        }
        decoded.map_err(|error| refused(&error))?;
    }
    // Files without bytes: in no folder.
    for entry in archive
        .files
        .iter()
        .filter(|e| !e.has_stream() && !e.is_directory() && !e.is_anti_item())
    {
        if entry.size() > 0 {
            return Err(ARCHIVE);
        }
        run.begin(&header(entry), false)?;
    }
    Ok(())
}

/// The signature header: its checksum present and right (a zero checksum sends the crate guessing where the
/// header is), the next header ending the object. Returns where the next header starts.
fn check_start<R: Read + Seek>(object: &mut R, container: u64) -> Result<u64, Stop> {
    let mut start = [0_u8; 32];
    object.seek(SeekFrom::Start(0)).map_err(|_| ARCHIVE)?;
    object.read_exact(&mut start).map_err(|_| ARCHIVE)?;
    object.seek(SeekFrom::Start(0)).map_err(|_| ARCHIVE)?;
    let [_, _, _, _, _, _, _, _, c0, c1, c2, c3, rest @ ..] = start;
    let mut crc = Crc::new();
    crc.update(&rest);
    let checksum = u32::from_le_bytes([c0, c1, c2, c3]);
    let [
        o0,
        o1,
        o2,
        o3,
        o4,
        o5,
        o6,
        o7,
        s0,
        s1,
        s2,
        s3,
        s4,
        s5,
        s6,
        s7,
        ..,
    ] = rest;
    let offset = u64::from_le_bytes([o0, o1, o2, o3, o4, o5, o6, o7]);
    let size = u64::from_le_bytes([s0, s1, s2, s3, s4, s5, s6, s7]);
    let header_at = START.checked_add(offset).ok_or(ARCHIVE)?;
    if checksum == 0 || crc.sum() != checksum || header_at.checked_add(size) != Some(container) {
        return Err(ARCHIVE);
    }
    Ok(header_at)
}

/// Encryption, multi-input filters and dictionaries, judged from the folders' coders before decoding.
fn check_coders(archive: &Archive) -> Result<(), Stop> {
    for coder in archive.blocks.iter().flat_map(|block| &block.coders) {
        let id = coder.encoder_method_id();
        let properties = coder.properties();
        let dictionary = if id == AES {
            return Err(Stop::Malformed(Malformed::Encrypted));
        } else if id == BCJ2 {
            return Err(Stop::Malformed(Malformed::Method));
        } else if id == LZMA {
            let bytes = properties.get(1..5).ok_or(ARCHIVE)?;
            u64::from(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
        } else if id == LZMA2 {
            match properties.first() {
                Some(40) => u64::from(u32::MAX),
                Some(&bits) if bits < 40 => (2 | u64::from(bits & 1)) << (bits / 2 + 11),
                _ => return Err(ARCHIVE),
            }
        } else {
            0
        };
        if dictionary > DICTIONARY {
            return Err(Stop::Malformed(Malformed::Method));
        }
    }
    Ok(())
}

/// Puts the files with bytes first, in folder order (`counts` sub-streams per folder), the others after,
/// and maps each file to its folder again. Every folder has a file, every file with bytes has a folder.
fn regroup(archive: &mut Archive, counts: &[usize]) -> Result<(), Stop> {
    let total = counts
        .iter()
        .try_fold(0_usize, |total, count| total.checked_add(*count))
        .ok_or(ARCHIVE)?;
    let (mut files, rest): (Vec<ArchiveEntry>, Vec<ArchiveEntry>) =
        archive.files.drain(..).partition(ArchiveEntry::has_stream);
    if counts.contains(&0) || files.len() != total {
        return Err(ARCHIVE);
    }
    let mut firsts = Vec::with_capacity(counts.len());
    let mut owners = Vec::with_capacity(files.len() + rest.len());
    for (index, count) in counts.iter().enumerate() {
        firsts.push(owners.len());
        owners.extend(std::iter::repeat_n(Some(index), *count));
    }
    owners.extend(std::iter::repeat_n(None, rest.len()));
    files.extend(rest);
    archive.files = files;
    archive.stream_map.block_first_file_index = firsts;
    archive.stream_map.file_block_index = owners;
    Ok(())
}

/// One entry of a folder, its bytes streamed from the folder's decoder.
fn one(
    run: &mut Run<'_>,
    packed: &mut Packed,
    entry: &ArchiveEntry,
    reader: &mut dyn Read,
) -> Result<(), Stop> {
    if entry.is_directory() || entry.is_anti_item() {
        // Checked above; a directory carrying bytes is hidden data.
        return if entry.size() > 0 {
            Err(ARCHIVE)
        } else {
            Ok(())
        };
    }
    let header = header(entry);
    run.begin(&header, false)?;
    // The folder holds exactly the declared sizes: fewer bytes is a cut or corrupt folder.
    run.stream_from(reader, packed, header.size, Malformed::Archive)
}

fn header(entry: &ArchiveEntry) -> Header {
    let modified = entry.has_last_modified_date.then(|| {
        let ticks = u64::from(entry.last_modified_date());
        i64::try_from(ticks / TICKS).map_or(i64::MAX, |seconds| seconds - FILETIME_TO_UNIX)
    });
    Header {
        path: entry.name().as_bytes().to_vec(),
        kind: Kind::Regular,
        size: entry.size(),
        modified,
    }
}

/// The malformation behind a 7z error.
fn refused(error: &Error) -> Stop {
    Stop::Malformed(match error {
        Error::PasswordRequired | Error::MaybeBadPassword(_) => Malformed::Encrypted,
        Error::UnsupportedCompressionMethod(_) | Error::Unsupported(_) => Malformed::Method,
        _ => Malformed::Archive,
    })
}
