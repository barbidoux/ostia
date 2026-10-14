//! 7z (WP-1.9): each folder is decoded once, front to back, and its entries stream from it; the folder's
//! ratio is the ratio of every entry decoded from it (Q-64). Files without bytes, which belong to no folder,
//! follow. An encrypted folder (AES coder) or header is malformed as encrypted, a coder this build lacks as
//! an unsupported method.

use std::io::{Read, Seek};

use sevenz_rust2::{Archive, ArchiveEntry, BlockDecoder, Error, Password};

use super::{ARCHIVE, Header, Kind, Malformed, Packed, Run, Stop};

/// The 7zAES coder.
const AES: [u8; 4] = [0x06, 0xF1, 0x07, 0x01];

/// 100-nanosecond intervals per second, and seconds from 1601-01-01 (Windows FILETIME) to 1970-01-01.
const TICKS: u64 = 10_000_000;
const FILETIME_TO_UNIX: i64 = 11_644_473_600;

pub(super) fn extract<R: Read + Seek>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let password = Password::empty();
    let archive = Archive::read(object, &password).map_err(|error| refused(&error))?;
    if archive
        .blocks
        .iter()
        .flat_map(|block| &block.coders)
        .any(|coder| coder.encoder_method_id() == AES)
    {
        return Err(Stop::Malformed(Malformed::Encrypted));
    }
    for entry in archive
        .files
        .iter()
        .filter(|e| e.is_directory() || e.is_anti_item())
    {
        if entry.has_stream() && entry.size() > 0 {
            return Err(ARCHIVE);
        }
        run.check_path(entry.name().as_bytes(), false)?;
    }
    let firsts = archive.stream_map.block_first_pack_stream_index();
    let sizes = archive.pack_sizes();
    for index in 0..archive.blocks.len() {
        let first = *firsts.get(index).ok_or(ARCHIVE)?;
        let end = firsts.get(index + 1).copied().unwrap_or(sizes.len());
        let packed = sizes
            .get(first..end)
            .ok_or(ARCHIVE)?
            .iter()
            .fold(0_u64, |total, size| total.saturating_add(*size));
        let mut packed = Packed::new(packed);
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
    for (index, entry) in archive.files.iter().enumerate() {
        let in_folder = archive
            .stream_map
            .file_block_index
            .get(index)
            .copied()
            .flatten()
            .is_some();
        if !in_folder && !entry.is_directory() && !entry.is_anti_item() {
            // In no folder, a file has no bytes: one claiming some is malformed.
            if entry.has_stream() || entry.size() > 0 {
                return Err(ARCHIVE);
            }
            run.begin(&header(entry), false)?;
        }
    }
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
