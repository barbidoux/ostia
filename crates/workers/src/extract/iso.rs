//! ISO 9660 (WP-1.9), read by this code (Q-63, Q-65): the volume descriptors from sector 16 up to their
//! terminator. Every tree is walked, the primary one and each supplementary one, and they must list the same
//! files (extent and size): a file one tree hides from another is malformed. The entries are those of the
//! Joliet tree when there is one, else of the primary tree: named without their version (`;1`) and, for
//! primary names, their trailing dot, dated by their record. Directories are walked breadth first, every extent
//! checked to lie in the image, every directory visited once, and no more directory sectors read than the
//! volume has. Fail closed on what this code does not read (Q-65): a boot record (El Torito), a volume
//! partition descriptor or a UDF volume recognition sequence after the terminator is an unsupported method,
//! and the volume must be the whole object. A value whose two byte orders disagree is malformed;
//! multi-extent and interleaved files and extended attribute records are unsupported methods. Nothing is
//! compressed: a file's ratio is 1, and the container's ratio bounds files sharing their bytes.

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};

use super::{ARCHIVE, Header, Kind, Malformed, Run, Stop, epoch_seconds};

const SECTOR: u64 = 2048;
/// The first volume descriptor's sector, and how many descriptors may precede the terminator.
const FIRST: u64 = 16;
const DESCRIPTORS: u64 = 64;
/// The smallest directory record (one-byte identifier).
const RECORD: usize = 34;
const DIRECTORY: u8 = 0x02;
const MULTI_EXTENT: u8 = 0x80;
/// Descriptor types: boot record, primary, supplementary, volume partition, terminator.
const BOOT: u8 = 0;
const PRIMARY: u8 = 1;
const SUPPLEMENTARY: u8 = 2;
const PARTITION: u8 = 3;
const TERMINATOR: u8 = 255;
/// Identifiers of the volume recognition sequence (ECMA-167) that follows the descriptors on a UDF volume.
const RECOGNITION: [&[u8]; 6] = [b"BEA01", b"NSR02", b"NSR03", b"TEA01", b"BOOT2", b"CDW02"];

/// A directory record, as far as extraction needs it.
struct Record {
    extent: u32,
    size: u32,
    flags: u8,
    /// Extended attribute record length, file unit size, interleave gap: all zero for a plain extent.
    layout: [u8; 3],
    date: [u8; 7],
    name: Vec<u8>,
}

/// A directory tree: its root, and whether its names are Joliet (UCS-2) ones.
struct Tree {
    root: Record,
    joliet: bool,
}

pub(super) fn extract<R: Read + Seek>(object: &mut R, run: &mut Run<'_>) -> Result<(), Stop> {
    let trees = volume(object, run.container)?;
    let mut listed: Option<Vec<(u32, u32)>> = None;
    for tree in &trees {
        let mut files = walk(object, run, tree, false)?;
        files.sort_unstable();
        match &listed {
            Some(first) if *first != files => return Err(ARCHIVE),
            Some(_) => {}
            None => listed = Some(files),
        }
    }
    let shown = trees
        .iter()
        .find(|tree| tree.joliet)
        .or_else(|| trees.first())
        .ok_or(ARCHIVE)?;
    walk(object, run, shown, true).map(|_| ())
}

/// Walks `tree` breadth first and returns its files (extent and size; an empty file's extent counts as 0).
/// With `entries`, each file is also an entry and each path is checked.
fn walk<R: Read + Seek>(
    object: &mut R,
    run: &mut Run<'_>,
    tree: &Tree,
    entries: bool,
) -> Result<Vec<(u32, u32)>, Stop> {
    let mut files = Vec::new();
    let mut budget = run.container / SECTOR;
    let mut visited = HashSet::from([tree.root.extent]);
    let root = Record {
        name: Vec::new(),
        ..tree.root
    };
    let mut pending = VecDeque::from([(Vec::new(), root)]);
    while let Some((prefix, directory)) = pending.pop_front() {
        let sectors = u64::from(directory.size).div_ceil(SECTOR);
        within(u64::from(directory.extent), sectors * SECTOR, run.container)?;
        // Directories that overlap could make the walk read the image many times over.
        budget = budget.checked_sub(sectors).ok_or(ARCHIVE)?;
        for sector in 0..sectors {
            let block = read_sector(object, u64::from(directory.extent) + sector)?;
            let mut at = 0;
            while let Some(record) = next_record(&block, &mut at)? {
                if record.name == [0] || record.name == [1] {
                    continue; // `.` and `..`
                }
                if record.flags & MULTI_EXTENT != 0 || record.layout != [0, 0, 0] {
                    return Err(Stop::Malformed(Malformed::Method));
                }
                let is_directory = record.flags & DIRECTORY != 0;
                let mut path = prefix.clone();
                if entries {
                    if !path.is_empty() {
                        path.push(b'/');
                    }
                    path.extend_from_slice(&name(&record.name, tree.joliet, is_directory)?);
                }
                if is_directory {
                    if entries {
                        run.check_path(&path, false)?;
                    }
                    // A directory reached twice (a loop, or two names for one) is malformed.
                    if !visited.insert(record.extent) {
                        return Err(ARCHIVE);
                    }
                    pending.push_back((path, record));
                } else {
                    files.push(if record.size == 0 {
                        (0, 0)
                    } else {
                        (record.extent, record.size)
                    });
                    if entries {
                        file(object, run, path, &record)?;
                    }
                }
            }
        }
    }
    Ok(files)
}

/// The trees of the volume, the primary one first. A boot record, a volume partition descriptor or a
/// recognition sequence after the terminator is refused; the volume must be the whole image.
fn volume<R: Read + Seek>(object: &mut R, image: u64) -> Result<Vec<Tree>, Stop> {
    let mut trees: Vec<Tree> = Vec::new();
    let mut size = None;
    for index in 0..DESCRIPTORS {
        let block = read_sector(object, FIRST + index)?;
        if block.get(1..6) != Some(b"CD001".as_slice()) {
            return Err(ARCHIVE);
        }
        match block.first().copied() {
            Some(TERMINATOR) => {
                recognition(object, image, FIRST + index + 1)?;
                // The primary descriptor gives the volume's size, and its tree comes first.
                if trees.first().is_none_or(|tree| tree.joliet) || size != Some(image) {
                    return Err(ARCHIVE);
                }
                for tree in &trees {
                    within(
                        u64::from(tree.root.extent),
                        u64::from(tree.root.size),
                        image,
                    )?;
                }
                return Ok(trees);
            }
            Some(kind @ (PRIMARY | SUPPLEMENTARY)) => {
                if both16(&block, 128)? != 2048 {
                    return Err(ARCHIVE);
                }
                let mut at = 156;
                let root = next_record(&block, &mut at)?.ok_or(ARCHIVE)?;
                if root.flags & DIRECTORY == 0 {
                    return Err(ARCHIVE);
                }
                let escape = block.get(88..91);
                let joliet =
                    kind == SUPPLEMENTARY && matches!(escape, Some(b"%/@" | b"%/C" | b"%/E"));
                if kind == PRIMARY {
                    if size.is_some() {
                        return Err(ARCHIVE);
                    }
                    size = Some(u64::from(both32(&block, 80)?) * SECTOR);
                    trees.insert(0, Tree { root, joliet });
                } else {
                    trees.push(Tree { root, joliet });
                }
            }
            Some(BOOT | PARTITION) => return Err(Stop::Malformed(Malformed::Method)),
            _ => return Err(ARCHIVE),
        }
    }
    Err(ARCHIVE)
}

/// Refuses a UDF volume recognition sequence starting at `sector` (a UDF tree this code does not read).
fn recognition<R: Read + Seek>(object: &mut R, image: u64, sector: u64) -> Result<(), Stop> {
    if (sector + 1) * SECTOR > image {
        return Ok(());
    }
    let block = read_sector(object, sector)?;
    match block.get(1..6) {
        Some(id) if RECOGNITION.contains(&id) => Err(Stop::Malformed(Malformed::Method)),
        _ => Ok(()),
    }
}

/// The record at `at` of a directory sector, moving `at` past it; `None` at the sector's end (a zero length
/// byte pads the rest of a sector).
fn next_record(block: &[u8], at: &mut usize) -> Result<Option<Record>, Stop> {
    let Some(&length) = block.get(*at) else {
        return Ok(None);
    };
    if length == 0 {
        return Ok(None);
    }
    let raw = block
        .get(*at..*at + usize::from(length))
        .filter(|raw| raw.len() >= RECORD)
        .ok_or(ARCHIVE)?;
    let name_length = usize::from(*raw.get(32).ok_or(ARCHIVE)?);
    let name = raw.get(33..33 + name_length).ok_or(ARCHIVE)?.to_vec();
    let mut date = [0_u8; 7];
    date.copy_from_slice(raw.get(18..25).ok_or(ARCHIVE)?);
    let record = Record {
        extent: both32(raw, 2)?,
        size: both32(raw, 10)?,
        flags: *raw.get(25).ok_or(ARCHIVE)?,
        layout: [
            *raw.get(1).ok_or(ARCHIVE)?,
            *raw.get(26).ok_or(ARCHIVE)?,
            *raw.get(27).ok_or(ARCHIVE)?,
        ],
        date,
        name,
    };
    *at += usize::from(length);
    Ok(Some(record))
}

/// A file's entry and bytes.
fn file<R: Read + Seek>(
    object: &mut R,
    run: &mut Run<'_>,
    path: Vec<u8>,
    record: &Record,
) -> Result<(), Stop> {
    let size = u64::from(record.size);
    let header = Header {
        path,
        kind: Kind::Regular,
        size,
        modified: record_time(record.date),
    };
    run.begin(&header, false)?;
    if size == 0 {
        return Ok(());
    }
    let start = u64::from(record.extent) * SECTOR;
    within(u64::from(record.extent), size, run.container)?;
    object.seek(SeekFrom::Start(start)).map_err(|_| ARCHIVE)?;
    let mut bytes = (&mut *object).take(size);
    run.stream(&mut bytes, size, size, Malformed::Archive)
}

/// An entry name from a record identifier: UCS-2 (big-endian) for Joliet, bytes otherwise; a file's
/// `;<version>` dropped, and a primary file name's trailing dot.
fn name(identifier: &[u8], joliet: bool, directory: bool) -> Result<Vec<u8>, Stop> {
    let mut name = if joliet {
        if !identifier.len().is_multiple_of(2) {
            return Err(ARCHIVE);
        }
        let units = identifier
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_be_bytes(*pair));
        char::decode_utf16(units)
            .collect::<Result<String, _>>()
            .map_err(|_| ARCHIVE)?
            .into_bytes()
    } else {
        identifier.to_vec()
    };
    if !directory {
        if let Some(semicolon) = name.iter().rposition(|&b| b == b';')
            && name
                .get(semicolon + 1..)
                .is_some_and(|v| v.iter().all(u8::is_ascii_digit))
        {
            name.truncate(semicolon);
        }
        if !joliet && name.last() == Some(&b'.') {
            name.pop();
        }
    }
    Ok(name)
}

/// The record's time: years since 1900, month, day, hour, minute, second, offset from UTC in quarter hours.
fn record_time(date: [u8; 7]) -> Option<i64> {
    let [year, month, day, hour, minute, second, offset] = date;
    let local = epoch_seconds(1900 + u16::from(year), month, day, hour, minute, second)?;
    Some(local - i64::from(i8::from_le_bytes([offset])) * 900)
}

/// `size` bytes from sector `extent` lie in an image of `image` bytes.
fn within(extent: u64, size: u64, image: u64) -> Result<(), Stop> {
    let end = extent
        .checked_mul(SECTOR)
        .and_then(|start| start.checked_add(size));
    if end.is_some_and(|end| end <= image) {
        Ok(())
    } else {
        Err(ARCHIVE)
    }
}

fn read_sector<R: Read + Seek>(object: &mut R, sector: u64) -> Result<[u8; 2048], Stop> {
    let mut block = [0_u8; 2048];
    object
        .seek(SeekFrom::Start(sector * SECTOR))
        .map_err(|_| ARCHIVE)?;
    object.read_exact(&mut block).map_err(|_| ARCHIVE)?;
    Ok(block)
}

/// A 32-bit value stored little-endian then big-endian at `at`; the two must agree.
fn both32(raw: &[u8], at: usize) -> Result<u32, Stop> {
    let [l0, l1, l2, l3, b0, b1, b2, b3] = array(raw, at)?;
    let little = u32::from_le_bytes([l0, l1, l2, l3]);
    if little == u32::from_be_bytes([b0, b1, b2, b3]) {
        Ok(little)
    } else {
        Err(ARCHIVE)
    }
}

/// A 16-bit value stored little-endian then big-endian at `at`; the two must agree.
fn both16(raw: &[u8], at: usize) -> Result<u16, Stop> {
    let [l0, l1, b0, b1] = array(raw, at)?;
    let little = u16::from_le_bytes([l0, l1]);
    if little == u16::from_be_bytes([b0, b1]) {
        Ok(little)
    } else {
        Err(ARCHIVE)
    }
}

/// The `N` bytes of `raw` at `at`.
fn array<const N: usize>(raw: &[u8], at: usize) -> Result<[u8; N], Stop> {
    raw.get(at..)
        .and_then(|rest| rest.first_chunk::<N>())
        .copied()
        .ok_or(ARCHIVE)
}
