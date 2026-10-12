//! Type identification from the content (FR-05), by the magic numbers of report.md's "Types" table.
//!
//! Only the bytes the rules look at are read: the first 512 bytes, the 4 bytes `e_lfanew` points to, a compound
//! file's root directory entry, and 5 bytes at offset 32769. A rule whose bytes are missing does not match.

use std::io::{ErrorKind, Read, Seek, SeekFrom};

use ostia_core_domain::types::DetectedType;

/// Bytes read from the start of the object: enough for every rule at a fixed offset below 512.
const HEAD: usize = 512;

/// Offset of `CD001` in an ISO 9660 image (the first volume descriptor, sector 16, plus one byte).
const ISO_MAGIC_AT: u64 = 32_769;

/// The compound file signature.
const COMPOUND_FILE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The Windows Installer package CLSID {000C1084-0000-0000-C000-000000000046}, as stored (little-endian GUID).
const MSI_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// Signatures at offset 0, in report.md's order.
const AT_START: [(&[u8], DetectedType); 9] = [
    (b"\x7fELF", DetectedType::Elf),
    (b"%PDF-", DetectedType::Pdf),
    (b"\x89PNG\r\n\x1a\n", DetectedType::Png),
    (b"PK\x03\x04", DetectedType::Zip),
    (b"PK\x05\x06", DetectedType::Zip),
    (b"\x1f\x8b", DetectedType::Gzip),
    (b"7z\xbc\xaf\x27\x1c", DetectedType::SevenZip),
    (b"Rar!\x1a\x07", DetectedType::Rar),
    (b"MSCF", DetectedType::Cab),
];

/// Every type whose rule `object` matches, in report.md's order: none for an object of no known type, one
/// for a typed object, several for a polyglot (never typed, Q-55). Reads only the bytes the rules look at.
///
/// # Errors
/// Reading or seeking the object failed.
pub fn matching_types(object: &mut (impl Read + Seek)) -> std::io::Result<Vec<DetectedType>> {
    let _ = object;
    todo!("WP-1.7: every rule, no early return")
}

/// The type of the object read from `object`; `unknown` when no rule matches. Reads only the bytes the rules
/// look at.
///
/// # Errors
/// Reading or seeking the object failed.
pub fn identify(object: &mut (impl Read + Seek)) -> std::io::Result<DetectedType> {
    let head = read_at(object, 0, HEAD)?;
    if head.starts_with(b"MZ") {
        return pe(object, &head);
    }
    if head.starts_with(&COMPOUND_FILE) {
        return compound_file(object, &head);
    }
    if let Some((_, detected)) = AT_START.iter().find(|(magic, _)| head.starts_with(magic)) {
        return Ok(*detected);
    }
    if head.get(257..262) == Some(b"ustar".as_slice()) {
        return Ok(DetectedType::Tar);
    }
    if read_at(object, ISO_MAGIC_AT, 5)? == b"CD001" {
        return Ok(DetectedType::Iso9660);
    }
    Ok(DetectedType::Unknown)
}

/// `MZ` whose `e_lfanew` (offset 0x3C) points to `PE\0\0`; any other `MZ` is unknown.
fn pe(object: &mut (impl Read + Seek), head: &[u8]) -> std::io::Result<DetectedType> {
    let Some(lfanew) = le_u32(head, 0x3C) else {
        return Ok(DetectedType::Unknown);
    };
    if read_at(object, u64::from(lfanew), 4)? == b"PE\0\0" {
        Ok(DetectedType::Pe)
    } else {
        Ok(DetectedType::Unknown)
    }
}

/// A compound file whose root directory entry (the first entry of the first directory sector) carries the
/// Windows Installer package CLSID; any other compound file is unknown.
fn compound_file(object: &mut (impl Read + Seek), head: &[u8]) -> std::io::Result<DetectedType> {
    let (Some(shift), Some(first_directory)) = (le_u16(head, 0x1E), le_u32(head, 0x30)) else {
        return Ok(DetectedType::Unknown);
    };
    // Version 3 files use 512-byte sectors, version 4 files 4096-byte ones: nothing else is valid.
    if shift != 9 && shift != 12 {
        return Ok(DetectedType::Unknown);
    }
    let sector = 1_u64 << shift;
    let Some(root) = (u64::from(first_directory) + 1)
        .checked_mul(sector)
        .and_then(|offset| offset.checked_add(0x50))
    else {
        return Ok(DetectedType::Unknown);
    };
    if read_at(object, root, MSI_CLSID.len())? == MSI_CLSID {
        Ok(DetectedType::Msi)
    } else {
        Ok(DetectedType::Unknown)
    }
}

/// Up to `len` bytes at `offset`: fewer at the end of the object, none past it.
fn read_at(object: &mut (impl Read + Seek), offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
    object.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0_u8; len];
    let mut filled = 0;
    while filled < len {
        let Some(rest) = bytes.get_mut(filled..) else {
            break;
        };
        match object.read(rest) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    bytes.truncate(filled);
    Ok(bytes)
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let field = bytes.get(at..at + 2)?;
    Some(u16::from_le_bytes(field.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes(field.try_into().ok()?))
}
