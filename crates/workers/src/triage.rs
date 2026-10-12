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
    // Offsets past the end are never sought: a file system may refuse a seek that far (ext4 above 16 TiB).
    let end = object.seek(SeekFrom::End(0))?;
    let head = read_at(object, end, 0, HEAD)?;
    let mut matched = Vec::new();
    // Every rule is tried: a failed rule never stops the others, and a polyglot shows all its types.
    if head.starts_with(b"MZ") && is_pe(object, end, &head)? {
        matched.push(DetectedType::Pe);
    }
    if let Some((_, detected)) = AT_START.iter().find(|(magic, _)| head.starts_with(magic)) {
        matched.push(*detected);
    }
    if head.get(257..262) == Some(b"ustar".as_slice()) {
        matched.push(DetectedType::Tar);
    }
    if read_at(object, end, ISO_MAGIC_AT, 5)? == b"CD001" {
        matched.push(DetectedType::Iso9660);
    }
    if head.starts_with(&COMPOUND_FILE) && is_msi(object, end, &head)? {
        matched.push(DetectedType::Msi);
    }
    matched.sort_by_key(|detected| DetectedType::ALL.iter().position(|t| t == detected));
    Ok(matched)
}

/// `MZ` whose `e_lfanew` (offset 0x3C) points to `PE\0\0`.
fn is_pe(object: &mut (impl Read + Seek), end: u64, head: &[u8]) -> std::io::Result<bool> {
    let Some(lfanew) = le_u32(head, 0x3C) else {
        return Ok(false);
    };
    Ok(read_at(object, end, u64::from(lfanew), 4)? == b"PE\0\0")
}

/// A compound file whose root directory entry (the first entry of the first directory sector) carries the
/// Windows Installer package CLSID.
fn is_msi(object: &mut (impl Read + Seek), end: u64, head: &[u8]) -> std::io::Result<bool> {
    let (Some(shift), Some(first_directory)) = (le_u16(head, 0x1E), le_u32(head, 0x30)) else {
        return Ok(false);
    };
    // Version 3 files use 512-byte sectors, version 4 files 4096-byte ones: nothing else is valid.
    if shift != 9 && shift != 12 {
        return Ok(false);
    }
    let sector = 1_u64 << shift;
    let Some(root) = (u64::from(first_directory) + 1)
        .checked_mul(sector)
        .and_then(|offset| offset.checked_add(0x50))
    else {
        return Ok(false);
    };
    Ok(read_at(object, end, root, MSI_CLSID.len())? == MSI_CLSID)
}

/// Up to `len` bytes at `offset` of an object of `end` bytes: fewer at its end, none past it (no seek then).
fn read_at(
    object: &mut (impl Read + Seek),
    end: u64,
    offset: u64,
    len: usize,
) -> std::io::Result<Vec<u8>> {
    if offset >= end {
        return Ok(Vec::new());
    }
    let len = len.min(usize::try_from(end - offset).unwrap_or(usize::MAX));
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
