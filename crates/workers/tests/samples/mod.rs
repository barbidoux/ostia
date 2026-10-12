//! Minimal objects of each type of report.md's "Types" table, built here from the table's rules (no binary is
//! committed, nothing is executable), near misses of each rule, and polyglots matching two rules (Q-55).

/// The Windows Installer package CLSID {000C1084-0000-0000-C000-000000000046}, as stored (little-endian GUID).
pub const MSI_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// A DOS header whose `e_lfanew` (offset 0x3C) is `lfanew`, then `signature` at `lfanew` when it fits in
/// `len` bytes (at least 0x40).
pub fn pe(lfanew: u32, signature: [u8; 4], len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len.max(0x40)];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());
    let at = usize::try_from(lfanew).expect("offset");
    if at + 4 <= bytes.len() {
        bytes[at..at + 4].copy_from_slice(&signature);
    }
    bytes
}

/// `magic` at `offset`, zeros around it, `len` bytes in all.
pub fn at(offset: usize, magic: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len.max(offset + magic.len())];
    bytes[offset..offset + magic.len()].copy_from_slice(magic);
    bytes
}

/// `bytes` with `magic` written at `offset` (growing it when needed).
pub fn with(mut bytes: Vec<u8>, offset: usize, magic: &[u8]) -> Vec<u8> {
    if bytes.len() < offset + magic.len() {
        bytes.resize(offset + magic.len(), 0);
    }
    bytes[offset..offset + magic.len()].copy_from_slice(magic);
    bytes
}

/// A compound file with sector shift `shift`, first directory sector `directory`, whose root entry (the first
/// entry of that sector) carries `clsid`.
pub fn compound_file(shift: u16, directory: u32, clsid: [u8; 16]) -> Vec<u8> {
    let sector = 1_usize << shift;
    let root = (usize::try_from(directory).unwrap_or(0) + 1) * sector;
    let mut bytes = vec![0_u8; root + 128];
    bytes[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    bytes[0x1E..0x20].copy_from_slice(&shift.to_le_bytes());
    bytes[0x30..0x34].copy_from_slice(&directory.to_le_bytes());
    for (i, unit) in "Root Entry".encode_utf16().enumerate() {
        bytes[root + 2 * i..root + 2 * i + 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes[root + 0x42] = 5;
    bytes[root + 0x50..root + 0x60].copy_from_slice(&clsid);
    bytes
}

/// A compound file header alone, with `directory` as first directory sector and `shift` as sector shift.
pub fn compound_header(shift: u16, directory: u32) -> Vec<u8> {
    let mut bytes = vec![0_u8; 512];
    bytes[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    bytes[0x1E..0x20].copy_from_slice(&shift.to_le_bytes());
    bytes[0x30..0x34].copy_from_slice(&directory.to_le_bytes());
    bytes
}

/// A 512-byte ustar header whose member name (offset 0) starts with `name`.
pub fn tar_named(name: &[u8]) -> Vec<u8> {
    with(at(257, b"ustar\x0000", 512), 0, name)
}

/// One object of each type, with the literal name report.md gives it, including the variants each rule
/// allows and objects that end exactly where the rule's bytes end.
pub fn typed() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("pe", pe(0x80, *b"PE\0\0", 0xA0)),
        ("pe", pe(0x40, *b"PE\0\0", 0x60)),
        ("pe", pe(0x1000, *b"PE\0\0", 0x1010)),
        ("pe", pe(0x80, *b"PE\0\0", 0x84)),
        ("elf", at(0, b"\x7fELF\x02\x01\x01", 64)),
        ("pdf", b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n".to_vec()),
        ("png", at(0, b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR", 33)),
        ("png", b"\x89PNG\r\n\x1a\n".to_vec()),
        ("zip", at(0, b"PK\x03\x04", 30)),
        ("zip", at(0, b"PK\x05\x06", 22)),
        ("gzip", at(0, b"\x1f\x8b\x08", 20)),
        ("tar", at(257, b"ustar\x0000", 512)),
        ("tar", at(257, b"ustar  \0", 512)),
        ("tar", at(257, b"ustar", 262)),
        // The first member's name is the attacker's: a failed MZ or compound file rule falls through.
        ("tar", tar_named(b"MZ-not-a-program")),
        (
            "tar",
            tar_named(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]),
        ),
        ("7z", at(0, b"7z\xbc\xaf\x27\x1c", 32)),
        ("rar", at(0, b"Rar!\x1a\x07\x01\x00", 32)),
        ("cab", at(0, b"MSCF\0\0\0\0", 36)),
        ("iso9660", at(32769, b"CD001", 34816)),
        ("iso9660", at(32769, b"CD001", 32774)),
        // The 32 KiB system area is free: a failed MZ rule falls through.
        ("iso9660", with(at(32769, b"CD001", 34816), 0, b"MZ")),
        ("msi", compound_file(9, 0, MSI_CLSID)),
        ("msi", compound_file(9, 3, MSI_CLSID)),
        ("msi", compound_file(12, 0, MSI_CLSID)),
    ]
}

/// Near misses: no rule matches.
pub fn untyped() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("text", b"just some text\n".to_vec()),
        ("MZ alone", b"MZ".to_vec()),
        ("MZ without PE", pe(0x80, *b"NE\0\0", 0xA0)),
        ("e_lfanew past the end", pe(0x0001_0000, *b"PE\0\0", 0xA0)),
        (
            "e_lfanew at the very end",
            pe(0x80, *b"PE\0\0", 0x84)[..0x82].to_vec(),
        ),
        (
            "e_lfanew at the largest offset",
            pe(0xFFFF_FFFF, *b"PE\0\0", 0xA0),
        ),
        ("ELF cut", b"\x7fEL".to_vec()),
        ("ELF in lower case", b"\x7felf\x02\x01".to_vec()),
        ("PDF marker not at the start", b" %PDF-1.4\n".to_vec()),
        ("PDF marker without its dash", b"%PDF1.4\n".to_vec()),
        ("PDF marker in lower case", b"%pdf-1.4\n".to_vec()),
        ("PNG signature cut", b"\x89PNG\r\n".to_vec()),
        ("zip local header cut", b"PK\x03".to_vec()),
        ("zip central directory first", at(0, b"PK\x01\x02", 46)),
        ("gzip magic cut", b"\x1f".to_vec()),
        ("gzip second byte wrong", at(0, b"\x1f\x8c\x08", 20)),
        ("7z signature cut", at(0, b"7z\xbc\xaf\x27", 5)),
        ("rar version byte wrong", at(0, b"Rar!\x1a\x08", 32)),
        ("rar signature cut", b"Rar!\x1a".to_vec()),
        ("cab signature cut", b"MSC".to_vec()),
        ("cab signature in lower case", at(0, b"mscf", 36)),
        ("ustar at 256", at(256, b"ustar", 512)),
        ("tar too short", at(0, b"name", 260)),
        ("CD001 at 32768", at(32768, b"CD001", 34816)),
        ("ISO too short", vec![0_u8; 32770]),
        (
            "compound file of another kind",
            compound_file(9, 0, [0x11; 16]),
        ),
        (
            "compound file cut before its root",
            compound_file(9, 0, MSI_CLSID)[..600].to_vec(),
        ),
        ("compound file with sector shift 10", {
            let mut bytes = compound_file(10, 0, MSI_CLSID);
            bytes[0x1E..0x20].copy_from_slice(&10_u16.to_le_bytes());
            bytes
        }),
        (
            "compound file whose directory is ENDOFCHAIN",
            compound_header(9, 0xFFFF_FFFE),
        ),
        (
            "compound file whose directory is the largest sector",
            compound_header(12, 0xFFFF_FFFF),
        ),
    ]
}

/// Objects matching two rules, with the types they match in report.md's order: never typed (Q-55).
pub fn polyglots() -> Vec<(&'static str, Vec<u8>, Vec<&'static str>)> {
    vec![
        (
            "tar whose first member is named %PDF-",
            tar_named(b"%PDF-1.4"),
            vec!["pdf", "tar"],
        ),
        (
            "zip with ustar at 257",
            with(at(0, b"PK\x03\x04", 512), 257, b"ustar"),
            vec!["zip", "tar"],
        ),
        (
            "gzip with ustar at 257",
            with(at(0, b"\x1f\x8b\x08", 512), 257, b"ustar"),
            vec!["gzip", "tar"],
        ),
        (
            "ISO whose system area is a zip",
            with(at(32769, b"CD001", 34816), 0, b"PK\x03\x04"),
            vec!["zip", "iso9660"],
        ),
        (
            "PE with CD001 at 32769",
            with(pe(0x80, *b"PE\0\0", 0xA0), 32769, b"CD001"),
            vec!["pe", "iso9660"],
        ),
        (
            "MSI with CD001 at 32769",
            with(compound_file(9, 0, MSI_CLSID), 32769, b"CD001"),
            vec!["iso9660", "msi"],
        ),
    ]
}
