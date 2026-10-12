//! Minimal objects of each type of report.md's "Types" table, built here from the table's rules (no binary is
//! committed, nothing is executable), and near misses of each rule.

/// The Windows Installer package CLSID {000C1084-0000-0000-C000-000000000046}, as stored (little-endian GUID).
pub const MSI_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];

/// A DOS header whose `e_lfanew` (offset 0x3C) is `lfanew`, then `signature` at 0x80.
pub fn pe(lfanew: u32, signature: [u8; 4]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x80];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[0x3C..0x40].copy_from_slice(&lfanew.to_le_bytes());
    bytes.extend_from_slice(&signature);
    bytes.extend_from_slice(&[0_u8; 0x20]);
    bytes
}

/// `magic` at `offset`, zeros around it, `len` bytes in all.
pub fn at(offset: usize, magic: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; len.max(offset + magic.len())];
    bytes[offset..offset + magic.len()].copy_from_slice(magic);
    bytes
}

/// A compound file (512-byte sectors) whose first directory sector is sector 0 and whose root entry carries
/// `clsid`.
pub fn compound_file(clsid: [u8; 16]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 1024];
    bytes[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    bytes[0x1E..0x20].copy_from_slice(&9_u16.to_le_bytes());
    bytes[0x30..0x34].copy_from_slice(&0_u32.to_le_bytes());
    // The root entry: name "Root Entry" (UTF-16), type 5, CLSID at 0x50 of the entry.
    let root = 512;
    for (i, unit) in "Root Entry".encode_utf16().enumerate() {
        bytes[root + 2 * i..root + 2 * i + 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes[root + 0x42] = 5;
    bytes[root + 0x50..root + 0x60].copy_from_slice(&clsid);
    bytes
}

/// One object of each type, with the literal name report.md gives it.
pub fn typed() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("pe", pe(0x80, *b"PE\0\0")),
        ("elf", at(0, b"\x7fELF\x02\x01\x01", 64)),
        ("pdf", b"%PDF-1.4\n1 0 obj\n<< >>\nendobj\n".to_vec()),
        ("png", at(0, b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR", 33)),
        ("zip", at(0, b"PK\x03\x04", 30)),
        ("zip", at(0, b"PK\x05\x06", 22)),
        ("gzip", at(0, b"\x1f\x8b\x08", 20)),
        ("tar", at(257, b"ustar\x0000", 512)),
        ("tar", at(257, b"ustar  \0", 512)),
        ("7z", at(0, b"7z\xbc\xaf\x27\x1c", 32)),
        ("rar", at(0, b"Rar!\x1a\x07\x01\x00", 32)),
        ("cab", at(0, b"MSCF\0\0\0\0", 36)),
        ("iso9660", at(32769, b"CD001", 34816)),
        ("msi", compound_file(MSI_CLSID)),
    ]
}

/// Near misses: each is `unknown`.
pub fn untyped() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("empty", Vec::new()),
        ("text", b"just some text\n".to_vec()),
        ("MZ alone", b"MZ".to_vec()),
        ("MZ without PE", pe(0x80, *b"NE\0\0")),
        ("e_lfanew past the end", pe(0x0001_0000, *b"PE\0\0")),
        ("e_lfanew at the very end", {
            let mut bytes = pe(0x80, *b"PE\0\0");
            bytes.truncate(0x82);
            bytes
        }),
        ("PDF marker not at the start", b" %PDF-1.4\n".to_vec()),
        ("PNG signature cut", b"\x89PNG\r\n".to_vec()),
        ("ustar at 256", at(256, b"ustar", 512)),
        ("tar too short", at(0, b"name", 260)),
        ("CD001 at 32768", at(32768, b"CD001", 34816)),
        ("ISO too short", vec![0_u8; 32770]),
        ("compound file of another kind", compound_file([0x11; 16])),
        (
            "compound file cut before its root",
            compound_file(MSI_CLSID)[..600].to_vec(),
        ),
    ]
}
