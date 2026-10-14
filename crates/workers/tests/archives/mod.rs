//! Archives built at test time (nothing is committed): zip through the `zip` writer, tar headers written by
//! hand from the ustar layout (so hostile names can be planted), gzip through `flate2`, and byte patches that
//! break one rule of a valid archive.

use std::io::{Cursor, Write};

use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc, GzBuilder};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

/// 1980-01-01T00:00:00Z, the earliest zip time.
pub const EPOCH_1980: i64 = 315_532_800;
/// 2024-02-29T12:34:56Z.
pub const LEAP_DAY: i64 = 1_709_210_096;

/// How a zip entry is stored.
#[derive(Debug, Clone, Copy)]
pub enum Method {
    Stored,
    Deflated,
}

fn options(method: Method, time: DateTime) -> SimpleFileOptions {
    let (compression, level) = match method {
        Method::Stored => (CompressionMethod::Stored, None),
        Method::Deflated => (CompressionMethod::Deflated, Some(9)),
    };
    SimpleFileOptions::default()
        .compression_method(compression)
        .compression_level(level)
        .last_modified_time(time)
}

fn time_1980() -> DateTime {
    DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).expect("valid time")
}

/// A zip of `entries` (name, content, method), every one dated 1980-01-01; a name ending in `/` is a
/// directory.
pub fn zip(entries: &[(&str, &[u8], Method)]) -> Vec<u8> {
    zip_at(entries, time_1980())
}

/// As [`zip`], every entry dated `time`.
pub fn zip_at(entries: &[(&str, &[u8], Method)], time: DateTime) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    for (name, content, method) in entries {
        if let Some(directory) = name.strip_suffix('/') {
            writer
                .add_directory(directory, options(*method, time))
                .expect("directory");
        } else {
            writer
                .start_file(*name, options(*method, time))
                .expect("entry");
            writer.write_all(content).expect("content");
        }
    }
    writer.finish().expect("archive").into_inner()
}

/// 2024-02-29T12:34:56 as a zip time.
pub fn leap_day() -> DateTime {
    DateTime::from_date_and_time(2024, 2, 29, 12, 34, 56).expect("valid time")
}

/// A zip holding a symbolic link `name` to `target`.
pub fn zip_symlink(name: &str, target: &str) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_symlink(name, target, options(Method::Stored, time_1980()))
        .expect("symlink");
    writer.finish().expect("archive").into_inner()
}

/// Offset of the first central directory record.
pub fn central(archive: &[u8]) -> usize {
    archive
        .windows(4)
        .position(|w| w == b"PK\x01\x02")
        .expect("a central directory record")
}

/// The first entry with general-purpose flag bit 0 (encrypted) set, in both headers.
pub fn encrypted(mut archive: Vec<u8>) -> Vec<u8> {
    let at = central(&archive);
    archive[6] |= 1;
    archive[at + 8] |= 1;
    archive
}

/// The first entry announcing compression method `method`, in both headers.
pub fn with_method(mut archive: Vec<u8>, method: u16) -> Vec<u8> {
    let at = central(&archive);
    archive[8..10].copy_from_slice(&method.to_le_bytes());
    archive[at + 10..at + 12].copy_from_slice(&method.to_le_bytes());
    archive
}

/// The first entry declaring `size` uncompressed bytes, in both headers.
pub fn declaring(mut archive: Vec<u8>, size: u32) -> Vec<u8> {
    let at = central(&archive);
    archive[22..26].copy_from_slice(&size.to_le_bytes());
    archive[at + 24..at + 28].copy_from_slice(&size.to_le_bytes());
    archive
}

/// The first entry's name byte `index` replaced by `byte`, in both headers.
pub fn renamed_byte(mut archive: Vec<u8>, index: usize, byte: u8) -> Vec<u8> {
    let at = central(&archive);
    archive[30 + index] = byte;
    archive[at + 46 + index] = byte;
    archive
}

/// A zip whose `count` central records, named `f000`, `f001`..., all point to one deflated entry holding
/// `content` (overlapping entries: each one's own ratio is the content's, the container's is `count` times
/// it).
pub fn overlapping(content: &[u8], count: u16) -> Vec<u8> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(content).expect("deflate");
    let deflated = encoder.finish().expect("deflate");
    let mut crc = Crc::new();
    crc.update(content);
    let compressed = u32::try_from(deflated.len()).expect("size");
    let size = u32::try_from(content.len()).expect("size");
    let mut out = Vec::new();
    let fixed = |out: &mut Vec<u8>| {
        out.extend_from_slice(&20_u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0_u16.to_le_bytes()); // flags
        out.extend_from_slice(&8_u16.to_le_bytes()); // deflated
        out.extend_from_slice(&0_u16.to_le_bytes()); // time
        out.extend_from_slice(&0x21_u16.to_le_bytes()); // date 1980-01-01
        out.extend_from_slice(&crc.sum().to_le_bytes());
        out.extend_from_slice(&compressed.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
    };
    out.extend_from_slice(b"PK\x03\x04");
    fixed(&mut out);
    out.extend_from_slice(&4_u16.to_le_bytes()); // name length
    out.extend_from_slice(&0_u16.to_le_bytes()); // extra length
    out.extend_from_slice(b"f000");
    out.extend_from_slice(&deflated);
    let directory = u32::try_from(out.len()).expect("offset");
    for index in 0..count {
        out.extend_from_slice(b"PK\x01\x02");
        out.extend_from_slice(&20_u16.to_le_bytes()); // version made by
        fixed(&mut out);
        out.extend_from_slice(&4_u16.to_le_bytes()); // name length
        out.extend_from_slice(&[0; 8]); // extra, comment, disk, internal attributes
        out.extend_from_slice(&0_u32.to_le_bytes()); // external attributes
        out.extend_from_slice(&0_u32.to_le_bytes()); // local header offset
        out.extend_from_slice(format!("f{index:03}").as_bytes());
    }
    let length = u32::try_from(out.len()).expect("size") - directory;
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]); // disk numbers
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&directory.to_le_bytes());
    out.extend_from_slice(&0_u16.to_le_bytes()); // comment length
    out
}

/// One tar member: name, ustar type flag, content, link target, modification time.
pub struct Member<'a> {
    pub name: &'a [u8],
    pub flag: u8,
    pub content: &'a [u8],
    pub link: &'a [u8],
    pub mtime: u64,
}

impl<'a> Member<'a> {
    /// A regular file dated 2024-02-29T12:34:56Z.
    pub fn file(name: &'a [u8], content: &'a [u8]) -> Self {
        Self {
            name,
            flag: b'0',
            content,
            link: b"",
            mtime: 1_709_210_096,
        }
    }

    /// A member of type `flag` with no content.
    pub fn bare(name: &'a [u8], flag: u8, link: &'a [u8]) -> Self {
        Self {
            name,
            flag,
            content: b"",
            link,
            mtime: 1_709_210_096,
        }
    }
}

fn octal(field: &mut [u8], value: u64) {
    let digits = format!("{value:0width$o}", width = field.len() - 1);
    field[..digits.len()].copy_from_slice(digits.as_bytes());
    field[digits.len()] = 0;
}

/// The 512-byte ustar header of `member`.
pub fn tar_header(member: &Member<'_>) -> [u8; 512] {
    let mut header = [0_u8; 512];
    header[..member.name.len()].copy_from_slice(member.name);
    octal(&mut header[100..108], 0o644);
    octal(&mut header[108..116], 0);
    octal(&mut header[116..124], 0);
    octal(&mut header[124..136], member.content.len() as u64);
    octal(&mut header[136..148], member.mtime);
    header[156] = member.flag;
    header[157..157 + member.link.len()].copy_from_slice(member.link);
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    let digits = format!("{sum:06o}");
    header[148..154].copy_from_slice(digits.as_bytes());
    header[154] = 0;
    header[155] = b' ';
    header
}

/// A ustar archive of `members`, each content padded to 512 bytes, ended by two zero blocks.
pub fn tar(members: &[Member<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    for member in members {
        out.extend_from_slice(&tar_header(member));
        out.extend_from_slice(member.content);
        out.resize(out.len().div_ceil(512) * 512, 0);
    }
    out.resize(out.len() + 1024, 0);
    out
}

/// A tar whose one member has a 150-byte name, written by the `tar` crate as a GNU long name.
pub fn tar_long_name(name: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(1_709_210_096);
    header.set_entry_type(tar::EntryType::Regular);
    builder
        .append_data(&mut header, name, content)
        .expect("member");
    builder.into_inner().expect("archive")
}

/// A gzip member holding `content`, its header naming `name` (FNAME) when given, dated `mtime`.
pub fn gzip(name: Option<&[u8]>, content: &[u8], mtime: u32) -> Vec<u8> {
    let mut builder = GzBuilder::new().mtime(mtime);
    if let Some(name) = name {
        builder = builder.filename(name);
    }
    let mut encoder = builder.write(Vec::new(), Compression::best());
    encoder.write_all(content).expect("gzip");
    encoder.finish().expect("gzip")
}
