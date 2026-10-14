//! The extraction worker's formats (FR-06, ADR-18): entries, kinds, sizes, times and bytes of zip, tar and gzip;
//! the budget's limits reached while streaming; malformed containers refused, never half-trusted.

mod archives;

use std::io::{self, Cursor, Write};

use archives::{
    EPOCH_1980, Member, Method, central, declaring, encrypted, gzip, options, tar, tar_header,
    time_1980, with_method, zip, zip_at,
};
use flate2::write::DeflateEncoder;
use flate2::{Compression, Crc};
use ostia_core_domain::types::DetectedType;
use ostia_core_domain::verdict::Limit;
use ostia_traceability::req;
use ostia_workers::extract::{Budget, CHUNK, Format, Header, Kind, Malformed, Sink, Stop, extract};
use zip::{DateTime, ZipWriter};

/// 2024-02-29T12:34:56Z.
const LEAP_DAY: i64 = 1_709_210_096;

/// 2024-02-29T12:34:56 as a zip time.
fn leap_day() -> DateTime {
    DateTime::from_date_and_time(2024, 2, 29, 12, 34, 56).expect("valid time")
}

/// A zip holding a symbolic link `name` to `target`.
fn zip_symlink(name: &str, target: &str) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .add_symlink(name, target, options(Method::Stored, time_1980()))
        .expect("symlink");
    writer.finish().expect("archive").into_inner()
}

/// The first entry's name byte `index` replaced by `byte`, in both headers.
fn renamed_byte(mut archive: Vec<u8>, index: usize, byte: u8) -> Vec<u8> {
    let at = central(&archive);
    archive[30 + index] = byte;
    archive[at + 46 + index] = byte;
    archive
}

/// A zip whose `count` central records, named `f000`, `f001`..., all point to one deflated entry holding
/// `content` (overlapping entries: each one's own ratio is the content's, the container's is `count` times
/// it).
fn overlapping(content: &[u8], count: u16) -> Vec<u8> {
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

/// A tar whose one member has a long name, written by the `tar` crate as a GNU long name.
fn tar_long_name(name: &str, content: &[u8]) -> Vec<u8> {
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

/// Far from every limit.
const OPEN: Budget = Budget {
    max_ratio: 1_000_000,
    remaining_bytes: 1 << 40,
    remaining_entries: 1 << 20,
    max_path_length: 4096,
};

/// Every entry and every chunk the extraction handed over.
#[derive(Default)]
struct Collect {
    entries: Vec<(Header, Vec<u8>)>,
    largest_chunk: usize,
    refuse_data: bool,
}

impl Sink for Collect {
    fn entry(&mut self, header: &Header) -> io::Result<()> {
        self.entries.push((header.clone(), Vec::new()));
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> io::Result<()> {
        if self.refuse_data {
            return Err(io::Error::other("workspace full"));
        }
        self.largest_chunk = self.largest_chunk.max(bytes.len());
        let (_, content) = self.entries.last_mut().expect("data after an entry");
        content.extend_from_slice(bytes);
        Ok(())
    }
}

impl Collect {
    fn produced(&self) -> usize {
        self.entries.iter().map(|(_, content)| content.len()).sum()
    }
}

fn run(format: Format, archive: &[u8], budget: &Budget) -> (Result<(), Stop>, Collect) {
    let mut sink = Collect::default();
    let result = extract(format, Cursor::new(archive.to_vec()), budget, &mut sink);
    (result, sink)
}

fn entries(format: Format, archive: &[u8]) -> Vec<(Header, Vec<u8>)> {
    let (result, sink) = run(format, archive, &OPEN);
    if let Err(stop) = result {
        panic!("{format:?} refused: {stop:?}");
    }
    sink.entries
}

fn header(path: &[u8], kind: Kind, size: u64, modified: Option<i64>) -> Header {
    Header {
        path: path.to_vec(),
        kind,
        size,
        modified,
    }
}

fn limit(format: Format, archive: &[u8], budget: &Budget) -> Option<Limit> {
    match run(format, archive, budget).0 {
        Err(Stop::Limit(limit)) => Some(limit),
        _ => None,
    }
}

fn malformed(format: Format, archive: &[u8]) -> Option<Malformed> {
    match run(format, archive, &OPEN).0 {
        Err(Stop::Malformed(why)) => Some(why),
        _ => None,
    }
}

/// `len` zero bytes: they deflate about 1000:1.
fn zeros(len: usize) -> Vec<u8> {
    vec![0; len]
}

#[req("FR-06")]
#[test]
fn the_formats_are_the_eight_containers_of_fr_06() {
    assert_eq!(Format::of(DetectedType::Zip), Some(Format::Zip));
    assert_eq!(Format::of(DetectedType::Tar), Some(Format::Tar));
    assert_eq!(Format::of(DetectedType::Gzip), Some(Format::Gzip));
    assert_eq!(Format::of(DetectedType::SevenZip), Some(Format::SevenZip));
    assert_eq!(Format::of(DetectedType::Rar), Some(Format::Rar));
    assert_eq!(Format::of(DetectedType::Cab), Some(Format::Cab));
    assert_eq!(Format::of(DetectedType::Iso9660), Some(Format::Iso));
    assert_eq!(Format::of(DetectedType::Msi), Some(Format::Msi));
    for other in [
        DetectedType::Pe,
        DetectedType::Elf,
        DetectedType::Pdf,
        DetectedType::Png,
        DetectedType::Unknown,
    ] {
        assert_eq!(Format::of(other), None, "{other:?}");
    }
}

#[req("FR-06")]
#[test]
fn zip_entries_come_with_their_path_size_time_and_bytes() {
    let archive = zip(&[
        ("a.txt", b"alpha", Method::Stored),
        ("dir/", b"", Method::Stored),
        ("dir/b.bin", &[7_u8; 3000], Method::Deflated),
        ("empty", b"", Method::Deflated),
    ]);
    assert_eq!(
        entries(Format::Zip, &archive),
        vec![
            (
                header(b"a.txt", Kind::Regular, 5, Some(EPOCH_1980)),
                b"alpha".to_vec()
            ),
            (
                header(b"dir/b.bin", Kind::Regular, 3000, Some(EPOCH_1980)),
                vec![7; 3000]
            ),
            (header(b"empty", Kind::Regular, 0, Some(EPOCH_1980)), vec![]),
        ]
    );
}

#[req("FR-06")]
#[test]
fn zip_time_is_read_as_utc() {
    let archive = zip_at(&[("x", b"x", Method::Stored)], leap_day());
    assert_eq!(entries(Format::Zip, &archive)[0].0.modified, Some(LEAP_DAY));
}

#[req("FR-06")]
#[test]
fn zip_symbolic_link_is_a_link_entry_without_bytes() {
    let found = entries(Format::Zip, &zip_symlink("link", "/etc/passwd"));
    assert_eq!(
        found,
        vec![(header(b"link", Kind::Link, 0, Some(EPOCH_1980)), vec![])]
    );
}

#[req("FR-06")]
#[test]
fn large_entries_arrive_in_bounded_chunks() {
    let content: Vec<u8> = (0..200_000_u32).map(|i| (i % 251) as u8).collect();
    let archive = zip(&[("big", &content, Method::Deflated)]);
    let (result, sink) = run(Format::Zip, &archive, &OPEN);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(sink.entries[0].1, content);
    assert!(sink.largest_chunk <= CHUNK, "{}", sink.largest_chunk);
}

#[req("FR-06")]
#[test]
fn tar_members_give_files_links_and_special_entries() {
    let archive = tar(&[
        Member::file(b"a.txt", b"tar entry"),
        Member::bare(b"dir/", b'5', b""),
        Member::file(b"dir/b.bin", &[9; 1500]),
        Member::bare(b"soft", b'2', b"a.txt"),
        Member::bare(b"hard", b'1', b"a.txt"),
        Member::bare(b"fifo", b'6', b""),
        Member::bare(b"tty", b'3', b""),
        Member::bare(b"disk", b'4', b""),
    ]);
    let at = Some(LEAP_DAY);
    assert_eq!(
        entries(Format::Tar, &archive),
        vec![
            (
                header(b"a.txt", Kind::Regular, 9, at),
                b"tar entry".to_vec()
            ),
            (header(b"dir/b.bin", Kind::Regular, 1500, at), vec![9; 1500]),
            (header(b"soft", Kind::Link, 0, at), vec![]),
            (header(b"hard", Kind::Link, 0, at), vec![]),
            (header(b"fifo", Kind::Special, 0, at), vec![]),
            (header(b"tty", Kind::Special, 0, at), vec![]),
            (header(b"disk", Kind::Special, 0, at), vec![]),
        ]
    );
}

#[req("FR-06")]
#[test]
fn tar_long_names_are_kept_whole() {
    let name = format!("d/{}.txt", "n".repeat(150));
    let found = entries(Format::Tar, &tar_long_name(&name, b"long"));
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].0.path, name.as_bytes());
    assert_eq!(found[0].1, b"long");
}

#[req("FR-06")]
#[test]
fn gzip_gives_one_entry_named_by_its_header() {
    let found = entries(
        Format::Gzip,
        &gzip(Some(b"letter.txt"), b"gzip member", 1_709_210_096),
    );
    assert_eq!(
        found,
        vec![(
            header(b"letter.txt", Kind::Regular, 11, Some(LEAP_DAY)),
            b"gzip member".to_vec()
        )]
    );
}

#[req("FR-06")]
#[test]
fn gzip_without_a_name_or_a_time_gives_an_unnamed_undated_entry() {
    // report.md: the host names it after the container, without its last extension.
    let found = entries(Format::Gzip, &gzip(None, b"anonymous", 0));
    assert_eq!(
        found,
        vec![(header(b"", Kind::Regular, 9, None), b"anonymous".to_vec())]
    );
}

#[req("FR-06")]
#[test]
fn concatenated_gzip_members_form_one_entry() {
    let mut archive = gzip(Some(b"first.txt"), b"one ", 0);
    archive.extend(gzip(Some(b"second.txt"), b"two", 0));
    assert_eq!(
        entries(Format::Gzip, &archive),
        vec![(
            header(b"first.txt", Kind::Regular, 7, None),
            b"one two".to_vec()
        )]
    );
}

// --- limits ------------------------------------------------------------------------------------------

fn budget(change: impl FnOnce(&mut Budget)) -> Budget {
    let mut budget = OPEN;
    change(&mut budget);
    budget
}

#[req("FR-06")]
#[test]
fn an_entry_over_the_ratio_is_stopped_while_streaming() {
    let archive = zip(&[("zeros.bin", &zeros(16 << 20), Method::Deflated)]);
    let tight = budget(|b| b.max_ratio = 100);
    let (result, sink) = run(Format::Zip, &archive, &tight);
    assert!(
        matches!(result, Err(Stop::Limit(Limit::Ratio))),
        "{result:?}"
    );
    // A chunk that would breach the limit never reaches the sink: no slack.
    let compressed = archive.len();
    assert!(sink.produced() <= 100 * compressed, "{}", sink.produced());
}

#[req("FR-06")]
#[test]
fn a_ratio_equal_to_the_limit_is_allowed() {
    // A stored entry's ratio is exactly 1.
    let archive = zip(&[("same.bin", &[5_u8; 4096], Method::Stored)]);
    assert!(
        run(Format::Zip, &archive, &budget(|b| b.max_ratio = 1))
            .0
            .is_ok()
    );
    let deflated = zip(&[("text", &[b'x'; 4096], Method::Deflated)]);
    assert_eq!(
        limit(Format::Zip, &deflated, &budget(|b| b.max_ratio = 1)),
        Some(Limit::Ratio)
    );
}

#[req("FR-06")]
#[test]
fn gzip_over_the_ratio_is_stopped() {
    let archive = gzip(Some(b"zeros.bin"), &zeros(16 << 20), 0);
    let tight = budget(|b| b.max_ratio = 100);
    let (result, sink) = run(Format::Gzip, &archive, &tight);
    assert!(
        matches!(result, Err(Stop::Limit(Limit::Ratio))),
        "{result:?}"
    );
    // The first pass counts under the limits: nothing reaches the sink.
    assert_eq!(sink.entries.len(), 0);
}

#[req("FR-06")]
#[test]
fn overlapping_entries_are_malformed() {
    // Each entry: 64 KiB from about 90 bytes (under 1000); together, 200 times that from a few kB. Entries
    // sharing their bytes are refused before any ratio is reached, whatever the budget.
    let archive = overlapping(&zeros(64 * 1024), 200);
    assert_eq!(malformed(Format::Zip, &archive), Some(Malformed::Archive));
    let (result, sink) = run(Format::Zip, &archive, &budget(|b| b.max_ratio = 1000));
    assert!(
        matches!(result, Err(Stop::Malformed(Malformed::Archive))),
        "{result:?}"
    );
    assert_eq!(sink.entries.len(), 0);
}

#[req("FR-06")]
#[test]
fn bytes_beyond_the_remaining_total_are_refused() {
    let archive = zip(&[
        ("a", &[1_u8; 600], Method::Stored),
        ("b", &[2_u8; 600], Method::Stored),
    ]);
    let (result, sink) = run(Format::Zip, &archive, &budget(|b| b.remaining_bytes = 1000));
    assert!(
        matches!(result, Err(Stop::Limit(Limit::TotalSize))),
        "{result:?}"
    );
    assert!(sink.produced() <= 1000, "{}", sink.produced());
    assert!(
        run(Format::Zip, &archive, &budget(|b| b.remaining_bytes = 1200))
            .0
            .is_ok()
    );
}

#[req("FR-06")]
#[test]
fn entries_beyond_the_remaining_count_are_refused() {
    let archive = tar(&[
        Member::file(b"one", b"1"),
        Member::bare(b"dir/", b'5', b""),
        Member::bare(b"link", b'2', b"one"),
        Member::file(b"three", b"3"),
    ]);
    // Directories are not entries: three entries.
    assert!(
        run(Format::Tar, &archive, &budget(|b| b.remaining_entries = 3))
            .0
            .is_ok()
    );
    let (result, sink) = run(Format::Tar, &archive, &budget(|b| b.remaining_entries = 2));
    assert!(
        matches!(result, Err(Stop::Limit(Limit::EntryCount))),
        "{result:?}"
    );
    assert_eq!(sink.entries.len(), 2);
}

#[req("FR-06")]
#[test]
fn a_path_longer_than_the_limit_is_refused() {
    let archive = zip(&[("abcdefgh", b"8", Method::Stored)]);
    assert!(
        run(Format::Zip, &archive, &budget(|b| b.max_path_length = 8))
            .0
            .is_ok()
    );
    assert_eq!(
        limit(Format::Zip, &archive, &budget(|b| b.max_path_length = 7)),
        Some(Limit::PathLength)
    );
    let long = tar_long_name(&"x".repeat(150), b"x");
    assert_eq!(
        limit(Format::Tar, &long, &budget(|b| b.max_path_length = 149)),
        Some(Limit::PathLength)
    );
}

// --- malformed containers ----------------------------------------------------------------------------

#[req("FR-06")]
#[test]
fn a_cut_or_corrupt_zip_is_malformed() {
    let archive = zip(&[("x.bin", &[3_u8; 5000], Method::Stored)]);
    let truncated = &archive[..archive.len() * 6 / 10];
    assert_eq!(malformed(Format::Zip, truncated), Some(Malformed::Archive));
    let mut corrupt = zip(&[(
        "y.txt",
        &b"corrupted deflate stream".repeat(200),
        Method::Deflated,
    )]);
    for byte in &mut corrupt[40..60] {
        *byte ^= 0xFF;
    }
    assert_eq!(malformed(Format::Zip, &corrupt), Some(Malformed::Archive));
    assert_eq!(
        malformed(Format::Zip, b"PK\x03\x04"),
        Some(Malformed::Archive)
    );
}

#[req("FR-06")]
#[test]
fn sizes_that_do_not_match_the_declared_ones_are_malformed() {
    // Declares 1000 bytes; inflates to 16 MiB: stopped right after the declared size.
    let lying = declaring(
        zip(&[("zeros.bin", &zeros(16 << 20), Method::Deflated)]),
        1000,
    );
    let (result, sink) = run(Format::Zip, &lying, &OPEN);
    assert!(
        matches!(result, Err(Stop::Malformed(Malformed::Size))),
        "{result:?}"
    );
    assert!(sink.produced() <= 1000, "{}", sink.produced());
    // Declares more than the stream holds.
    let short = declaring(zip(&[("a", b"abc", Method::Deflated)]), 10);
    assert_eq!(malformed(Format::Zip, &short), Some(Malformed::Size));
}

#[req("FR-06")]
#[test]
fn an_encrypted_entry_is_malformed() {
    let archive = encrypted(zip(&[("secret.bin", &[4_u8; 2000], Method::Stored)]));
    assert_eq!(malformed(Format::Zip, &archive), Some(Malformed::Encrypted));
}

#[req("FR-06")]
#[test]
fn an_entry_compressed_with_another_method_is_malformed() {
    // 12: bzip2, 14: lzma, 93: zstd; this worker extracts stored and deflated entries only.
    for method in [12, 14, 93] {
        let archive = with_method(zip(&[("x", b"xxxx", Method::Stored)]), method);
        assert_eq!(
            malformed(Format::Zip, &archive),
            Some(Malformed::Method),
            "{method}"
        );
    }
}

#[req("FR-06")]
#[test]
fn entry_paths_leaving_the_container_are_malformed() {
    for name in ["../escape.txt", "/etc/escape.txt", "a/../../b", "a/.."] {
        let archive = zip(&[(name, b"x", Method::Stored)]);
        assert_eq!(
            malformed(Format::Zip, &archive),
            Some(Malformed::Path),
            "{name}"
        );
        let member = tar(&[Member::file(name.as_bytes(), b"x")]);
        assert_eq!(
            malformed(Format::Tar, &member),
            Some(Malformed::Path),
            "tar {name}"
        );
    }
    let nul = renamed_byte(zip(&[("ab", b"x", Method::Stored)]), 1, 0);
    assert_eq!(malformed(Format::Zip, &nul), Some(Malformed::Path));
    let gz = gzip(Some(b"../up.txt"), b"x", 0);
    assert_eq!(malformed(Format::Gzip, &gz), Some(Malformed::Path));
}

#[req("FR-06")]
#[test]
fn a_cut_or_corrupt_tar_is_malformed() {
    let archive = tar(&[Member::file(b"a", &[1; 2000])]);
    assert_eq!(
        malformed(Format::Tar, &archive[..1200]),
        Some(Malformed::Archive)
    );
    let mut checksum = tar_header(&Member::file(b"a", b"x")).to_vec();
    checksum[0] = b'b';
    checksum.resize(512 + 1024 + 512, 0);
    assert_eq!(malformed(Format::Tar, &checksum), Some(Malformed::Archive));
}

#[req("FR-06")]
#[test]
fn a_cut_or_corrupt_gzip_is_malformed() {
    let archive = gzip(Some(b"a.txt"), &b"gzip content ".repeat(100), 0);
    assert_eq!(
        malformed(Format::Gzip, &archive[..archive.len() - 6]),
        Some(Malformed::Archive)
    );
    let mut crc = archive.clone();
    let at = crc.len() - 8;
    crc[at] ^= 0xFF;
    assert_eq!(malformed(Format::Gzip, &crc), Some(Malformed::Archive));
    let mut trailing = archive.clone();
    trailing.extend_from_slice(b"not a member");
    assert_eq!(malformed(Format::Gzip, &trailing), Some(Malformed::Archive));
}

#[req("FR-06")]
#[test]
fn a_sink_error_stops_the_extraction() {
    let archive = zip(&[("a", b"abc", Method::Stored)]);
    let mut sink = Collect {
        refuse_data: true,
        ..Collect::default()
    };
    let result = extract(Format::Zip, Cursor::new(archive), &OPEN, &mut sink);
    assert!(matches!(result, Err(Stop::Sink(_))), "{result:?}");
}

// --- zip layouts the writer refuses to produce (review of WP-1.8) ------------------------------------

/// One entry of a hand-written zip.
struct Raw {
    name: Vec<u8>,
    /// 0 stored, 8 deflated.
    method: u16,
    /// The bytes as stored in the archive.
    stored: Vec<u8>,
    /// CRC-32 and size of the content.
    crc: u32,
    size: u32,
    /// The compressed size the headers declare (normally `stored.len()`).
    declared: u32,
    /// A data descriptor (with its signature) follows the bytes.
    descriptor: bool,
    /// The central directory lists the entry.
    listed: bool,
    /// Bytes after the entry (and its descriptor), before the next one.
    gap: Vec<u8>,
}

impl Raw {
    fn stored(name: &[u8], content: &[u8]) -> Self {
        let mut crc = Crc::new();
        crc.update(content);
        let size = u32::try_from(content.len()).expect("size");
        Self {
            name: name.to_vec(),
            method: 0,
            stored: content.to_vec(),
            crc: crc.sum(),
            size,
            declared: size,
            descriptor: false,
            listed: true,
            gap: Vec::new(),
        }
    }

    fn deflated(name: &[u8], content: &[u8]) -> Self {
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(content).expect("deflate");
        let stored = encoder.finish().expect("deflate");
        let declared = u32::try_from(stored.len()).expect("size");
        Self {
            method: 8,
            stored,
            declared,
            ..Self::stored(name, content)
        }
    }
}

fn u16le(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn u32le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

/// The zip of `entries`, laid out as described, with a central directory for the listed ones.
fn raw_zip(entries: &[Raw]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut offsets = Vec::new();
    for entry in entries {
        offsets.push(u32::try_from(out.len()).expect("offset"));
        out.extend_from_slice(b"PK\x03\x04");
        u16le(&mut out, 20);
        u16le(&mut out, if entry.descriptor { 8 } else { 0 });
        u16le(&mut out, entry.method);
        u16le(&mut out, 0);
        u16le(&mut out, 0x21);
        u32le(&mut out, entry.crc);
        u32le(&mut out, entry.declared);
        u32le(&mut out, entry.size);
        u16le(&mut out, u16::try_from(entry.name.len()).expect("name"));
        u16le(&mut out, 0);
        out.extend_from_slice(&entry.name);
        out.extend_from_slice(&entry.stored);
        if entry.descriptor {
            out.extend_from_slice(b"PK\x07\x08");
            u32le(&mut out, entry.crc);
            u32le(&mut out, entry.declared);
            u32le(&mut out, entry.size);
        }
        out.extend_from_slice(&entry.gap);
    }
    let directory = u32::try_from(out.len()).expect("offset");
    let mut listed: u16 = 0;
    for (entry, offset) in entries.iter().zip(offsets) {
        if !entry.listed {
            continue;
        }
        listed += 1;
        out.extend_from_slice(b"PK\x01\x02");
        u16le(&mut out, 20);
        u16le(&mut out, 20);
        u16le(&mut out, if entry.descriptor { 8 } else { 0 });
        u16le(&mut out, entry.method);
        u16le(&mut out, 0);
        u16le(&mut out, 0x21);
        u32le(&mut out, entry.crc);
        u32le(&mut out, entry.declared);
        u32le(&mut out, entry.size);
        u16le(&mut out, u16::try_from(entry.name.len()).expect("name"));
        out.extend_from_slice(&[0; 8]); // extra, comment, disk, internal attributes
        u32le(&mut out, 0); // external attributes
        u32le(&mut out, offset);
        out.extend_from_slice(&entry.name);
    }
    let length = u32::try_from(out.len()).expect("size") - directory;
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&[0; 4]);
    u16le(&mut out, listed);
    u16le(&mut out, listed);
    u32le(&mut out, length);
    u32le(&mut out, directory);
    u16le(&mut out, 0);
    out
}

#[req("FR-06")]
#[test]
fn a_hand_written_zip_with_a_data_descriptor_is_extracted() {
    // The control for the layout checks below: every byte belongs to an entry, a descriptor or the directory.
    let archive = raw_zip(&[
        Raw {
            descriptor: true,
            ..Raw::deflated(b"a.txt", &b"alpha ".repeat(50))
        },
        Raw::stored(b"b.txt", b"beta"),
    ]);
    let found = entries(Format::Zip, &archive);
    assert_eq!(found.len(), 2);
    assert_eq!(found[0].1, b"alpha ".repeat(50));
    assert_eq!(found[1].1, b"beta");
}

#[req("FR-06")]
#[test]
fn a_name_listed_twice_is_malformed() {
    // A reader keeping one record per name would scan only the second; desktop tools show both.
    let archive = raw_zip(&[
        Raw::stored(b"a.txt", b"MALICIOUS-FIRST"),
        Raw::stored(b"a.txt", b"benign-second"),
    ]);
    assert_eq!(malformed(Format::Zip, &archive), Some(Malformed::Archive));
}

#[req("FR-06")]
#[test]
fn bytes_no_central_record_accounts_for_are_malformed() {
    // An entry with a local header only: streaming readers extract it.
    let unlisted = raw_zip(&[
        Raw::stored(b"seen.txt", b"seen"),
        Raw {
            listed: false,
            ..Raw::stored(b"hidden.exe", b"MZ hidden")
        },
    ]);
    assert_eq!(malformed(Format::Zip, &unlisted), Some(Malformed::Archive));
    // Bytes between two entries, even descriptor-sized ones that are not a descriptor.
    for gap in [b"hidden payload between entries".to_vec(), vec![0x41; 16]] {
        let gapped = raw_zip(&[
            Raw {
                gap,
                ..Raw::stored(b"a.txt", b"a")
            },
            Raw::stored(b"b.txt", b"b"),
        ]);
        assert_eq!(malformed(Format::Zip, &gapped), Some(Malformed::Archive));
    }
}

#[req("FR-06")]
#[test]
fn a_lying_compressed_size_is_malformed() {
    // Larger than the bytes (the entry would swallow the next one), then smaller (a gap left behind).
    let zeros = zeros(1 << 20);
    for delta in [200_000_i64, -40] {
        let mut bomb = Raw::deflated(b"zeros.bin", &zeros);
        bomb.declared = u32::try_from(i64::from(bomb.declared) + delta).expect("size");
        let archive = raw_zip(&[bomb, Raw::stored(b"pad.bin", &vec![9; 300_000])]);
        assert_eq!(
            malformed(Format::Zip, &archive),
            Some(Malformed::Archive),
            "{delta}"
        );
    }
}

#[req("FR-06")]
#[test]
fn a_deflate_stream_ending_before_its_compressed_size_is_malformed() {
    // The sizes and the layout agree, but the stream's last block comes before its last declared byte.
    let mut entry = Raw::deflated(b"a.txt", &b"text ".repeat(100));
    entry.stored.extend_from_slice(&[0x55; 100]);
    entry.declared = u32::try_from(entry.stored.len()).expect("size");
    assert_eq!(
        malformed(Format::Zip, &raw_zip(&[entry])),
        Some(Malformed::Size)
    );
}

#[req("FR-06")]
#[test]
fn a_stored_entry_whose_sizes_differ_is_malformed() {
    let mut entry = Raw::stored(b"a.txt", b"abcdef");
    entry.size = 4;
    assert_eq!(
        malformed(Format::Zip, &raw_zip(&[entry])),
        Some(Malformed::Size)
    );
}

#[req("FR-06")]
#[test]
fn a_bad_crc_alone_is_malformed() {
    // A stored entry with one byte changed: sizes and layout intact, only the CRC tells.
    let mut entry = Raw::stored(b"a.txt", b"original content");
    entry.stored[3] ^= 0x20;
    assert_eq!(
        malformed(Format::Zip, &raw_zip(&[entry])),
        Some(Malformed::Archive)
    );
}

#[req("FR-06")]
#[test]
fn a_directory_entry_carrying_bytes_is_malformed() {
    // A name ending in `\` reads as a directory, yet Unix extractors write it as a file.
    let zipped = raw_zip(&[Raw::stored(b"payload.exe\\", b"MZ payload")]);
    assert_eq!(malformed(Format::Zip, &zipped), Some(Malformed::Archive));
    let zipped = raw_zip(&[Raw::stored(b"dir/", b"32 bytes hidden in a directory..")]);
    assert_eq!(malformed(Format::Zip, &zipped), Some(Malformed::Archive));
    let member = Member {
        flag: b'5',
        ..Member::file(b"dir/", b"bytes in a directory member")
    };
    assert_eq!(
        malformed(Format::Tar, &tar(&[member])),
        Some(Malformed::Archive)
    );
}

#[req("FR-06")]
#[test]
fn an_empty_entry_name_is_malformed() {
    let zipped = raw_zip(&[Raw::stored(b"", b"no name")]);
    assert_eq!(malformed(Format::Zip, &zipped), Some(Malformed::Path));
    assert_eq!(
        malformed(Format::Tar, &tar(&[Member::file(b"", b"no name")])),
        Some(Malformed::Path)
    );
}

#[req("FR-06")]
#[test]
fn windows_forms_of_paths_and_device_names_are_malformed() {
    // Q-61: `\` separates components too; drive letters, UNC prefixes and device names are refused.
    for name in [
        "..\\..\\evil.exe",
        "C:\\evil.exe",
        "c:evil.exe",
        "\\\\host\\share\\evil.exe",
        "dir\\..\\..\\evil.exe",
        "CON",
        "aux.txt",
    ] {
        let zipped = raw_zip(&[Raw::stored(name.as_bytes(), b"x")]);
        assert_eq!(
            malformed(Format::Zip, &zipped),
            Some(Malformed::Path),
            "{name}"
        );
        let member = tar(&[Member::file(name.as_bytes(), b"x")]);
        assert_eq!(
            malformed(Format::Tar, &member),
            Some(Malformed::Path),
            "tar {name}"
        );
    }
}

#[req("FR-06")]
#[test]
fn directory_paths_are_held_to_the_rules_too() {
    let leaving = tar(&[Member::bare(b"../dir/", b'5', b"")]);
    assert_eq!(malformed(Format::Tar, &leaving), Some(Malformed::Path));
    let long = tar(&[Member::bare(b"abcdefghij/", b'5', b"")]);
    assert_eq!(
        limit(Format::Tar, &long, &budget(|b| b.max_path_length = 8)),
        Some(Limit::PathLength)
    );
}

#[req("FR-06")]
#[test]
fn a_pax_path_leaving_the_container_is_malformed() {
    let mut builder = tar::Builder::new(Vec::new());
    builder
        .append_pax_extensions([("path", b"../evil.txt".as_slice())])
        .expect("pax");
    let mut header = tar::Header::new_ustar();
    header.set_size(1);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Regular);
    builder
        .append_data(&mut header, "harmless.txt", b"x".as_slice())
        .expect("member");
    let archive = builder.into_inner().expect("archive");
    assert_eq!(malformed(Format::Tar, &archive), Some(Malformed::Path));
}

#[req("FR-06")]
#[test]
fn bytes_after_the_tar_end_are_malformed_unless_zero() {
    let hidden = tar_header(&Member::file(b"hidden.exe", b"MZ"));
    // After the two zero blocks.
    let mut after_end = tar(&[Member::file(b"a.txt", b"a")]);
    after_end.extend_from_slice(&hidden);
    assert_eq!(malformed(Format::Tar, &after_end), Some(Malformed::Archive));
    // After a lone zero block.
    let mut lone = tar(&[Member::file(b"a.txt", b"a")]);
    lone.truncate(lone.len() - 512);
    lone.extend_from_slice(&hidden);
    lone.resize(lone.len() + 1024, 0);
    assert_eq!(malformed(Format::Tar, &lone), Some(Malformed::Archive));
    // Zero padding to a 10240-byte record is normal.
    let mut padded = tar(&[Member::file(b"a.txt", b"a")]);
    padded.resize(10_240, 0);
    assert_eq!(entries(Format::Tar, &padded).len(), 1);
}

#[req("FR-06")]
#[test]
fn an_unknown_tar_member_type_is_malformed() {
    let member = Member::bare(b"volume", b'V', b"");
    assert_eq!(
        malformed(Format::Tar, &tar(&[member])),
        Some(Malformed::Archive)
    );
}

#[req("FR-06")]
#[test]
fn gzip_is_held_to_every_limit_and_rule() {
    let archive = gzip(Some(b"a.txt"), &[b'a'; 1000], 0);
    assert_eq!(
        limit(Format::Gzip, &archive, &budget(|b| b.remaining_bytes = 999)),
        Some(Limit::TotalSize)
    );
    assert_eq!(
        limit(Format::Gzip, &archive, &budget(|b| b.remaining_entries = 0)),
        Some(Limit::EntryCount)
    );
    assert_eq!(
        limit(Format::Gzip, &archive, &budget(|b| b.max_path_length = 4)),
        Some(Limit::PathLength)
    );
    assert_eq!(
        malformed(Format::Gzip, &gzip(Some(b"/etc/passwd"), b"x", 0)),
        Some(Malformed::Path)
    );
    assert_eq!(
        malformed(Format::Gzip, b"not a gzip member"),
        Some(Malformed::Archive)
    );
    // ISIZE changed, CRC intact.
    let mut size = archive.clone();
    let at = size.len() - 4;
    size[at] ^= 0x01;
    assert_eq!(malformed(Format::Gzip, &size), Some(Malformed::Archive));
}

#[req("FR-06")]
#[test]
fn a_local_header_disagreeing_with_its_central_record_is_malformed() {
    // Streaming extractors read the local header: its name, method, flags, CRC and sizes must be the central
    // record's, or they would write other bytes under another name than the ones scanned.
    let valid = raw_zip(&[Raw::stored(b"readme.txt", b"harmless")]);
    assert_eq!(entries(Format::Zip, &valid).len(), 1);
    // (offset in the local header, new bytes): name, method, encryption flag, CRC, compressed size, size.
    let cases: [(usize, &[u8]); 6] = [
        (30, b"../../x.ex"),
        (8, &[8, 0]),
        (6, &[1, 0]),
        (14, &[0, 0, 0, 0]),
        (18, &[9, 0, 0, 0]),
        (22, &[9, 0, 0, 0]),
    ];
    for (offset, bytes) in cases {
        let mut archive = valid.clone();
        archive[offset..offset + bytes.len()].copy_from_slice(bytes);
        assert_eq!(
            malformed(Format::Zip, &archive),
            Some(Malformed::Archive),
            "local header at {offset}"
        );
    }
}
