//! The extraction worker's formats (FR-06, ADR-18): entries, kinds, sizes, times and bytes of zip, tar and gzip;
//! the budget's limits reached while streaming; malformed containers refused, never half-trusted.

mod archives;

use std::io::{self, Cursor};

use archives::{
    EPOCH_1980, LEAP_DAY, Member, Method, declaring, encrypted, gzip, leap_day, overlapping,
    renamed_byte, tar, tar_header, tar_long_name, with_method, zip, zip_at, zip_symlink,
};
use ostia_core_domain::types::DetectedType;
use ostia_core_domain::verdict::Limit;
use ostia_traceability::req;
use ostia_workers::extract::{Budget, CHUNK, Format, Header, Kind, Malformed, Sink, Stop, extract};

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
    let result = extract(format, &mut Cursor::new(archive), budget, &mut sink);
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
fn the_formats_are_zip_tar_and_gzip() {
    assert_eq!(Format::of(DetectedType::Zip), Some(Format::Zip));
    assert_eq!(Format::of(DetectedType::Tar), Some(Format::Tar));
    assert_eq!(Format::of(DetectedType::Gzip), Some(Format::Gzip));
    for other in [
        DetectedType::Pe,
        DetectedType::Pdf,
        DetectedType::SevenZip,
        DetectedType::Rar,
        DetectedType::Cab,
        DetectedType::Iso9660,
        DetectedType::Msi,
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
    // Never more than the limit allows, plus one chunk.
    let compressed = archive.len();
    assert!(
        sink.produced() <= 100 * compressed + CHUNK,
        "{}",
        sink.produced()
    );
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
    assert!(sink.produced() <= 100 * archive.len() + CHUNK);
}

#[req("FR-06")]
#[test]
fn overlapping_entries_breach_the_container_ratio() {
    // Each entry: 64 KiB from about 90 bytes (under 1000); the container: 200 times that from a few kB.
    let archive = overlapping(&zeros(64 * 1024), 200);
    let found = limit(Format::Zip, &archive, &budget(|b| b.max_ratio = 1000));
    assert_eq!(found, Some(Limit::Ratio));
    // The same archive under an open budget is extracted whole: the entries are readable.
    assert_eq!(entries(Format::Zip, &archive).len(), 200);
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
    let result = extract(Format::Zip, &mut Cursor::new(&archive), &OPEN, &mut sink);
    assert!(matches!(result, Err(Stop::Sink(_))), "{result:?}");
}
