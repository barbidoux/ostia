//! The extraction worker's formats of part 2 (FR-06, ADR-18, WP-1.9): 7z, rar, cab, iso and msi archives
//! built at test time by `tests/fixtures/archives.py`, read back through the extraction: entries, sizes, times
//! and bytes; the budget's limits reached while streaming, a folder's ratio shared by its entries (Q-64);
//! malformed containers refused, never half-trusted.

mod built;

use std::io::{self, Cursor};

use built::build;
use ostia_core_domain::verdict::Limit;
use ostia_traceability::req;
use ostia_workers::extract::{Budget, Format, Header, Kind, Malformed, Sink, Stop, extract};

/// 1980-01-01T00:00:00Z, every builder's time.
const EPOCH_1980: i64 = 315_532_800;
const A: &[u8] = b"Ostia part two: entry a\n";
const MIB: usize = 1024 * 1024;

/// Far from every limit.
const OPEN: Budget = Budget {
    max_ratio: 1_000_000,
    remaining_bytes: 1 << 40,
    remaining_entries: 1 << 20,
    max_path_length: 4096,
};

/// `len` incompressible bytes (xorshift).
fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[3]
        })
        .collect()
}

/// The second entry of the two-entry archives.
fn b() -> Vec<u8> {
    noise(4096, 7)
}

/// `a.txt` and `dir/b.bin`, built by `builder` with `options`.
fn two(builder: &str, options: &str) -> Vec<u8> {
    build(builder, &[("a.txt", A), ("dir/b.bin", &b())], options)
}

/// Every entry and its bytes.
#[derive(Default)]
struct Collect {
    entries: Vec<(Header, Vec<u8>)>,
}

impl Sink for Collect {
    fn entry(&mut self, header: &Header) -> io::Result<()> {
        self.entries.push((header.clone(), Vec::new()));
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> io::Result<()> {
        let (_, content) = self.entries.last_mut().expect("data after an entry");
        content.extend_from_slice(bytes);
        Ok(())
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

fn regular(path: &str, content: &[u8], modified: Option<i64>) -> (Header, Vec<u8>) {
    let header = Header {
        path: path.as_bytes().to_vec(),
        kind: Kind::Regular,
        size: content.len() as u64,
        modified,
    };
    (header, content.to_vec())
}

fn limit(format: Format, archive: &[u8], budget: &Budget) -> Limit {
    match run(format, archive, budget).0 {
        Err(Stop::Limit(limit)) => limit,
        other => panic!("{format:?}: no limit: {other:?}"),
    }
}

fn malformed(format: Format, archive: &[u8]) -> Malformed {
    match run(format, archive, &OPEN).0 {
        Err(Stop::Malformed(why)) => why,
        other => panic!("{format:?}: not malformed: {other:?}"),
    }
}

fn budget(change: impl FnOnce(&mut Budget)) -> Budget {
    let mut budget = OPEN;
    change(&mut budget);
    budget
}

/// The builder of each format, and an archive of it holding `a.txt` and `dir/b.bin`.
fn every_format() -> Vec<(Format, &'static str)> {
    vec![
        (Format::SevenZip, "seven_zip"),
        (Format::Rar, "rar"),
        (Format::Cab, "cab"),
        (Format::Iso, "iso"),
        (Format::Msi, "msi"),
    ]
}

/// `archive` cut to 60 % of its length.
fn truncated(archive: &[u8]) -> Vec<u8> {
    archive[..archive.len() * 6 / 10].to_vec()
}

/// The offset of the first occurrence of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("found")
}

fn utf16be(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

// --- entries ---------------------------------------------------------------------------------------------

#[req("FR-06")]
#[test]
fn seven_zip_entries_come_with_their_path_size_time_and_bytes() {
    assert_eq!(
        entries(Format::SevenZip, &two("seven_zip", "")),
        vec![
            regular("a.txt", A, Some(EPOCH_1980)),
            regular("dir/b.bin", &b(), Some(EPOCH_1980)),
        ]
    );
}

#[req("FR-06")]
#[test]
fn a_seven_zip_empty_file_is_an_entry_without_bytes() {
    let archive = build("seven_zip", &[("a.txt", A), ("empty.txt", b"")], "");
    assert_eq!(
        entries(Format::SevenZip, &archive),
        vec![
            regular("a.txt", A, Some(EPOCH_1980)),
            regular("empty.txt", b"", Some(EPOCH_1980)),
        ]
    );
}

#[req("FR-06")]
#[test]
fn rar_entries_come_with_their_path_size_time_and_bytes() {
    assert_eq!(
        entries(Format::Rar, &two("rar", "")),
        vec![
            regular("a.txt", A, Some(EPOCH_1980)),
            regular("dir/b.bin", &b(), Some(EPOCH_1980)),
        ]
    );
}

#[req("FR-06")]
#[test]
fn cab_entries_come_with_their_path_size_time_and_bytes() {
    // The cabinet's `\` separator becomes `/`.
    let expected = vec![
        regular("a.txt", A, Some(EPOCH_1980)),
        regular("dir/b.bin", &b(), Some(EPOCH_1980)),
    ];
    for compression in ["mszip", "lzx", "none"] {
        let archive = two("cab", &format!("compression={compression:?}"));
        assert_eq!(entries(Format::Cab, &archive), expected, "{compression}");
    }
}

#[req("FR-06")]
#[test]
fn cab_folders_spanning_several_blocks_are_decoded_whole() {
    // 100,000 bytes: four data blocks of at most 32 KiB, MSZIP and LZX keeping their window across blocks.
    let long: Vec<u8> = noise(1000, 3).repeat(100);
    for compression in ["mszip", "lzx"] {
        let archive = build(
            "cab",
            &[("a.txt", A), ("long.bin", &long)],
            &format!("compression={compression:?}"),
        );
        assert_eq!(
            entries(Format::Cab, &archive),
            vec![
                regular("a.txt", A, Some(EPOCH_1980)),
                regular("long.bin", &long, Some(EPOCH_1980)),
            ],
            "{compression}"
        );
    }
}

#[req("FR-06")]
#[test]
fn iso_entries_carry_their_joliet_names_without_versions() {
    assert_eq!(
        entries(Format::Iso, &two("iso", "")),
        vec![
            regular("a.txt", A, Some(EPOCH_1980)),
            regular("dir/b.bin", &b(), Some(EPOCH_1980)),
        ]
    );
}

#[req("FR-06")]
#[test]
fn an_iso_without_joliet_gives_its_primary_names() {
    assert_eq!(
        entries(Format::Iso, &two("iso", "joliet=False")),
        vec![
            regular("A.TXT", A, Some(EPOCH_1980)),
            regular("DIR/B.BIN", &b(), Some(EPOCH_1980)),
        ]
    );
}

#[req("FR-06")]
#[test]
fn msi_streams_are_entries_under_their_decoded_names() {
    let cabinet = two("cab", "");
    // Directory order: shorter encoded names first, then by upper-case code units.
    assert_eq!(
        entries(Format::Msi, &two("msi", "")),
        vec![
            regular("product.cab", &cabinet, None),
            regular("!_StringData", b"", None),
            regular("!_StringPool", &[0xE4, 0x04, 0x00, 0x00], None),
        ]
    );
}

// --- limits ----------------------------------------------------------------------------------------------

#[req("FR-06")]
#[test]
fn every_format_stops_at_the_entry_count() {
    for (format, builder) in every_format() {
        let one = budget(|b| b.remaining_entries = 1);
        assert_eq!(
            limit(format, &two(builder, ""), &one),
            Limit::EntryCount,
            "{format:?}"
        );
    }
}

#[req("FR-06")]
#[test]
fn every_format_stops_at_the_remaining_total() {
    for (format, builder) in every_format() {
        let small = budget(|b| b.remaining_bytes = 1000);
        assert_eq!(
            limit(format, &two(builder, ""), &small),
            Limit::TotalSize,
            "{format:?}"
        );
    }
}

#[req("FR-06")]
#[test]
fn every_format_stops_at_the_path_length() {
    for (format, builder) in every_format() {
        let short = budget(|b| b.max_path_length = 4);
        assert_eq!(
            limit(format, &two(builder, ""), &short),
            Limit::PathLength,
            "{format:?}"
        );
    }
}

#[req("FR-06")]
#[test]
fn compressed_bombs_stop_at_the_ratio() {
    let zeros = vec![0; 4 * MIB];
    let tight = budget(|b| b.max_ratio = 100);
    for (format, builder) in [(Format::SevenZip, "seven_zip"), (Format::Cab, "cab")] {
        let bomb = build(builder, &[("zeros.bin", &zeros)], "");
        assert_eq!(limit(format, &bomb, &tight), Limit::Ratio, "{format:?}");
    }
}

#[req("FR-06")]
#[test]
fn stored_entries_are_held_to_the_ratio() {
    // Nothing is compressed in a stored rar, an iso or an msi: a ratio of 1 holds, a ratio of 0 does not.
    for (format, builder) in [
        (Format::Rar, "rar"),
        (Format::Iso, "iso"),
        (Format::Msi, "msi"),
    ] {
        let archive = two(builder, "");
        let (result, _) = run(format, &archive, &budget(|b| b.max_ratio = 1));
        assert!(result.is_ok(), "{format:?}: {result:?}");
        let none = budget(|b| b.max_ratio = 0);
        assert_eq!(limit(format, &archive, &none), Limit::Ratio, "{format:?}");
    }
}

#[req("FR-06")]
#[test]
fn a_seven_zip_folder_of_its_own_is_held_to_its_ratio() {
    // One folder per entry: the zeros' folder is about 5000:1 although the whole archive is about 2:1.
    let entries = [("noise.bin", noise(MIB, 5)), ("zeros.bin", vec![0; MIB])];
    let entries: Vec<(&str, &[u8])> = entries.iter().map(|(n, c)| (*n, c.as_slice())).collect();
    let tight = budget(|b| b.max_ratio = 100);
    let separate = build("seven_zip", &entries, "solid=False");
    assert_eq!(limit(Format::SevenZip, &separate, &tight), Limit::Ratio);
}

#[req("FR-06")]
#[test]
fn entries_sharing_a_seven_zip_folder_share_its_ratio() {
    // One folder for both (Q-64): about 2:1, within the limit.
    let entries = [("noise.bin", noise(MIB, 5)), ("zeros.bin", vec![0; MIB])];
    let entries: Vec<(&str, &[u8])> = entries.iter().map(|(n, c)| (*n, c.as_slice())).collect();
    let tight = budget(|b| b.max_ratio = 100);
    let solid = build("seven_zip", &entries, "solid=True");
    let (result, sink) = run(Format::SevenZip, &solid, &tight);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(sink.entries.len(), 2);
}

// --- malformed -------------------------------------------------------------------------------------------

#[req("FR-06", "NFR-05")]
#[test]
fn cut_archives_are_malformed() {
    for (format, builder) in every_format() {
        assert_eq!(
            malformed(format, &truncated(&two(builder, ""))),
            Malformed::Archive,
            "{format:?}"
        );
    }
}

#[req("FR-06", "NFR-05")]
#[test]
fn corrupt_bytes_under_a_checksum_are_malformed() {
    // 7z: the LZMA2 stream (after the 32-byte signature header); rar: a stored entry's bytes (CRC32); cab:
    // a data block's stored deflate bytes (its checksum). Five bytes: an even count of flipped words would
    // leave the cabinet's XOR checksum unchanged.
    for (format, builder) in [
        (Format::SevenZip, "seven_zip"),
        (Format::Rar, "rar"),
        (Format::Cab, "cab"),
    ] {
        let mut archive = two(builder, "");
        let at = if format == Format::SevenZip {
            40
        } else {
            find(&archive, &b()[..16])
        };
        for byte in &mut archive[at..at + 5] {
            *byte ^= 0xFF;
        }
        assert_eq!(
            malformed(format, &archive),
            Malformed::Archive,
            "{format:?}"
        );
    }
}

#[req("FR-06")]
#[test]
fn encrypted_entries_are_malformed_as_encrypted() {
    assert_eq!(
        malformed(Format::SevenZip, &two("seven_zip", "coder=\"aes\"")),
        Malformed::Encrypted
    );
    assert_eq!(
        malformed(Format::Rar, &two("rar", "encrypted=True")),
        Malformed::Encrypted
    );
}

#[req("FR-06")]
#[test]
fn methods_this_worker_lacks_are_malformed_as_methods() {
    for coder in ["ppmd", "bzip2"] {
        assert_eq!(
            malformed(
                Format::SevenZip,
                &two("seven_zip", &format!("coder={coder:?}"))
            ),
            Malformed::Method,
            "{coder}"
        );
    }
    assert_eq!(
        malformed(Format::Cab, &two("cab", "compression=\"quantum\"")),
        Malformed::Method
    );
}

#[req("FR-06")]
#[test]
fn entry_paths_leaving_the_container_are_malformed() {
    for (format, builder) in every_format() {
        if format == Format::Msi {
            continue; // msi entries are stream names: below
        }
        for path in ["../escape.txt", "/etc/escape.txt"] {
            if format == Format::Iso && path.starts_with('/') {
                continue; // an iso tree has no absolute names: `/` separates its directories
            }
            let archive = build(builder, &[(path, A)], "");
            assert_eq!(
                malformed(format, &archive),
                Malformed::Path,
                "{format:?} {path}"
            );
        }
    }
    let streams = build("compound_file", &[("..", A)], "");
    assert_eq!(malformed(Format::Msi, &streams), Malformed::Path);
}

#[req("FR-06")]
#[test]
fn cab_bytes_after_the_cabinet_are_malformed() {
    let mut archive = two("cab", "");
    archive.push(b'x');
    assert_eq!(malformed(Format::Cab, &archive), Malformed::Archive);
}

#[req("FR-06")]
#[test]
fn a_cabinet_continued_from_or_into_another_is_malformed() {
    // The header's flags (offset 30): previous cabinet, next cabinet.
    for flag in [0x0001_u16, 0x0002] {
        let mut archive = two("cab", "");
        archive[30..32].copy_from_slice(&flag.to_le_bytes());
        assert_eq!(
            malformed(Format::Cab, &archive),
            Malformed::Archive,
            "{flag}"
        );
    }
}

#[req("FR-06")]
#[test]
fn cab_files_that_do_not_cover_their_folder_are_malformed() {
    // The second file record starts at 44 + 16 + "a.txt\0"; its folder offset is 4 bytes in. Moved one byte
    // on, a byte of the folder belongs to no file.
    let mut archive = two("cab", "");
    let offset = 44 + 16 + 6 + 4;
    let moved = u32::try_from(A.len() + 1).expect("offset").to_le_bytes();
    archive[offset..offset + 4].copy_from_slice(&moved);
    assert_eq!(malformed(Format::Cab, &archive), Malformed::Archive);
}

/// The start of the Joliet directory record named `name`: its identifier's length at 32, the identifier at
/// 33 (a path table record has its parent number before the identifier, never the length).
fn joliet_record(image: &[u8], name: &str) -> usize {
    let identifier = utf16be(name);
    let mut needle = vec![u8::try_from(identifier.len()).expect("length")];
    needle.extend_from_slice(&identifier);
    find(image, &needle) - 32
}

#[req("FR-06")]
#[test]
fn an_iso_directory_reached_twice_is_malformed() {
    // The Joliet `dir` record pointed at the root directory: a loop.
    let mut image = two("iso", "");
    let root = 17 * 2048 + 156 + 2;
    let root_extent: [u8; 8] = image[root..root + 8].try_into().expect("extent");
    let record = joliet_record(&image, "dir");
    image[record + 2..record + 10].copy_from_slice(&root_extent);
    assert_eq!(malformed(Format::Iso, &image), Malformed::Archive);
}

#[req("FR-06")]
#[test]
fn iso_values_whose_byte_orders_disagree_are_malformed() {
    let mut image = two("iso", "");
    let record = joliet_record(&image, "a.txt;1");
    image[record + 17] ^= 0x01; // the big-endian half of the size
    assert_eq!(malformed(Format::Iso, &image), Malformed::Archive);
}

#[req("FR-06")]
#[test]
fn iso_multi_extent_files_are_an_unsupported_method() {
    let mut image = two("iso", "");
    let record = joliet_record(&image, "a.txt;1");
    image[record + 25] |= 0x80;
    assert_eq!(malformed(Format::Iso, &image), Malformed::Method);
}

#[req("FR-06")]
#[test]
fn an_msi_that_is_not_a_compound_file_is_malformed() {
    assert_eq!(malformed(Format::Msi, &two("cab", "")), Malformed::Archive);
}
