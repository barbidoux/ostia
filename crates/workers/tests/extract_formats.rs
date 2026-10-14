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

/// Per format: the bytes, entries and longest path of `two(builder, "")`. The files are `a.txt` (24 bytes) and
/// `dir/b.bin` (4096); the msi's streams are `product.cab` (the cabinet of those), `!_StringData` (0) and
/// `!_StringPool` (4).
fn sizes(format: Format) -> (u64, u64, u32) {
    if format == Format::Msi {
        (two("cab", "").len() as u64 + 4, 3, 12)
    } else {
        (24 + 4096, 2, 9)
    }
}

#[req("FR-06")]
#[test]
fn every_format_stops_at_the_entry_count() {
    for (format, builder) in every_format() {
        let (_, count, _) = sizes(format);
        let exact = budget(|b| b.remaining_entries = count);
        let (result, _) = run(format, &two(builder, ""), &exact);
        assert!(result.is_ok(), "{format:?}: {result:?}");
        let fewer = budget(|b| b.remaining_entries = count - 1);
        let (result, sink) = run(format, &two(builder, ""), &fewer);
        assert!(
            matches!(result, Err(Stop::Limit(Limit::EntryCount))),
            "{format:?}: {result:?}"
        );
        assert_eq!(sink.entries.len() as u64, count - 1, "{format:?}");
    }
}

#[req("FR-06")]
#[test]
fn every_format_stops_at_the_remaining_total() {
    for (format, builder) in every_format() {
        let (total, _, _) = sizes(format);
        let exact = budget(|b| b.remaining_bytes = total);
        let (result, _) = run(format, &two(builder, ""), &exact);
        assert!(result.is_ok(), "{format:?}: {result:?}");
        let short = budget(|b| b.remaining_bytes = total - 1);
        let (result, sink) = run(format, &two(builder, ""), &short);
        assert!(
            matches!(result, Err(Stop::Limit(Limit::TotalSize))),
            "{format:?}: {result:?}"
        );
        let produced: u64 = sink.entries.iter().map(|(_, c)| c.len() as u64).sum();
        assert!(produced < total, "{format:?}: {produced}");
    }
}

#[req("FR-06")]
#[test]
fn every_format_stops_at_the_path_length() {
    for (format, builder) in every_format() {
        let (_, _, longest) = sizes(format);
        let exact = budget(|b| b.max_path_length = longest);
        let (result, _) = run(format, &two(builder, ""), &exact);
        assert!(result.is_ok(), "{format:?}: {result:?}");
        let shorter = budget(|b| b.max_path_length = longest - 1);
        assert_eq!(
            limit(format, &two(builder, ""), &shorter),
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

#[req("FR-06")]
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

#[req("FR-06")]
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
    // The second file record starts at 44 + 16 + "a.txt\0": its size at 0, its folder offset at 4. Its
    // offset one byte on leaves a byte no file covers; one byte back, two files share it; its size one byte
    // short leaves the folder's last byte to no file.
    let second = 44 + 16 + 6;
    let a = u32::try_from(A.len()).expect("size");
    for (at, value) in [(second + 4, a + 1), (second + 4, a - 1), (second, 4095)] {
        let mut archive = two("cab", "");
        archive[at..at + 4].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            malformed(Format::Cab, &archive),
            Malformed::Archive,
            "{at} {value}"
        );
    }
}

#[req("FR-06")]
#[test]
fn bytes_between_the_cab_tables_and_its_data_are_malformed() {
    // One byte inserted where the data blocks start (after the file table: 44 + 16 + 6 + 16 + 10), the
    // cabinet's size and its folder's first block moved on by one: every other field still agrees.
    let mut archive = two("cab", "");
    let data_at = 44 + 16 + 6 + 16 + 10;
    archive.insert(data_at, 0);
    for at in [8, 36] {
        let value = u32::from_le_bytes(archive[at..at + 4].try_into().expect("u32")) + 1;
        archive[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }
    assert_eq!(malformed(Format::Cab, &archive), Malformed::Archive);
}

#[req("FR-06")]
#[test]
fn a_cab_folder_of_its_own_is_held_to_its_ratio() {
    // Noise in one folder, zeros in another: the zeros' folder is far over 100:1, the cabinet about 2:1.
    let entries = [("noise.bin", noise(MIB, 5)), ("zeros.bin", vec![0; MIB])];
    let entries: Vec<(&str, &[u8])> = entries.iter().map(|(n, c)| (*n, c.as_slice())).collect();
    let tight = budget(|b| b.max_ratio = 100);
    let separate = build("cab", &entries, "folder_per_entry=True");
    assert_eq!(limit(Format::Cab, &separate, &tight), Limit::Ratio);
    let shared = build("cab", &entries, "");
    let (result, sink) = run(Format::Cab, &shared, &tight);
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(sink.entries.len(), 2);
}

#[req("FR-06")]
#[test]
fn bytes_after_the_archive_are_malformed() {
    // A byte after a 7z's header or a rar's end block; a sector after an iso's volume.
    for (format, builder, tail) in [
        (Format::SevenZip, "seven_zip", vec![0]),
        (Format::Rar, "rar", vec![0]),
        (Format::Iso, "iso", vec![0; 2048]),
    ] {
        let mut archive = two(builder, "");
        archive.extend_from_slice(&tail);
        assert_eq!(
            malformed(format, &archive),
            Malformed::Archive,
            "{format:?}"
        );
    }
}

#[req("FR-06")]
#[test]
fn a_seven_zip_start_header_without_its_checksum_is_malformed() {
    // A zero checksum makes readers search for the header themselves.
    let mut archive = two("seven_zip", "");
    archive[8..12].copy_from_slice(&[0; 4]);
    assert_eq!(malformed(Format::SevenZip, &archive), Malformed::Archive);
}

#[req("FR-06")]
#[test]
fn an_empty_file_between_a_folders_files_leaves_none_unread() {
    // The empty file is listed between the two files of the one folder: both are still extracted.
    let archive = build(
        "seven_zip",
        &[("a.txt", A), ("empty.txt", b""), ("b.bin", &b())],
        "",
    );
    assert_eq!(
        entries(Format::SevenZip, &archive),
        vec![
            regular("a.txt", A, Some(EPOCH_1980)),
            regular("b.bin", &b(), Some(EPOCH_1980)),
            regular("empty.txt", b"", Some(EPOCH_1980)),
        ]
    );
}

#[req("FR-06")]
#[test]
fn a_seven_zip_folder_with_more_sub_streams_than_files_is_malformed() {
    assert_eq!(
        malformed(Format::SevenZip, &two("seven_zip", "extra_substreams=1")),
        Malformed::Archive
    );
}

#[req("FR-06")]
#[test]
fn a_seven_zip_dictionary_over_256_mib_is_an_unsupported_method() {
    // LZMA2 property 32: 256 MiB, the cap (Q-67); 33: 384 MiB.
    let (result, _) = run(
        Format::SevenZip,
        &two("seven_zip", "lzma2_property=32"),
        &OPEN,
    );
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        malformed(Format::SevenZip, &two("seven_zip", "lzma2_property=33")),
        Malformed::Method
    );
}

#[req("FR-06")]
#[test]
fn rar_links_are_entries_without_bytes() {
    let archive = build("rar", &[("a.txt", A)], "links=[(\"soft\", \"a.txt\")]");
    let link = Header {
        path: b"soft".to_vec(),
        kind: Kind::Link,
        size: 0,
        modified: None,
    };
    assert_eq!(
        entries(Format::Rar, &archive),
        vec![(link, vec![]), regular("a.txt", A, Some(EPOCH_1980))]
    );
}

#[req("FR-06")]
#[test]
fn rar_directories_and_links_carrying_bytes_are_malformed() {
    for options in [
        "directory_data=b\"hidden\"",
        "links=[(\"soft\", \"a.txt\")], link_data=b\"hidden\"",
    ] {
        assert_eq!(
            malformed(Format::Rar, &two("rar", options)),
            Malformed::Archive,
            "{options}"
        );
    }
}

#[req("FR-06")]
#[test]
fn rar_services_other_than_the_archive_comment_are_unsupported() {
    // An NTFS alternate stream after a file, an unknown service, a comment attached to a file (Q-66).
    for options in [
        "file_services=[(\"STM\", b\"payload\")]",
        "services=[(\"XYZ\", b\"payload\")]",
        "file_services=[(\"CMT\", b\"payload\")]",
    ] {
        assert_eq!(
            malformed(Format::Rar, &two("rar", options)),
            Malformed::Method,
            "{options}"
        );
    }
}

#[req("FR-06")]
#[test]
fn the_rar_comment_is_an_entry() {
    let archive = build(
        "rar",
        &[("a.txt", A)],
        "services=[(\"CMT\", b\"Ostia comment\")]",
    );
    assert_eq!(
        entries(Format::Rar, &archive),
        vec![
            regular("a.txt", A, Some(EPOCH_1980)),
            regular("[comment]", b"Ostia comment", None),
        ]
    );
}

#[req("FR-06")]
#[test]
fn a_rar_member_continued_in_another_volume_is_malformed() {
    assert_eq!(
        malformed(Format::Rar, &two("rar", "split=True")),
        Malformed::Archive
    );
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
fn iso_multi_extent_interleaved_and_extended_files_are_unsupported_methods() {
    // The record's flags (multi-extent), its file unit size (interleaving), its extended attribute length.
    for (offset, value) in [(25, 0x80), (26, 1), (1, 1)] {
        let mut image = two("iso", "");
        let record = joliet_record(&image, "a.txt;1");
        image[record + offset] |= value;
        assert_eq!(
            malformed(Format::Iso, &image),
            Malformed::Method,
            "{offset}"
        );
    }
}

#[req("FR-06")]
#[test]
fn iso_trees_listing_different_files_are_malformed() {
    // The Joliet `a.txt` record given `b.bin`'s extent and size: the primary tree still lists `a.txt`'s.
    let mut image = two("iso", "");
    let b = joliet_record(&image, "b.bin;1");
    let extent_and_size: [u8; 16] = image[b + 2..b + 18].try_into().expect("fields");
    let a = joliet_record(&image, "a.txt;1");
    image[a + 2..a + 18].copy_from_slice(&extent_and_size);
    assert_eq!(malformed(Format::Iso, &image), Malformed::Archive);
}

#[req("FR-06")]
#[test]
fn an_iso_boot_record_or_udf_sequence_is_an_unsupported_method() {
    // What this reader does not read is refused (Q-65).
    for options in ["boot_record=True", "udf=True"] {
        assert_eq!(
            malformed(Format::Iso, &two("iso", options)),
            Malformed::Method,
            "{options}"
        );
    }
}

#[req("FR-06")]
#[test]
fn an_iso_primary_name_loses_its_version_and_trailing_dot() {
    // `readme` is written `README.;1` in the primary tree.
    let image = build("iso", &[("readme", A)], "joliet=False");
    assert_eq!(
        entries(Format::Iso, &image),
        vec![regular("README", A, Some(EPOCH_1980))]
    );
}

#[req("FR-06")]
#[test]
fn an_msi_that_is_not_a_compound_file_is_malformed() {
    assert_eq!(malformed(Format::Msi, &two("cab", "")), Malformed::Archive);
}
