//! What the extraction fuzz target does with one input: extract it as each format under a small budget,
//! checking the properties the stream must hold (FR-06). Any panic, a broken property included, is a finding.

use std::io::Cursor;

use ostia_workers::extract::{Budget, CHUNK, Format, Header, Kind, Sink, Stop, extract};

/// Small enough that the limits are reached often.
const BUDGET: Budget = Budget {
    max_ratio: 50,
    remaining_bytes: 1 << 20,
    remaining_entries: 64,
    max_path_length: 256,
};

/// Extracts `data` as each format: zip, tar, gzip, 7z, rar, cab, iso and msi.
///
/// # Panics
/// When a property breaks: that is what the fuzzer looks for.
pub fn exercise_extract(data: &[u8]) {
    for format in [
        Format::Zip,
        Format::Tar,
        Format::Gzip,
        Format::SevenZip,
        Format::Rar,
        Format::Cab,
        Format::Iso,
        Format::Msi,
    ] {
        let mut sink = Check::default();
        let result = extract(format, Cursor::new(data.to_vec()), &BUDGET, &mut sink);
        assert!(
            !matches!(result, Err(Stop::Sink(_))),
            "this sink never refuses"
        );
        let container = u64::try_from(data.len()).unwrap_or(u64::MAX).max(1);
        assert!(sink.produced <= BUDGET.remaining_bytes, "total size");
        assert!(sink.entries <= BUDGET.remaining_entries, "entry count");
        assert!(
            u128::from(sink.produced) <= u128::from(BUDGET.max_ratio) * u128::from(container),
            "container ratio"
        );
        if result.is_ok() {
            assert_eq!(
                sink.due, 0,
                "an extraction ended with an entry short of its size"
            );
        }
    }
}

/// Checks the stream as it comes.
#[derive(Default)]
struct Check {
    entries: u64,
    produced: u64,
    /// Bytes still due for the open entry.
    due: u64,
    open: bool,
}

impl Sink for Check {
    fn entry(&mut self, header: &Header) -> std::io::Result<()> {
        assert!(
            !self.open || self.due == 0,
            "an entry began before the last one's bytes"
        );
        let path = &header.path;
        assert!(path.len() <= 256, "path length");
        assert!(path.first() != Some(&b'/'), "absolute path");
        assert!(!path.contains(&0), "NUL in a path");
        assert!(
            !path.split(|&b| b == b'/').any(|part| part == b".."),
            "a path leaving its container"
        );
        if header.kind != Kind::Regular {
            assert_eq!(
                header.size, 0,
                "bytes announced for a link or special entry"
            );
        }
        self.entries += 1;
        self.due = header.size;
        self.open = true;
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        assert!(self.open, "bytes before any entry");
        assert!(!bytes.is_empty(), "an empty chunk");
        assert!(bytes.len() <= CHUNK, "a chunk over the cap");
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        assert!(len <= self.due, "more bytes than the entry announced");
        self.due -= len;
        self.produced += len;
        Ok(())
    }
}
