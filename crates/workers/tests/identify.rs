//! FR-05: the type comes from the content by report.md's rules; a near miss of any rule matches nothing; an
//! object matching two rules is reported with both, never given one of them (Q-55); a read failure anywhere is
//! an error, never a type; only the bytes the rules look at are read.

mod samples;

use std::io::{Cursor, Read, Seek, SeekFrom};

use ostia_core_domain::types::DetectedType;
use ostia_traceability::req;
use ostia_workers::triage::matching_types;

fn matched(bytes: &[u8]) -> Vec<&'static str> {
    matching_types(&mut Cursor::new(bytes))
        .expect("readable")
        .into_iter()
        .map(DetectedType::name)
        .collect()
}

#[req("FR-05")]
#[test]
fn every_type_of_the_report_is_identified_from_its_content() {
    for (name, bytes) in samples::typed() {
        assert_eq!(matched(&bytes), [name], "{name}: {} bytes", bytes.len());
    }
}

#[req("FR-05")]
#[test]
fn near_misses_match_no_rule() {
    for (case, bytes) in samples::untyped() {
        assert_eq!(matched(&bytes), Vec::<&str>::new(), "{case}");
    }
}

#[req("FR-05")]
#[test]
fn polyglots_report_every_rule_they_match() {
    for (case, bytes, types) in samples::polyglots() {
        assert_eq!(matched(&bytes), types, "{case}");
    }
}

#[req("FR-05")]
#[test]
fn every_type_has_a_sample() {
    let covered: Vec<_> = samples::typed().into_iter().map(|(name, _)| name).collect();
    for detected in DetectedType::ALL {
        if detected != DetectedType::Unknown {
            assert!(covered.contains(&detected.name()), "{detected:?}");
        }
    }
}

/// Serves `bytes` up to `readable`, and fails like a bad sector (EIO) for any read starting at or beyond it.
struct BadSector {
    inner: Cursor<Vec<u8>>,
    readable: u64,
}

impl Read for BadSector {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.inner.position() >= self.readable {
            return Err(std::io::Error::from_raw_os_error(5));
        }
        let room = usize::try_from(self.readable - self.inner.position()).unwrap_or(usize::MAX);
        let len = buf.len().min(room);
        self.inner.read(&mut buf[..len])
    }
}

impl Seek for BadSector {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

#[req("FR-05")]
#[test]
fn read_failure_anywhere_is_an_error_never_a_type() {
    let cases: [(&str, Vec<u8>, u64); 4] = [
        ("the first bytes", b"%PDF-1.4\n".to_vec(), 0),
        (
            "the PE signature e_lfanew points to",
            samples::pe(0x1000, *b"PE\0\0", 0x1010),
            512,
        ),
        (
            "a compound file's root entry",
            samples::compound_file(9, 3, samples::MSI_CLSID),
            512,
        ),
        (
            "the ISO 9660 descriptor",
            samples::at(32769, b"CD001", 34816),
            512,
        ),
    ];
    for (case, bytes, readable) in cases {
        let mut source = BadSector {
            inner: Cursor::new(bytes),
            readable,
        };
        let failed = matching_types(&mut source);
        assert_eq!(
            failed.map_err(|error| error.raw_os_error()),
            Err(Some(5)),
            "{case}"
        );
    }
}

/// Counts the bytes read.
struct Counting {
    inner: Cursor<Vec<u8>>,
    read: usize,
}

impl Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read += read;
        Ok(read)
    }
}

impl Seek for Counting {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}

#[req("FR-05")]
#[test]
fn only_the_bytes_the_rules_look_at_are_read() {
    // 512 first bytes, 4 at e_lfanew, 16 of a root entry's CLSID, 5 at 32769: at most 537 bytes, whatever the
    // object's size.
    let mebibyte = 1 << 20;
    let objects = [
        samples::with(samples::pe(0x1000, *b"PE\0\0", 0x1010), mebibyte - 1, b"\0"),
        samples::with(
            samples::compound_file(9, 3, samples::MSI_CLSID),
            mebibyte - 1,
            b"\0",
        ),
        samples::at(32769, b"CD001", mebibyte),
        vec![0x41; mebibyte],
    ];
    for bytes in objects {
        let mut source = Counting {
            inner: Cursor::new(bytes),
            read: 0,
        };
        matching_types(&mut source).expect("readable");
        assert!(source.read <= 537, "{} bytes read", source.read);
    }
}
