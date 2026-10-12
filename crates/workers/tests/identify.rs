//! FR-05: the type comes from the content by report.md's rules, and a near miss of any rule is `unknown`.

mod samples;

use std::io::Cursor;

use ostia_core_domain::types::DetectedType;
use ostia_traceability::req;
use ostia_workers::triage::identify;

fn identified(bytes: &[u8]) -> &'static str {
    identify(&mut Cursor::new(bytes)).expect("readable").name()
}

#[req("FR-05")]
#[test]
fn every_type_of_the_report_is_identified_from_its_content() {
    for (name, bytes) in samples::typed() {
        assert_eq!(identified(&bytes), name, "{name}");
    }
}

#[req("FR-05")]
#[test]
fn near_misses_are_unknown() {
    for (case, bytes) in samples::untyped() {
        assert_eq!(identified(&bytes), "unknown", "{case}");
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

/// A source that fails like a medium with a bad sector.
struct Failing;

impl std::io::Read for Failing {
    fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::from_raw_os_error(5))
    }
}

impl std::io::Seek for Failing {
    fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
        Ok(0)
    }
}

#[req("FR-05")]
#[test]
fn read_failure_is_an_error_never_a_type() {
    let failed = identify(&mut Failing);
    assert_eq!(failed.map_err(|error| error.raw_os_error()), Err(Some(5)));
}
