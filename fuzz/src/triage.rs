//! What the triage fuzz target does with one input: identify the type of the input as an object, and read
//! the input as a file name for the name flags, checking the properties both must hold (FR-05). Any panic, a
//! broken property included, is a finding.

use std::io::{Cursor, Read, Seek, SeekFrom};

use ostia_core_domain::types::{DetectedType, double_extension, extension_mismatch};
use ostia_workers::triage::matching_types;

/// The most bytes the type rules read: 512 first bytes, 4 at `e_lfanew`, 16 of a root entry, 5 at 32769.
const MAX_READ: usize = 537;

/// Runs the type rules and the name flags on `data`.
///
/// # Panics
/// When a property breaks: that is what the fuzzer looks for.
pub fn exercise_triage(data: &[u8]) {
    let mut object = Counting {
        inner: Cursor::new(data),
        read: 0,
    };
    let types = matching_types(&mut object).expect("an in-memory object is always readable");
    assert!(object.read <= MAX_READ, "{} bytes read", object.read);
    assert!(
        !types.contains(&DetectedType::Unknown),
        "unknown is no rule"
    );
    let order: Vec<_> = types
        .iter()
        .map(|t| DetectedType::ALL.iter().position(|a| a == t))
        .collect();
    assert!(
        order.windows(2).all(|w| w[0] < w[1]),
        "types repeated or out of report order"
    );

    let name = String::from_utf8_lossy(data);
    let _ = double_extension(&name);
    assert!(
        !extension_mismatch(&name, DetectedType::Unknown),
        "unknown is never a mismatch"
    );
    for detected in DetectedType::ALL {
        let _ = extension_mismatch(&name, detected);
    }
}

/// Counts the bytes read from an in-memory object.
struct Counting<'a> {
    inner: Cursor<&'a [u8]>,
    read: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.read += read;
        Ok(read)
    }
}

impl Seek for Counting<'_> {
    fn seek(&mut self, to: SeekFrom) -> std::io::Result<u64> {
        self.inner.seek(to)
    }
}
