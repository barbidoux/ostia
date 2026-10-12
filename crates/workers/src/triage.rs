//! Type identification from the content (FR-05), by the magic numbers of report.md's "Types" table.

use std::io::{Read, Seek};

use ostia_core_domain::types::DetectedType;

/// The type of the object read from `object`; `unknown` when no rule matches. Reads only the bytes the rules
/// look at.
///
/// # Errors
/// Reading or seeking the object failed.
pub fn identify(object: &mut (impl Read + Seek)) -> std::io::Result<DetectedType> {
    let _ = object;
    todo!("WP-1.7")
}
