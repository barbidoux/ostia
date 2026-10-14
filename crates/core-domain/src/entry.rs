//! The rules an extracted entry's path must follow (FR-06, Q-61, `docs/contracts/report.md`, `path`). Paths
//! are metadata the extraction worker reports; nothing here reads content.

/// Why an entry path is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryPathError {
    /// The path is empty.
    Empty,
    /// The path leaves its container (absolute in Unix or Windows form, a `..` component, a NUL byte) or names a
    /// Windows device: the container is malformed.
    Leaves,
    /// The path is longer than the policy's `max_path_length`, in bytes.
    TooLong,
}

/// Checks `path` against the rules, then against `max_length` bytes.
///
/// # Errors
/// [`EntryPathError`] for an empty path, a path that leaves its container or names a device, a path too long.
pub fn check_entry_path(path: &[u8], max_length: u32) -> Result<(), EntryPathError> {
    let _ = (path, max_length);
    todo!("WP-1.8: check_entry_path")
}
