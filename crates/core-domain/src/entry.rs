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
    if path.is_empty() {
        return Err(EntryPathError::Empty);
    }
    if leaves(path) {
        return Err(EntryPathError::Leaves);
    }
    if path.len() > usize::try_from(max_length).unwrap_or(usize::MAX) {
        return Err(EntryPathError::TooLong);
    }
    Ok(())
}

/// Windows device names: a component whose stem is one of them opens the device (Q-61).
const DEVICES: [&[u8]; 24] = [
    b"CON", b"PRN", b"AUX", b"NUL", b"CONIN$", b"CONOUT$", b"COM1", b"COM2", b"COM3", b"COM4",
    b"COM5", b"COM6", b"COM7", b"COM8", b"COM9", b"LPT1", b"LPT2", b"LPT3", b"LPT4", b"LPT5",
    b"LPT6", b"LPT7", b"LPT8", b"LPT9",
];

/// `/` and `\` both separate components (Q-61).
fn is_separator(byte: u8) -> bool {
    byte == b'/' || byte == b'\\'
}

/// Absolute (`/`, `\`, `\\host`, a drive letter `X:`), a `..` component, a NUL byte, or a device name.
fn leaves(path: &[u8]) -> bool {
    let drive = matches!(path, [letter, b':', ..] if letter.is_ascii_alphabetic());
    path.contains(&0)
        || path.first().is_some_and(|&b| is_separator(b))
        || drive
        || path
            .split(|&b| is_separator(b))
            .any(|part| part == b".." || is_device(part))
}

/// The component's stem (before its first dot, trailing spaces dropped) is a device name, in any case.
fn is_device(part: &[u8]) -> bool {
    let stem = part.split(|&b| b == b'.').next().unwrap_or(part);
    let end = stem
        .iter()
        .rposition(|&b| b != b' ')
        .map_or(0, |last| last + 1);
    let stem = stem.get(..end).unwrap_or(stem);
    DEVICES
        .iter()
        .any(|device| stem.eq_ignore_ascii_case(device))
}
