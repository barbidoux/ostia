//! FR-06 and Q-61: the rules an extracted entry's path must follow (`docs/contracts/report.md`, `path`). A path
//! that leaves its container, in Unix or Windows form, or names a Windows device makes the container malformed;
//! a path longer than the policy's `max_path_length` (bytes) breaches that limit.

use ostia_core_domain::entry::{EntryPathError, check_entry_path};
use ostia_traceability::req;

#[req("FR-06")]
#[test]
fn paths_inside_their_container_are_accepted() {
    for path in [
        "a.txt",
        "dir/b.bin",
        "./a",
        "a..b",
        "...",
        ".hidden",
        "a/./b",
        "console.txt",
        "COM10",
        "LPT0.txt",
        "nul-terminated.txt",
        "dir/connect/x",
    ] {
        assert_eq!(check_entry_path(path.as_bytes(), 4096), Ok(()), "{path}");
    }
}

#[req("FR-06")]
#[test]
fn paths_leaving_their_container_are_refused() {
    for path in [
        "/etc/escape.txt",
        "\\escape.txt",
        "\\\\host\\share\\x",
        "C:\\x",
        "c:x",
        "C:/x",
        "../escape.txt",
        "a/../../b",
        "a/..",
        "..\\..\\evil.exe",
        "a\\..\\b",
        "dir/..\\x",
    ] {
        assert_eq!(
            check_entry_path(path.as_bytes(), 4096),
            Err(EntryPathError::Leaves),
            "{path}"
        );
    }
    assert_eq!(check_entry_path(b"a\0b", 4096), Err(EntryPathError::Leaves));
}

#[req("FR-06")]
#[test]
fn windows_device_names_are_refused() {
    for path in [
        "CON",
        "con.txt",
        "Nul",
        "PRN",
        "aux.tar.gz",
        "COM1",
        "com9.log",
        "LPT1",
        "lpt9",
        "CONIN$",
        "conout$.txt",
        "dir/AUX",
        "dir\\prn.doc",
        "CON ",
        "con..txt",
    ] {
        assert_eq!(
            check_entry_path(path.as_bytes(), 4096),
            Err(EntryPathError::Leaves),
            "{path}"
        );
    }
}

#[req("FR-06")]
#[test]
fn the_length_limit_counts_bytes() {
    assert_eq!(check_entry_path(b"abcdefgh", 8), Ok(()));
    assert_eq!(
        check_entry_path(b"abcdefghi", 8),
        Err(EntryPathError::TooLong)
    );
    // Four two-byte characters: 8 bytes, 4 characters.
    assert_eq!(check_entry_path("éééé".as_bytes(), 8), Ok(()));
    assert_eq!(
        check_entry_path("éééé".as_bytes(), 7),
        Err(EntryPathError::TooLong)
    );
    // A path that leaves is refused as such, whatever its length.
    assert_eq!(
        check_entry_path(b"../much-too-long", 4),
        Err(EntryPathError::Leaves)
    );
}

#[req("FR-06")]
#[test]
fn an_empty_path_is_reported_as_such() {
    assert_eq!(check_entry_path(b"", 4096), Err(EntryPathError::Empty));
}
