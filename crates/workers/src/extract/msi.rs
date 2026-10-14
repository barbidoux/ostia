//! Windows Installer package (WP-1.9): every stream of its compound file (read by `cfb`) is an entry, under
//! the path of its storages and its name decoded from the MSI stream-name encoding (Q-63): tables appear
//! as `!<table>`, an embedded cabinet under its own name, which the tree then extracts one level deeper.
//! Nothing is compressed: a stream's ratio is 1, and the container's ratio bounds streams sharing sectors.

use std::io::{Read, Seek};
use std::path::{Component, Path};

use cfb::CompoundFile;

use super::{ARCHIVE, Header, Kind, Malformed, Run, Stop};

/// The characters packed by the encoding, in their 6-bit order.
const PACKED: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._";
/// Two packed characters: U+3800 + first + (second << 6).
const PAIRS: u32 = 0x3800;
/// One packed character: U+4800 + it.
const SINGLE: u32 = 0x4800;
/// The mark before a table name.
const TABLE: u32 = 0x4840;

pub(super) fn extract<R: Read + Seek>(object: R, run: &mut Run<'_>) -> Result<(), Stop> {
    let mut file = CompoundFile::open(object).map_err(|_| ARCHIVE)?;
    let streams: Vec<(std::path::PathBuf, u64)> = file
        .walk()
        .filter(cfb::Entry::is_stream)
        .map(|entry| (entry.path().to_path_buf(), entry.len()))
        .collect();
    for (path, size) in streams {
        let header = Header {
            path: decoded_path(&path)?,
            kind: Kind::Regular,
            size,
            modified: None,
        };
        run.begin(&header, false)?;
        let mut stream = file.open_stream(&path).map_err(|_| ARCHIVE)?;
        run.stream(&mut stream, size, size, Malformed::Archive)?;
    }
    Ok(())
}

/// The storages and the stream of `path`, each name decoded, joined by `/`.
fn decoded_path(path: &Path) -> Result<Vec<u8>, Stop> {
    let mut out = Vec::new();
    for component in path.components() {
        // A stream named `..` or `.` stays one, for the path check to refuse.
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => decoded(name.to_str().ok_or(ARCHIVE)?),
            Component::ParentDir => "..".to_owned(),
            Component::CurDir => ".".to_owned(),
            Component::Prefix(_) => return Err(ARCHIVE),
        };
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(name.as_bytes());
    }
    Ok(out)
}

/// A stream name decoded from the MSI encoding; characters outside it are kept.
fn decoded(name: &str) -> String {
    let packed = |index: u32| {
        usize::try_from(index & 0x3F)
            .ok()
            .and_then(|index| PACKED.get(index))
            .map_or('?', |&byte| char::from(byte))
    };
    let mut out = String::with_capacity(name.len());
    for character in name.chars() {
        let code = u32::from(character);
        if (PAIRS..SINGLE).contains(&code) {
            out.push(packed(code - PAIRS));
            out.push(packed((code - PAIRS) >> 6));
        } else if (SINGLE..TABLE).contains(&code) {
            out.push(packed(code - SINGLE));
        } else if code == TABLE {
            out.push('!');
        } else {
            out.push(character);
        }
    }
    out
}
