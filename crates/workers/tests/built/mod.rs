//! Archives of part 2 (7z, rar, cab, iso, msi) built at test time by `tests/fixtures/archives.py`, the
//! standard-library builder the locked acceptance tests use (nothing is committed). The entries go to
//! Python on standard input, the archive comes back on standard output.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

/// Calls `builder` (a function of `tests/fixtures/archives.py`: `build_archive`'s format builders, or
/// `compound_file`) on `entries` with the keyword `options` (Python source, for example `coder="aes"`).
pub fn build(builder: &str, entries: &[(&str, &[u8])], options: &str) -> Vec<u8> {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let script = format!(
        "import struct, sys\n\
         sys.path.insert(0, {repository:?})\n\
         from tests.fixtures import archives\n\
         data = sys.stdin.buffer.read()\n\
         entries, at = [], 0\n\
         while at < len(data):\n\
         \x20   name_length, content_length = struct.unpack_from('<IQ', data, at)\n\
         \x20   at += 12\n\
         \x20   name = data[at : at + name_length].decode()\n\
         \x20   at += name_length\n\
         \x20   entries.append((name, data[at : at + content_length]))\n\
         \x20   at += content_length\n\
         sys.stdout.buffer.write(archives.{builder}(entries, {options}))\n",
        repository = repository.display().to_string(),
    );
    let mut input = Vec::new();
    for (name, content) in entries {
        input.extend_from_slice(&u32::try_from(name.len()).expect("name").to_le_bytes());
        input.extend_from_slice(&u64::try_from(content.len()).expect("size").to_le_bytes());
        input.extend_from_slice(name.as_bytes());
        input.extend_from_slice(content);
    }
    let mut child = Command::new("python3")
        .args(["-I", "-c", &script])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("python3 runs");
    let mut stdin = child.stdin.take().expect("stdin");
    let writer = std::thread::spawn(move || stdin.write_all(&input).expect("entries written"));
    let output = child.wait_with_output().expect("python3 ends");
    writer.join().expect("writer");
    assert!(
        output.status.success(),
        "{builder}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}
