//! SEC-10 and FR-06: an extracted object is copied into the workspace as its bytes arrive, hashed on the way
//! (SHA-256, SHA-1), and sealed read-only; the copy is the only one used afterwards.
//!
//! Expected hashes are literals (`sha256sum`, `sha1sum` of the contents written here).

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

use ostia_media::inventory::{Copied, Workspace};
use ostia_traceability::req;

static DIRS: AtomicU32 = AtomicU32::new(0);

/// A workspace directory of its own, removed when dropped.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ostia-workspace-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        Self { dir }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        if let Ok(entries) = std::fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let _ = std::fs::set_permissions(entry.path(), PermissionsExt::from_mode(0o600));
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0_u8; N];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[2 * index..2 * index + 2], 16).expect("hex");
    }
    out
}

#[req("SEC-10", "FR-06")]
#[test]
fn a_streamed_copy_is_hashed_and_sealed() {
    let scratch = Scratch::new();
    let mut workspace = Workspace::create(&scratch.dir).expect("workspace");
    let mut copy = workspace.begin_copy().expect("copy");
    // 100000 bytes of `extracted ` in uneven chunks.
    let content = b"extracted ".repeat(10_000);
    for chunk in content.chunks(4093) {
        copy.write(chunk).expect("write");
    }
    let copied = copy.finish().expect("finish");
    assert_eq!(
        copied,
        Copied {
            size: 100_000,
            sha256: hex("67de89bc6b3aaf2f8a4fbf689dfe8cae8ae442772960fa712e3581ff95b9e0bf"),
            sha1: hex("d151090d32ce1f3d404d0a10e3dad2081bb49f42"),
            copy: scratch.dir.join("00000000"),
        }
    );
    assert_eq!(std::fs::read(&copied.copy).expect("copy"), content);
    let mode = std::fs::metadata(&copied.copy)
        .expect("copy")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o400);
}

#[req("SEC-10", "FR-06")]
#[test]
fn an_empty_copy_has_the_empty_hashes_and_each_copy_its_own_file() {
    let scratch = Scratch::new();
    let mut workspace = Workspace::create(&scratch.dir).expect("workspace");
    let first = workspace
        .begin_copy()
        .expect("copy")
        .finish()
        .expect("finish");
    assert_eq!(
        first,
        Copied {
            size: 0,
            sha256: hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            sha1: hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
            copy: scratch.dir.join("00000000"),
        }
    );
    let mut second = workspace.begin_copy().expect("copy");
    second.write(b"x").expect("write");
    assert_eq!(
        second.finish().expect("finish").copy,
        scratch.dir.join("00000001")
    );
}
