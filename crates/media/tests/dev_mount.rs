//! FR-03 through the development mount layer (WP-1.4): each supported image mounts read-only and is reported
//! with its file system; an image with no file system or another one is refused as an unsupported file system;
//! a damaged supported one is a mount failure, never a refusal or a mount.
//!
//! Images come from the WP-1.3 generator (`tests/fixtures/images.py`, standard library only) and mounting needs
//! the development helper of docs/dev-setup.md, as in `tests/tooling/test_dev_images.py`.

use std::path::{Path, PathBuf};
use std::process::Command;

use ostia_core_domain::session::FileSystem;
use ostia_media::{DevLoopMount, MediaAccess, MediaError};
use ostia_traceability::req;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn layer() -> DevLoopMount {
    DevLoopMount::for_repository(&repository())
}

/// An image of `fs` holding `probe.txt` with `content`, from the WP-1.3 generator.
fn generated(fs: &str, content: &str) -> PathBuf {
    let script = format!(
        "import sys\nsys.path.insert(0, {repo:?})\nfrom tests.fixtures.images import build_image\n\
         print(build_image({fs:?}, [{{'path': 'probe.txt', 'content': {content:?}.encode(), \
         'hidden': False, 'read_only': False, 'modified': None, 'streams': {{}}, 'xattrs': {{}}, \
         'symlink': None}}]))",
        repo = repository().display().to_string(),
    );
    let output = Command::new("python3")
        .args(["-I", "-c", &script])
        .output()
        .expect("python3 runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    PathBuf::from(String::from_utf8(output.stdout).expect("a path").trim())
}

/// A new image file under target/fixtures/ (where the helper accepts images), removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str, bytes: &[u8]) -> Self {
        let dir = repository().join("target/fixtures");
        std::fs::create_dir_all(&dir).expect("fixtures directory");
        let path = dir.join(format!("media-{name}-{}.img", std::process::id()));
        std::fs::write(&path, bytes).expect("scratch image");
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const SUPPORTED: [(&str, FileSystem); 8] = [
    ("fat12", FileSystem::Fat12),
    ("fat16", FileSystem::Fat16),
    ("fat32", FileSystem::Fat32),
    ("exfat", FileSystem::Exfat),
    ("ntfs", FileSystem::Ntfs),
    ("ext2", FileSystem::Ext2),
    ("ext3", FileSystem::Ext3),
    ("ext4", FileSystem::Ext4),
];

const EROFS: i32 = 30;

#[req("FR-03")]
#[test]
fn every_supported_file_system_mounts_read_only() {
    for (fs, expected) in SUPPORTED {
        let image = generated(fs, &format!("probe of {fs}"));
        let mounted = layer()
            .mount_read_only(&image)
            .unwrap_or_else(|e| panic!("{fs}: {e}"));
        assert_eq!(mounted.file_system(), expected, "{fs}");
        let root = mounted.root().to_path_buf();
        assert_eq!(
            std::fs::read_to_string(root.join("probe.txt")).expect("planted file"),
            format!("probe of {fs}"),
        );
        let refused = std::fs::write(root.join("new.txt"), b"must not be written")
            .expect_err("the mount is read-only");
        assert_eq!(refused.raw_os_error(), Some(EROFS), "{fs}: {refused}");
        mounted.unmount().unwrap_or_else(|e| panic!("{fs}: {e}"));
        assert!(!root.exists(), "{fs}: {} is still there", root.display());
    }
}

#[req("FR-03")]
#[test]
fn image_without_a_file_system_is_refused_as_unsupported() {
    let blank = Scratch::new("blank", &vec![0; 4 << 20]);
    let refused = layer()
        .mount_read_only(&blank.0)
        .expect_err("nothing to mount");
    assert!(
        matches!(refused, MediaError::UnsupportedFileSystem(_)),
        "{refused:?}"
    );
    assert!(
        refused.to_string().contains("unsupported file system"),
        "{refused}"
    );
    assert_eq!(refused.refusal_code(), Some("unsupported_file_system"));
    assert_eq!(refused.to_string().lines().count(), 1, "{refused}");
}

#[req("FR-03")]
#[test]
fn file_system_outside_fr03_is_refused_as_unsupported() {
    let minix = Scratch::new("minix", &vec![0; 4 << 20]);
    let made = Command::new("mkfs.minix")
        .arg("-3")
        .arg(&minix.0)
        .output()
        .expect("mkfs.minix runs");
    assert!(
        made.status.success(),
        "{}",
        String::from_utf8_lossy(&made.stderr)
    );
    let refused = layer()
        .mount_read_only(&minix.0)
        .expect_err("minix is not supported");
    assert!(
        matches!(refused, MediaError::UnsupportedFileSystem(_)),
        "{refused:?}"
    );
    assert!(
        refused.to_string().contains("unsupported file system"),
        "{refused}"
    );
    assert!(refused.to_string().contains("minix"), "{refused}");
}

#[req("FR-03")]
#[test]
fn damaged_supported_file_system_is_a_mount_failure() {
    // The ext4 superblock (bytes 1024-2047) stays; the 512 KiB after it, group descriptors included, are
    // zeroed: blkid still finds ext4, the kernel refuses to mount it.
    let mut bytes = std::fs::read(generated("ext4", "behind broken metadata")).expect("image");
    bytes[2048..2048 + (512 << 10)].fill(0);
    let damaged = Scratch::new("damaged", &bytes);
    let failed = layer().mount_read_only(&damaged.0).expect_err("damaged");
    assert!(matches!(failed, MediaError::MountFailed(_)), "{failed:?}");
    assert_eq!(failed.refusal_code(), None);
}

#[req("FR-03")]
#[test]
fn dropping_a_mount_unmounts_it() {
    let image = generated("ext4", "dropped");
    let mounted = layer().mount_read_only(&image).expect("mounts");
    let root = mounted.root().to_path_buf();
    assert!(root.join("probe.txt").is_file());
    drop(mounted);
    assert!(!root.exists(), "{} is still there", root.display());
}

#[req("FR-03")]
#[test]
fn two_mounts_of_one_layer_do_not_collide() {
    let first = layer()
        .mount_read_only(&generated("ext4", "first"))
        .expect("first");
    let second = layer()
        .mount_read_only(&generated("fat16", "second"))
        .expect("second");
    assert_ne!(first.root(), second.root());
    assert_eq!(
        std::fs::read_to_string(first.root().join("probe.txt")).expect("read"),
        "first"
    );
    assert_eq!(
        std::fs::read_to_string(second.root().join("probe.txt")).expect("read"),
        "second"
    );
}

#[req("FR-03")]
#[test]
fn image_the_helper_refuses_is_a_helper_error() {
    // The helper accepts images under a target/ directory only.
    let outside = std::env::temp_dir().join(format!("media-outside-{}.img", std::process::id()));
    std::fs::write(&outside, vec![0; 1 << 20]).expect("image");
    let refused = layer().mount_read_only(&outside);
    let _ = std::fs::remove_file(&outside);
    let refused = refused.expect_err("outside target/");
    assert!(matches!(refused, MediaError::Helper(_)), "{refused:?}");
    assert_eq!(refused.refusal_code(), None);
}

#[req("FR-03")]
#[test]
fn only_an_unsupported_file_system_is_a_refusal() {
    assert_eq!(
        MediaError::UnsupportedFileSystem("unsupported file system 'minix'".into()).refusal_code(),
        Some("unsupported_file_system"),
    );
    assert_eq!(MediaError::MountFailed("x".into()).refusal_code(), None);
    assert_eq!(MediaError::Helper("x".into()).refusal_code(), None);
}
