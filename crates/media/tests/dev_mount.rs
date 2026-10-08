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

/// The invoking user's real uid (`Uid:` line of /proc/self/status): the helper mounts under
/// /run/ostia-loopmount/<that uid>/.
fn real_uid() -> String {
    let status = std::fs::read_to_string("/proc/self/status").expect("status");
    let line = status
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .expect("Uid line");
    line.split_whitespace().nth(1).expect("real uid").to_owned()
}

/// Mount points of this process still present under the helper's directory.
fn leftover_mounts() -> Vec<String> {
    let base = Path::new("/run/ostia-loopmount").join(real_uid());
    let prefix = format!("ostia-{}-", std::process::id());
    std::fs::read_dir(base).map_or_else(
        |_| Vec::new(),
        |entries| {
            entries
                .filter_map(Result::ok)
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .filter(|name| name.starts_with(&prefix))
                .collect()
        },
    )
}

fn attached_loops(image: &Path) -> String {
    let output = Command::new("losetup")
        .arg("-n")
        .arg("-j")
        .arg(image)
        .output()
        .expect("losetup");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[req("FR-03")]
#[test]
fn damaged_supported_file_system_is_a_mount_failure_leaving_nothing_behind() {
    // The ext4 superblock (bytes 1024-2047) stays; the 512 KiB after it, group descriptors included, are
    // zeroed: blkid still finds ext4, the kernel refuses to mount it.
    let mut bytes = std::fs::read(generated("ext4", "behind broken metadata")).expect("image");
    bytes[2048..2048 + (512 << 10)].fill(0);
    let damaged = Scratch::new("damaged", &bytes);
    let failed = layer().mount_read_only(&damaged.0).expect_err("damaged");
    let MediaError::MountFailed(reason) = &failed else {
        panic!("{failed:?}")
    };
    assert!(
        reason.starts_with("mounting ") && reason.contains(" (ext4, "),
        "{reason}"
    );
    assert_eq!(failed.refusal_code(), None);
    assert_eq!(attached_loops(&damaged.0), "");
    assert_eq!(leftover_mounts(), Vec::<String>::new());
}

// --- the layer against a fake helper: every answer it can get ------------------------------------

static FAKES: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// A layer whose helper is a bash script running `body` after logging its arguments, one call per line.
struct Fake {
    layer: DevLoopMount,
    log: PathBuf,
    dir: PathBuf,
}

impl Fake {
    fn new(body: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "media-fake-{}-{}",
            std::process::id(),
            FAKES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("fake directory");
        let log = dir.join("calls.log");
        let script = dir.join("helper.sh");
        let line = format!("echo \"$@\" >> '{}'\n{body}\n", log.display());
        std::fs::write(&script, line).expect("script");
        let layer = DevLoopMount::with_helper(vec!["bash".into(), script.into()]);
        Self { layer, log, dir }
    }

    fn calls(&self) -> Vec<String> {
        std::fs::read_to_string(&self.log)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn unmounts(&self) -> usize {
        self.calls()
            .iter()
            .filter(|c| c.starts_with("umount "))
            .count()
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

const IMAGE: &str = "/srv/target/fixtures/x.img";

#[req("FR-03")]
#[test]
fn helper_answer_the_layer_cannot_read_is_refused_and_unmounted() {
    for body in [
        r#"[[ $1 == ro ]] && echo "something else""#,
        r#"[[ $1 == ro ]] && echo "loopmount: mounted $2 (vfat, kernel driver, ro) on /run/m/$3""#,
        r#"[[ $1 == ro ]] && echo "loopmount: mounted $2 (ext4, kernel driver, ro) on /run/m/other-$3""#,
        r#"[[ $1 == ro ]] && echo "loopmount: mounted $2 (ext4, kernel driver, ro) on run/m/$3""#,
        r#"[[ $1 == ro ]] && echo "loopmount: mounted $2 (ext4, kernel driver, ro) /run/m/$3""#,
        "true",
    ] {
        let fake = Fake::new(body);
        let refused = fake
            .layer
            .mount_read_only(Path::new(IMAGE))
            .expect_err(body);
        assert!(
            matches!(refused, MediaError::Helper(_)),
            "{body}: {refused:?}"
        );
        let calls = fake.calls();
        assert_eq!(calls.len(), 2, "{body}: {calls:?}");
        let name = calls[0].rsplit(' ').next().expect("mount name");
        assert_eq!(calls[0], format!("ro {IMAGE} {name}"), "{body}");
        assert_eq!(
            calls[1],
            format!("umount {name}"),
            "{body}: the mount is not left behind"
        );
    }
}

/// A fake helper's script, the kind of error expected, and its exact message.
type Case = (&'static str, fn(&MediaError) -> bool, &'static str);

#[req("FR-03")]
#[test]
fn helper_exit_codes_are_told_apart() {
    let cases: [Case; 8] = [
        (
            "echo \"loopmount: unsupported file system 'minix' in x\" >&2; exit 4",
            |e| matches!(e, MediaError::UnsupportedFileSystem(_)),
            "unsupported file system 'minix' in x",
        ),
        (
            "echo 'loopmount: no idea' >&2; exit 4",
            |e| matches!(e, MediaError::UnsupportedFileSystem(_)),
            "unsupported file system: no idea",
        ),
        (
            "echo 'loopmount: mounting x (ext4, kernel driver) failed' >&2; exit 5",
            |e| matches!(e, MediaError::MountFailed(_)),
            "mounting x (ext4, kernel driver) failed",
        ),
        (
            "echo 'mount: noise' >&2; echo 'loopmount: no free loop device' >&2; exit 1",
            |e| matches!(e, MediaError::Helper(_)),
            "no free loop device",
        ),
        (
            "echo 'sudo: a password is required' >&2; exit 1",
            |e| matches!(e, MediaError::Helper(_)),
            "sudo: a password is required",
        ),
        (
            "echo 'loopmount: image must be <dir>/target/[fixtures/]<name>.img' >&2; exit 2",
            |e| matches!(e, MediaError::Helper(_)),
            "image must be <dir>/target/[fixtures/]<name>.img",
        ),
        (
            "echo 'loopmount: needs root' >&2; exit 3",
            |e| matches!(e, MediaError::Helper(_)),
            "needs root",
        ),
        (
            "exit 1",
            |e| matches!(e, MediaError::Helper(_)),
            "the mount helper exited with exit status: 1",
        ),
    ];
    for (body, kind, message) in cases {
        let fake = Fake::new(body);
        let error = fake
            .layer
            .mount_read_only(Path::new(IMAGE))
            .expect_err(body);
        assert!(kind(&error), "{body}: {error:?}");
        assert_eq!(error.to_string(), message, "{body}");
        assert_eq!(fake.unmounts(), 0, "{body}: nothing was mounted");
    }
}

#[req("FR-03")]
#[test]
fn helper_killed_by_a_signal_is_a_helper_error() {
    let fake = Fake::new("kill -KILL $$");
    let error = fake
        .layer
        .mount_read_only(Path::new(IMAGE))
        .expect_err("killed");
    assert!(matches!(error, MediaError::Helper(_)), "{error:?}");
    assert!(error.to_string().contains("signal: 9"), "{error}");
}

const MOUNTED: &str = r#"[[ $1 == ro ]] && echo "loopmount: mounted $2 (ext4, kernel driver, ro,noexec) on /run/m/$3""#;

#[req("FR-03")]
#[test]
fn readable_answer_gives_a_mount_unmounted_once() {
    let fake = Fake::new(MOUNTED);
    let mounted = fake
        .layer
        .mount_read_only(Path::new(IMAGE))
        .expect("mounted");
    assert_eq!(mounted.file_system(), FileSystem::Ext4);
    let name = fake.calls()[0].rsplit(' ').next().expect("name").to_owned();
    assert_eq!(mounted.root(), Path::new("/run/m").join(&name));
    mounted.unmount().expect("unmounted");
    assert_eq!(
        fake.calls(),
        vec![format!("ro {IMAGE} {name}"), format!("umount {name}")]
    );
}

#[req("FR-03")]
#[test]
fn failed_unmount_is_reported_and_retried_when_dropped() {
    let fake = Fake::new(&format!(
        "{MOUNTED}\n[[ $1 == umount ]] && {{ echo 'loopmount: target is busy' >&2; exit 1; }}"
    ));
    let mounted = fake
        .layer
        .mount_read_only(Path::new(IMAGE))
        .expect("mounted");
    let failed = mounted.unmount().expect_err("busy");
    assert_eq!(failed, MediaError::Helper("target is busy".into()));
    assert_eq!(fake.unmounts(), 2, "{:?}", fake.calls());
}

#[req("FR-03")]
#[test]
fn installed_helper_other_than_the_repository_one_is_never_run() {
    // A repository whose helper differs from the installed copy: never run through sudo (stale copy);
    // as root, the repository's script itself runs, and its unreadable answer is refused.
    let repository = std::env::temp_dir().join(format!("media-stale-{}", std::process::id()));
    std::fs::create_dir_all(repository.join("tools/dev")).expect("repository");
    std::fs::write(repository.join("tools/dev/loopmount.sh"), "echo garbage\n").expect("script");
    let refused = DevLoopMount::for_repository(&repository).mount_read_only(Path::new(IMAGE));
    let _ = std::fs::remove_dir_all(&repository);
    let refused = refused.expect_err("stale or unreadable");
    assert!(matches!(refused, MediaError::Helper(_)), "{refused:?}");
    let effective_root = std::fs::read_to_string("/proc/self/status")
        .expect("status")
        .lines()
        .find(|l| l.starts_with("Uid:"))
        .and_then(|l| l.split_whitespace().nth(2))
        == Some("0");
    let expected = if effective_root {
        "unexpected answer"
    } else {
        "differs from"
    };
    assert!(refused.to_string().contains(expected), "{refused}");
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
    assert!(
        refused.to_string().contains(&outside.display().to_string()),
        "{refused}"
    );
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
