//! FR-04, SEC-10 and DEEP-05 on a plain directory standing for a mounted medium (WP-1.5): every object is
//! listed, never through a symbolic link, and read once into the workspace, whose copy keeps the bytes that
//! were hashed whatever happens to the source afterwards.
//!
//! Expected sizes and hashes are literals (`sha256sum`, `sha1sum` of the contents written here).

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use Attribute::{Archive, Hidden, ReadOnly, System};
use ostia_core_domain::object::{Kind, Origin};
use ostia_core_domain::session::FileSystem;
use ostia_media::inventory::{
    Attribute, Attributes, Content, Entry, Inventory, InventoryError, MAX_DIRECTORY_DEPTH,
    Workspace, fat_attributes, ntfs_attributes, report_path, take_inventory,
};
use ostia_traceability::req;
use rustix::fs::{XattrFlags, inotify};

static DIRS: AtomicU32 = AtomicU32::new(0);

/// A medium directory and a workspace directory of their own, removed when dropped.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        Self::under(&std::env::temp_dir())
    }

    /// Under cargo's target directory, on the repository's file system, which keeps `user.*` attributes (a
    /// temporary directory may be a tmpfs that does not, before Linux 6.6).
    fn keeping_attributes() -> Self {
        Self::under(Path::new(env!("CARGO_TARGET_TMPDIR")))
    }

    fn under(base: &Path) -> Self {
        let dir = base.join(format!(
            "ostia-inventory-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("medium")).expect("medium directory");
        Self { dir }
    }

    fn medium(&self) -> PathBuf {
        self.dir.join("medium")
    }

    fn plant(&self, path: &str, content: &[u8]) {
        let target = self.medium().join(path);
        std::fs::create_dir_all(target.parent().expect("parent")).expect("directories");
        std::fs::write(target, content).expect("planted file");
    }

    fn workspace(&self) -> Workspace {
        Workspace::create(&self.dir.join("workspace")).expect("workspace")
    }

    fn inventory(&self) -> Inventory {
        take_inventory(&self.medium(), FileSystem::Ext4, &mut self.workspace()).expect("inventory")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn set(attributes: &[Attribute]) -> Attributes {
    attributes.iter().copied().collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn entry<'a>(inventory: &'a Inventory, path: &str) -> &'a Entry {
    let found: Vec<_> = inventory
        .entries
        .iter()
        .filter(|e| e.path == path && e.origin == Origin::File)
        .collect();
    assert_eq!(found.len(), 1, "{path}: {:?}", inventory.entries);
    found[0]
}

/// (size, SHA-256, SHA-1) of a read entry.
fn read(entry: &Entry) -> (u64, String, String) {
    match &entry.content {
        Content::Read {
            size, sha256, sha1, ..
        } => (*size, hex(sha256), hex(sha1)),
        other => panic!("{}: {other:?}", entry.path),
    }
}

fn copy(entry: &Entry) -> &Path {
    match &entry.content {
        Content::Read { copy, .. } => copy,
        other => panic!("{}: {other:?}", entry.path),
    }
}

fn big() -> Vec<u8> {
    (0..1_048_579_u32)
        .map(|i| u8::try_from(i % 251).expect("byte"))
        .collect()
}

const README: (u64, &str, &str) = (
    7,
    "00d75b5176b48ccc71d91bcc1d7b90fc2820429b1629b77fd1d5f4c5dcee4f6d",
    "0753dda729217d9bd892d252bdd35f2ee6774a5b",
);
const REPORT: (u64, &str, &str) = (
    7,
    "331d26d6d8f862e46ba900811be8a7a1e4dbaa229b14c99becfd5e5151490d95",
    "07d3306fc65e0b9aa387dba6d69add3e83c95e30",
);
const PHOTO: (u64, &str, &str) = (
    6,
    "9fe36faa6e710cbbfe894e2ed0ee227ca2179beea08210789c73971ba565ea10",
    "02842ad40f8c0ba06427c7917a82ff7b201db09e",
);
const EMPTY: (u64, &str, &str) = (
    0,
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",
);
const DOT: (u64, &str, &str) = (
    9,
    "f71d16ee97b5afbe123b0fa22e51ee83b05111ec2a023fa651db25b55dbff8fb",
    "afbdcaf280ae2d559317013eb2f5054a0ecedd96",
);
const BIG: (u64, &str, &str) = (
    1_048_579,
    "aca6f4d81a88030dc3e4b99988449ba2943885a56a5ebda5be275f64149677fe",
    "f1877fc75b687b904b3444014cb4d40cd260da47",
);

fn owned(expected: (u64, &str, &str)) -> (u64, String, String) {
    (expected.0, expected.1.to_owned(), expected.2.to_owned())
}

fn plant_tree(scratch: &Scratch) {
    scratch.plant("readme.txt", b"readme\n");
    scratch.plant("docs/report.txt", b"report\n");
    scratch.plant("docs/deep/nested/photo.bin", b"photo\n");
    scratch.plant("empty.dat", b"");
    scratch.plant("big.bin", &big());
    scratch.plant(".dotfile", b"dot file\n");
}

#[req("FR-04", "SEC-10")]
#[test]
fn plain_tree_is_inventoried_with_sizes_and_hashes() {
    let scratch = Scratch::new();
    plant_tree(&scratch);
    let inventory = scratch.inventory();
    let expected = [
        ("readme.txt", README),
        ("docs/report.txt", REPORT),
        ("docs/deep/nested/photo.bin", PHOTO),
        ("empty.dat", EMPTY),
        ("big.bin", BIG),
        (".dotfile", DOT),
    ];
    assert_eq!(inventory.entries.len(), expected.len(), "{inventory:?}");
    for (path, hashes) in expected {
        let found = entry(&inventory, path);
        assert_eq!(read(found), owned(hashes), "{path}");
        assert_eq!(
            (found.kind, found.parent, found.stream.as_deref()),
            (Kind::File, None, None),
            "{path}"
        );
        assert_eq!(found.name, Path::new(path), "{path}");
    }
    assert!(inventory.unlisted.is_empty(), "{:?}", inventory.unlisted);
}

#[req("FR-04")]
#[test]
fn entries_come_depth_first_in_name_order() {
    let scratch = Scratch::new();
    plant_tree(&scratch);
    // Byte order, not a locale or case-insensitive one: "Zeta" (0x5a) before "alpha" (0x61).
    scratch.plant("alpha.txt", b"readme\n");
    scratch.plant("Zeta.txt", b"readme\n");
    let paths: Vec<_> = scratch
        .inventory()
        .entries
        .iter()
        .map(|e| e.path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            ".dotfile",
            "Zeta.txt",
            "alpha.txt",
            "big.bin",
            "docs/deep/nested/photo.bin",
            "docs/report.txt",
            "empty.dat",
            "readme.txt",
        ]
    );
}

#[req("FR-04")]
#[test]
fn modification_time_is_the_source_one() {
    let scratch = Scratch::new();
    scratch.plant("readme.txt", b"readme\n");
    // 2024-03-01T10:20:30Z
    let modified = std::time::UNIX_EPOCH + Duration::from_secs(1_709_288_430);
    std::fs::File::options()
        .write(true)
        .open(scratch.medium().join("readme.txt"))
        .expect("open")
        .set_modified(modified)
        .expect("set mtime");
    assert_eq!(
        entry(&scratch.inventory(), "readme.txt").modified,
        Some(modified)
    );
}

#[req("SEC-10")]
#[test]
fn workspace_copy_holds_the_bytes_that_were_hashed() {
    let scratch = Scratch::new();
    plant_tree(&scratch);
    let inventory = scratch.inventory();
    let workspace = scratch.dir.join("workspace");
    for (path, content) in [
        ("readme.txt", b"readme\n".to_vec()),
        ("big.bin", big()),
        ("empty.dat", Vec::new()),
    ] {
        let copy = copy(entry(&inventory, path));
        assert!(copy.starts_with(&workspace), "{path}: {}", copy.display());
        assert_eq!(std::fs::read(copy).expect("copy"), content, "{path}");
        let mode = std::fs::metadata(copy).expect("copy").permissions().mode();
        assert_eq!(mode & 0o777, 0o400, "{path}");
    }
}

#[req("SEC-10")]
#[test]
fn source_changed_after_the_read_leaves_copy_and_hashes_unchanged() {
    let scratch = Scratch::new();
    scratch.plant("readme.txt", b"readme\n");
    let inventory = scratch.inventory();
    std::fs::write(
        scratch.medium().join("readme.txt"),
        b"changed after the read\n",
    )
    .expect("change the source");
    let found = entry(&inventory, "readme.txt");
    assert_eq!(read(found), owned(README));
    assert_eq!(std::fs::read(copy(found)).expect("copy"), b"readme\n");
}

#[req("FR-04", "SEC-10")]
#[test]
fn symbolic_links_are_listed_and_never_followed() {
    let scratch = Scratch::new();
    scratch.plant("real.txt", b"target of a link\n");
    let medium = scratch.medium();
    for (name, target) in [
        ("escape-absolute", "/etc/hostname"),
        ("escape-relative", "../../../etc/hostname"),
        ("inside", "real.txt"),
        ("dangling", "nowhere.txt"),
        ("loop", "loop"),
    ] {
        std::os::unix::fs::symlink(target, medium.join(name)).expect("symlink");
    }
    std::os::unix::fs::symlink("/etc", medium.join("dir-link")).expect("directory symlink");
    let inventory = scratch.inventory();
    for name in [
        "escape-absolute",
        "escape-relative",
        "inside",
        "dangling",
        "loop",
        "dir-link",
    ] {
        let link = entry(&inventory, name);
        assert_eq!(
            (link.kind, &link.content),
            (Kind::Symlink, &Content::NotRead),
            "{name}"
        );
    }
    assert_eq!(inventory.entries.len(), 7, "{inventory:?}");
    assert!(
        inventory
            .entries
            .iter()
            .all(|e| !e.path.starts_with("dir-link/"))
    );
}

#[req("FR-04")]
#[test]
fn special_files_are_listed_and_never_opened() {
    let scratch = Scratch::new();
    let fifo = std::process::Command::new("mkfifo")
        .arg(scratch.medium().join("pipe"))
        .status()
        .expect("mkfifo");
    assert!(fifo.success());
    let socket =
        std::os::unix::net::UnixListener::bind(scratch.medium().join("socket")).expect("socket");
    let inventory = scratch.inventory();
    drop(socket);
    for name in ["pipe", "socket"] {
        let special = entry(&inventory, name);
        assert_eq!(
            (special.kind, &special.content),
            (Kind::Special, &Content::NotRead),
            "{name}"
        );
    }
}

#[req("FR-04")]
#[test]
fn dot_names_are_hidden_and_nothing_else_is_set_on_ext() {
    let scratch = Scratch::new();
    scratch.plant(".dotfile", b"dot file\n");
    scratch.plant(".config/settings", b"report\n");
    scratch.plant("readme.txt", b"readme\n");
    let inventory = scratch.inventory();
    assert_eq!(
        entry(&inventory, ".dotfile").attributes,
        set(&[Attribute::Hidden])
    );
    // Only the object's own name counts: a file inside a dot directory is not hidden.
    assert_eq!(entry(&inventory, ".config/settings").attributes, set(&[]));
    assert_eq!(entry(&inventory, "readme.txt").attributes, set(&[]));
}

#[req("FR-04")]
#[test]
fn hard_linked_names_are_objects_of_their_own() {
    let scratch = Scratch::new();
    scratch.plant("one.txt", b"readme\n");
    std::fs::hard_link(
        scratch.medium().join("one.txt"),
        scratch.medium().join("two.txt"),
    )
    .expect("hard link");
    let inventory = scratch.inventory();
    let (one, two) = (entry(&inventory, "one.txt"), entry(&inventory, "two.txt"));
    assert_eq!((read(one), read(two)), (owned(README), owned(README)));
    assert_ne!(copy(one), copy(two));
}

#[req("FR-04")]
#[test]
fn names_that_are_not_utf8_are_escaped_and_kept_as_bytes() {
    let scratch = Scratch::new();
    let latin1 = OsStr::from_bytes(b"caf\xe9.txt");
    std::fs::write(scratch.medium().join(latin1), b"readme\n").expect("latin-1 name");
    std::fs::write(scratch.medium().join("back\\slash.txt"), b"report\n").expect("backslash");
    let inventory = scratch.inventory();
    let escaped = entry(&inventory, "caf\\xe9.txt");
    assert_eq!(escaped.name, Path::new(latin1));
    assert_eq!(read(escaped), owned(README));
    assert_eq!(read(entry(&inventory, "back\\\\slash.txt")), owned(REPORT));
}

#[req("FR-04")]
#[test]
fn report_path_encoding() {
    assert_eq!(report_path(b"docs/report.pdf"), "docs/report.pdf");
    assert_eq!(report_path("été/ü.txt".as_bytes()), "été/ü.txt");
    assert_eq!(report_path(b"caf\xe9"), "caf\\xe9");
    assert_eq!(report_path(b"a\\b"), "a\\\\b");
    assert_eq!(report_path(b"\xff\xfe"), "\\xff\\xfe");
    // A truncated UTF-8 sequence: each byte escaped, the valid character after it kept.
    assert_eq!(report_path(b"\xc3x\xc3\xa9"), "\\xc3xé");
}

#[req("FR-04")]
#[test]
fn fat_attribute_bits() {
    assert_eq!(
        fat_attributes(0x27),
        set(&[Hidden, System, ReadOnly, Archive])
    );
    assert_eq!(fat_attributes(0x00), set(&[]));
    assert_eq!(fat_attributes(0x01), set(&[ReadOnly]));
    assert_eq!(fat_attributes(0x02), set(&[Hidden]));
    assert_eq!(fat_attributes(0x04), set(&[System]));
    assert_eq!(fat_attributes(0x20), set(&[Archive]));
    // Volume label 0x08 and directory 0x10 are no attributes of the report.
    assert_eq!(fat_attributes(0x18), set(&[]));
}

#[req("FR-04")]
#[test]
fn ntfs_attribute_flags() {
    assert_eq!(
        ntfs_attributes(0x27),
        set(&[Hidden, System, ReadOnly, Archive])
    );
    // NORMAL 0x80, DIRECTORY 0x10, COMPRESSED 0x800: no attribute of the report.
    assert_eq!(ntfs_attributes(0x890), set(&[]));
    assert_eq!(ntfs_attributes(0x2002), set(&[Hidden]));
}

#[req("FR-04")]
#[test]
fn attribute_names_are_the_report_ones() {
    let names: Vec<_> = [
        Attribute::Hidden,
        Attribute::System,
        Attribute::ReadOnly,
        Attribute::Archive,
    ]
    .into_iter()
    .map(Attribute::name)
    .collect();
    assert_eq!(names, ["hidden", "system", "read_only", "archive"]);
}

#[req("SEC-10")]
#[test]
fn workspace_must_be_private_and_new_or_empty() {
    let scratch = Scratch::new();
    let private = |name: &str| {
        let dir = scratch.dir.join(name);
        std::fs::create_dir_all(&dir).expect("directory");
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("mode");
        dir
    };
    let refused = |dir: &Path| {
        let answer = Workspace::create(dir);
        assert!(
            matches!(answer, Err(InventoryError::Workspace(_))),
            "{}: {answer:?}",
            dir.display()
        );
    };
    let used = private("used");
    std::fs::write(used.join("left-over"), b"x").expect("left-over");
    refused(&used);
    // Another user could replace a sealed copy in a directory open to the group or to others (SEC-10).
    let shared = private("shared");
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770)).expect("mode");
    refused(&shared);
    let link = scratch.dir.join("link");
    std::os::unix::fs::symlink(private("target"), &link).expect("symlink");
    refused(&link);
    let empty = private("empty");
    assert_eq!(Workspace::create(&empty).expect("empty").root(), empty);
    let fresh = scratch.dir.join("fresh/nested");
    assert_eq!(Workspace::create(&fresh).expect("fresh").root(), fresh);
    let mode = std::fs::metadata(&fresh)
        .expect("fresh")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[req("SEC-10")]
#[test]
fn copy_that_cannot_be_written_stops_the_inventory() {
    let scratch = Scratch::new();
    scratch.plant("readme.txt", b"readme\n");
    let mut workspace = scratch.workspace();
    // The workspace disappears: no copy can be made, so nothing may be analysed.
    std::fs::remove_dir_all(workspace.root()).expect("remove the workspace");
    std::fs::write(workspace.root(), b"not a directory").expect("a file in its place");
    let refused = take_inventory(&scratch.medium(), FileSystem::Ext4, &mut workspace);
    assert!(
        matches!(refused, Err(InventoryError::Workspace(_))),
        "{refused:?}"
    );
}

#[req("FR-04")]
#[test]
fn missing_root_is_an_error() {
    let scratch = Scratch::new();
    let refused = take_inventory(
        &scratch.dir.join("absent"),
        FileSystem::Ext4,
        &mut scratch.workspace(),
    );
    assert!(
        matches!(refused, Err(InventoryError::Root(_))),
        "{refused:?}"
    );
}

fn unlisted_paths(inventory: &Inventory) -> Vec<&str> {
    inventory.unlisted.iter().map(|u| u.path.as_str()).collect()
}

fn set_user_attribute(path: &Path) {
    rustix::fs::setxattr(path, "user.hidden", b"payload", XattrFlags::empty())
        .expect("user.* attribute");
}

#[req("DEEP-05", "FR-04")]
#[test]
fn stream_or_attribute_on_a_directory_is_recorded_as_unlisted() {
    // No host file to hang it from in the report: never silently dropped.
    let scratch = Scratch::keeping_attributes();
    scratch.plant("docs/report.txt", b"report\n");
    set_user_attribute(&scratch.medium().join("docs"));
    let inventory = scratch.inventory();
    assert_eq!(unlisted_paths(&inventory), ["docs"]);
    assert_eq!(read(entry(&inventory, "docs/report.txt")), owned(REPORT));
}

#[req("DEEP-05", "FR-04")]
#[test]
fn stream_or_attribute_on_the_medium_root_is_recorded_as_unlisted() {
    let scratch = Scratch::keeping_attributes();
    scratch.plant("readme.txt", b"readme\n");
    set_user_attribute(&scratch.medium());
    let inventory = scratch.inventory();
    // The medium root's path is empty.
    assert_eq!(unlisted_paths(&inventory), [""]);
    assert_eq!(read(entry(&inventory, "readme.txt")), owned(README));
}

#[req("FR-04")]
#[test]
fn attributes_that_cannot_be_read_are_recorded_as_unlisted() {
    // A plain directory is no vfat mount (the FAT ioctl fails) and has no ntfs-3g attribute: the hidden
    // attribute is unknown, never guessed absent.
    for file_system in [FileSystem::Fat32, FileSystem::Ntfs] {
        let scratch = Scratch::new();
        scratch.plant("readme.txt", b"readme\n");
        let inventory = take_inventory(&scratch.medium(), file_system, &mut scratch.workspace())
            .expect("inventory");
        assert_eq!(
            unlisted_paths(&inventory),
            ["readme.txt"],
            "{file_system:?}"
        );
        assert_eq!(
            read(entry(&inventory, "readme.txt")),
            owned(README),
            "{file_system:?}"
        );
    }
}

#[req("SEC-10")]
#[test]
fn each_regular_file_is_opened_once_and_nothing_else_is_opened() {
    let scratch = Scratch::new();
    plant_tree(&scratch);
    let medium = scratch.medium();
    std::os::unix::fs::symlink("readme.txt", medium.join("link")).expect("symlink");
    let fifo = std::process::Command::new("mkfifo")
        .arg(medium.join("pipe"))
        .status()
        .expect("mkfifo");
    assert!(fifo.success());
    let watcher = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK)
        .expect("inotify");
    let mut directories = std::collections::HashMap::new();
    for dir in ["", "docs", "docs/deep", "docs/deep/nested"] {
        let wd = inotify::add_watch(&watcher, medium.join(dir), inotify::WatchFlags::OPEN)
            .expect("watch");
        directories.insert(wd, dir);
    }
    let _ = scratch.inventory();
    let mut opened: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut buffer = [std::mem::MaybeUninit::<u8>::uninit(); 8192];
    let mut events = inotify::Reader::new(&watcher, &mut buffer);
    while let Ok(event) = events.next() {
        if event.events().contains(inotify::ReadFlags::ISDIR) {
            continue;
        }
        let name = event
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let dir = directories[&event.wd()];
        let path = if dir.is_empty() {
            name
        } else {
            format!("{dir}/{name}")
        };
        *opened.entry(path).or_default() += 1;
    }
    let expected: std::collections::BTreeMap<String, u32> = [
        ".dotfile",
        "big.bin",
        "docs/deep/nested/photo.bin",
        "docs/report.txt",
        "empty.dat",
        "readme.txt",
    ]
    .into_iter()
    .map(|path| (path.to_owned(), 1))
    .collect();
    assert_eq!(opened, expected);
}

#[req("FR-04")]
#[test]
fn nesting_deeper_than_the_limit_is_recorded_as_unlisted() {
    assert_eq!(MAX_DIRECTORY_DEPTH, 128);
    let scratch = Scratch::new();
    let deep = vec!["d"; 130].join("/");
    scratch.plant(&format!("{deep}/deep.txt"), b"readme\n");
    scratch.plant("readme.txt", b"readme\n");
    let inventory = scratch.inventory();
    // Directories at depths 1 to 128 are listed; the one at depth 129 is not opened.
    let limit = vec!["d"; 129].join("/");
    assert_eq!(unlisted_paths(&inventory), [limit.as_str()]);
    let paths: Vec<_> = inventory.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["readme.txt"]);
}

#[req("FR-04", "SEC-10")]
#[test]
fn directory_swapped_for_a_link_during_the_walk_is_not_followed() {
    let scratch = Scratch::new();
    let medium = scratch.medium();
    // Large enough that reading it leaves time to swap its directory before the next file is opened.
    let large: Vec<u8> = (0..64 * 1024 * 1024_u32)
        .map(|i| u8::try_from(i % 253).expect("byte"))
        .collect();
    scratch.plant("a/big.bin", &large);
    scratch.plant("a/zz.txt", b"report\n");
    let outside = scratch.dir.join("outside");
    std::fs::create_dir_all(&outside).expect("outside");
    std::fs::write(outside.join("zz.txt"), b"secret outside the medium\n").expect("secret");
    let workspace_dir = scratch.dir.join("workspace");
    let mut workspace = Workspace::create(&workspace_dir).expect("workspace");
    let swapper = {
        let medium = medium.clone();
        std::thread::spawn(move || {
            // The first copy appears when a/big.bin starts being read: swap a/ for a link to outside/.
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while std::time::Instant::now() < deadline {
                if std::fs::read_dir(&workspace_dir).is_ok_and(|mut e| e.next().is_some()) {
                    std::fs::rename(medium.join("a"), medium.join("a.moved")).expect("move a/");
                    std::os::unix::fs::symlink(&outside, medium.join("a")).expect("link a");
                    return true;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            false
        })
    };
    let inventory = take_inventory(&medium, FileSystem::Ext4, &mut workspace).expect("inventory");
    assert!(swapper.join().expect("swapper"), "the swap never happened");
    let paths: Vec<_> = inventory.entries.iter().map(|e| e.path.as_str()).collect();
    assert_eq!(paths, ["a/big.bin", "a/zz.txt"]);
    assert_eq!(read(entry(&inventory, "a/zz.txt")), owned(REPORT));
}
