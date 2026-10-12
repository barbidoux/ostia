//! FR-04, SEC-10 and DEEP-05 on generated disk images mounted read-only through the development mount layer
//! (WP-1.5): the inventory of every supported file system holds exactly the planted files with their sizes,
//! hashes and times; NTFS alternate data streams and ext `user.*` attributes are listed as children of their
//! host; file-system attributes are reported.
//!
//! Images come from the WP-1.3 generator (`tests/fixtures/images.py`) and mounting needs the development helper
//! of docs/dev-setup.md, as in `dev_mount.rs`. Expected values are literals (`sha256sum`, `sha1sum` of the
//! contents planted here).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ostia_core_domain::object::{Kind, Origin};
use ostia_core_domain::session::FileSystem;
use ostia_media::inventory::{Attribute, Content, Entry, Inventory, Workspace, take_inventory};
use ostia_media::{DevLoopMount, MediaAccess};
use ostia_traceability::req;

/// 2024-03-01T10:20:30Z
const MODIFIED: &str = "2024-03-01T10:20:30Z";
const MODIFIED_SECONDS: u64 = 1_709_288_430;

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

static WORKSPACES: AtomicU32 = AtomicU32::new(0);

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A file to plant: path, content, hidden, read-only, streams, extended attributes.
struct Planted {
    path: &'static str,
    content: Vec<u8>,
    hidden: bool,
    read_only: bool,
    streams: Vec<(&'static str, &'static [u8])>,
    xattrs: Vec<(&'static str, &'static [u8])>,
}

fn file(path: &'static str, content: &[u8]) -> Planted {
    Planted {
        path,
        content: content.to_vec(),
        hidden: false,
        read_only: false,
        streams: Vec::new(),
        xattrs: Vec::new(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn pairs(items: &[(&str, &[u8])]) -> String {
    let inner: Vec<_> = items
        .iter()
        .map(|(name, value)| format!("{name:?}: bytes.fromhex({:?})", hex(value)))
        .collect();
    format!("{{{}}}", inner.join(", "))
}

/// An image of `fs` holding `files`, all modified at [`MODIFIED`], from the WP-1.3 generator.
fn generated(fs: &str, files: &[Planted]) -> PathBuf {
    let specs: Vec<_> = files
        .iter()
        .map(|f| {
            format!(
                "{{'path': {path:?}, 'content': bytes.fromhex({content:?}), 'hidden': {hidden}, \
                 'read_only': {read_only}, 'modified': {MODIFIED:?}, 'streams': {streams}, \
                 'xattrs': {xattrs}, 'symlink': None}}",
                path = f.path,
                content = hex(&f.content),
                hidden = if f.hidden { "True" } else { "False" },
                read_only = if f.read_only { "True" } else { "False" },
                streams = pairs(&f.streams),
                xattrs = pairs(&f.xattrs),
            )
        })
        .collect();
    let script = format!(
        "import sys\nsys.path.insert(0, {repo:?})\nfrom tests.fixtures.images import build_image\n\
         print(build_image({fs:?}, [{files}]))",
        repo = repository().display().to_string(),
        files = specs.join(", "),
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

/// Mounts `image`, takes its inventory into a fresh workspace, unmounts; the workspace stays for the test.
fn inventory_of(image: &Path, fs: FileSystem) -> (Inventory, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "ostia-inventory-images-{}-{}",
        std::process::id(),
        WORKSPACES.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let mut workspace = Workspace::create(&dir).expect("workspace");
    let mounted = DevLoopMount::for_repository(&repository())
        .mount_read_only(image)
        .expect("mounted");
    let inventory = take_inventory(mounted.root(), fs, &mut workspace);
    mounted.unmount().expect("unmounted");
    (inventory.expect("inventory"), dir)
}

fn files(inventory: &Inventory) -> Vec<&Entry> {
    inventory
        .entries
        .iter()
        .filter(|e| e.origin == Origin::File)
        .collect()
}

fn entry<'a>(inventory: &'a Inventory, path: &str) -> &'a Entry {
    let found: Vec<_> = files(inventory)
        .into_iter()
        .filter(|e| e.path == path)
        .collect();
    assert_eq!(found.len(), 1, "{path}: {:?}", inventory.entries);
    found[0]
}

fn read(entry: &Entry) -> (u64, String, String) {
    match &entry.content {
        Content::Read {
            size, sha256, sha1, ..
        } => (*size, hex(sha256), hex(sha1)),
        other => panic!("{}: {other:?}", entry.path),
    }
}

fn copied(entry: &Entry) -> Vec<u8> {
    match &entry.content {
        Content::Read { copy, .. } => std::fs::read(copy).expect("copy"),
        other => panic!("{}: {other:?}", entry.path),
    }
}

fn big() -> Vec<u8> {
    (0..1_048_579_u32)
        .map(|i| u8::try_from(i % 251).expect("byte"))
        .collect()
}

fn owned(expected: (u64, &str, &str)) -> (u64, String, String) {
    (expected.0, expected.1.to_owned(), expected.2.to_owned())
}

#[req("FR-04", "SEC-10")]
#[test]
fn every_file_system_inventories_exactly_its_planted_files() {
    let planted = [
        file("readme.txt", b"readme\n"),
        file("docs/report.txt", b"report\n"),
        file("docs/deep/nested/photo.bin", b"photo\n"),
        file("empty.dat", b""),
        file("big.bin", &big()),
        file(".dotfile", b"dot file\n"),
    ];
    let expected = [
        (
            "readme.txt",
            (
                7,
                "00d75b5176b48ccc71d91bcc1d7b90fc2820429b1629b77fd1d5f4c5dcee4f6d",
                "0753dda729217d9bd892d252bdd35f2ee6774a5b",
            ),
        ),
        (
            "docs/report.txt",
            (
                7,
                "331d26d6d8f862e46ba900811be8a7a1e4dbaa229b14c99becfd5e5151490d95",
                "07d3306fc65e0b9aa387dba6d69add3e83c95e30",
            ),
        ),
        (
            "docs/deep/nested/photo.bin",
            (
                6,
                "9fe36faa6e710cbbfe894e2ed0ee227ca2179beea08210789c73971ba565ea10",
                "02842ad40f8c0ba06427c7917a82ff7b201db09e",
            ),
        ),
        (
            "empty.dat",
            (
                0,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            ),
        ),
        (
            "big.bin",
            (
                1_048_579,
                "aca6f4d81a88030dc3e4b99988449ba2943885a56a5ebda5be275f64149677fe",
                "f1877fc75b687b904b3444014cb4d40cd260da47",
            ),
        ),
        (
            ".dotfile",
            (
                9,
                "f71d16ee97b5afbe123b0fa22e51ee83b05111ec2a023fa651db25b55dbff8fb",
                "afbdcaf280ae2d559317013eb2f5054a0ecedd96",
            ),
        ),
    ];
    let modified: SystemTime = UNIX_EPOCH + Duration::from_secs(MODIFIED_SECONDS);
    for (name, fs) in SUPPORTED {
        let (inventory, workspace) = inventory_of(&generated(name, &planted), fs);
        let mut listed: Vec<_> = files(&inventory).iter().map(|e| e.path.clone()).collect();
        listed.sort();
        let mut wanted: Vec<_> = expected.iter().map(|(p, _)| (*p).to_owned()).collect();
        wanted.sort();
        assert_eq!(listed, wanted, "{name}");
        assert_eq!(
            inventory.entries.len(),
            expected.len(),
            "{name}: {inventory:?}"
        );
        for (path, hashes) in expected {
            let found = entry(&inventory, path);
            assert_eq!(read(found), owned(hashes), "{name} {path}");
            assert_eq!(found.kind, Kind::File, "{name} {path}");
            assert_eq!(found.modified, Some(modified), "{name} {path}");
            assert_eq!(
                found.attributes.contains(&Attribute::Hidden),
                path == ".dotfile",
                "{name} {path}"
            );
        }
        assert_eq!(copied(entry(&inventory, "big.bin")), big(), "{name}");
        assert!(
            inventory.unlisted.is_empty(),
            "{name}: {:?}",
            inventory.unlisted
        );
        let _ = std::fs::remove_dir_all(workspace);
    }
}

const ZONE: &[u8] = b"[ZoneTransfer]\r\nZoneId=3\r\n";
const COMMENT: &[u8] = b"planted extended attribute";

#[req("DEEP-05", "FR-04")]
#[test]
fn ntfs_alternate_data_stream_is_listed_after_its_host() {
    let mut host = file("readme.txt", b"readme\n");
    host.streams.push(("Zone.Identifier", ZONE));
    let planted = [host, file("clean.txt", b"report\n")];
    let (inventory, workspace) = inventory_of(&generated("ntfs", &planted), FileSystem::Ntfs);
    let paths: Vec<_> = inventory
        .entries
        .iter()
        .map(|e| (e.path.as_str(), e.origin, e.stream.as_deref(), e.parent))
        .collect();
    assert_eq!(
        paths,
        [
            ("clean.txt", Origin::File, None, None),
            ("readme.txt", Origin::File, None, None),
            (
                "readme.txt",
                Origin::AltStream,
                Some("Zone.Identifier"),
                Some(1)
            ),
        ]
    );
    let stream = &inventory.entries[2];
    assert_eq!((stream.kind, stream.modified), (Kind::File, None));
    assert_eq!(
        read(stream),
        owned((
            26,
            "eacd09517ce90d34ba562171d15ac40d302f0e691b439f91be1b6406e25f5913",
            "d59fc84cdd5217c6cf74785703655f78da6b582b"
        ))
    );
    assert_eq!(copied(stream), ZONE);
    let _ = std::fs::remove_dir_all(workspace);
}

#[req("DEEP-05", "FR-04")]
#[test]
fn ext_user_attribute_is_listed_after_its_host() {
    for (name, fs) in [
        ("ext2", FileSystem::Ext2),
        ("ext3", FileSystem::Ext3),
        ("ext4", FileSystem::Ext4),
    ] {
        let mut host = file("tagged.txt", b"readme\n");
        host.xattrs.push(("user.comment", COMMENT));
        let planted = [host, file("clean.txt", b"report\n")];
        let (inventory, workspace) = inventory_of(&generated(name, &planted), fs);
        let paths: Vec<_> = inventory
            .entries
            .iter()
            .map(|e| (e.path.as_str(), e.origin, e.stream.as_deref(), e.parent))
            .collect();
        assert_eq!(
            paths,
            [
                ("clean.txt", Origin::File, None, None),
                ("tagged.txt", Origin::File, None, None),
                ("tagged.txt", Origin::Xattr, Some("user.comment"), Some(1)),
            ],
            "{name}"
        );
        let attribute = &inventory.entries[2];
        assert_eq!(
            read(attribute),
            owned((
                26,
                "d04c5344d9726dd4dcb2aebf1a2bb2067424a365cec90ecfae6a0b7f859491cd",
                "82cbe2b5c2fcd4a86ef1f59abd3813329bb375fb"
            )),
            "{name}"
        );
        assert_eq!(copied(attribute), COMMENT, "{name}");
        let _ = std::fs::remove_dir_all(workspace);
    }
}

fn attribute_planted() -> [Planted; 3] {
    let mut hidden = file("attrib-hidden.txt", b"hidden attribute\n");
    hidden.hidden = true;
    let mut read_only = file("attrib-readonly.txt", b"read-only attribute\n");
    read_only.read_only = true;
    [hidden, read_only, file("readme.txt", b"readme\n")]
}

/// (hidden, read-only) of each planted file.
fn hidden_and_read_only(inventory: &Inventory) -> Vec<(&str, bool, bool)> {
    files(inventory)
        .into_iter()
        .map(|e| {
            (
                e.path.as_str(),
                e.attributes.contains(&Attribute::Hidden),
                e.attributes.contains(&Attribute::ReadOnly),
            )
        })
        .collect()
}

#[req("FR-04")]
#[test]
fn ntfs_hidden_and_read_only_attributes_are_reported() {
    let (inventory, workspace) =
        inventory_of(&generated("ntfs", &attribute_planted()), FileSystem::Ntfs);
    assert_eq!(
        hidden_and_read_only(&inventory),
        [
            ("attrib-hidden.txt", true, false),
            ("attrib-readonly.txt", false, true),
            ("readme.txt", false, false),
        ]
    );
    let _ = std::fs::remove_dir_all(workspace);
}

#[req("FR-04")]
#[test]
fn fat_hidden_and_read_only_attributes_are_reported() {
    for (name, fs) in [
        ("fat12", FileSystem::Fat12),
        ("fat16", FileSystem::Fat16),
        ("fat32", FileSystem::Fat32),
    ] {
        let (inventory, workspace) = inventory_of(&generated(name, &attribute_planted()), fs);
        assert_eq!(
            hidden_and_read_only(&inventory),
            [
                ("attrib-hidden.txt", true, false),
                ("attrib-readonly.txt", false, true),
                ("readme.txt", false, false),
            ],
            "{name}"
        );
        let _ = std::fs::remove_dir_all(workspace);
    }
}

#[req("FR-04", "SEC-10")]
#[test]
fn symbolic_links_of_an_image_are_listed_and_never_followed() {
    let script_links = [
        ("escape-absolute", "/etc/hostname"),
        ("escape-relative", "../../../etc/hostname"),
        ("inside", "real.txt"),
    ];
    let mut specs = vec![format!(
        "{{'path': 'real.txt', 'content': bytes.fromhex({:?}), 'hidden': False, 'read_only': False, \
         'modified': None, 'streams': {{}}, 'xattrs': {{}}, 'symlink': None}}",
        hex(b"target of a link\n")
    )];
    for (name, target) in script_links {
        specs.push(format!(
            "{{'path': {name:?}, 'content': b'', 'hidden': False, 'read_only': False, 'modified': None, \
             'streams': {{}}, 'xattrs': {{}}, 'symlink': {target:?}}}"
        ));
    }
    let script = format!(
        "import sys\nsys.path.insert(0, {repo:?})\nfrom tests.fixtures.images import build_image\n\
         print(build_image('ext4', [{files}]))",
        repo = repository().display().to_string(),
        files = specs.join(", "),
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
    let image = PathBuf::from(String::from_utf8(output.stdout).expect("a path").trim());
    let (inventory, workspace) = inventory_of(&image, FileSystem::Ext4);
    for (name, _) in script_links {
        let link = entry(&inventory, name);
        assert_eq!(
            (link.kind, &link.content),
            (Kind::Symlink, &Content::NotRead),
            "{name}"
        );
    }
    assert_eq!(
        read(entry(&inventory, "real.txt")),
        owned((
            17,
            "6ece4a0ca6ddd85b74a85621c08d24df56f26672fad38d0acb459d31a0df0897",
            "d113e072d2ac097bf50c064538e89cfa7550f5be"
        ))
    );
    assert_eq!(inventory.entries.len(), 4, "{inventory:?}");
    let _ = std::fs::remove_dir_all(workspace);
}
