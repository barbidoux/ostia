//! Inventory of a mounted medium and single read of its content (FR-04, SEC-10, DEEP-05).
//!
//! [`take_inventory`] walks the mounted tree without following symbolic links and lists every file, symbolic
//! link and special file, the NTFS alternate data streams and the ext `user.*` extended attributes, with their
//! path, size, modification time and attributes. Each regular file, stream and attribute value is read once:
//! the bytes feed SHA-256, SHA-1 and a copy in the [`Workspace`] in the same pass, and only that copy is used
//! afterwards (SEC-10). Nothing here interprets content: the kernel's mount does the file-system parsing.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ostia_core_domain::object::{Kind, Origin};
use ostia_core_domain::session::FileSystem;

/// The directory that holds the copies of a session's objects (plain in P1, encrypted in P4).
#[derive(Debug)]
pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    /// A workspace in `dir`, which must not exist or be empty.
    ///
    /// # Errors
    /// [`InventoryError::Workspace`] when `dir` holds anything or cannot be created.
    pub fn create(dir: &Path) -> Result<Self, InventoryError> {
        let _ = dir;
        todo!("WP-1.5")
    }

    /// The workspace directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// A file-system attribute of an object (`docs/contracts/report.md`, `attributes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Attribute {
    /// Hidden attribute, or a name starting with `.`.
    Hidden,
    /// System attribute (FAT, exFAT, NTFS).
    System,
    /// Read-only attribute (FAT, exFAT, NTFS).
    ReadOnly,
    /// Archive attribute (FAT, exFAT, NTFS).
    Archive,
}

impl Attribute {
    /// The attribute's name in the report: `hidden`, `system`, `read_only`, `archive`.
    #[must_use]
    pub fn name(self) -> &'static str {
        let _ = self;
        todo!("WP-1.5")
    }
}

/// The attributes of an object.
pub type Attributes = BTreeSet<Attribute>;

/// What the single read of an object gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Content {
    /// Never read: a symbolic link or a special file.
    NotRead,
    /// Read once, hashed and copied.
    Read {
        /// Bytes read.
        size: u64,
        /// SHA-256 of the bytes read.
        sha256: [u8; 32],
        /// SHA-1 of the bytes read.
        sha1: [u8; 20],
        /// The copy in the workspace: the only one used afterwards.
        copy: PathBuf,
    },
    /// The object could not be read (it is UNSCANNABLE).
    Unreadable(String),
}

/// One object of the inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Index of the host file in [`Inventory::entries`] for a stream or attribute value.
    pub parent: Option<usize>,
    /// `File`, `AltStream` or `Xattr`.
    pub origin: Origin,
    /// What it is.
    pub kind: Kind,
    /// Path from the medium root in the report's encoding (`\xNN` for bytes that are not UTF-8, `\\`); the
    /// host file's path for a stream or attribute.
    pub path: String,
    /// The path's original bytes, relative to the medium root.
    pub name: PathBuf,
    /// Stream name (`Zone.Identifier`) or attribute name (`user.comment`).
    pub stream: Option<String>,
    /// Last modification time; none for streams and attribute values.
    pub modified: Option<SystemTime>,
    /// File-system attributes.
    pub attributes: Attributes,
    /// The single read.
    pub content: Content,
}

/// A part of the medium the inventory could not list: its content is unknown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlisted {
    /// Path in the report's encoding.
    pub path: String,
    /// Why.
    pub reason: String,
}

/// The inventory of a medium.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Every object, depth first, names in byte order within a directory, each host followed by its streams
    /// and attribute values.
    pub entries: Vec<Entry>,
    /// What could not be listed (a directory that cannot be read, a stream on a directory).
    pub unlisted: Vec<Unlisted>,
}

/// Why an inventory could not be taken at all.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InventoryError {
    /// The workspace cannot be created or written.
    #[error("{0}")]
    Workspace(String),
    /// The medium's root cannot be listed.
    #[error("{0}")]
    Root(String),
}

/// Inventories the medium mounted at `root` and reads each object once into `workspace`.
///
/// # Errors
/// [`InventoryError::Root`] when the root cannot be listed, [`InventoryError::Workspace`] when a copy cannot be
/// written. An object that cannot be read is listed as [`Content::Unreadable`], not an error.
pub fn take_inventory(
    root: &Path,
    file_system: FileSystem,
    workspace: &mut Workspace,
) -> Result<Inventory, InventoryError> {
    let _ = (root, file_system, workspace);
    todo!("WP-1.5")
}

/// A path's bytes in the report's encoding: UTF-8, `\xNN` for a byte that is not valid UTF-8, `\\` for a
/// backslash.
#[must_use]
pub fn report_path(raw: &[u8]) -> String {
    let _ = raw;
    todo!("WP-1.5")
}

/// The attributes of a FAT attribute byte (`ATTR_RO` 0x01, `ATTR_HIDDEN` 0x02, `ATTR_SYS` 0x04, `ATTR_ARCH`
/// 0x20).
#[must_use]
pub fn fat_attributes(bits: u32) -> Attributes {
    let _ = bits;
    todo!("WP-1.5")
}

/// The attributes of NTFS file attribute flags (`READONLY` 0x1, `HIDDEN` 0x2, `SYSTEM` 0x4, `ARCHIVE` 0x20).
#[must_use]
pub fn ntfs_attributes(flags: u32) -> Attributes {
    let _ = flags;
    todo!("WP-1.5")
}
