//! Inventory of a mounted medium and single read of its content (FR-04, SEC-10, DEEP-05).
//!
//! [`take_inventory`] walks the mounted tree without following symbolic links and lists every file, symbolic
//! link and special file, the NTFS alternate data streams and the ext `user.*` extended attributes, with their
//! path, size, modification time and attributes. Each regular file, stream and attribute value is read once:
//! the bytes feed SHA-256, SHA-1 and a copy in the [`Workspace`] in the same pass, and only that copy is used
//! afterwards (SEC-10). Nothing here interprets content: the kernel's mount does the file-system parsing, and
//! streams, attributes and file-system attributes come from kernel calls on the descriptor that was opened.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use ostia_core_domain::object::{Kind, Origin};
use ostia_core_domain::session::FileSystem;
use rustix::fs::{OFlags, fgetxattr, flistxattr, llistxattr};
use sha1::Sha1;
use sha2::{Digest, Sha256};

/// Bytes read at a time from an object.
const CHUNK: usize = 64 * 1024;

/// The kernel's limit on one extended attribute value, and on the list of a file's attribute names.
const XATTR_MAX: usize = 64 * 1024;

/// ntfs-3g's extended attribute holding the NTFS file attribute flags, big-endian.
const NTFS_ATTRIBUTES: &str = "system.ntfs_attrib_be";

/// The namespace of the attributes listed: ext `user.*` attributes, ntfs-3g's streams (`streams_interface=xattr`).
const USER: &[u8] = b"user.";

/// The directory that holds the copies of a session's objects (plain in P1, encrypted in P4).
#[derive(Debug)]
pub struct Workspace {
    root: PathBuf,
    copies: u64,
}

impl Workspace {
    /// A workspace in `dir`, which must not exist or be empty.
    ///
    /// # Errors
    /// [`InventoryError::Workspace`] when `dir` holds anything or cannot be created.
    pub fn create(dir: &Path) -> Result<Self, InventoryError> {
        match std::fs::read_dir(dir) {
            Ok(mut entries) => {
                if entries.next().is_some() {
                    return Err(InventoryError::Workspace(format!(
                        "workspace {} is not empty",
                        dir.display()
                    )));
                }
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                std::fs::create_dir_all(dir).map_err(|error| {
                    InventoryError::Workspace(format!(
                        "cannot create the workspace {}: {error}",
                        dir.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(InventoryError::Workspace(format!(
                    "cannot use the workspace {}: {error}",
                    dir.display()
                )));
            }
        }
        Ok(Self {
            root: dir.to_path_buf(),
            copies: 0,
        })
    }

    /// The workspace directory.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// A new, empty copy file, writable by this process only until it is sealed.
    fn new_copy(&mut self) -> Result<(PathBuf, File), InventoryError> {
        let path = self.root.join(format!("{:08}", self.copies));
        self.copies += 1;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|error| workspace_error(&path, &error))?;
        Ok((path, file))
    }
}

fn workspace_error(path: &Path, error: &std::io::Error) -> InventoryError {
    InventoryError::Workspace(format!("cannot write the copy {}: {error}", path.display()))
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
        match self {
            Self::Hidden => "hidden",
            Self::System => "system",
            Self::ReadOnly => "read_only",
            Self::Archive => "archive",
        }
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
    let names = children(root).map_err(|error| {
        InventoryError::Root(format!(
            "cannot list the medium {}: {error}",
            root.display()
        ))
    })?;
    let mut walk = Walk {
        file_system,
        workspace,
        inventory: Inventory {
            entries: Vec::new(),
            unlisted: Vec::new(),
        },
    };
    walk.directory(root, Path::new(""), names)?;
    Ok(walk.inventory)
}

/// The names in `dir`, in byte order.
fn children(dir: &Path) -> std::io::Result<Vec<OsString>> {
    let mut names = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

/// A path's bytes in the report's encoding: UTF-8, `\xNN` for a byte that is not valid UTF-8, `\\` for a
/// backslash.
#[must_use]
pub fn report_path(raw: &[u8]) -> String {
    let mut path = String::with_capacity(raw.len());
    for chunk in raw.utf8_chunks() {
        for character in chunk.valid().chars() {
            if character == '\\' {
                path.push_str("\\\\");
            } else {
                path.push(character);
            }
        }
        for byte in chunk.invalid() {
            let _ = write!(path, "\\x{byte:02x}");
        }
    }
    path
}

/// The attributes of a FAT attribute byte (`ATTR_RO` 0x01, `ATTR_HIDDEN` 0x02, `ATTR_SYS` 0x04, `ATTR_ARCH`
/// 0x20).
#[must_use]
pub fn fat_attributes(bits: u32) -> Attributes {
    flags_to_attributes(bits)
}

/// The attributes of NTFS file attribute flags (`READONLY` 0x1, `HIDDEN` 0x2, `SYSTEM` 0x4, `ARCHIVE` 0x20).
#[must_use]
pub fn ntfs_attributes(flags: u32) -> Attributes {
    flags_to_attributes(flags)
}

/// FAT and NTFS share the bits of the four attributes of the report.
fn flags_to_attributes(flags: u32) -> Attributes {
    [
        (0x01, Attribute::ReadOnly),
        (0x02, Attribute::Hidden),
        (0x04, Attribute::System),
        (0x20, Attribute::Archive),
    ]
    .into_iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, attribute)| attribute)
    .collect()
}

/// A name starting with `.` is hidden on every file system.
fn dot_name(name: &OsStr) -> Attributes {
    if name.as_bytes().first() == Some(&b'.') {
        BTreeSet::from([Attribute::Hidden])
    } else {
        BTreeSet::new()
    }
}

struct Walk<'a> {
    file_system: FileSystem,
    workspace: &'a mut Workspace,
    inventory: Inventory,
}

impl Walk<'_> {
    fn unlisted(&mut self, relative: &Path, reason: String) {
        self.inventory.unlisted.push(Unlisted {
            path: report_path(relative.as_os_str().as_bytes()),
            reason,
        });
    }

    fn directory(
        &mut self,
        dir: &Path,
        relative: &Path,
        names: Vec<OsString>,
    ) -> Result<(), InventoryError> {
        for name in names {
            let path = dir.join(&name);
            let child = relative.join(&name);
            let metadata = match std::fs::symlink_metadata(&path) {
                Ok(metadata) => metadata,
                Err(error) => {
                    self.unlisted(&child, format!("cannot inspect: {error}"));
                    continue;
                }
            };
            let kind = metadata.file_type();
            if kind.is_dir() {
                self.check_directory_attributes(&path, &child);
                match children(&path) {
                    Ok(names) => self.directory(&path, &child, names)?,
                    Err(error) => self.unlisted(&child, format!("cannot list: {error}")),
                }
            } else if kind.is_file() {
                self.file(&path, &child, &name, metadata.modified().ok())?;
            } else {
                let kind = if kind.is_symlink() {
                    Kind::Symlink
                } else {
                    Kind::Special
                };
                self.push(Entry {
                    parent: None,
                    origin: Origin::File,
                    kind,
                    path: report_path(child.as_os_str().as_bytes()),
                    name: child,
                    stream: None,
                    modified: metadata.modified().ok(),
                    attributes: dot_name(&name),
                    content: Content::NotRead,
                });
            }
        }
        Ok(())
    }

    /// A stream or attribute on a directory has no host file to hang from in the report: its content is
    /// recorded as unlisted, never silently dropped.
    fn check_directory_attributes(&mut self, path: &Path, relative: &Path) {
        let mut list = vec![0_u8; XATTR_MAX];
        match llistxattr(path, &mut list[..]) {
            Ok(len) => {
                let listed = list.get(..len).unwrap_or_default();
                if listed
                    .split(|byte| *byte == 0)
                    .any(|name| name.starts_with(USER))
                {
                    self.unlisted(
                        relative,
                        "stream or extended attribute on a directory".into(),
                    );
                }
            }
            Err(rustix::io::Errno::OPNOTSUPP) => {}
            Err(error) => self.unlisted(relative, format!("cannot list attributes: {error}")),
        }
    }

    fn push(&mut self, entry: Entry) -> usize {
        self.inventory.entries.push(entry);
        self.inventory.entries.len() - 1
    }

    fn file(
        &mut self,
        path: &Path,
        relative: &Path,
        name: &OsStr,
        listed_modified: Option<SystemTime>,
    ) -> Result<(), InventoryError> {
        let mut entry = Entry {
            parent: None,
            origin: Origin::File,
            kind: Kind::File,
            path: report_path(relative.as_os_str().as_bytes()),
            name: relative.to_path_buf(),
            stream: None,
            modified: listed_modified,
            attributes: dot_name(name),
            content: Content::NotRead,
        };
        let opened = OpenOptions::new()
            .read(true)
            .custom_flags((OFlags::NOFOLLOW | OFlags::NONBLOCK).bits().cast_signed())
            .open(path);
        let mut file = match opened {
            Ok(file) => file,
            Err(error) => {
                entry.content = Content::Unreadable(format!("cannot open: {error}"));
                self.push(entry);
                return Ok(());
            }
        };
        match file.metadata() {
            Ok(metadata) if metadata.is_file() => entry.modified = metadata.modified().ok(),
            Ok(_) => {
                // Replaced by something else since it was listed: never read.
                entry.kind = Kind::Special;
                self.push(entry);
                return Ok(());
            }
            Err(error) => {
                entry.content = Content::Unreadable(format!("cannot inspect: {error}"));
                self.push(entry);
                return Ok(());
            }
        }
        entry.attributes.extend(self.file_system_attributes(&file));
        entry.content = read_once(&mut file, self.workspace)?;
        let host = self.push(entry);
        self.streams(&file, relative, host)
    }

    fn file_system_attributes(&self, file: &File) -> Attributes {
        match self.file_system {
            FileSystem::Ntfs => {
                let mut flags = [0_u8; 4];
                match fgetxattr(file, NTFS_ATTRIBUTES, &mut flags[..]) {
                    Ok(4) => ntfs_attributes(u32::from_be_bytes(flags)),
                    _ => Attributes::new(),
                }
            }
            // The byte the vfat driver holds (Q-48); a refused ioctl reports no attribute.
            FileSystem::Fat12 | FileSystem::Fat16 | FileSystem::Fat32 => {
                ostia_fat_attributes::attributes(file)
                    .map_or_else(|_| Attributes::new(), fat_attributes)
            }
            // exFAT attributes are read from the image by a worker (WP-1.13); ext has none of these.
            FileSystem::Exfat | FileSystem::Ext2 | FileSystem::Ext3 | FileSystem::Ext4 => {
                Attributes::new()
            }
        }
    }

    /// The streams (NTFS) or `user.*` attributes (other file systems) of the opened file, after their host.
    fn streams(&mut self, file: &File, relative: &Path, host: usize) -> Result<(), InventoryError> {
        let (origin, keep_prefix) = if self.file_system == FileSystem::Ntfs {
            (Origin::AltStream, false)
        } else {
            (Origin::Xattr, true)
        };
        let mut list = vec![0_u8; XATTR_MAX];
        let names: Vec<Vec<u8>> = match flistxattr(file, &mut list[..]) {
            Ok(len) => {
                let mut names: Vec<_> = list
                    .get(..len)
                    .unwrap_or_default()
                    .split(|byte| *byte == 0)
                    .filter(|name| name.starts_with(USER))
                    .map(<[u8]>::to_vec)
                    .collect();
                names.sort();
                names
            }
            Err(rustix::io::Errno::OPNOTSUPP) => Vec::new(),
            Err(error) => {
                self.unlisted(relative, format!("cannot list streams: {error}"));
                Vec::new()
            }
        };
        let host_path = report_path(relative.as_os_str().as_bytes());
        for name in names {
            let shown = if keep_prefix {
                name.as_slice()
            } else {
                name.get(USER.len()..).unwrap_or_default()
            };
            let mut value = vec![0_u8; XATTR_MAX];
            let content = match fgetxattr(file, OsStr::from_bytes(&name), &mut value[..]) {
                Ok(len) => copy_bytes(value.get(..len).unwrap_or_default(), self.workspace)?,
                Err(error) => Content::Unreadable(format!("cannot read: {error}")),
            };
            self.push(Entry {
                parent: Some(host),
                origin,
                kind: Kind::File,
                path: host_path.clone(),
                name: relative.to_path_buf(),
                stream: Some(report_path(shown)),
                modified: None,
                attributes: Attributes::new(),
                content,
            });
        }
        Ok(())
    }
}

/// Hashes and copies one read of `source`; a read failure leaves no copy behind.
fn read_once(source: &mut File, workspace: &mut Workspace) -> Result<Content, InventoryError> {
    let (path, mut copy) = workspace.new_copy()?;
    match hash_and_copy(source, &mut copy) {
        Ok((size, sha256, sha1)) => {
            seal(&path, &copy)?;
            Ok(Content::Read {
                size,
                sha256,
                sha1,
                copy: path,
            })
        }
        Err(CopyError::Read(error)) => {
            drop(copy);
            std::fs::remove_file(&path).map_err(|removal| workspace_error(&path, &removal))?;
            Ok(Content::Unreadable(format!("cannot read: {error}")))
        }
        Err(CopyError::Write(error)) => Err(workspace_error(&path, &error)),
    }
}

/// Why [`hash_and_copy`] stopped.
#[derive(Debug)]
enum CopyError {
    /// The source failed: the object is unreadable.
    Read(std::io::Error),
    /// The copy failed: the inventory cannot go on.
    Write(std::io::Error),
}

/// One pass over `source` to its end: each chunk feeds SHA-256, SHA-1 and `copy`; returns the size and hashes.
fn hash_and_copy(
    source: &mut impl Read,
    copy: &mut impl Write,
) -> Result<(u64, [u8; 32], [u8; 20]), CopyError> {
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    let mut size: u64 = 0;
    let mut chunk = vec![0_u8; CHUNK];
    loop {
        let read = match source.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(CopyError::Read(error)),
        };
        let bytes = chunk.get(..read).unwrap_or_default();
        sha256.update(bytes);
        sha1.update(bytes);
        copy.write_all(bytes).map_err(CopyError::Write)?;
        size += u64::try_from(read).unwrap_or(u64::MAX);
    }
    Ok((size, sha256.finalize().into(), sha1.finalize().into()))
}

/// Hashes and copies bytes already read (a stream or attribute value).
fn copy_bytes(bytes: &[u8], workspace: &mut Workspace) -> Result<Content, InventoryError> {
    let (path, mut copy) = workspace.new_copy()?;
    copy.write_all(bytes)
        .map_err(|error| workspace_error(&path, &error))?;
    seal(&path, &copy)?;
    Ok(Content::Read {
        size: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        sha256: Sha256::digest(bytes).into(),
        sha1: Sha1::digest(bytes).into(),
        copy: path,
    })
}

/// Flushes a copy and makes it read-only.
fn seal(path: &Path, copy: &File) -> Result<(), InventoryError> {
    copy.sync_all()
        .and_then(|()| copy.set_permissions(Permissions::from_mode(0o400)))
        .map_err(|error| workspace_error(path, &error))
}
