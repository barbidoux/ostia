//! The object tree: files of the medium, their alternate streams and extended attributes, and the objects
//! extracted from archives (`docs/contracts/report.md`, "Objects").
//!
//! Identifiers are assigned by the tree and a child is inserted only below an existing parent, so the tree
//! has no duplicate identifier and no cycle by construction; depth is checked against the policy's
//! `max_depth` on every insertion.

use thiserror::Error;

/// Largest `max_depth` a policy may set (`schemas/policy.schema.json`).
const MAX_DEPTH_LIMIT: u32 = 64;

/// Identifier of an object, unique in its tree. It is the insertion index: an identifier from another tree
/// is refused only when it is out of range, so identifiers of different trees are never mixed (one tree
/// per session).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ObjectId(u32);

impl ObjectId {
    /// The number of the identifier (insertion order, from 0).
    #[must_use]
    pub fn index(self) -> u32 {
        self.0
    }
}

/// Where an object comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Origin {
    /// A file of the medium (always a root of the tree).
    File,
    /// An entry extracted from an archive.
    Extracted,
    /// An NTFS alternate data stream.
    AltStream,
    /// An extended attribute value (ext2/3/4 `user.*`).
    Xattr,
}

/// What an object is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A regular file, stream or attribute value.
    File,
    /// A symbolic link, reparse point or junction: never followed.
    Symlink,
    /// A FIFO, socket or device node: never opened.
    Special,
}

/// An object to insert, as the inventory or an extraction found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewObject {
    /// Where it comes from.
    pub origin: Origin,
    /// What it is.
    pub kind: Kind,
    /// Path from the medium root, entry path inside its container, or the host file's path.
    pub path: String,
    /// Stream or attribute name.
    pub stream: Option<String>,
    /// Size in bytes.
    pub size: u64,
    /// SHA-256 of the bytes read (none for links and special files).
    pub sha256: Option<[u8; 32]>,
    /// SHA-1 of the bytes read.
    pub sha1: Option<[u8; 20]>,
}

/// An object of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectNode {
    /// Its identifier.
    pub id: ObjectId,
    /// Its container or host file; none for a file of the medium.
    pub parent: Option<ObjectId>,
    /// 0 for a file of the medium, parent's depth + 1 otherwise.
    pub depth: u32,
    /// What the inventory or the extraction found.
    pub object: NewObject,
}

/// An insertion the tree refuses.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TreeError {
    /// `max_depth` outside 1 to 64 (the policy's range).
    #[error("max depth {0} is outside 1..=64")]
    InvalidMaxDepth(u32),
    /// The parent is not in the tree.
    #[error("unknown parent {0:?}")]
    UnknownParent(ObjectId),
    /// The child would be deeper than `max_depth`.
    #[error("depth {depth} is beyond the maximum {max_depth}")]
    TooDeep {
        /// The depth the child would have.
        depth: u32,
        /// The tree's maximum.
        max_depth: u32,
    },
    /// A root must be a file of the medium.
    #[error("a root object must have origin File, not {0:?}")]
    RootNotAFile(Origin),
    /// A file of the medium is never below another object.
    #[error("an object of origin File cannot have a parent")]
    FileWithParent,
    /// A symbolic link or special file is never read, so nothing hangs below it.
    #[error("a {0:?} object is never read and cannot have children")]
    ParentNotReadable(Kind),
    /// An alternate data stream or extended attribute hangs on a file of the medium only.
    #[error("a stream or attribute needs a file of the medium as its host, not {0:?}")]
    StreamWithoutHostFile(Origin),
    /// A symbolic link or special file is never read: size 0 and no hash.
    #[error("a {0:?} object carries no content (size 0, no hash)")]
    LinkWithContent(Kind),
    /// SHA-256 and SHA-1 are computed together from the same read.
    #[error("an object has both hashes or neither")]
    PartialHashes,
    /// More objects than identifiers (2^32); the policy's entry limits stop extraction long before.
    #[error("the object tree is full")]
    Full,
}

/// Links and special files are never read (size 0, no hash); a read gives both hashes or, when it
/// failed, neither.
fn check_content(object: &NewObject) -> Result<(), TreeError> {
    if object.kind != Kind::File
        && (object.size != 0 || object.sha256.is_some() || object.sha1.is_some())
    {
        return Err(TreeError::LinkWithContent(object.kind));
    }
    if object.sha256.is_some() != object.sha1.is_some() {
        return Err(TreeError::PartialHashes);
    }
    Ok(())
}

/// The objects of one medium.
#[derive(Debug, Clone)]
pub struct ObjectTree {
    max_depth: u32,
    nodes: Vec<ObjectNode>,
}

impl ObjectTree {
    /// An empty tree whose objects are at most `max_depth` deep.
    ///
    /// # Errors
    /// [`TreeError::InvalidMaxDepth`].
    pub fn new(max_depth: u32) -> Result<Self, TreeError> {
        if !(1..=MAX_DEPTH_LIMIT).contains(&max_depth) {
            return Err(TreeError::InvalidMaxDepth(max_depth));
        }
        Ok(Self {
            max_depth,
            nodes: Vec::new(),
        })
    }

    /// Insert a file of the medium (depth 0).
    ///
    /// # Errors
    /// [`TreeError::RootNotAFile`], [`TreeError::LinkWithContent`], [`TreeError::PartialHashes`],
    /// [`TreeError::Full`].
    pub fn insert_file(&mut self, object: NewObject) -> Result<ObjectId, TreeError> {
        if object.origin != Origin::File {
            return Err(TreeError::RootNotAFile(object.origin));
        }
        check_content(&object)?;
        self.push(None, 0, object)
    }

    /// Insert an object below `parent` (extracted entry, stream or attribute).
    ///
    /// # Errors
    /// [`TreeError::UnknownParent`], [`TreeError::ParentNotReadable`], [`TreeError::FileWithParent`],
    /// [`TreeError::StreamWithoutHostFile`], [`TreeError::TooDeep`], [`TreeError::LinkWithContent`],
    /// [`TreeError::PartialHashes`], [`TreeError::Full`].
    pub fn insert_child(
        &mut self,
        parent: ObjectId,
        object: NewObject,
    ) -> Result<ObjectId, TreeError> {
        let host = self.get(parent).ok_or(TreeError::UnknownParent(parent))?;
        if host.object.kind != Kind::File {
            return Err(TreeError::ParentNotReadable(host.object.kind));
        }
        if object.origin == Origin::File {
            return Err(TreeError::FileWithParent);
        }
        if matches!(object.origin, Origin::AltStream | Origin::Xattr)
            && host.object.origin != Origin::File
        {
            return Err(TreeError::StreamWithoutHostFile(host.object.origin));
        }
        let depth = host.depth + 1;
        if depth > self.max_depth {
            return Err(TreeError::TooDeep {
                depth,
                max_depth: self.max_depth,
            });
        }
        check_content(&object)?;
        self.push(Some(parent), depth, object)
    }

    /// The object with this identifier.
    #[must_use]
    pub fn get(&self, id: ObjectId) -> Option<&ObjectNode> {
        usize::try_from(id.0)
            .ok()
            .and_then(|index| self.nodes.get(index))
    }

    /// Every object, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &ObjectNode> {
        self.nodes.iter()
    }

    fn push(
        &mut self,
        parent: Option<ObjectId>,
        depth: u32,
        object: NewObject,
    ) -> Result<ObjectId, TreeError> {
        let id = ObjectId(u32::try_from(self.nodes.len()).map_err(|_| TreeError::Full)?);
        self.nodes.push(ObjectNode {
            id,
            parent,
            depth,
            object,
        });
        Ok(id)
    }

    /// The tree's maximum depth.
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }
}
