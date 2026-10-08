//! The object tree: files of the medium, their alternate streams and extended attributes, and the objects
//! extracted from archives (`docs/contracts/report.md`, "Objects").
//!
//! Identifiers are assigned by the tree and a child is inserted only below an existing parent, so the tree
//! has no duplicate identifier and no cycle by construction; depth is checked against the policy's
//! `max_depth` on every insertion.

use thiserror::Error;

/// Identifier of an object, unique in its tree.
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
    pub fn new(_max_depth: u32) -> Result<Self, TreeError> {
        todo!("WP-1.1: object tree")
    }

    /// Insert a file of the medium (depth 0).
    ///
    /// # Errors
    /// [`TreeError::RootNotAFile`].
    pub fn insert_file(&mut self, _object: NewObject) -> Result<ObjectId, TreeError> {
        todo!("WP-1.1: object tree")
    }

    /// Insert an object below `parent` (extracted entry, stream or attribute).
    ///
    /// # Errors
    /// [`TreeError::UnknownParent`], [`TreeError::FileWithParent`], [`TreeError::TooDeep`].
    pub fn insert_child(
        &mut self,
        _parent: ObjectId,
        _object: NewObject,
    ) -> Result<ObjectId, TreeError> {
        todo!("WP-1.1: object tree")
    }

    /// The object with this identifier.
    #[must_use]
    pub fn get(&self, _id: ObjectId) -> Option<&ObjectNode> {
        todo!("WP-1.1: object tree")
    }

    /// Every object, in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = &ObjectNode> {
        self.nodes.iter()
    }

    /// The tree's maximum depth.
    #[must_use]
    pub fn max_depth(&self) -> u32 {
        self.max_depth
    }
}
