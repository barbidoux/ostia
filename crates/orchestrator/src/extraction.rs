//! The tree of one file of the medium (FR-06, ADR-18, Q-59): the triage worker types each object, the
//! extraction worker opens each container, and the entries come back as new objects copied into the workspace,
//! under the policy's limits counted over the whole tree.

use std::path::Path;

use ostia_core_domain::object::Kind;
use ostia_core_domain::policy::{Failure, Limits};
use ostia_core_domain::types::DetectedType;
use ostia_media::inventory::{Copied, Workspace};
use ostia_sandbox::{EngineIdentity, Launcher, WorkerCommand, WorkerHost};

/// A worker program and the identity its answers must carry.
#[derive(Debug, Clone)]
pub struct Worker {
    /// The program and its arguments.
    pub command: WorkerCommand,
    /// The identity its answers must carry (CTR-03).
    pub identity: EngineIdentity,
}

/// The workers the tree needs, run through one host.
#[derive(Debug)]
pub struct Workers<'a, L: Launcher> {
    /// Runs every worker.
    pub host: &'a WorkerHost<L>,
    /// The triage worker (`ostia-triage`).
    pub triage: &'a Worker,
    /// The extraction worker (`ostia-extract`).
    pub extract: &'a Worker,
}

/// The file of the medium the tree grows from, as the inventory read it.
#[derive(Debug, Clone, Copy)]
pub struct Root<'a> {
    /// Its copy in the workspace.
    pub copy: &'a Path,
    /// Its name on the medium (an unnamed gzip member is named after it).
    pub name: &'a [u8],
    /// Its size.
    pub size: u64,
    /// Its SHA-256.
    pub sha256: [u8; 32],
}

/// What triage and extraction found about one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    /// Its type, when the triage worker could type it.
    pub detected: Option<DetectedType>,
    /// Why it could not be typed or extracted (a limit, a malformation), if so: UNSCANNABLE through R1.
    pub failure: Option<Failure>,
}

/// An object extracted from a container of the tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extracted {
    /// Index of its container in [`Tree::extracted`]; `None` for an entry of the root.
    pub parent: Option<usize>,
    /// Its depth: the root is 0.
    pub depth: u32,
    /// Its path inside its container (`report.md`: a gzip member without a name gets its container's name
    /// without the last extension).
    pub path: Vec<u8>,
    /// What it is.
    pub kind: Kind,
    /// Its modification time in seconds since the Unix epoch, when the container records one.
    pub modified: Option<i64>,
    /// Its copy in the workspace; none for a link or a special entry.
    pub content: Option<Copied>,
    /// Triage and extraction of the object (nothing for a link or a special entry).
    pub analysis: Analysis,
}

/// The root's analysis and every object extracted from its tree, each container before its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    /// Triage and extraction of the root.
    pub root: Analysis,
    /// Every extracted object.
    pub extracted: Vec<Extracted>,
}

/// Types `root`, extracts it if it is a container, then types and extracts each entry in turn, never deeper
/// than `limits.max_depth` and within the tree's total size and entry count. Never fails: what cannot be done
/// is a failure of the object concerned.
pub fn expand<L: Launcher>(
    workers: &Workers<'_, L>,
    limits: &Limits,
    workspace: &mut Workspace,
    session_id: &str,
    root: &Root<'_>,
) -> Tree {
    let _ = (workers, limits, workspace, session_id, root);
    todo!("WP-1.8: expand")
}
