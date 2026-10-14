//! The tree of one file of the medium (FR-06, ADR-18, Q-59): the triage worker types each object, the
//! extraction worker opens each container, and the entries come back as new objects copied into the workspace,
//! under the policy's limits counted over the whole tree.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use ostia_contracts::current_version;
use ostia_contracts::v1::{AnalyzeRequest, Entry, EntryKind, ExtractionBudget, Origin, Status};
use ostia_core_domain::object::Kind;
use ostia_core_domain::policy::{Failure, Limits};
use ostia_core_domain::types::DetectedType;
use ostia_core_domain::verdict::Limit;
use ostia_media::inventory::{Copied, Copy, Workspace};
use ostia_sandbox::{
    EngineIdentity, EntrySink, Failure as RunFailure, Launcher, StreamFault, WorkerCommand,
    WorkerHost,
};

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
    let mut run = Run {
        workers,
        session_id,
        objects: 0,
        used_bytes: 0,
        used_entries: 0,
    };
    let root_object = Object {
        copy: root.copy.to_path_buf(),
        size: root.size,
        sha256: root.sha256,
        origin: Origin::File,
    };
    let mut tree = Tree {
        root: run.triage(&root_object),
        extracted: Vec::new(),
    };
    let mut containers = VecDeque::new();
    if let Some(detected) = tree.root.detected.filter(|t| t.is_container()) {
        containers.push_back(Container {
            index: None,
            depth: 0,
            name: last_part(root.name).to_vec(),
            object: root_object,
            detected,
        });
    }
    while let Some(container) = containers.pop_front() {
        let failure = if container.depth >= limits.max_depth {
            Some(Failure::Limit(Limit::Depth))
        } else {
            match run.extract(&container, limits, workspace) {
                Ok(entries) => {
                    for entry in entries {
                        let index = tree.extracted.len();
                        let (extracted, next) = run.child(&container, entry, index);
                        tree.extracted.push(extracted);
                        containers.extend(next);
                    }
                    None
                }
                Err(failure) => Some(failure),
            }
        };
        match container
            .index
            .and_then(|index| tree.extracted.get_mut(index))
        {
            Some(extracted) => extracted.analysis.failure = failure,
            None => tree.root.failure = failure,
        }
    }
    tree
}

/// An object a worker reads: its copy and what the request says about it.
#[derive(Debug, Clone)]
struct Object {
    copy: PathBuf,
    size: u64,
    sha256: [u8; 32],
    origin: Origin,
}

/// A container waiting for extraction.
#[derive(Debug)]
struct Container {
    /// Its index in [`Tree::extracted`]; `None` for the root.
    index: Option<usize>,
    depth: u32,
    /// Its own name, which an unnamed gzip member takes without the last extension.
    name: Vec<u8>,
    object: Object,
    detected: DetectedType,
}

/// An entry as the extraction streamed it, copied when it is a regular file.
#[derive(Debug)]
struct Received {
    path: Vec<u8>,
    kind: Kind,
    modified: Option<i64>,
    content: Option<Copied>,
}

/// One tree's progress: the workers, the object identifiers, what the tree already used of the budget.
struct Run<'r, 'w, L: Launcher> {
    workers: &'r Workers<'w, L>,
    session_id: &'r str,
    objects: u64,
    used_bytes: u64,
    used_entries: u64,
}

impl<L: Launcher> Run<'_, '_, L> {
    fn request(&mut self, object: &Object, detected: Option<DetectedType>) -> AnalyzeRequest {
        self.objects += 1;
        AnalyzeRequest {
            session_id: self.session_id.to_owned(),
            object_id: format!("tree-{}", self.objects),
            sha256: object.sha256.to_vec(),
            detected_type: detected.map(|t| t.name().to_owned()).unwrap_or_default(),
            size: object.size,
            origin: object.origin.into(),
            limits: None,
            extraction: None,
            version: Some(current_version()),
        }
    }

    /// Types `object` with the triage worker: a type the domain knows, or a failure (R1: could not be typed).
    fn triage(&mut self, object: &Object) -> Analysis {
        let request = self.request(object, None);
        let triage = self.workers.triage;
        let run = self
            .workers
            .host
            .run(&triage.command, &triage.identity, &request, &object.copy);
        let detected = (run.failure.is_none() && run.response.status == i32::from(Status::Ok))
            .then(|| DetectedType::from_name(&run.response.detected_type))
            .flatten();
        Analysis {
            detected,
            failure: detected.is_none().then_some(Failure::Malformed),
        }
    }

    /// Extracts `container` under what is left of the tree's budget: its entries, or why it keeps none.
    fn extract(
        &mut self,
        container: &Container,
        limits: &Limits,
        workspace: &mut Workspace,
    ) -> Result<Vec<Received>, Failure> {
        let mut request = self.request(&container.object, Some(container.detected));
        request.extraction = Some(ExtractionBudget {
            max_ratio: limits.max_ratio,
            remaining_bytes: limits.max_total_bytes.saturating_sub(self.used_bytes),
            remaining_entries: limits.max_entries.saturating_sub(self.used_entries),
            max_path_length: limits.max_path_length,
        });
        let mut sink = Collect {
            workspace,
            received: Vec::new(),
            current: None,
            entries: 0,
            bytes: 0,
        };
        let extract = self.workers.extract;
        let run = self.workers.host.extract(
            &extract.command,
            &extract.identity,
            &request,
            &container.object.copy,
            &mut sink,
        );
        // What the host received counts, kept or not.
        self.used_entries = self.used_entries.saturating_add(sink.entries);
        self.used_bytes = self.used_bytes.saturating_add(sink.bytes);
        match run.failure {
            Some(RunFailure::Stream(StreamFault::TooManyEntries)) => {
                Err(Failure::Limit(Limit::EntryCount))
            }
            Some(RunFailure::Stream(StreamFault::TooManyBytes)) => {
                Err(Failure::Limit(Limit::TotalSize))
            }
            Some(_) => Err(Failure::Malformed),
            None if run.response.status == i32::from(Status::Ok) => Ok(sink.received),
            None => Err(limit(&run.response.limit).map_or(Failure::Malformed, Failure::Limit)),
        }
    }

    /// The extracted object of `entry`, typed when it was read, and the container it is, if any.
    fn child(
        &mut self,
        container: &Container,
        entry: Received,
        index: usize,
    ) -> (Extracted, Option<Container>) {
        let path = if entry.path.is_empty() {
            without_extension(&container.name).to_vec()
        } else {
            entry.path
        };
        let depth = container.depth + 1;
        let mut next = None;
        let analysis = match &entry.content {
            Some(copied) => {
                let object = Object {
                    copy: copied.copy.clone(),
                    size: copied.size,
                    sha256: copied.sha256,
                    origin: Origin::Extracted,
                };
                let analysis = self.triage(&object);
                if let Some(detected) = analysis.detected.filter(|t| t.is_container()) {
                    next = Some(Container {
                        index: Some(index),
                        depth,
                        name: last_part(&path).to_vec(),
                        object,
                        detected,
                    });
                }
                analysis
            }
            None => Analysis {
                detected: None,
                failure: None,
            },
        };
        let extracted = Extracted {
            parent: container.index,
            depth,
            path,
            kind: entry.kind,
            modified: entry.modified,
            content: entry.content,
            analysis,
        };
        (extracted, next)
    }
}

/// The limit a worker named, in report.md's words.
fn limit(name: &str) -> Option<Limit> {
    match name {
        "ratio" => Some(Limit::Ratio),
        "total_size" => Some(Limit::TotalSize),
        "entry_count" => Some(Limit::EntryCount),
        "path_length" => Some(Limit::PathLength),
        _ => None,
    }
}

/// The last `/`-separated part of a path.
fn last_part(path: &[u8]) -> &[u8] {
    path.rsplit(|&b| b == b'/').next().unwrap_or(path)
}

/// A name without its last extension; the first dot of a dot name belongs to the stem (`.gz` stays `.gz`).
fn without_extension(name: &[u8]) -> &[u8] {
    match name.iter().rposition(|&b| b == b'.') {
        Some(dot) if dot > 0 => name.get(..dot).unwrap_or(name),
        _ => name,
    }
}

/// Receives the entries of one extraction, copying regular files into the workspace as they stream.
struct Collect<'a> {
    workspace: &'a mut Workspace,
    received: Vec<Received>,
    /// The entry being received and its copy, if it is a regular file.
    current: Option<(Received, Option<Copy>)>,
    entries: u64,
    bytes: u64,
}

impl EntrySink for Collect<'_> {
    fn entry(&mut self, entry: &Entry) -> std::io::Result<()> {
        self.entries += 1;
        let kind = match EntryKind::try_from(entry.kind) {
            Ok(EntryKind::Regular) => Kind::File,
            Ok(EntryKind::Link) => Kind::Symlink,
            Ok(EntryKind::Special) => Kind::Special,
            Ok(EntryKind::Unspecified) | Err(_) => {
                return Err(std::io::Error::other("unknown entry kind"));
            }
        };
        let copy = match kind {
            Kind::File => Some(self.workspace.begin_copy().map_err(std::io::Error::other)?),
            Kind::Symlink | Kind::Special => None,
        };
        let received = Received {
            path: entry.path.clone(),
            kind,
            modified: entry.modified,
            content: None,
        };
        self.current = Some((received, copy));
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        match &mut self.current {
            Some((_, Some(copy))) => copy.write(bytes).map_err(std::io::Error::other),
            _ => Err(std::io::Error::other("bytes for an entry that has none")),
        }
    }

    fn end(&mut self) -> std::io::Result<()> {
        let Some((mut received, copy)) = self.current.take() else {
            return Err(std::io::Error::other("no entry to end"));
        };
        if let Some(copy) = copy {
            received.content = Some(copy.finish().map_err(std::io::Error::other)?);
        }
        self.received.push(received);
        Ok(())
    }
}
