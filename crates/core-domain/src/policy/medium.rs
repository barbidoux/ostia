//! Mode semantics: the medium verdict and the transferable objects (`docs/contracts/report.md`, "Medium
//! verdict" and "Transferable"; FR-10, spec §5 and §8).

use std::collections::{BTreeMap, BTreeSet};

use super::{MediumFinding, SessionState};
use crate::object::{Kind, ObjectId, ObjectNode, ObjectTree, Origin};
use crate::session::Mode;
use crate::verdict::{MediumVerdict, Verdict, worst_of};

/// The medium verdict: the worst object verdict (ADR-16), with an UNSCANNABLE for the unanalysed rest when
/// the scan expired or the session was aborted; blocked as the mode says.
#[must_use]
pub fn medium_verdict(objects: &[(ObjectId, Verdict)], state: &SessionState) -> MediumVerdict {
    let stopped = stopped(state);
    let mut verdict = worst_of(objects.iter().map(|&(_, v)| v));
    if state.expired || stopped {
        verdict = Some(verdict.map_or(Verdict::Unscannable, |v| v.worst(Verdict::Unscannable)));
    }
    let blocking_objects: Vec<ObjectId> = objects
        .iter()
        .filter(|(_, v)| matches!(v, Verdict::Malicious | Verdict::Unscannable))
        .map(|&(id, _)| id)
        .collect();
    let blocked_by_objects = match state.mode {
        Mode::Compliant | Mode::ScanOnly => !blocking_objects.is_empty() || state.expired,
        Mode::Selective => false,
    };
    MediumVerdict {
        verdict: verdict.unwrap_or(Verdict::Clean),
        blocked: stopped || blocked_by_objects,
        blocking_objects,
        findings: state.findings.clone(),
    }
}

/// The objects that may be transferred: files of the medium (regular files with a safe path) whose verdict
/// is CLEAN, as is every object extracted from them; none in scan-only mode, nor when the medium is blocked.
#[must_use]
pub fn transferable(
    tree: &ObjectTree,
    verdicts: &BTreeMap<ObjectId, Verdict>,
    state: &SessionState,
    medium: &MediumVerdict,
) -> BTreeSet<ObjectId> {
    let blocked = state.mode == Mode::Compliant && medium.blocked;
    if state.mode == Mode::ScanOnly || stopped(state) || blocked {
        return BTreeSet::new();
    }
    let clean = |id: ObjectId| verdicts.get(&id) == Some(&Verdict::Clean);
    // Files of the medium that carry a non-CLEAN extracted object, at any depth.
    let tainted: BTreeSet<ObjectId> = tree
        .iter()
        .filter(|node| node.object.origin == Origin::Extracted && !clean(node.id))
        .filter_map(|node| root_of(tree, node))
        .collect();
    tree.iter()
        .filter(|node| {
            node.parent.is_none()
                && node.object.origin == Origin::File
                && node.object.kind == Kind::File
                && clean(node.id)
                && is_safe_path(&node.object.path)
                && !tainted.contains(&node.id)
        })
        .map(|node| node.id)
        .collect()
}

/// Nothing of the medium may be transferred: the input was refused, the session aborted, or the device
/// rejected (D1 aborts the session).
fn stopped(state: &SessionState) -> bool {
    state.refused || state.aborted || state.findings.contains(&MediumFinding::DeviceRejected)
}

/// The file of the medium an object belongs to.
fn root_of(tree: &ObjectTree, node: &ObjectNode) -> Option<ObjectId> {
    let mut current = node;
    while let Some(parent) = current.parent {
        current = tree.get(parent)?;
    }
    Some(current.id)
}

/// Relative, with no empty, `.` or `..` component: a copy can never leave the output directory.
fn is_safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && path.split('/').all(|part| !matches!(part, "" | "." | ".."))
}
