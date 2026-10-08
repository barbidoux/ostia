//! Mode semantics (`docs/contracts/report.md`, "Medium verdict" and "Transferable"; FR-10, spec §5 and §8):
//! compliant mode blocks the medium on a MALICIOUS or UNSCANNABLE object, selective mode transfers only CLEAN
//! files, scan-only transfers nothing; D1 blocks, D2 alerts.

use std::collections::{BTreeMap, BTreeSet};

use ostia_core_domain::object::{Kind, NewObject, ObjectId, ObjectTree, Origin};
use ostia_core_domain::policy::{MediumFinding, SessionState, medium_verdict, transferable};
use ostia_core_domain::session::Mode;
use ostia_core_domain::verdict::{MediumVerdict, Verdict};
use ostia_traceability::req;

use Verdict::{Clean, Malicious, Suspicious, Unscannable};

fn state(mode: Mode) -> SessionState {
    SessionState {
        mode,
        ..SessionState::default()
    }
}

/// Medium verdict of objects 0, 1, ... with these verdicts.
fn verdict_of(verdicts: &[Verdict], state: &SessionState) -> MediumVerdict {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let objects: Vec<(ObjectId, Verdict)> = verdicts
        .iter()
        .enumerate()
        .map(|(i, &v)| (tree.insert_file(file(&format!("f{i}"))).expect("root"), v))
        .collect();
    medium_verdict(&objects, state)
}

/// Verdict, blocked, indices of the blocking objects.
type Summary = (Verdict, bool, Vec<u32>);

fn summary(medium: &MediumVerdict) -> Summary {
    let blocking = medium
        .blocking_objects
        .iter()
        .map(|id| id.index())
        .collect();
    (medium.verdict, medium.blocked, blocking)
}

#[req("FR-10")]
#[test]
fn compliant_medium_is_blocked_by_malicious_or_unscannable_only() {
    let compliant = state(Mode::Compliant);
    let cases: [(&[Verdict], Summary); 6] = [
        (&[], (Clean, false, vec![])),
        (&[Clean, Clean], (Clean, false, vec![])),
        (&[Clean, Suspicious], (Suspicious, false, vec![])),
        (&[Clean, Malicious], (Malicious, true, vec![1])),
        (&[Unscannable, Clean], (Unscannable, true, vec![0])),
        (
            &[Unscannable, Suspicious, Malicious],
            (Malicious, true, vec![0, 2]),
        ),
    ];
    for (verdicts, expected) in cases {
        assert_eq!(
            summary(&verdict_of(verdicts, &compliant)),
            expected,
            "{verdicts:?}"
        );
    }
}

#[req("FR-10")]
#[test]
fn selective_medium_is_not_blocked_by_objects() {
    let medium = verdict_of(&[Clean, Malicious, Unscannable], &state(Mode::Selective));
    assert_eq!(summary(&medium), (Malicious, false, vec![1, 2]));
}

#[req("FR-10")]
#[test]
fn scan_only_medium_is_blocked_like_compliant() {
    let medium = verdict_of(&[Clean, Malicious], &state(Mode::ScanOnly));
    assert_eq!(summary(&medium), (Malicious, true, vec![1]));
    let clean = verdict_of(&[Clean], &state(Mode::ScanOnly));
    assert_eq!(summary(&clean), (Clean, false, vec![]));
}

#[req("FR-10", "FR-14")]
#[test]
fn expired_scan_counts_the_unanalysed_rest_as_unscannable() {
    for (mode, blocked) in [
        (Mode::Compliant, true),
        (Mode::ScanOnly, true),
        (Mode::Selective, false),
    ] {
        let expired = SessionState {
            expired: true,
            ..state(mode)
        };
        assert_eq!(
            summary(&verdict_of(&[Clean], &expired)),
            (Unscannable, blocked, vec![]),
            "{mode:?}"
        );
        assert_eq!(
            summary(&verdict_of(&[], &expired)),
            (Unscannable, blocked, vec![]),
            "{mode:?}"
        );
    }
    // MALICIOUS stays above the implicit UNSCANNABLE (ADR-16).
    let expired = SessionState {
        expired: true,
        ..state(Mode::Compliant)
    };
    assert_eq!(
        summary(&verdict_of(&[Malicious], &expired)),
        (Malicious, true, vec![0])
    );
}

#[req("FR-10", "FR-14")]
#[test]
fn aborted_session_is_blocked_in_every_mode() {
    for mode in [Mode::Compliant, Mode::Selective, Mode::ScanOnly] {
        let aborted = SessionState {
            aborted: true,
            ..state(mode)
        };
        assert_eq!(
            summary(&verdict_of(&[], &aborted)),
            (Unscannable, true, vec![]),
            "{mode:?}"
        );
        assert_eq!(
            summary(&verdict_of(&[Clean], &aborted)),
            (Unscannable, true, vec![]),
            "{mode:?}"
        );
    }
}

#[req("FR-10")]
#[test]
fn rejected_device_blocks_in_every_mode() {
    for mode in [Mode::Compliant, Mode::Selective, Mode::ScanOnly] {
        let rejected = SessionState {
            findings: vec![MediumFinding::DeviceRejected],
            ..state(mode)
        };
        // D1 aborts the session: UNSCANNABLE and blocked, whatever the objects.
        let medium = verdict_of(&[Clean], &rejected);
        assert_eq!(summary(&medium), (Unscannable, true, vec![]), "{mode:?}");
        assert_eq!(medium.findings, [MediumFinding::DeviceRejected]);
        let empty = verdict_of(&[], &rejected);
        assert_eq!(summary(&empty), (Unscannable, true, vec![]), "{mode:?}");
    }
}

#[req("FR-10")]
#[test]
fn refused_input_is_blocked_in_every_mode() {
    for mode in [Mode::Compliant, Mode::Selective, Mode::ScanOnly] {
        let refused = SessionState {
            refused: true,
            ..state(mode)
        };
        assert_eq!(
            summary(&verdict_of(&[], &refused)),
            (Unscannable, true, vec![]),
            "{mode:?}"
        );
    }
}

#[req("FR-10")]
#[test]
fn hidden_payload_is_an_alert_only() {
    let alerted = SessionState {
        findings: vec![MediumFinding::HiddenPayload],
        ..state(Mode::Compliant)
    };
    let medium = verdict_of(&[Clean], &alerted);
    assert_eq!(summary(&medium), (Clean, false, vec![]));
    assert_eq!(medium.findings, [MediumFinding::HiddenPayload]);
}

// --- transferable -----------------------------------------------------------------------------------

fn object(origin: Origin, path: &str) -> NewObject {
    NewObject {
        origin,
        kind: Kind::File,
        path: path.to_owned(),
        stream: None,
        size: 6,
        sha256: Some([0x5a; 32]),
        sha1: Some([0xa5; 20]),
    }
}

fn file(path: &str) -> NewObject {
    object(Origin::File, path)
}

/// a.txt, readme.txt with a stream, box.zip holding sub.zip holding inner.txt, a link.
struct Medium {
    tree: ObjectTree,
    a: ObjectId,
    readme: ObjectId,
    stream: ObjectId,
    archive: ObjectId,
    sub: ObjectId,
    inner: ObjectId,
}

fn medium() -> Medium {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let a = tree.insert_file(file("a.txt")).expect("root");
    let readme = tree.insert_file(file("docs/readme.txt")).expect("root");
    let stream = tree
        .insert_child(readme, object(Origin::AltStream, "docs/readme.txt"))
        .expect("stream");
    let archive = tree.insert_file(file("box.zip")).expect("root");
    let sub = tree
        .insert_child(archive, object(Origin::Extracted, "sub.zip"))
        .expect("entry");
    let inner = tree
        .insert_child(sub, object(Origin::Extracted, "inner.txt"))
        .expect("entry");
    Medium {
        tree,
        a,
        readme,
        stream,
        archive,
        sub,
        inner,
    }
}

/// Transferable objects when every object is CLEAN except those listed.
fn transferable_with(
    m: &Medium,
    state: &SessionState,
    not_clean: &[(ObjectId, Verdict)],
) -> BTreeSet<ObjectId> {
    let mut verdicts: BTreeMap<ObjectId, Verdict> = m.tree.iter().map(|n| (n.id, Clean)).collect();
    verdicts.extend(not_clean.iter().copied());
    let pairs: Vec<(ObjectId, Verdict)> = verdicts.iter().map(|(&id, &v)| (id, v)).collect();
    let medium = medium_verdict(&pairs, state);
    transferable(&m.tree, &verdicts, state, &medium)
}

#[req("FR-10")]
#[test]
fn clean_files_of_the_medium_are_transferable_not_their_streams_or_entries() {
    let m = medium();
    assert_eq!(
        transferable_with(&m, &state(Mode::Compliant), &[]),
        BTreeSet::from([m.a, m.readme, m.archive])
    );
}

#[req("FR-10")]
#[test]
fn file_with_a_non_clean_extracted_descendant_is_not_transferable() {
    let m = medium();
    assert_eq!(
        transferable_with(&m, &state(Mode::Compliant), &[(m.inner, Suspicious)]),
        BTreeSet::from([m.a, m.readme])
    );
    assert_eq!(
        transferable_with(&m, &state(Mode::Compliant), &[(m.sub, Suspicious)]),
        BTreeSet::from([m.a, m.readme])
    );
}

#[req("FR-10")]
#[test]
fn suspicious_file_blocks_only_itself() {
    let m = medium();
    assert_eq!(
        transferable_with(&m, &state(Mode::Compliant), &[(m.a, Suspicious)]),
        BTreeSet::from([m.readme, m.archive])
    );
}

#[req("FR-10")]
#[test]
fn suspicious_stream_does_not_block_its_host_file() {
    // Streams are never copied; only EXTRACTED descendants travel inside a file.
    let m = medium();
    assert_eq!(
        transferable_with(&m, &state(Mode::Compliant), &[(m.stream, Suspicious)]),
        BTreeSet::from([m.a, m.readme, m.archive])
    );
}

#[req("FR-10")]
#[test]
fn blocked_compliant_medium_transfers_nothing() {
    let m = medium();
    for not_clean in [
        (m.a, Malicious),
        (m.inner, Unscannable),
        (m.stream, Malicious),
    ] {
        assert_eq!(
            transferable_with(&m, &state(Mode::Compliant), &[not_clean]),
            BTreeSet::new(),
            "{not_clean:?}"
        );
    }
}

#[req("FR-10")]
#[test]
fn selective_mode_transfers_the_clean_files() {
    let m = medium();
    assert_eq!(
        transferable_with(
            &m,
            &state(Mode::Selective),
            &[(m.a, Malicious), (m.inner, Unscannable)]
        ),
        BTreeSet::from([m.readme])
    );
}

#[req("FR-10")]
#[test]
fn scan_only_and_aborted_sessions_transfer_nothing() {
    let m = medium();
    assert_eq!(
        transferable_with(&m, &state(Mode::ScanOnly), &[]),
        BTreeSet::new()
    );
    let aborted = SessionState {
        aborted: true,
        ..state(Mode::Selective)
    };
    assert_eq!(transferable_with(&m, &aborted, &[]), BTreeSet::new());
}

#[req("FR-10")]
#[test]
fn rejected_device_or_refused_input_transfers_nothing_even_in_selective_mode() {
    let m = medium();
    for state in [
        SessionState {
            findings: vec![MediumFinding::DeviceRejected],
            ..state(Mode::Selective)
        },
        SessionState {
            refused: true,
            ..state(Mode::Selective)
        },
    ] {
        assert_eq!(
            transferable_with(&m, &state, &[]),
            BTreeSet::new(),
            "{state:?}"
        );
    }
}

#[req("FR-10")]
#[test]
fn objects_without_a_verdict_are_not_clean() {
    let m = medium();
    let mut verdicts: BTreeMap<ObjectId, Verdict> = m.tree.iter().map(|n| (n.id, Clean)).collect();
    // Selective mode, so that a missing verdict does not block the medium through medium_verdict.
    let selective = state(Mode::Selective);
    verdicts.remove(&m.a);
    verdicts.remove(&m.inner);
    let pairs: Vec<(ObjectId, Verdict)> = verdicts.iter().map(|(&id, &v)| (id, v)).collect();
    let medium = medium_verdict(&pairs, &selective);
    assert_eq!(
        transferable(&m.tree, &verdicts, &selective, &medium),
        BTreeSet::from([m.readme])
    );
}

#[req("FR-10")]
#[test]
fn expired_selective_scan_transfers_the_clean_files() {
    let m = medium();
    let expired = SessionState {
        expired: true,
        ..state(Mode::Selective)
    };
    assert_eq!(
        transferable_with(&m, &expired, &[(m.a, Unscannable)]),
        BTreeSet::from([m.readme, m.archive])
    );
}

#[req("FR-10")]
#[test]
fn links_and_unsafe_paths_are_never_transferable() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let safe = tree.insert_file(file("dir/ok.txt")).expect("root");
    let link = tree
        .insert_file(NewObject {
            kind: Kind::Symlink,
            size: 0,
            sha256: None,
            sha1: None,
            ..file("link")
        })
        .expect("root");
    let special = tree
        .insert_file(NewObject {
            kind: Kind::Special,
            size: 0,
            sha256: None,
            sha1: None,
            ..file("fifo")
        })
        .expect("root");
    let unsafe_paths: Vec<ObjectId> = [
        "../escape.txt",
        "/etc/passwd",
        "a//b.txt",
        "./a.txt",
        "a/./b.txt",
        "a/..",
        "",
    ]
    .iter()
    .map(|p| tree.insert_file(file(p)).expect("root"))
    .collect();
    let verdicts: BTreeMap<ObjectId, Verdict> = tree.iter().map(|n| (n.id, Clean)).collect();
    // Selective mode, so that nothing blocks the medium as a whole.
    let selective = state(Mode::Selective);
    let pairs: Vec<(ObjectId, Verdict)> = verdicts.iter().map(|(&id, &v)| (id, v)).collect();
    let medium = medium_verdict(&pairs, &selective);
    let chosen = transferable(&tree, &verdicts, &selective, &medium);
    assert_eq!(chosen, BTreeSet::from([safe]));
    assert!(!chosen.contains(&link));
    assert!(!chosen.contains(&special));
    assert!(unsafe_paths.iter().all(|id| !chosen.contains(id)));
}
