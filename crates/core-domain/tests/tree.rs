//! Object tree invariants: roots are files of the medium at depth 0, every other object sits below an
//! existing, readable parent at its depth + 1, no deeper than the policy's `max_depth`; streams and
//! attributes hang on a file of the medium; links and special files carry no content; the tree has no
//! cycle (`docs/contracts/report.md`, "Objects").

use ostia_core_domain::object::{Kind, NewObject, ObjectId, ObjectTree, Origin, TreeError};
use ostia_traceability::req;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

fn fixed_seed() -> Config {
    Config {
        cases: 256,
        rng_seed: RngSeed::Fixed(0x07_2e_e0_11),
        // A fixed seed replays every case; no regression file is written.
        failure_persistence: None,
        ..Config::default()
    }
}

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

fn entry(path: &str) -> NewObject {
    object(Origin::Extracted, path)
}

fn link(origin: Origin, kind: Kind, path: &str) -> NewObject {
    NewObject {
        origin,
        kind,
        path: path.to_owned(),
        stream: None,
        size: 0,
        sha256: None,
        sha1: None,
    }
}

#[req("FR-09")]
#[test]
fn file_of_the_medium_is_a_root_at_depth_0() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let id = tree.insert_file(file("docs/report.pdf")).expect("root");
    let node = tree.get(id).expect("inserted");
    assert_eq!((node.parent, node.depth), (None, 0));
    assert_eq!(node.object, file("docs/report.pdf"));
}

#[req("FR-09")]
#[test]
fn child_is_one_level_below_its_parent() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let archive = tree.insert_file(file("bundle.zip")).expect("root");
    let inner = tree
        .insert_child(archive, entry("inner.zip"))
        .expect("child");
    let leaf = tree
        .insert_child(inner, entry("a.txt"))
        .expect("grandchild");
    let stream = tree
        .insert_child(archive, object(Origin::AltStream, "bundle.zip"))
        .expect("stream");
    assert_eq!(
        tree.get(inner).map(|n| (n.parent, n.depth)),
        Some((Some(archive), 1))
    );
    assert_eq!(
        tree.get(leaf).map(|n| (n.parent, n.depth)),
        Some((Some(inner), 2))
    );
    assert_eq!(
        tree.get(stream).map(|n| (n.parent, n.depth)),
        Some((Some(archive), 1))
    );
}

#[req("FR-09")]
#[test]
fn identifiers_are_unique_in_insertion_order() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let a = tree.insert_file(file("a.txt")).expect("root");
    let b = tree.insert_file(file("b.txt")).expect("root");
    let c = tree.insert_child(a, entry("c.txt")).expect("child");
    assert_eq!([a.index(), b.index(), c.index()], [0, 1, 2]);
    assert_eq!(tree.iter().map(|n| n.id).collect::<Vec<_>>(), [a, b, c]);
}

#[req("FR-09")]
#[test]
fn unknown_parent_is_refused() {
    let mut other = ObjectTree::new(8).expect("valid max depth");
    other.insert_file(file("x.txt")).expect("root");
    let foreign = other.insert_file(file("y.txt")).expect("root");
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    tree.insert_file(file("a.txt")).expect("root");
    assert_eq!(
        tree.insert_child(foreign, entry("b.txt")),
        Err(TreeError::UnknownParent(foreign))
    );
    assert_eq!(tree.iter().count(), 1);
}

#[req("FR-09")]
#[test]
fn child_beyond_the_maximum_depth_is_refused() {
    let mut tree = ObjectTree::new(3).expect("valid max depth");
    let mut level = tree.insert_file(file("l0.zip")).expect("root");
    for depth in 1..=3 {
        level = tree
            .insert_child(level, entry(&format!("l{depth}.zip")))
            .expect("within the limit");
    }
    assert_eq!(
        tree.insert_child(level, entry("leaf.txt")),
        Err(TreeError::TooDeep {
            depth: 4,
            max_depth: 3
        })
    );
    assert_eq!(tree.iter().count(), 4);
    assert_eq!(tree.iter().map(|n| n.depth).max(), Some(3));
}

#[req("FR-09")]
#[test]
fn depth_limit_holds_at_both_ends_of_the_policy_range() {
    for max_depth in [1, 64] {
        let mut tree = ObjectTree::new(max_depth).expect("valid max depth");
        let mut level = tree.insert_file(file("l0.zip")).expect("root");
        for depth in 1..=max_depth {
            level = tree
                .insert_child(level, entry(&format!("l{depth}.zip")))
                .expect("within the limit");
        }
        assert_eq!(tree.get(level).map(|n| n.depth), Some(max_depth));
        assert_eq!(
            tree.insert_child(level, entry("leaf.txt")),
            Err(TreeError::TooDeep {
                depth: max_depth + 1,
                max_depth
            })
        );
    }
}

#[req("FR-09")]
#[test]
fn maximum_depth_is_the_policy_range() {
    for max_depth in [1, 8, 64] {
        assert_eq!(
            ObjectTree::new(max_depth).map(|t| t.max_depth()),
            Ok(max_depth)
        );
    }
    for max_depth in [0, 65] {
        assert_eq!(
            ObjectTree::new(max_depth).err(),
            Some(TreeError::InvalidMaxDepth(max_depth))
        );
    }
}

#[req("FR-09")]
#[test]
fn root_must_be_a_file_of_the_medium() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    for origin in [Origin::Extracted, Origin::AltStream, Origin::Xattr] {
        assert_eq!(
            tree.insert_file(object(origin, "x")),
            Err(TreeError::RootNotAFile(origin))
        );
    }
    assert_eq!(tree.iter().count(), 0);
}

#[req("FR-09")]
#[test]
fn file_of_the_medium_never_has_a_parent() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let archive = tree.insert_file(file("bundle.zip")).expect("root");
    assert_eq!(
        tree.insert_child(archive, file("a.txt")),
        Err(TreeError::FileWithParent)
    );
    assert_eq!(tree.iter().count(), 1);
}

#[req("FR-09")]
#[test]
fn links_and_special_files_have_no_children() {
    // Never followed, opened or read: nothing can be extracted from them or hang on them.
    for kind in [Kind::Symlink, Kind::Special] {
        let mut tree = ObjectTree::new(8).expect("valid max depth");
        let target = tree
            .insert_file(link(Origin::File, kind, "escape"))
            .expect("root");
        for child in [
            entry("inside"),
            object(Origin::AltStream, "escape"),
            object(Origin::Xattr, "escape"),
        ] {
            assert_eq!(
                tree.insert_child(target, child),
                Err(TreeError::ParentNotReadable(kind))
            );
        }
        assert_eq!(tree.iter().count(), 1);
    }
}

#[req("FR-09")]
#[test]
fn streams_and_attributes_hang_on_a_file_of_the_medium() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let archive = tree.insert_file(file("bundle.zip")).expect("root");
    let inner = tree.insert_child(archive, entry("a.txt")).expect("entry");
    let stream = tree
        .insert_child(archive, object(Origin::AltStream, "bundle.zip"))
        .expect("stream on a medium file");
    for (parent, origin, parent_origin) in [
        (inner, Origin::AltStream, Origin::Extracted),
        (inner, Origin::Xattr, Origin::Extracted),
        (stream, Origin::AltStream, Origin::AltStream),
        (stream, Origin::Xattr, Origin::AltStream),
    ] {
        assert_eq!(
            tree.insert_child(parent, object(origin, "x")),
            Err(TreeError::StreamWithoutHostFile(parent_origin)),
            "{origin:?} under {parent_origin:?}"
        );
    }
    assert_eq!(tree.iter().count(), 3);
}

#[req("FR-09")]
#[test]
fn links_and_special_files_carry_no_content() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    for kind in [Kind::Symlink, Kind::Special] {
        let sized = NewObject {
            size: 3,
            ..link(Origin::File, kind, "sized")
        };
        let hashed = NewObject {
            sha256: Some([0x11; 32]),
            ..link(Origin::File, kind, "hashed")
        };
        for refused in [sized, hashed] {
            assert_eq!(
                tree.insert_file(refused),
                Err(TreeError::LinkWithContent(kind))
            );
        }
        tree.insert_file(link(Origin::File, kind, "plain"))
            .expect("a link without content");
    }
    assert_eq!(tree.iter().count(), 2);
}

#[req("FR-09")]
#[test]
fn hashes_come_together_or_not_at_all() {
    // A file read once has both hashes (SEC-10); one that could not be read has none (then R1).
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let only_sha256 = NewObject {
        sha1: None,
        ..file("a.txt")
    };
    let only_sha1 = NewObject {
        sha256: None,
        ..file("b.txt")
    };
    for refused in [only_sha256, only_sha1] {
        assert_eq!(tree.insert_file(refused), Err(TreeError::PartialHashes));
    }
    let unread = NewObject {
        sha256: None,
        sha1: None,
        ..file("unreadable.bin")
    };
    tree.insert_file(unread)
        .expect("an unread file has no hash");
    assert_eq!(tree.iter().count(), 1);
}

/// One step of a random tree.
#[derive(Debug, Clone)]
enum Step {
    /// A new file of the medium.
    Root,
    /// A child of the n-th object inserted so far.
    Child(usize, Origin),
    /// A child of the last object inserted (builds deep chains).
    Chain(Origin),
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let origin = || {
        prop::sample::select(vec![
            Origin::Extracted,
            Origin::Extracted,
            Origin::AltStream,
            Origin::Xattr,
        ])
    };
    let step = prop_oneof![
        1 => Just(Step::Root),
        4 => (0usize..128, origin()).prop_map(|(n, o)| Step::Child(n, o)),
        3 => origin().prop_map(Step::Chain),
    ];
    prop::collection::vec(step, 1..128)
}

/// What the model expects for one insertion.
#[derive(Debug, PartialEq, Eq)]
enum Expected {
    Inserted {
        parent: Option<ObjectId>,
        depth: u32,
    },
    Refused(TreeError),
}

/// Build a tree from the steps; for every step, what the tree did and what a model of the contract
/// expected (depth and parent from the model's own bookkeeping).
fn build(max_depth: u32, steps: &[Step]) -> (ObjectTree, Vec<(Expected, Expected)>) {
    let mut tree = ObjectTree::new(max_depth).expect("valid max depth");
    // Model: (id, origin, depth) of every inserted object.
    let mut model: Vec<(ObjectId, Origin, u32)> = Vec::new();
    let mut outcomes = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let chosen = match step {
            Step::Root => None,
            Step::Child(n, origin) => model.get(n % model.len().max(1)).map(|m| (*m, *origin)),
            Step::Chain(origin) => model.last().map(|m| (*m, *origin)),
        };
        let (result, expected) = match chosen {
            None => {
                let result = tree.insert_file(file(&format!("f{i}")));
                (result, None)
            }
            Some(((parent, parent_origin, parent_depth), origin)) => {
                let result = tree.insert_child(parent, object(origin, &format!("e{i}")));
                let expected = if matches!(origin, Origin::AltStream | Origin::Xattr)
                    && parent_origin != Origin::File
                {
                    Expected::Refused(TreeError::StreamWithoutHostFile(parent_origin))
                } else if parent_depth + 1 > max_depth {
                    Expected::Refused(TreeError::TooDeep {
                        depth: parent_depth + 1,
                        max_depth,
                    })
                } else {
                    Expected::Inserted {
                        parent: Some(parent),
                        depth: parent_depth + 1,
                    }
                };
                (result, Some((expected, origin, parent_depth + 1)))
            }
        };
        let (expected, origin, depth) = expected.unwrap_or((
            Expected::Inserted {
                parent: None,
                depth: 0,
            },
            Origin::File,
            0,
        ));
        let actual = match result {
            Ok(id) => {
                model.push((id, origin, depth));
                let node = tree.get(id).expect("an inserted object is in the tree");
                Expected::Inserted {
                    parent: node.parent,
                    depth: node.depth,
                }
            }
            Err(error) => Expected::Refused(error),
        };
        outcomes.push((actual, expected));
    }
    (tree, outcomes)
}

proptest! {
    #![proptest_config(fixed_seed())]

    #[req("FR-09")]
    #[test]
    fn every_insertion_does_what_the_contract_says(max_depth in 1u32..=64, steps in steps()) {
        let (tree, outcomes) = build(max_depth, &steps);
        let inserted = outcomes
            .iter()
            .filter(|(actual, _)| matches!(actual, Expected::Inserted { .. }))
            .count();
        for (actual, expected) in outcomes {
            prop_assert_eq!(actual, expected);
        }
        prop_assert_eq!(tree.iter().count(), inserted);
    }

    #[req("FR-09")]
    #[test]
    fn every_object_is_at_its_parent_depth_plus_one(max_depth in 1u32..=64, steps in steps()) {
        let (tree, _) = build(max_depth, &steps);
        for node in tree.iter() {
            match node.parent {
                None => {
                    prop_assert_eq!(node.depth, 0);
                    prop_assert_eq!(node.object.origin, Origin::File);
                }
                Some(parent) => {
                    let parent = tree.get(parent).expect("the parent exists");
                    prop_assert_eq!(node.depth, parent.depth + 1);
                    prop_assert_ne!(node.object.origin, Origin::File);
                }
            }
        }
    }

    #[req("FR-09")]
    #[test]
    fn no_object_is_deeper_than_the_maximum(max_depth in 1u32..=64, steps in steps()) {
        let (tree, _) = build(max_depth, &steps);
        prop_assert!(tree.iter().all(|node| node.depth <= max_depth));
    }

    #[req("FR-09")]
    #[test]
    fn every_object_reaches_a_root_within_its_depth(max_depth in 1u32..=64, steps in steps()) {
        // No cycle: following parents from any object ends at a root in exactly `depth` steps.
        let (tree, _) = build(max_depth, &steps);
        for node in tree.iter() {
            let mut current = node;
            let mut hops = 0;
            while let Some(parent) = current.parent {
                current = tree.get(parent).expect("the parent exists");
                hops += 1;
                prop_assert!(hops <= node.depth);
            }
            prop_assert_eq!(hops, node.depth);
        }
    }
}
