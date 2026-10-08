//! Object tree invariants: roots are files of the medium at depth 0, every other object sits below an
//! existing parent at its depth + 1, no deeper than the policy's `max_depth`, and the tree has no cycle.

use ostia_core_domain::object::{Kind, NewObject, ObjectId, ObjectTree, Origin, TreeError};
use ostia_traceability::req;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

fn fixed_seed() -> Config {
    Config {
        rng_seed: RngSeed::Fixed(0x07_2e_e0_11),
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

#[req("FR-04")]
#[test]
fn file_of_the_medium_is_a_root_at_depth_0() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let id = tree.insert_file(file("docs/report.pdf")).expect("root");
    let node = tree.get(id).expect("inserted");
    assert_eq!((node.parent, node.depth), (None, 0));
    assert_eq!(node.object, file("docs/report.pdf"));
}

#[req("FR-04", "FR-06")]
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

#[req("FR-04")]
#[test]
fn identifiers_are_unique_in_insertion_order() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let a = tree.insert_file(file("a.txt")).expect("root");
    let b = tree.insert_file(file("b.txt")).expect("root");
    let c = tree.insert_child(a, entry("c.txt")).expect("child");
    assert_eq!([a.index(), b.index(), c.index()], [0, 1, 2]);
    assert_eq!(tree.iter().map(|n| n.id).collect::<Vec<_>>(), [a, b, c]);
}

#[req("FR-04")]
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

#[req("FR-06")]
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
    assert_eq!(tree.iter().map(|n| n.depth).max(), Some(3));
}

#[req("FR-06")]
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

#[req("FR-04")]
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

#[req("FR-04")]
#[test]
fn file_of_the_medium_never_has_a_parent() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let archive = tree.insert_file(file("bundle.zip")).expect("root");
    assert_eq!(
        tree.insert_child(archive, file("a.txt")),
        Err(TreeError::FileWithParent)
    );
}

/// One step of a random tree: a new root, or a child of the n-th existing object.
#[derive(Debug, Clone)]
enum Step {
    Root,
    Child(usize, Origin),
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let origin = prop::sample::select(vec![Origin::Extracted, Origin::AltStream, Origin::Xattr]);
    let step = prop_oneof![
        1 => Just(Step::Root),
        4 => (0usize..64, origin).prop_map(|(n, o)| Step::Child(n, o)),
    ];
    prop::collection::vec(step, 1..64)
}

fn build(max_depth: u32, steps: &[Step]) -> ObjectTree {
    let mut tree = ObjectTree::new(max_depth).expect("valid max depth");
    let mut ids: Vec<ObjectId> = Vec::new();
    for (i, step) in steps.iter().enumerate() {
        let inserted = match step {
            Step::Child(n, origin) if !ids.is_empty() => {
                tree.insert_child(ids[n % ids.len()], object(*origin, &format!("e{i}")))
            }
            // A child step before any object exists starts a new root.
            Step::Root | Step::Child(..) => tree.insert_file(file(&format!("f{i}"))),
        };
        if let Ok(id) = inserted {
            ids.push(id);
        }
    }
    tree
}

proptest! {
    #![proptest_config(fixed_seed())]

    #[req("FR-04", "FR-06")]
    #[test]
    fn every_object_is_at_its_parent_depth_plus_one(max_depth in 1u32..6, steps in steps()) {
        let tree = build(max_depth, &steps);
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

    #[req("FR-06")]
    #[test]
    fn no_object_is_deeper_than_the_maximum(max_depth in 1u32..6, steps in steps()) {
        let tree = build(max_depth, &steps);
        prop_assert!(tree.iter().all(|node| node.depth <= max_depth));
    }

    #[req("FR-04")]
    #[test]
    fn every_object_reaches_a_root_within_its_depth(max_depth in 1u32..6, steps in steps()) {
        // No cycle: following parents from any object ends at a root in exactly `depth` steps.
        let tree = build(max_depth, &steps);
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

#[req("FR-04")]
#[test]
fn symbolic_link_keeps_no_hashes() {
    let mut tree = ObjectTree::new(8).expect("valid max depth");
    let link = NewObject {
        origin: Origin::File,
        kind: Kind::Symlink,
        path: "escape".to_owned(),
        stream: None,
        size: 0,
        sha256: None,
        sha1: None,
    };
    let id = tree.insert_file(link.clone()).expect("root");
    assert_eq!(tree.get(id).map(|n| &n.object), Some(&link));
}
