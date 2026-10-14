//! FR-06 through the orchestrator's tree driver (Q-59) and the real workers: every object of a file's tree is
//! typed, every container extracted, the entries copied into the workspace as new objects; the policy's limits
//! hold over the whole tree, and a container that breaks one, or cannot be extracted, keeps no entry.
//!
//! The driver lives in `ostia-orchestrator`, which never links this crate (SEC-05); its tests live here, where
//! the worker binaries are built.

mod archives;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use archives::{EPOCH_1980, Member, Method, declaring, encrypted, gzip, tar, with_method, zip};
use ostia_contracts::v1::extract_frame::Frame;
use ostia_contracts::v1::{
    AnalyzeResponse, ContractVersion, Entry, EntryKind, ExtractFrame, Hint, Status,
};
use ostia_contracts::{DEFAULT_MAX_FRAME, encode_frame};
use ostia_core_domain::object::Kind;
use ostia_core_domain::policy::{Failure, Limits};
use ostia_core_domain::types::DetectedType;
use ostia_core_domain::verdict::Limit;
use ostia_media::inventory::Workspace;
use ostia_orchestrator::extraction::{Analysis, Extracted, Root, Tree, Worker, Workers, expand};
use ostia_sandbox::{EngineIdentity, HostLimits, WorkerCommand, WorkerHost};
use ostia_traceability::req;

static DIRS: AtomicU32 = AtomicU32::new(0);

const ONE: &[u8] = b"level one\n";
const TWO: &[u8] = b"level two\n";
const THREE: &[u8] = b"level three\n";

/// The policy defaults (policy.md "Limits").
const DEFAULTS: Limits = Limits {
    max_depth: 8,
    max_ratio: 200,
    max_total_bytes: 4_294_967_296,
    max_entries: 100_000,
    max_path_length: 4096,
    engine_timeout_seconds: 30,
};

const MIB: usize = 1024 * 1024;

/// The tight limits of the locked acceptance tests.
const TIGHT: Limits = Limits {
    max_entries: 20,
    max_total_bytes: 1_048_576,
    max_ratio: 100,
    max_path_length: 64,
    ..DEFAULTS
};

/// A directory of its own: the root file and the workspace.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ostia-tree-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        Self { dir }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let copies = self.dir.join("workspace");
        if let Ok(entries) = std::fs::read_dir(&copies) {
            for entry in entries.flatten() {
                let _ = std::fs::set_permissions(
                    entry.path(),
                    std::os::unix::fs::PermissionsExt::from_mode(0o600),
                );
            }
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn worker(program: &str, id: &str, content_version: &str) -> Worker {
    Worker {
        command: WorkerCommand::new(program, Vec::<String>::new()),
        identity: EngineIdentity {
            id: id.into(),
            version: "0.0.0".into(),
            content_version: content_version.into(),
        },
    }
}

/// The tree of a medium file named `name` holding `bytes`, under `limits`.
fn grow(name: &str, bytes: &[u8], limits: &Limits) -> (Tree, Scratch) {
    let extract = worker(
        env!("CARGO_BIN_EXE_ostia-extract"),
        "ostia-extract",
        "formats-1",
    );
    grow_with(name, bytes, limits, &extract, Scratch::new())
}

/// The tree of a zip root whose extraction worker is a script sending `frames` whatever it gets.
fn grow_faked(frames: &[ExtractFrame], limits: &Limits) -> Tree {
    let scratch = Scratch::new();
    let mut output = Vec::new();
    for frame in frames {
        output.extend(encode_frame(frame, DEFAULT_MAX_FRAME).expect("frame"));
    }
    let out = scratch.dir.join("out.bin");
    std::fs::write(&out, output).expect("frames");
    let script = scratch.dir.join("extract.sh");
    std::fs::write(
        &script,
        format!("cat > /dev/null; cat '{}'\n", out.display()),
    )
    .expect("script");
    let fake = Worker {
        command: WorkerCommand::new("/bin/sh", [script]),
        identity: EngineIdentity {
            id: "ostia-extract".into(),
            version: "0.0.0".into(),
            content_version: "formats-1".into(),
        },
    };
    let root = stored(&[("a.txt", b"a")]);
    grow_with("fake.zip", &root, limits, &fake, scratch).0
}

fn grow_with(
    name: &str,
    bytes: &[u8],
    limits: &Limits,
    extract: &Worker,
    scratch: Scratch,
) -> (Tree, Scratch) {
    let file = scratch.dir.join("root");
    std::fs::write(&file, bytes).expect("root");
    let mut workspace = Workspace::create(&scratch.dir.join("workspace")).expect("workspace");
    let host = WorkerHost::unconfined(HostLimits::new(Duration::from_secs(30)));
    let triage = worker(
        env!("CARGO_BIN_EXE_ostia-triage"),
        "ostia-triage",
        "magic-1",
    );
    let workers = Workers {
        host: &host,
        triage: &triage,
        extract,
    };
    let root = Root {
        copy: &file,
        name: name.as_bytes(),
        size: bytes.len() as u64,
        sha256: [0; 32],
    };
    let tree = expand(&workers, limits, &mut workspace, "session-1", &root);
    (tree, scratch)
}

fn typed(detected: DetectedType) -> Analysis {
    Analysis {
        detected: Some(detected),
        failure: None,
    }
}

fn failed(detected: DetectedType, failure: Failure) -> Analysis {
    Analysis {
        detected: Some(detected),
        failure: Some(failure),
    }
}

/// (parent, depth, path, kind, analysis) of each extracted object.
fn shape(tree: &Tree) -> Vec<(Option<usize>, u32, String, Kind, Analysis)> {
    tree.extracted
        .iter()
        .map(|e| {
            (
                e.parent,
                e.depth,
                String::from_utf8_lossy(&e.path).into_owned(),
                e.kind,
                e.analysis.clone(),
            )
        })
        .collect()
}

fn named<'a>(tree: &'a Tree, path: &str) -> &'a Extracted {
    tree.extracted
        .iter()
        .find(|e| e.path == path.as_bytes())
        .unwrap_or_else(|| panic!("no {path} in {:?}", shape(tree)))
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

fn nested() -> Vec<u8> {
    let core = tar(&[Member::file(b"three.txt", THREE)]);
    let inner = zip(&[
        ("two.txt", TWO, Method::Deflated),
        ("core.tar", &core, Method::Stored),
    ]);
    zip(&[
        ("one.txt", ONE, Method::Deflated),
        ("inner.zip", &inner, Method::Stored),
    ])
}

#[req("FR-06")]
#[test]
fn nested_archives_within_limits_are_fully_listed() {
    let (tree, _scratch) = grow("nested.zip", &nested(), &DEFAULTS);
    assert_eq!(tree.root, typed(DetectedType::Zip));
    let unknown = typed(DetectedType::Unknown);
    assert_eq!(
        shape(&tree),
        vec![
            (None, 1, "one.txt".into(), Kind::File, unknown.clone()),
            (
                None,
                1,
                "inner.zip".into(),
                Kind::File,
                typed(DetectedType::Zip)
            ),
            (Some(1), 2, "two.txt".into(), Kind::File, unknown.clone()),
            (
                Some(1),
                2,
                "core.tar".into(),
                Kind::File,
                typed(DetectedType::Tar)
            ),
            (Some(3), 3, "three.txt".into(), Kind::File, unknown),
        ]
    );
    for (path, content, sha256, sha1) in [
        (
            "one.txt",
            ONE,
            "62e1631ef3faf6dfd977a86251e4f3db7da7236f890efb92f5089fca41fe6f8b",
            "36ff6d34265feb10076f8181c25c3aeb93d86a89",
        ),
        (
            "two.txt",
            TWO,
            "ca8071aaabbacf06be64998b541131f27676669a8721c33f3461fdef1f9c6c1d",
            "27bb6e19fcf81114413845370a0c1a190dbca75d",
        ),
        (
            "three.txt",
            THREE,
            "8f01447581b6435fbeb16550f2616926ec7659d76c7a8e008587be167a6519ea",
            "d8324b67e904d05fc7bbcb0579986fcf0cae60ac",
        ),
    ] {
        let copied = named(&tree, path).content.as_ref().expect("a copy");
        assert_eq!(copied.size, content.len() as u64, "{path}");
        assert_eq!(copied.sha256.to_vec(), hex(sha256), "{path}");
        assert_eq!(copied.sha1.to_vec(), hex(sha1), "{path}");
        assert_eq!(
            std::fs::read(&copied.copy).expect("copy"),
            content,
            "{path}"
        );
    }
    assert_eq!(named(&tree, "one.txt").modified, Some(EPOCH_1980));
    assert_eq!(named(&tree, "three.txt").modified, Some(1_709_210_096));
}

/// l0.zip holds l1.zip ... holds l<levels-1>.zip, which holds leaf.txt.
fn nest(levels: usize) -> Vec<u8> {
    let mut archive = zip(&[("leaf.txt", b"leaf\n", Method::Deflated)]);
    for level in (1..levels).rev() {
        let name = format!("l{level}.zip");
        archive = zip(&[(name.as_str(), &archive, Method::Stored)]);
    }
    archive
}

#[req("FR-06")]
#[test]
fn a_container_whose_entries_would_be_too_deep_is_not_extracted() {
    let limits = Limits {
        max_depth: 3,
        ..DEFAULTS
    };
    let (tree, _scratch) = grow("l0.zip", &nest(5), &limits);
    assert_eq!(tree.root, typed(DetectedType::Zip));
    assert_eq!(
        shape(&tree),
        vec![
            (
                None,
                1,
                "l1.zip".into(),
                Kind::File,
                typed(DetectedType::Zip)
            ),
            (
                Some(0),
                2,
                "l2.zip".into(),
                Kind::File,
                typed(DetectedType::Zip)
            ),
            (
                Some(1),
                3,
                "l3.zip".into(),
                Kind::File,
                failed(DetectedType::Zip, Failure::Limit(Limit::Depth))
            ),
        ]
    );
}

#[req("FR-06")]
#[test]
fn a_container_breaking_a_limit_keeps_no_entry() {
    let zeros = vec![0_u8; 16 * MIB];
    let dense = Limits {
        max_ratio: 100,
        max_total_bytes: 1 << 30,
        ..DEFAULTS
    };
    let many: Vec<(String, &[u8], Method)> = (0..30)
        .map(|i| (format!("f{i:02}.txt"), b"x".as_slice(), Method::Stored))
        .collect();
    let many: Vec<(&str, &[u8], Method)> =
        many.iter().map(|(n, c, m)| (n.as_str(), *c, *m)).collect();
    let parts: Vec<Vec<u8>> = (0..3_u8).map(|i| vec![i + 1; 512 * 1024]).collect();
    let cases = [
        (
            "bomb.zip",
            zip(&[("zeros.bin", &zeros, Method::Deflated)]),
            dense,
            DetectedType::Zip,
            Limit::Ratio,
        ),
        (
            "zeros.gz",
            gzip(Some(b"zeros.bin"), &zeros, 0),
            dense,
            DetectedType::Gzip,
            Limit::Ratio,
        ),
        (
            "big.zip",
            zip(&[
                ("part0.bin", &parts[0], Method::Stored),
                ("part1.bin", &parts[1], Method::Stored),
                ("part2.bin", &parts[2], Method::Stored),
            ]),
            TIGHT,
            DetectedType::Zip,
            Limit::TotalSize,
        ),
        (
            "many.zip",
            zip(&many),
            TIGHT,
            DetectedType::Zip,
            Limit::EntryCount,
        ),
        (
            "long-name.zip",
            zip(&[(
                format!("d/{}.txt", "n".repeat(100)).as_str(),
                b"long name\n",
                Method::Deflated,
            )]),
            TIGHT,
            DetectedType::Zip,
            Limit::PathLength,
        ),
    ];
    for (name, archive, limits, detected, limit) in cases {
        let (tree, _scratch) = grow(name, &archive, &limits);
        assert_eq!(tree.root, failed(detected, Failure::Limit(limit)), "{name}");
        assert_eq!(tree.extracted, vec![], "{name}");
    }
}

fn stored(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let entries: Vec<_> = entries
        .iter()
        .map(|(n, c)| (*n, *c, Method::Stored))
        .collect();
    zip(&entries)
}

#[req("FR-06")]
#[test]
fn limits_count_the_whole_tree() {
    // 2 + 15 + 15 entries: each archive is under 20, the tree is not; the second inner archive breaches it.
    let fifteen: Vec<(String, Vec<u8>)> = (0..15)
        .map(|i| (format!("f{i:02}.txt"), b"x".to_vec()))
        .collect();
    let fifteen: Vec<(&str, &[u8])> = fifteen
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();
    let inner = stored(&fifteen);
    let (tree, _scratch) = grow(
        "deep-count.zip",
        &stored(&[("in1.zip", &inner), ("in2.zip", &inner)]),
        &TIGHT,
    );
    assert_eq!(tree.root, typed(DetectedType::Zip));
    assert_eq!(named(&tree, "in1.zip").analysis, typed(DetectedType::Zip));
    assert_eq!(
        named(&tree, "in2.zip").analysis,
        failed(DetectedType::Zip, Failure::Limit(Limit::EntryCount))
    );
    // in2.zip keeps no entry: 2 + 15 objects.
    assert_eq!(tree.extracted.len(), 17);
    // 800 KiB at the first level, 800 KiB more at the second: over 1 MiB only in total.
    let in1 = stored(&[("part.bin", &vec![1; 400 * 1024])]);
    let in2 = stored(&[("part.bin", &vec![2; 400 * 1024])]);
    let (tree, _scratch) = grow(
        "deep-size.zip",
        &stored(&[("in1.zip", &in1), ("in2.zip", &in2)]),
        &TIGHT,
    );
    assert_eq!(tree.root, typed(DetectedType::Zip));
    for inner in ["in1.zip", "in2.zip"] {
        assert_eq!(
            named(&tree, inner).analysis,
            failed(DetectedType::Zip, Failure::Limit(Limit::TotalSize)),
            "{inner}"
        );
    }
    assert_eq!(tree.extracted.len(), 2);
}

#[req("FR-06")]
#[test]
fn archives_at_the_limits_are_extracted() {
    let twenty: Vec<(String, Vec<u8>)> = (0..20)
        .map(|i| (format!("f{i:02}.txt"), b"x".to_vec()))
        .collect();
    let twenty: Vec<(&str, &[u8])> = twenty
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();
    // About 50:1 once deflated: a kibibyte that does not compress (xorshift), then zeros.
    let mut state: u32 = 0x9e37_79b9;
    let mut dense: Vec<u8> = (0..1024)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect();
    dense.extend(vec![0; 54_000]);
    for (name, archive, count) in [
        ("twenty.zip", stored(&twenty), 20),
        ("exact.zip", stored(&[("mib.bin", &vec![7; MIB])]), 1),
        (
            "dense-but-allowed.zip",
            zip(&[("mixed.bin", &dense, Method::Deflated)]),
            1,
        ),
    ] {
        let (tree, _scratch) = grow(name, &archive, &TIGHT);
        assert_eq!(tree.root, typed(DetectedType::Zip), "{name}");
        assert_eq!(tree.extracted.len(), count, "{name}");
        assert!(
            tree.extracted.iter().all(|e| e.analysis.failure.is_none()),
            "{name}"
        );
    }
}

#[req("FR-06")]
#[test]
fn a_container_that_cannot_be_extracted_keeps_no_entry() {
    let valid = stored(&[("x.bin", &[3; 5000])]);
    let cases = [
        (
            "truncated.zip",
            valid[..valid.len() * 6 / 10].to_vec(),
            DetectedType::Zip,
        ),
        (
            "encrypted.zip",
            encrypted(stored(&[("secret.bin", &[4; 2000])])),
            DetectedType::Zip,
        ),
        (
            "slip-parent.zip",
            zip(&[("../escape.txt", b"outside\n", Method::Deflated)]),
            DetectedType::Zip,
        ),
        (
            "bzip2.zip",
            with_method(stored(&[("x", b"xxxx")]), 12),
            DetectedType::Zip,
        ),
        (
            "lying-sizes.zip",
            declaring(
                zip(&[("zeros.bin", &vec![0; 100_000], Method::Deflated)]),
                1000,
            ),
            DetectedType::Zip,
        ),
        // A 7z container: not extracted before WP-1.9, so its content cannot be scanned.
        (
            "bundle.7z",
            b"7z\xbc\xaf\x27\x1c\x00\x04".to_vec(),
            DetectedType::SevenZip,
        ),
    ];
    for (name, archive, detected) in cases {
        let (tree, _scratch) = grow(name, &archive, &DEFAULTS);
        assert_eq!(tree.root, failed(detected, Failure::Malformed), "{name}");
        assert_eq!(tree.extracted, vec![], "{name}");
    }
}

#[req("FR-06")]
#[test]
fn a_gzip_member_is_named_by_its_header_or_after_its_container() {
    let (tree, _scratch) = grow("letter.gz", &gzip(Some(b"letter.txt"), ONE, 0), &DEFAULTS);
    assert_eq!(
        shape(&tree),
        vec![(
            None,
            1,
            "letter.txt".into(),
            Kind::File,
            typed(DetectedType::Unknown)
        )]
    );
    // No name in the header: the container's name without its last extension, then typed and extracted.
    let saved = tar(&[Member::file(b"saved.txt", b"saved\n")]);
    let (tree, _scratch) = grow("backup.tar.gz", &gzip(None, &saved, 0), &DEFAULTS);
    assert_eq!(tree.root, typed(DetectedType::Gzip));
    assert_eq!(
        shape(&tree),
        vec![
            (
                None,
                1,
                "backup.tar".into(),
                Kind::File,
                typed(DetectedType::Tar)
            ),
            (
                Some(0),
                2,
                "saved.txt".into(),
                Kind::File,
                typed(DetectedType::Unknown)
            ),
        ]
    );
    let copied = named(&tree, "saved.txt").content.as_ref().expect("a copy");
    assert_eq!(
        copied.sha256.to_vec(),
        hex("2f0bc36d997d0234300e13257d8aaa4444ff4b6b24b4b56293da3bcdd5d9eb63")
    );
}

#[req("FR-06")]
#[test]
fn links_and_special_entries_are_objects_never_read() {
    let archive = tar(&[
        Member::file(b"a.txt", b"tar entry\n"),
        Member::bare(b"soft", b'2', b"a.txt"),
        Member::bare(b"fifo", b'6', b""),
    ]);
    let (tree, _scratch) = grow("plain.tar", &archive, &DEFAULTS);
    let nothing = Analysis {
        detected: None,
        failure: None,
    };
    assert_eq!(
        shape(&tree),
        vec![
            (
                None,
                1,
                "a.txt".into(),
                Kind::File,
                typed(DetectedType::Unknown)
            ),
            (None, 1, "soft".into(), Kind::Symlink, nothing.clone()),
            (None, 1, "fifo".into(), Kind::Special, nothing),
        ]
    );
    assert_eq!(named(&tree, "soft").content, None);
    assert_eq!(named(&tree, "fifo").content, None);
}

#[req("FR-06", "FR-05")]
#[test]
fn an_entry_that_cannot_be_typed_is_a_failure() {
    // A tar whose first member is named %PDF-: two type rules match (Q-55).
    let mut polyglot = tar(&[Member::file(b"%PDF-1.4", b"x")]);
    polyglot.truncate(2048);
    let (tree, _scratch) = grow("box.zip", &stored(&[("odd.bin", &polyglot)]), &DEFAULTS);
    assert_eq!(tree.root, typed(DetectedType::Zip));
    assert_eq!(
        named(&tree, "odd.bin").analysis,
        Analysis {
            detected: None,
            failure: Some(Failure::Malformed),
        }
    );
}

#[req("FR-06")]
#[test]
fn entries_a_failed_container_streamed_still_count() {
    // bad.zip streams 12 entries, then refuses `../x`; they are not kept, but they count: with the root's 2,
    // 14 of the 20 entries are used, and good.zip's 8 breach the limit. Without counting them, 10 would fit.
    let twelve: Vec<(String, Vec<u8>)> = (0..12)
        .map(|i| (format!("f{i:02}.txt"), b"x".to_vec()))
        .collect();
    let mut bad: Vec<(&str, &[u8])> = twelve
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();
    bad.push(("../x", b"x"));
    let eight: Vec<(String, Vec<u8>)> = (0..8)
        .map(|i| (format!("g{i}.txt"), b"y".to_vec()))
        .collect();
    let good: Vec<(&str, &[u8])> = eight
        .iter()
        .map(|(n, c)| (n.as_str(), c.as_slice()))
        .collect();
    let root = stored(&[("bad.zip", &stored(&bad)), ("good.zip", &stored(&good))]);
    let (tree, _scratch) = grow("pair.zip", &root, &TIGHT);
    assert_eq!(
        named(&tree, "bad.zip").analysis,
        failed(DetectedType::Zip, Failure::Malformed)
    );
    assert_eq!(
        named(&tree, "good.zip").analysis,
        failed(DetectedType::Zip, Failure::Limit(Limit::EntryCount))
    );
    assert_eq!(tree.extracted.len(), 2);
}

const MINOR_2: Option<ContractVersion> = Some(ContractVersion { major: 1, minor: 2 });

fn link(path: &[u8]) -> ExtractFrame {
    ExtractFrame {
        frame: Some(Frame::Entry(Entry {
            path: path.to_vec(),
            kind: EntryKind::Link.into(),
            size: 0,
            modified: None,
        })),
        version: MINOR_2,
    }
}

fn done(status: Status, limit: &str) -> ExtractFrame {
    ExtractFrame {
        frame: Some(Frame::Done(AnalyzeResponse {
            engine_id: "ostia-extract".into(),
            engine_version: "0.0.0".into(),
            content_version: "formats-1".into(),
            status: status.into(),
            hint: Hint::None.into(),
            score: None,
            findings: vec![],
            duration_ms: 1,
            detected_type: String::new(),
            limit: limit.into(),
            version: MINOR_2,
        })),
        version: MINOR_2,
    }
}

#[req("FR-06")]
#[test]
fn a_lying_extraction_worker_is_held_to_the_trees_limits() {
    // 21 entries against 20: the host stops it, the driver names the limit.
    let mut many: Vec<ExtractFrame> = (0..21).map(|i| link(format!("l{i}").as_bytes())).collect();
    many.push(done(Status::Ok, ""));
    assert_eq!(
        grow_faked(&many, &TIGHT).root,
        failed(DetectedType::Zip, Failure::Limit(Limit::EntryCount))
    );
    // 2 MiB announced and sent against 1 MiB.
    let chunk = ExtractFrame {
        frame: Some(Frame::Data(vec![0x41; 64 * 1024])),
        version: MINOR_2,
    };
    let mut big = vec![ExtractFrame {
        frame: Some(Frame::Entry(Entry {
            path: b"big.bin".to_vec(),
            kind: EntryKind::Regular.into(),
            size: 2 * 1024 * 1024,
            modified: None,
        })),
        version: MINOR_2,
    }];
    big.extend((0..32).map(|_| chunk.clone()));
    big.push(done(Status::Ok, ""));
    assert_eq!(
        grow_faked(&big, &TIGHT).root,
        failed(DetectedType::Zip, Failure::Limit(Limit::TotalSize))
    );
}

#[req("FR-06")]
#[test]
fn a_worker_answer_that_names_no_known_limit_is_malformed() {
    for (status, limit) in [
        (Status::Error, "depth"),
        (Status::Error, "bogus"),
        (Status::Error, ""),
        // An answer that contradicts itself.
        (Status::Ok, "ratio"),
        (Status::Unsupported, ""),
    ] {
        assert_eq!(
            grow_faked(&[done(status, limit)], &TIGHT).root,
            failed(DetectedType::Zip, Failure::Malformed),
            "{status:?} {limit}"
        );
    }
}

#[req("FR-06")]
#[test]
fn the_driver_checks_the_paths_a_worker_sends() {
    // A worker the host trusts for its frames, not for its paths (Q-61 rules, max_path_length).
    for path in [b"../x".as_slice(), b"C:\\x", b"CON", b"a\0b"] {
        assert_eq!(
            grow_faked(&[link(path), done(Status::Ok, "")], &TIGHT).root,
            failed(DetectedType::Zip, Failure::Malformed),
            "{}",
            String::from_utf8_lossy(path)
        );
    }
    let long = vec![b'n'; 65];
    assert_eq!(
        grow_faked(&[link(&long), done(Status::Ok, "")], &TIGHT).root,
        failed(DetectedType::Zip, Failure::Limit(Limit::PathLength))
    );
}
