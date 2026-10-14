//! FR-06 and CTR-01 through the worker host: the extraction worker reads the container on descriptor 3 and
//! streams its entries (ADR-18); a limit or a malformed container ends the stream with status `ERROR`, the
//! limit named or a finding saying why.

mod archives;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use archives::{EPOCH_1980, Member, Method, encrypted, gzip, tar, with_method, zip};
use ostia_contracts::v1::{
    AnalyzeRequest, AnalyzeResponse, ContractVersion, Entry, EntryKind, ExtractionBudget, Finding,
    Hint, Origin, Status,
};
use ostia_contracts::{DEFAULT_MAX_FRAME, encode_frame};
use ostia_sandbox::{EngineIdentity, EntrySink, ExtractRun, HostLimits, WorkerCommand, WorkerHost};
use ostia_traceability::req;

static OBJECTS: AtomicU32 = AtomicU32::new(0);

const OPEN: ExtractionBudget = ExtractionBudget {
    max_ratio: 1_000_000,
    remaining_bytes: 1 << 40,
    remaining_entries: 1 << 20,
    max_path_length: 4096,
};

fn worker() -> WorkerCommand {
    WorkerCommand::new(env!("CARGO_BIN_EXE_ostia-extract"), Vec::<String>::new())
}

fn identity() -> EngineIdentity {
    EngineIdentity {
        id: "ostia-extract".into(),
        version: "0.0.0".into(),
        content_version: "formats-1".into(),
    }
}

fn request(detected_type: &str, budget: Option<ExtractionBudget>) -> AnalyzeRequest {
    AnalyzeRequest {
        session_id: "session-1".into(),
        object_id: "object-1".into(),
        sha256: vec![0; 32],
        detected_type: detected_type.into(),
        size: 0,
        origin: Origin::File.into(),
        limits: None,
        extraction: budget,
        version: Some(ContractVersion { major: 1, minor: 2 }),
    }
}

/// A file holding the container, removed afterwards.
struct Object {
    path: PathBuf,
}

impl Object {
    fn new(bytes: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "ostia-extract-{}-{}",
            std::process::id(),
            OBJECTS.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, bytes).expect("object");
        Self { path }
    }
}

impl Drop for Object {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Every entry the host handed over, with its bytes, and whether it was ended.
#[derive(Default)]
struct Collect {
    entries: Vec<(Entry, Vec<u8>, bool)>,
}

impl EntrySink for Collect {
    fn entry(&mut self, entry: &Entry) -> std::io::Result<()> {
        self.entries.push((entry.clone(), Vec::new(), false));
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let last = self.entries.last_mut().expect("data after an entry");
        last.1.extend_from_slice(bytes);
        Ok(())
    }

    fn end(&mut self) -> std::io::Result<()> {
        self.entries.last_mut().expect("an entry").2 = true;
        Ok(())
    }
}

fn extract(
    detected_type: &str,
    bytes: &[u8],
    budget: ExtractionBudget,
) -> (ExtractRun, Vec<(Entry, Vec<u8>, bool)>) {
    let object = Object::new(bytes);
    let host = WorkerHost::unconfined(HostLimits::new(Duration::from_secs(30)));
    let mut sink = Collect::default();
    let run = host.extract(
        &worker(),
        &identity(),
        &request(detected_type, Some(budget)),
        &object.path,
        &mut sink,
    );
    (run, sink.entries)
}

fn entry(path: &[u8], kind: EntryKind, size: u64, modified: Option<i64>) -> Entry {
    Entry {
        path: path.to_vec(),
        kind: kind.into(),
        size,
        modified,
    }
}

fn answer(
    status: Status,
    limit: &str,
    findings: Vec<Finding>,
    run: &ExtractRun,
) -> AnalyzeResponse {
    AnalyzeResponse {
        engine_id: "ostia-extract".into(),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        content_version: "formats-1".into(),
        status: status.into(),
        hint: Hint::None.into(),
        score: None,
        findings,
        duration_ms: run.response.duration_ms,
        detected_type: String::new(),
        limit: limit.into(),
        version: Some(ContractVersion { major: 1, minor: 2 }),
    }
}

fn finding(id: &str, title: &str) -> Finding {
    Finding {
        id: id.into(),
        title: title.into(),
        severity: 2,
        evidence: String::new(),
        attack_ids: vec![],
    }
}

#[req("FR-06", "CTR-01")]
#[test]
fn zip_entries_are_streamed_through_the_host() {
    let archive = zip(&[
        ("a.txt", b"alpha", Method::Stored),
        ("dir/b.bin", &[7; 3000], Method::Deflated),
    ]);
    let (run, entries) = extract("zip", &archive, OPEN);
    assert_eq!(run.failure, None);
    assert_eq!(run.response, answer(Status::Ok, "", vec![], &run));
    assert_eq!(
        entries,
        vec![
            (
                entry(b"a.txt", EntryKind::Regular, 5, Some(EPOCH_1980)),
                b"alpha".to_vec(),
                true
            ),
            (
                entry(b"dir/b.bin", EntryKind::Regular, 3000, Some(EPOCH_1980)),
                vec![7; 3000],
                true
            ),
        ]
    );
}

#[req("FR-06")]
#[test]
fn tar_links_and_unnamed_gzip_entries_are_streamed() {
    let archive = tar(&[
        Member::file(b"a.txt", b"tar entry"),
        Member::bare(b"soft", b'2', b"a.txt"),
    ]);
    let (run, entries) = extract("tar", &archive, OPEN);
    assert_eq!(run.response.status, i32::from(Status::Ok));
    let kinds: Vec<_> = entries
        .iter()
        .map(|(e, _, _)| (e.path.clone(), e.kind))
        .collect();
    assert_eq!(
        kinds,
        vec![
            (b"a.txt".to_vec(), i32::from(EntryKind::Regular)),
            (b"soft".to_vec(), i32::from(EntryKind::Link)),
        ]
    );
    let (run, entries) = extract("gzip", &gzip(None, b"anonymous", 0), OPEN);
    assert_eq!(run.response.status, i32::from(Status::Ok));
    assert_eq!(
        entries,
        vec![(
            entry(b"", EntryKind::Regular, 9, None),
            b"anonymous".to_vec(),
            true
        )]
    );
}

#[req("FR-06")]
#[test]
fn a_limit_ends_the_stream_with_the_limit_named() {
    let bomb = zip(&[("zeros.bin", &vec![0; 16 << 20], Method::Deflated)]);
    let tight = ExtractionBudget {
        max_ratio: 100,
        ..OPEN
    };
    let (run, _) = extract("zip", &bomb, tight);
    assert_eq!(run.failure, None);
    assert_eq!(run.response, answer(Status::Error, "ratio", vec![], &run));
    let three = tar(&[
        Member::file(b"1", b"1"),
        Member::file(b"2", b"2"),
        Member::file(b"3", b"3"),
    ]);
    let few = ExtractionBudget {
        remaining_entries: 2,
        ..OPEN
    };
    let (run, entries) = extract("tar", &three, few);
    assert_eq!(run.failure, None);
    assert_eq!(
        run.response,
        answer(Status::Error, "entry_count", vec![], &run)
    );
    assert_eq!(entries.len(), 2);
    for (detected, archive, budget, limit) in [
        (
            "zip",
            zip(&[("abcdefgh", b"8", Method::Stored)]),
            ExtractionBudget {
                max_path_length: 7,
                ..OPEN
            },
            "path_length",
        ),
        (
            "zip",
            zip(&[
                ("a", &[1; 600], Method::Stored),
                ("b", &[2; 600], Method::Stored),
            ]),
            ExtractionBudget {
                remaining_bytes: 1000,
                ..OPEN
            },
            "total_size",
        ),
    ] {
        let (run, _) = extract(detected, &archive, budget);
        assert_eq!(run.response.limit, limit);
        assert_eq!(run.response.status, i32::from(Status::Error), "{limit}");
    }
}

#[req("FR-06")]
#[test]
fn a_malformed_container_ends_the_stream_with_a_finding() {
    let cases = [
        (
            "zip",
            encrypted(zip(&[("secret.bin", &[4; 2000], Method::Stored)])),
            finding("extract.encrypted", "encrypted entry"),
        ),
        (
            "zip",
            with_method(zip(&[("x", b"xxxx", Method::Stored)]), 12),
            finding(
                "extract.method",
                "entry compressed with an unsupported method",
            ),
        ),
        (
            "zip",
            zip(&[("../escape.txt", b"x", Method::Stored)]),
            finding("extract.path", "entry path leaving its container"),
        ),
        (
            "zip",
            archives::declaring(zip(&[("a", b"abc", Method::Deflated)]), 10),
            finding(
                "extract.size",
                "entry size does not match its declared size",
            ),
        ),
        (
            "tar",
            tar(&[Member::file(b"a", &[1; 2000])])[..1200].to_vec(),
            finding("extract.archive", "container cannot be read"),
        ),
    ];
    for (detected, archive, expected) in cases {
        let (run, _) = extract(detected, &archive, OPEN);
        assert_eq!(run.failure, None, "{}", expected.id);
        assert_eq!(
            run.response,
            answer(Status::Error, "", vec![expected.clone()], &run),
            "{}",
            expected.id
        );
    }
}

#[req("FR-06")]
#[test]
fn a_type_this_worker_does_not_extract_is_unsupported() {
    for detected in ["pdf", "7z", "unknown", "not-a-type"] {
        let (run, entries) = extract(detected, b"%PDF-1.4\n", OPEN);
        assert_eq!(run.failure, None, "{detected}");
        assert_eq!(
            run.response,
            answer(Status::Unsupported, "", vec![], &run),
            "{detected}"
        );
        assert_eq!(entries, vec![], "{detected}");
    }
}

/// Runs the worker directly with `input` on standard input; returns its exit code and standard output.
fn direct(input: &[u8]) -> (Option<i32>, Vec<u8>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ostia-extract"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("worker");
    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input).expect("request");
    drop(stdin);
    let output = child.wait_with_output().expect("exit");
    (output.status.code(), output.stdout)
}

#[req("FR-06", "CTR-02")]
#[test]
fn a_bad_request_gets_exit_2_and_no_output() {
    assert_eq!(direct(b"\x00\x00\x00\x03abc"), (Some(2), vec![]));
    // A valid request without a budget: the worker never guesses one.
    let unbudgeted = encode_frame(&request("zip", None), DEFAULT_MAX_FRAME).expect("frame");
    assert_eq!(direct(&unbudgeted), (Some(2), vec![]));
}
