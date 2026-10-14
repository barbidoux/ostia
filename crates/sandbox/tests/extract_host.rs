//! FR-06 and NFR-05 through the worker host's extraction run (ADR-18): the worker streams `ExtractFrame`s, the
//! host hands each entry and its bytes to the sink as they arrive and holds the stream to the declared sizes and
//! to the request's budget itself; a worker that breaks the protocol, overruns the budget, crashes or hangs gets
//! a synthesised result, and the host keeps serving.
//!
//! Workers are small `/bin/sh` scripts that `cat` frames prepared with the contract encoder.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ostia_contracts::v1::extract_frame::Frame;
use ostia_contracts::v1::{
    AnalyzeRequest, AnalyzeResponse, ContractVersion, Entry, EntryKind, ExtractFrame,
    ExtractionBudget, Hint, Origin, Status,
};
use ostia_contracts::{ContractError, DEFAULT_MAX_FRAME, encode_frame};
use ostia_sandbox::{
    EngineIdentity, EntrySink, ExtractRun, Failure, HostLimits, StreamFault, WorkerCommand,
    WorkerHost,
};
use ostia_traceability::req;

const GENEROUS: Duration = Duration::from_secs(30);
const SHORT: Duration = Duration::from_secs(1);
const VERSION: Option<ContractVersion> = Some(ContractVersion { major: 1, minor: 2 });

static DIRS: AtomicU32 = AtomicU32::new(0);

/// A directory of its own for one test: the object, the worker script and its prepared output.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ostia-extract-host-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        std::fs::write(dir.join("object"), b"container").expect("object");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// `/bin/sh` running `body`; `$D` is this directory, `$OUT` the prepared frames.
    fn worker(&self, body: &str) -> WorkerCommand {
        let script = self.path("worker.sh");
        let text = format!(
            "D='{dir}'\nOUT='{dir}/out.bin'\n{body}\n",
            dir = self.dir.display()
        );
        std::fs::write(&script, text).expect("worker script");
        WorkerCommand::new("/bin/sh", [script])
    }

    /// Prepares `frames` (then `tail`, raw bytes) for `cat "$OUT"`.
    fn output(&self, frames: &[ExtractFrame], tail: &[u8]) {
        let mut bytes = Vec::new();
        for frame in frames {
            bytes.extend(encode_frame(frame, DEFAULT_MAX_FRAME).expect("frame"));
        }
        bytes.extend_from_slice(tail);
        std::fs::write(self.path("out.bin"), bytes).expect("output");
    }

    fn exists(&self, name: &str) -> bool {
        self.path(name).exists()
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn identity() -> EngineIdentity {
    EngineIdentity {
        id: "ostia-extract".into(),
        version: "0.0.0".into(),
        content_version: "formats-1".into(),
    }
}

fn request(entries: u64, bytes: u64) -> AnalyzeRequest {
    AnalyzeRequest {
        session_id: "session-1".into(),
        object_id: "object-3".into(),
        sha256: vec![0x11; 32],
        detected_type: "zip".into(),
        size: 9,
        origin: Origin::File.into(),
        limits: None,
        extraction: Some(ExtractionBudget {
            max_ratio: 200,
            remaining_bytes: bytes,
            remaining_entries: entries,
            max_path_length: 4096,
        }),
        version: VERSION,
    }
}

fn frame(frame: Frame) -> ExtractFrame {
    ExtractFrame {
        frame: Some(frame),
        version: VERSION,
    }
}

fn entry(path: &[u8], kind: EntryKind, size: u64) -> ExtractFrame {
    frame(Frame::Entry(Entry {
        path: path.to_vec(),
        kind: kind.into(),
        size,
        modified: Some(315_532_800),
    }))
}

fn data(bytes: &[u8]) -> ExtractFrame {
    frame(Frame::Data(bytes.to_vec()))
}

fn finished() -> AnalyzeResponse {
    AnalyzeResponse {
        engine_id: "ostia-extract".into(),
        engine_version: "0.0.0".into(),
        content_version: "formats-1".into(),
        status: Status::Ok.into(),
        hint: Hint::None.into(),
        score: None,
        findings: vec![],
        duration_ms: 4,
        detected_type: String::new(),
        limit: String::new(),
        version: VERSION,
    }
}

fn done(response: AnalyzeResponse) -> ExtractFrame {
    frame(Frame::Done(response))
}

/// What the sink was told, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Entry(Vec<u8>, u64),
    Data(Vec<u8>),
    End,
}

#[derive(Default)]
struct Record {
    calls: Vec<Call>,
    refuse_entries: bool,
}

impl EntrySink for Record {
    fn entry(&mut self, entry: &Entry) -> std::io::Result<()> {
        if self.refuse_entries {
            return Err(std::io::Error::other("workspace full"));
        }
        self.calls.push(Call::Entry(entry.path.clone(), entry.size));
        Ok(())
    }

    fn data(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.calls.push(Call::Data(bytes.to_vec()));
        Ok(())
    }

    fn end(&mut self) -> std::io::Result<()> {
        self.calls.push(Call::End);
        Ok(())
    }
}

fn extract_with(
    scratch: &Scratch,
    body: &str,
    request: &AnalyzeRequest,
    timeout: Duration,
    sink: &mut Record,
) -> ExtractRun {
    let host = WorkerHost::unconfined(HostLimits::new(timeout));
    host.extract(
        &scratch.worker(body),
        &identity(),
        request,
        &scratch.path("object"),
        sink,
    )
}

/// Runs a worker that sends `frames` then `tail` and exits 0, under a budget of 10 entries and 1000 bytes.
fn stream(frames: &[ExtractFrame], tail: &[u8]) -> (ExtractRun, Vec<Call>) {
    let scratch = Scratch::new();
    scratch.output(frames, tail);
    let mut sink = Record::default();
    let run = extract_with(
        &scratch,
        r#"cat > /dev/null; cat "$OUT""#,
        &request(10, 1000),
        GENEROUS,
        &mut sink,
    );
    (run, sink.calls)
}

fn assert_synthesised(run: &ExtractRun, status: Status, failure: &Failure) {
    assert_eq!(run.failure.as_ref(), Some(failure));
    assert_eq!(run.response.status, i32::from(status));
    assert_eq!(run.response.engine_id, "ostia-extract");
    assert_eq!(run.response.hint, i32::from(Hint::None));
    assert_eq!(run.response.findings, vec![]);
}

#[req("FR-06", "CTR-01")]
#[test]
fn entries_and_their_bytes_reach_the_sink_in_order() {
    let (run, calls) = stream(
        &[
            entry(b"a.txt", EntryKind::Regular, 3),
            data(b"abc"),
            entry(b"link", EntryKind::Link, 0),
            entry(b"dir/b.bin", EntryKind::Regular, 5),
            data(b"he"),
            data(b"llo"),
            entry(b"empty", EntryKind::Regular, 0),
            done(finished()),
        ],
        b"",
    );
    assert_eq!(run.failure, None);
    assert_eq!(run.response, finished());
    assert_eq!(
        calls,
        vec![
            Call::Entry(b"a.txt".to_vec(), 3),
            Call::Data(b"abc".to_vec()),
            Call::End,
            Call::Entry(b"link".to_vec(), 0),
            Call::End,
            Call::Entry(b"dir/b.bin".to_vec(), 5),
            Call::Data(b"he".to_vec()),
            Call::Data(b"llo".to_vec()),
            Call::End,
            Call::Entry(b"empty".to_vec(), 0),
            Call::End,
        ]
    );
}

#[req("FR-06")]
#[test]
fn the_workers_limit_answer_is_kept() {
    let stopped = AnalyzeResponse {
        status: Status::Error.into(),
        limit: "ratio".into(),
        ..finished()
    };
    // The worker stops in the middle of an entry: its answer, naming the limit, ends the stream; the entry is
    // abandoned (never ended).
    let (run, calls) = stream(
        &[
            entry(b"zeros", EntryKind::Regular, 900),
            data(&[0; 400]),
            done(stopped.clone()),
        ],
        b"",
    );
    assert_eq!(run.failure, None);
    assert_eq!(run.response, stopped);
    assert_eq!(
        calls,
        vec![
            Call::Entry(b"zeros".to_vec(), 900),
            Call::Data(vec![0; 400])
        ]
    );
}

#[req("FR-06", "NFR-05")]
#[test]
fn bytes_without_an_entry_are_refused() {
    let (run, calls) = stream(&[data(b"orphan"), done(finished())], b"");
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Stream(StreamFault::DataWithoutEntry),
    );
    assert_eq!(calls, vec![]);
    let (run, _) = stream(
        &[
            entry(b"a", EntryKind::Regular, 1),
            data(b"a"),
            data(b"b"),
            done(finished()),
        ],
        b"",
    );
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Stream(StreamFault::DataWithoutEntry),
    );
    let (run, _) = stream(
        &[
            entry(b"l", EntryKind::Link, 0),
            data(b"target"),
            done(finished()),
        ],
        b"",
    );
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Stream(StreamFault::DataWithoutEntry),
    );
}

#[req("FR-06", "NFR-05")]
#[test]
fn bytes_beyond_the_announced_size_are_refused() {
    let (run, calls) = stream(
        &[
            entry(b"a", EntryKind::Regular, 3),
            data(b"abcd"),
            done(finished()),
        ],
        b"",
    );
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Stream(StreamFault::DataBeyondSize),
    );
    // The oversized chunk never reaches the sink.
    assert_eq!(calls, vec![Call::Entry(b"a".to_vec(), 3)]);
}

#[req("FR-06", "NFR-05")]
#[test]
fn an_entry_cut_short_is_refused() {
    // A next entry, or a final OK, before the current entry's last byte.
    for next in [entry(b"b", EntryKind::Regular, 1), done(finished())] {
        let (run, _) = stream(
            &[entry(b"a", EntryKind::Regular, 3), data(b"ab"), next],
            b"",
        );
        assert_synthesised(&run, Status::Error, &Failure::Stream(StreamFault::EntryCut));
    }
}

#[req("FR-06", "NFR-05")]
#[test]
fn an_output_without_its_final_response_is_refused() {
    let (run, _) = stream(&[entry(b"a", EntryKind::Regular, 1), data(b"a")], b"");
    assert_synthesised(&run, Status::Error, &Failure::Stream(StreamFault::NoDone));
    let (run, _) = stream(&[], b"");
    assert_synthesised(&run, Status::Error, &Failure::Stream(StreamFault::NoDone));
}

#[req("FR-06", "NFR-05")]
#[test]
fn anything_after_the_final_response_is_refused() {
    let (run, _) = stream(&[done(finished())], b"x");
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Protocol(ContractError::TrailingBytes),
    );
    let (run, _) = stream(&[done(finished()), entry(b"late", EntryKind::Link, 0)], b"");
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Protocol(ContractError::TrailingBytes),
    );
}

#[req("FR-06", "NFR-05")]
#[test]
fn an_invalid_frame_is_refused() {
    let (run, _) = stream(
        &[entry(b"a", EntryKind::Unspecified, 0), done(finished())],
        b"",
    );
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Protocol(ContractError::InvalidResponse("entry kind")),
    );
    let (run, _) = stream(&[], b"\x00\x00\x00\x05abc");
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Protocol(ContractError::TruncatedBody),
    );
}

#[req("FR-06", "NFR-05")]
#[test]
fn a_final_response_from_another_engine_is_refused() {
    let other = AnalyzeResponse {
        engine_id: "impostor".into(),
        ..finished()
    };
    let (run, _) = stream(&[done(other)], b"");
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::OtherEngine("impostor".into()),
    );
}

#[req("FR-06")]
#[test]
fn entries_beyond_the_budget_are_refused_by_the_host() {
    let scratch = Scratch::new();
    scratch.output(
        &[
            entry(b"one", EntryKind::Regular, 1),
            data(b"1"),
            entry(b"two", EntryKind::Link, 0),
            done(finished()),
        ],
        b"",
    );
    let mut sink = Record::default();
    let run = extract_with(
        &scratch,
        r#"cat > /dev/null; cat "$OUT""#,
        &request(1, 1000),
        GENEROUS,
        &mut sink,
    );
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Stream(StreamFault::TooManyEntries),
    );
    assert_eq!(
        sink.calls,
        vec![
            Call::Entry(b"one".to_vec(), 1),
            Call::Data(b"1".to_vec()),
            Call::End
        ]
    );
}

#[req("FR-06")]
#[test]
fn bytes_beyond_the_budget_are_refused_by_the_host() {
    let scratch = Scratch::new();
    scratch.output(
        &[
            entry(b"a", EntryKind::Regular, 8),
            data(b"1234"),
            data(b"5678"),
            done(finished()),
        ],
        b"",
    );
    let mut sink = Record::default();
    let run = extract_with(
        &scratch,
        r#"cat > /dev/null; cat "$OUT""#,
        &request(10, 6),
        GENEROUS,
        &mut sink,
    );
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Stream(StreamFault::TooManyBytes),
    );
    assert_eq!(
        sink.calls,
        vec![Call::Entry(b"a".to_vec(), 8), Call::Data(b"1234".to_vec())]
    );
}

#[req("FR-06", "NFR-05")]
#[test]
fn a_sink_error_stops_the_run() {
    let scratch = Scratch::new();
    scratch.output(
        &[
            entry(b"a", EntryKind::Regular, 1),
            data(b"a"),
            done(finished()),
        ],
        b"",
    );
    let mut sink = Record {
        refuse_entries: true,
        ..Record::default()
    };
    let run = extract_with(
        &scratch,
        r#"cat > /dev/null; cat "$OUT""#,
        &request(10, 1000),
        GENEROUS,
        &mut sink,
    );
    assert_synthesised(&run, Status::Error, &Failure::Sink("workspace full".into()));
}

#[req("FR-06", "NFR-05")]
#[test]
fn a_worker_hanging_in_the_middle_of_its_stream_times_out() {
    let scratch = Scratch::new();
    scratch.output(&[entry(b"a", EntryKind::Regular, 5), data(b"ab")], b"");
    let mut sink = Record::default();
    let started = Instant::now();
    let run = extract_with(
        &scratch,
        r#"cat > /dev/null; cat "$OUT"; exec sleep 60"#,
        &request(10, 1000),
        SHORT,
        &mut sink,
    );
    assert!(started.elapsed() < Duration::from_secs(10));
    assert_synthesised(&run, Status::Timeout, &Failure::Timeout);
    assert_eq!(
        sink.calls,
        vec![Call::Entry(b"a".to_vec(), 5), Call::Data(b"ab".to_vec())]
    );
}

#[req("FR-06", "NFR-05")]
#[test]
fn a_worker_exiting_with_an_error_after_a_valid_stream_is_refused() {
    let scratch = Scratch::new();
    scratch.output(&[done(finished())], b"");
    let mut sink = Record::default();
    let run = extract_with(
        &scratch,
        r#"cat > /dev/null; cat "$OUT"; exit 3"#,
        &request(10, 1000),
        GENEROUS,
        &mut sink,
    );
    assert_synthesised(&run, Status::Error, &Failure::Exited(3));
}

#[req("FR-06")]
#[test]
fn a_request_without_a_budget_is_not_sent() {
    let scratch = Scratch::new();
    scratch.output(&[done(finished())], b"");
    let mut sink = Record::default();
    let unbudgeted = AnalyzeRequest {
        extraction: None,
        ..request(10, 1000)
    };
    let run = extract_with(
        &scratch,
        r#"touch "$D/started"; cat > /dev/null; cat "$OUT""#,
        &unbudgeted,
        GENEROUS,
        &mut sink,
    );
    assert_synthesised(
        &run,
        Status::Error,
        &Failure::Request(ContractError::InvalidRequest("extraction")),
    );
    assert!(!scratch.exists("started"));
}

#[req("FR-06", "NFR-05")]
#[test]
fn a_long_stream_is_read_whole() {
    // 600 frames of 1 KiB: far more than a pipe holds, so the host must read while the worker writes.
    let mut frames = vec![entry(b"big", EntryKind::Regular, 600 * 1024)];
    frames.extend((0..600).map(|_| data(&[0x5a; 1024])));
    frames.push(done(finished()));
    let scratch = Scratch::new();
    scratch.output(&frames, b"");
    let mut sink = Record::default();
    let run = extract_with(
        &scratch,
        r#"cat > /dev/null; cat "$OUT""#,
        &request(10, 1 << 20),
        GENEROUS,
        &mut sink,
    );
    assert_eq!(run.failure, None);
    let received: usize = sink
        .calls
        .iter()
        .map(|call| match call {
            Call::Data(bytes) => bytes.len(),
            _ => 0,
        })
        .sum();
    assert_eq!(received, 600 * 1024);
    assert_eq!(sink.calls.last(), Some(&Call::End));
}
