//! CTR-01 and NFR-05 through the worker host (WP-1.6): one framed request in, one framed response out, the
//! object as descriptor 3, read-only; a worker that crashes, is killed, writes garbage or hangs yields a
//! synthesised `ERROR` or `TIMEOUT` result with the declared identity (docs/contracts/cli.md), and the host
//! keeps serving.
//!
//! Workers are small `/bin/sh` scripts written to a directory per test. Response frames are prepared with the
//! contract encoder of `ostia-contracts` (WP-0.5) and written by the script with `cat`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ostia_contracts::v1::{
    AnalyzeRequest, AnalyzeResponse, ContractVersion, Finding, Hint, Limits, Origin, Status,
};
use ostia_contracts::{
    ContractError, DEFAULT_MAX_FRAME, decode_frame, decode_request, encode_frame,
};
use ostia_sandbox::{
    DEFAULT_STDERR_CAP, EngineIdentity, Failure, HostLimits, WorkerCommand, WorkerHost, WorkerRun,
};
use ostia_traceability::req;

/// Content of the object every test passes, and its SHA-256 (`printf 'ostia object\n' | sha256sum`).
const OBJECT: &[u8] = b"ostia object\n";
const OBJECT_SHA256: &str = "867d87de441ccfd98a63cad4e0525959fef3a5bb0021c668016e0139c2046b1c";

/// Far above any normal run, even on a loaded machine; far below the hangs of the timeout tests.
const GENEROUS: Duration = Duration::from_secs(30);
const SHORT: Duration = Duration::from_secs(1);

static DIRS: AtomicU32 = AtomicU32::new(0);

/// A directory of its own for one test (or one worker of a test), holding the object and the scripts.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "ostia-worker-host-{}-{}",
            std::process::id(),
            DIRS.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch directory");
        std::fs::write(dir.join("object"), OBJECT).expect("object");
        Self { dir }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    fn object(&self) -> PathBuf {
        self.path("object")
    }

    /// `/bin/sh` running `body`; `$D` is this directory, `$ANSWER` the prepared answer frame.
    fn worker(&self, body: &str) -> WorkerCommand {
        let script = self.path("worker.sh");
        let text = format!(
            "D='{dir}'\nANSWER='{dir}/answer.bin'\n{body}\n",
            dir = self.dir.display()
        );
        std::fs::write(&script, text).expect("worker script");
        WorkerCommand::new("/bin/sh", [script])
    }

    /// Writes `bytes` as the answer the worker sends with `cat "$ANSWER"`.
    fn answer_bytes(&self, bytes: &[u8]) {
        std::fs::write(self.path("answer.bin"), bytes).expect("answer");
    }

    /// Writes `response` as one frame for `cat "$ANSWER"`.
    fn answer(&self, response: &AnalyzeResponse) {
        self.answer_bytes(&encode_frame(response, DEFAULT_MAX_FRAME).expect("frame"));
    }

    fn read(&self, name: &str) -> Vec<u8> {
        std::fs::read(self.path(name)).unwrap_or_else(|error| panic!("{name}: {error}"))
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
        id: "av".into(),
        version: "1.0.0".into(),
        content_version: "rules-1".into(),
    }
}

const VERSION: Option<ContractVersion> = Some(ContractVersion { major: 1, minor: 0 });

fn request() -> AnalyzeRequest {
    AnalyzeRequest {
        session_id: "session-1".into(),
        object_id: "object-7".into(),
        sha256: vec![0x86; 32],
        detected_type: "text".into(),
        size: 13,
        origin: Origin::File.into(),
        limits: Some(Limits {
            memory_bytes: 1 << 28,
            duration_ms: 30_000,
            write_bytes: 1 << 20,
        }),
        version: VERSION,
    }
}

/// The worker's own answer in the round-trip tests.
fn answer() -> AnalyzeResponse {
    AnalyzeResponse {
        engine_id: "av".into(),
        engine_version: "1.0.0".into(),
        content_version: "rules-1".into(),
        status: Status::Ok.into(),
        hint: Hint::Suspicious.into(),
        score: Some(0.25),
        findings: vec![Finding {
            id: "marker-1".into(),
            title: "test marker".into(),
            severity: 2,
            evidence: "offset 0".into(),
            attack_ids: vec!["T1204".into()],
        }],
        duration_ms: 7,
        version: VERSION,
    }
}

fn host(timeout: Duration) -> WorkerHost {
    WorkerHost::unconfined(HostLimits::new(timeout))
}

fn run(scratch: &Scratch, worker: &WorkerCommand, timeout: Duration) -> (WorkerRun, Duration) {
    let started = Instant::now();
    let done = host(timeout).run(worker, &identity(), &request(), &scratch.object());
    (done, started.elapsed())
}

/// A synthesised result: declared identity, `status`, hint NONE, no score, no findings, the time spent.
fn assert_synthesised(done: &WorkerRun, status: Status, failure: &Failure, elapsed: Duration) {
    let expected = AnalyzeResponse {
        engine_id: "av".into(),
        engine_version: "1.0.0".into(),
        content_version: "rules-1".into(),
        status: status.into(),
        hint: Hint::None.into(),
        score: None,
        findings: vec![],
        duration_ms: done.response.duration_ms,
        version: VERSION,
    };
    assert_eq!(done.failure.as_ref(), Some(failure));
    assert_eq!(done.response, expected);
    let spent = u128::from(done.response.duration_ms);
    assert!(spent <= elapsed.as_millis(), "{spent} ms > {elapsed:?}");
}

/// The process `pid` has ended: gone, or a zombie waiting for its new parent.
fn ended(pid: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            Err(_) => return true,
            Ok(stat)
                if stat
                    .rsplit(')')
                    .next()
                    .is_some_and(|s| s.trim_start().starts_with('Z')) =>
            {
                return true;
            }
            Ok(_) if Instant::now() > deadline => return false,
            Ok(_) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn grandchild(scratch: &Scratch) -> String {
    String::from_utf8(scratch.read("grandchild"))
        .expect("pid")
        .trim()
        .to_owned()
}

#[req("CTR-01")]
#[test]
fn echo_worker_round_trip() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    let worker = scratch.worker(r#"cat > "$D/request.bin"; cat "$ANSWER""#);
    let (done, _) = run(&scratch, &worker, GENEROUS);
    assert_eq!(done.failure, None);
    assert_eq!(done.response, answer());
    let sent = scratch.read("request.bin");
    let body = decode_frame(&sent, DEFAULT_MAX_FRAME).expect("exactly one frame on stdin");
    assert_eq!(decode_request(body).expect("request"), request());
    assert_eq!(
        sent.get(..4),
        Some(&u32::try_from(sent.len() - 4).expect("len").to_be_bytes()[..])
    );
}

#[req("CTR-01")]
#[test]
fn object_is_descriptor_3_read_only_from_its_start() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    let worker = scratch.worker(
        r#"sha256sum <&3 | cut -d' ' -f1 > "$D/fd3.sha256"
if (printf x >&3) 2>/dev/null; then echo yes > "$D/fd3.writable"; fi
cat "$ANSWER""#,
    );
    let (done, _) = run(&scratch, &worker, GENEROUS);
    assert_eq!(done.failure, None);
    assert_eq!(
        scratch.read("fd3.sha256"),
        format!("{OBJECT_SHA256}\n").into_bytes()
    );
    assert!(!scratch.exists("fd3.writable"), "descriptor 3 is writable");
    assert_eq!(scratch.read("object"), OBJECT);
}

#[req("CTR-01")]
#[test]
fn worker_gets_only_its_standard_streams_and_the_object() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    // ls opens the directory it lists on the lowest free descriptor: 4 when nothing else leaked.
    let worker = scratch.worker(r#"ls /proc/self/fd > "$D/fds"; cat "$ANSWER""#);
    let (done, _) = run(&scratch, &worker, GENEROUS);
    assert_eq!(done.failure, None);
    assert_eq!(scratch.read("fds"), b"0\n1\n2\n3\n4\n");
}

#[req("CTR-01")]
#[test]
fn worker_status_and_findings_are_kept() {
    for status in [Status::Unsupported, Status::Error, Status::Timeout] {
        let scratch = Scratch::new();
        let own = AnalyzeResponse {
            status: status.into(),
            hint: Hint::Unspecified.into(),
            score: None,
            ..answer()
        };
        scratch.answer(&own);
        let (done, _) = run(&scratch, &scratch.worker(r#"cat "$ANSWER""#), GENEROUS);
        assert_eq!(done.failure, None, "{status:?}");
        assert_eq!(done.response, own, "{status:?}");
    }
}

#[req("NFR-05")]
#[test]
fn sleeping_worker_yields_timeout() {
    let scratch = Scratch::new();
    let (done, elapsed) = run(&scratch, &scratch.worker("exec sleep 60"), SHORT);
    assert_synthesised(&done, Status::Timeout, &Failure::Timeout, elapsed);
    assert!(done.response.duration_ms >= 1000, "{:?}", done.response);
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[req("NFR-05")]
#[test]
fn timeout_kills_the_whole_process_group() {
    let scratch = Scratch::new();
    let worker = scratch.worker(r#"sleep 300 & echo $! > "$D/grandchild"; wait"#);
    let (done, elapsed) = run(&scratch, &worker, SHORT);
    assert_synthesised(&done, Status::Timeout, &Failure::Timeout, elapsed);
    let pid = grandchild(&scratch);
    assert!(ended(&pid), "process {pid} outlived its run");
}

#[req("NFR-05")]
#[test]
fn answer_without_exit_yields_timeout() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    let (done, elapsed) = run(
        &scratch,
        &scratch.worker(r#"cat "$ANSWER"; exec sleep 60"#),
        SHORT,
    );
    assert_synthesised(&done, Status::Timeout, &Failure::Timeout, elapsed);
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[req("NFR-05")]
#[test]
fn finished_worker_leaves_no_process_behind() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    // The background process keeps the worker's standard output open after the worker exits.
    let worker = scratch.worker(r#"sleep 300 & echo $! > "$D/grandchild"; cat "$ANSWER""#);
    let (done, elapsed) = run(&scratch, &worker, GENEROUS);
    assert_eq!(done.failure, None);
    assert_eq!(done.response, answer());
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
    let pid = grandchild(&scratch);
    assert!(ended(&pid), "process {pid} outlived its run");
}

#[req("NFR-05")]
#[test]
fn crashing_worker_yields_error() {
    let cases = [
        ("exit 3", Failure::Exited(3)),
        ("kill -SEGV $$", Failure::Signalled(11)),
        ("kill -KILL $$", Failure::Signalled(9)),
        ("kill -ABRT $$", Failure::Signalled(6)),
    ];
    for (body, failure) in cases {
        let scratch = Scratch::new();
        let (done, elapsed) = run(&scratch, &scratch.worker(body), GENEROUS);
        assert_synthesised(&done, Status::Error, &failure, elapsed);
    }
}

#[req("NFR-05")]
#[test]
fn valid_answer_then_failing_exit_yields_error() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    let (done, elapsed) = run(
        &scratch,
        &scratch.worker(r#"cat "$ANSWER"; exit 1"#),
        GENEROUS,
    );
    assert_synthesised(&done, Status::Error, &Failure::Exited(1), elapsed);
}

#[req("NFR-05")]
#[test]
fn garbage_yields_error() {
    let scratch = Scratch::new();
    scratch.answer_bytes(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0xff]);
    let (done, elapsed) = run(&scratch, &scratch.worker(r#"cat "$ANSWER""#), GENEROUS);
    let oversized = ContractError::Oversized {
        len: 3_735_928_559,
        cap: 16_777_216,
    };
    assert_synthesised(&done, Status::Error, &Failure::Protocol(oversized), elapsed);
}

#[req("NFR-05", "CTR-01")]
#[test]
fn answer_that_is_not_one_valid_response_frame_yields_error() {
    let valid = encode_frame(&answer(), DEFAULT_MAX_FRAME).expect("frame");
    let major_2 = AnalyzeResponse {
        version: Some(ContractVersion { major: 2, minor: 0 }),
        ..answer()
    };
    let anonymous = AnalyzeResponse {
        engine_id: String::new(),
        ..answer()
    };
    let cases: Vec<(&str, Vec<u8>, Failure)> = vec![
        (
            "nothing",
            vec![],
            Failure::Protocol(ContractError::TruncatedHeader),
        ),
        (
            "half a header",
            vec![0, 0],
            Failure::Protocol(ContractError::TruncatedHeader),
        ),
        (
            "empty frame",
            vec![0, 0, 0, 0],
            Failure::Protocol(ContractError::Empty),
        ),
        (
            "truncated body",
            valid[..valid.len() - 3].to_vec(),
            Failure::Protocol(ContractError::TruncatedBody),
        ),
        (
            "trailing bytes",
            [valid.as_slice(), b"x"].concat(),
            Failure::Protocol(ContractError::TrailingBytes),
        ),
        (
            "not protobuf",
            vec![0, 0, 0, 2, 0xff, 0xff],
            Failure::Protocol(ContractError::Malformed),
        ),
        (
            "major 2",
            encode_frame(&major_2, DEFAULT_MAX_FRAME).expect("frame"),
            Failure::Protocol(ContractError::UnsupportedMajor(2)),
        ),
        (
            "no engine id",
            encode_frame(&anonymous, DEFAULT_MAX_FRAME).expect("frame"),
            Failure::Protocol(ContractError::MissingEngineIdentity("engine_id")),
        ),
    ];
    for (case, bytes, failure) in cases {
        let scratch = Scratch::new();
        scratch.answer_bytes(&bytes);
        let (done, elapsed) = run(&scratch, &scratch.worker(r#"cat "$ANSWER""#), GENEROUS);
        assert_eq!(done.failure.as_ref(), Some(&failure), "{case}");
        assert_synthesised(&done, Status::Error, &failure, elapsed);
    }
}

#[req("NFR-05")]
#[test]
fn answer_from_another_engine_yields_error() {
    let scratch = Scratch::new();
    scratch.answer(&AnalyzeResponse {
        engine_id: "clamav".into(),
        ..answer()
    });
    let (done, elapsed) = run(&scratch, &scratch.worker(r#"cat "$ANSWER""#), GENEROUS);
    assert_synthesised(
        &done,
        Status::Error,
        &Failure::OtherEngine("clamav".into()),
        elapsed,
    );
}

#[req("NFR-05")]
#[test]
fn endless_output_is_cut_short() {
    let scratch = Scratch::new();
    // `yes` writes "y\ny\n…": a header announcing 0x790a790a bytes.
    let (done, elapsed) = run(&scratch, &scratch.worker("exec yes"), GENEROUS);
    let oversized = ContractError::Oversized {
        len: 2_030_729_482,
        cap: 16_777_216,
    };
    assert_synthesised(&done, Status::Error, &Failure::Protocol(oversized), elapsed);
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[req("NFR-05")]
#[test]
fn endless_output_after_the_answer_is_cut_short() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    let (done, elapsed) = run(
        &scratch,
        &scratch.worker(r#"cat "$ANSWER"; exec yes"#),
        GENEROUS,
    );
    let failure = Failure::Protocol(ContractError::TrailingBytes);
    assert_synthesised(&done, Status::Error, &failure, elapsed);
    assert!(elapsed < Duration::from_secs(10), "{elapsed:?}");
}

#[req("NFR-05")]
#[test]
fn answer_over_the_frame_cap_yields_error() {
    let scratch = Scratch::new();
    // The cap holds in both directions: the request (under 200 bytes) passes, the answer (over 300) does not.
    let mut long = answer();
    long.findings[0].evidence = "e".repeat(300);
    scratch.answer(&long);
    let limits = HostLimits {
        max_frame: 200,
        ..HostLimits::new(GENEROUS)
    };
    let started = Instant::now();
    let worker = scratch.worker(r#"cat > "$D/request.bin"; cat "$ANSWER""#);
    let done =
        WorkerHost::unconfined(limits).run(&worker, &identity(), &request(), &scratch.object());
    let elapsed = started.elapsed();
    assert!(scratch.exists("request.bin"), "the request was not sent");
    assert!(
        matches!(
            done.failure,
            Some(Failure::Protocol(ContractError::Oversized { cap: 200, .. }))
        ),
        "{:?}",
        done.failure
    );
    let failure = done.failure.clone().expect("failure");
    assert_synthesised(&done, Status::Error, &failure, elapsed);
}

#[req("CTR-01")]
#[test]
fn request_over_the_frame_cap_is_not_sent() {
    let scratch = Scratch::new();
    let limits = HostLimits {
        max_frame: 16,
        ..HostLimits::new(GENEROUS)
    };
    let started = Instant::now();
    let worker = scratch.worker(r#"touch "$D/started""#);
    let done =
        WorkerHost::unconfined(limits).run(&worker, &identity(), &request(), &scratch.object());
    let elapsed = started.elapsed();
    assert!(
        matches!(
            done.failure,
            Some(Failure::Request(ContractError::Oversized { cap: 16, .. }))
        ),
        "{:?}",
        done.failure
    );
    let failure = done.failure.clone().expect("failure");
    assert_synthesised(&done, Status::Error, &failure, elapsed);
    assert!(!scratch.exists("started"), "the worker ran");
}

#[req("NFR-05")]
#[test]
fn standard_error_is_kept_up_to_its_cap() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    let worker = scratch.worker(r#"head -c 10485760 /dev/zero | tr '\0' e >&2; cat "$ANSWER""#);
    let (done, _) = run(&scratch, &worker, GENEROUS);
    assert_eq!(done.failure, None);
    assert_eq!(done.response, answer());
    assert_eq!(DEFAULT_STDERR_CAP, 65_536);
    assert_eq!(done.stderr, vec![b'e'; 65_536]);
    assert!(done.stderr_truncated);
}

#[req("NFR-05")]
#[test]
fn short_standard_error_is_kept_whole() {
    let scratch = Scratch::new();
    let worker = scratch.worker(r"printf 'diag\n' >&2; exit 3");
    let (done, elapsed) = run(&scratch, &worker, GENEROUS);
    assert_synthesised(&done, Status::Error, &Failure::Exited(3), elapsed);
    assert_eq!(done.stderr, b"diag\n");
    assert!(!done.stderr_truncated);
}

#[req("NFR-05")]
#[test]
fn missing_program_yields_error() {
    let scratch = Scratch::new();
    let worker = WorkerCommand::new("/nonexistent/ostia-worker", ["--version"]);
    let (done, elapsed) = run(&scratch, &worker, GENEROUS);
    assert!(
        matches!(done.failure, Some(Failure::Spawn(_))),
        "{:?}",
        done.failure
    );
    let failure = done.failure.clone().expect("failure");
    assert_synthesised(&done, Status::Error, &failure, elapsed);
}

#[req("NFR-05")]
#[test]
fn object_that_is_not_a_regular_file_is_not_passed() {
    let scratch = Scratch::new();
    std::fs::create_dir(scratch.path("directory")).expect("directory");
    std::os::unix::fs::symlink(scratch.object(), scratch.path("link")).expect("symlink");
    let fifo = std::process::Command::new("mkfifo")
        .arg(scratch.path("fifo"))
        .status()
        .expect("mkfifo");
    assert!(fifo.success());
    let worker = scratch.worker(r#"touch "$D/started""#);
    for name in ["directory", "link", "fifo", "missing"] {
        let started = Instant::now();
        let done = host(GENEROUS).run(&worker, &identity(), &request(), &scratch.path(name));
        let elapsed = started.elapsed();
        assert!(
            matches!(done.failure, Some(Failure::Object(_))),
            "{name}: {:?}",
            done.failure
        );
        let failure = done.failure.clone().expect("failure");
        assert_synthesised(&done, Status::Error, &failure, elapsed);
        assert!(elapsed < Duration::from_secs(10), "{name}: {elapsed:?}");
        assert!(!scratch.exists("started"), "{name}: the worker ran");
    }
}

#[req("NFR-05")]
#[test]
fn host_keeps_serving_after_a_crash() {
    let scratch = Scratch::new();
    scratch.answer(&answer());
    let host = host(GENEROUS);
    let crash = host.run(
        &scratch.worker("kill -SEGV $$"),
        &identity(),
        &request(),
        &scratch.object(),
    );
    assert_eq!(crash.failure, Some(Failure::Signalled(11)));
    let next = host.run(
        &scratch.worker(r#"cat "$ANSWER""#),
        &identity(),
        &request(),
        &scratch.object(),
    );
    assert_eq!(next.failure, None);
    assert_eq!(next.response, answer());
}

#[req("NFR-05")]
#[test]
fn concurrent_runs_do_not_disturb_each_other() {
    let host = Arc::new(host(Duration::from_secs(3)));
    let bodies = [
        r#"cat > "$D/request.bin"; cat "$ANSWER""#,
        "exit 3",
        "exec sleep 60",
        r#"cat > "$D/request.bin"; cat "$ANSWER""#,
        "kill -KILL $$",
        r#"cat > "$D/request.bin"; cat "$ANSWER""#,
    ];
    let runs: Vec<_> = bodies
        .into_iter()
        .map(|body| {
            let host = Arc::clone(&host);
            std::thread::spawn(move || {
                let scratch = Scratch::new();
                scratch.answer(&answer());
                let worker = scratch.worker(body);
                (
                    body,
                    host.run(&worker, &identity(), &request(), &scratch.object()),
                )
            })
        })
        .collect();
    for handle in runs {
        let (body, done) = handle.join().expect("run thread");
        let expected = match body {
            "exit 3" => Some(Failure::Exited(3)),
            "exec sleep 60" => Some(Failure::Timeout),
            "kill -KILL $$" => Some(Failure::Signalled(9)),
            _ => None,
        };
        assert_eq!(done.failure, expected, "{body}");
    }
}
