//! One run of one worker: object, spawn, framed exchange, deadline, process group, classification.

use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::sys::signal::{Signal, killpg};
use nix::sys::wait::{Id, WaitPidFlag, waitid};
use nix::unistd::{Pid, getpgid};
use ostia_contracts::v1::extract_frame::Frame;
use ostia_contracts::v1::{AnalyzeResponse, ExtractFrame, ExtractionBudget, Hint, Status};
use ostia_contracts::{
    ContractError, current_version, decode_extract_frame, decode_response, read_frame,
};

use crate::{EngineIdentity, EntrySink, Failure, HostLimits, StreamFault};

/// How long the host waits for the standard error reader once the worker's process group is gone.
const STDERR_GRACE: Duration = Duration::from_secs(1);

/// Refuses a launch while this process holds a descriptor beyond the standard streams without the
/// close-on-exec flag: the worker would inherit it. Ostia opens every descriptor close-on-exec; one the
/// orchestrator inherited is caught here (closing it in the child would need unsafe code). Reads the
/// kernel's `/proc/self/fdinfo`, never medium data.
pub(crate) fn check_no_inheritable_descriptor() -> Result<(), Failure> {
    let unreadable = |error: std::io::Error| {
        Failure::Spawn(format!("cannot list the host's descriptors: {error}"))
    };
    let close_on_exec = u32::try_from(OFlag::O_CLOEXEC.bits())
        .map_err(|_| Failure::Spawn("cannot represent the close-on-exec flag".into()))?;
    let mut inheritable = Vec::new();
    for entry in std::fs::read_dir("/proc/self/fdinfo").map_err(unreadable)? {
        let entry = entry.map_err(unreadable)?;
        let Some(fd) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        if fd < 3 {
            continue;
        }
        let info = match std::fs::read_to_string(entry.path()) {
            Ok(info) => info,
            // Closed since the listing (the listing's own descriptor among them).
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(unreadable(error)),
        };
        let flags = info
            .lines()
            .find_map(|line| line.strip_prefix("flags:"))
            .and_then(|value| u32::from_str_radix(value.trim(), 8).ok())
            .ok_or_else(|| Failure::Spawn(format!("cannot read the flags of descriptor {fd}")))?;
        if flags & close_on_exec == 0 {
            inheritable.push(fd);
        }
    }
    if inheritable.is_empty() {
        Ok(())
    } else {
        inheritable.sort_unstable();
        Err(Failure::InheritedDescriptors(inheritable))
    }
}

/// Opens the object for the worker: read-only, never through a symbolic link, a regular file only (a FIFO
/// or a device could block the host or the worker).
pub(crate) fn open_object(path: &Path) -> Result<File, Failure> {
    let object = OpenOptions::new()
        .read(true)
        .custom_flags((OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK).bits())
        .open(path)
        .map_err(|error| Failure::Object(format!("cannot open the object: {error}")))?;
    let metadata = object
        .metadata()
        .map_err(|error| Failure::Object(format!("cannot inspect the object: {error}")))?;
    if !metadata.is_file() {
        return Err(Failure::Object("the object is not a regular file".into()));
    }
    fcntl(&object, FcntlArg::F_SETFL(OFlag::empty()))
        .map_err(|error| Failure::Object(format!("cannot prepare the object: {error}")))?;
    Ok(object)
}

/// The response a failed run gets (docs/contracts/cli.md, "Synthesised engine results").
pub(crate) fn synthesised(
    identity: &EngineIdentity,
    failure: &Failure,
    spent: Duration,
) -> AnalyzeResponse {
    let status = if *failure == Failure::Timeout {
        Status::Timeout
    } else {
        Status::Error
    };
    AnalyzeResponse {
        engine_id: identity.id.clone(),
        engine_version: identity.version.clone(),
        content_version: identity.content_version.clone(),
        status: status.into(),
        hint: Hint::None.into(),
        score: None,
        findings: Vec::new(),
        duration_ms: u32::try_from(spent.as_millis()).unwrap_or(u32::MAX),
        detected_type: String::new(),
        limit: String::new(),
        version: Some(current_version()),
    }
}

/// What the worker's threads report to the run.
enum Event {
    /// The worker's standard output ended (or was refused early): one frame's message, or why not.
    Answer(Result<Vec<u8>, ContractError>),
    /// The next frame of an extraction worker's stream, decoded and validated.
    Frame(ExtractFrame),
    /// An extraction worker's stream ended: after the end of the output (with or without a final response),
    /// or refused early.
    StreamEnd(Result<(), ContractError>),
    /// The worker (the process group leader) exited; it is not reaped yet.
    Exited,
}

/// Standard error kept up to its cap.
#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    truncated: bool,
}

/// How the exchange ended, before the worker's exit status is read.
struct Exchange {
    answer: Option<Result<Vec<u8>, ContractError>>,
    timed_out: bool,
    cut_short: bool,
}

/// The output of a run: the worker's answer or why there is none, and its standard error.
pub(crate) struct Outcome {
    pub(crate) answer: Result<AnalyzeResponse, Failure>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) stderr_truncated: bool,
}

/// A started worker whose request is being written, its output and standard error read, its exit watched.
struct Running {
    child: Child,
    group: Pid,
    received: mpsc::Receiver<Event>,
    capture: Arc<Mutex<Capture>>,
    stderr_done: mpsc::Receiver<()>,
}

/// Checks the launch, writes `frame` and starts the threads; `read_output` reads the worker's standard output
/// and reports on the channel. A launch the host does not run is killed and reaped: the `Err` failure.
fn start(
    mut child: Child,
    frame: Vec<u8>,
    limits: HostLimits,
    read_output: impl FnOnce(std::process::ChildStdout, mpsc::SyncSender<Event>),
) -> Result<Running, Failure> {
    let (Some(stdin), Some(stdout), Some(stderr), Ok(raw_pid)) = (
        child.stdin.take(),
        child.stdout.take(),
        child.stderr.take(),
        i32::try_from(child.id()),
    ) else {
        return Err(refused(
            child,
            "the launcher did not pipe the standard streams",
        ));
    };
    let group = Pid::from_raw(raw_pid);
    // Without a group of its own, killpg could not stop the worker's processes, nor the worker itself.
    if getpgid(Some(group)) != Ok(group) {
        return Err(refused(
            child,
            "the worker does not lead its own process group",
        ));
    }
    // A small bound: the output reader waits while the run handles what it sent.
    let (events, received) = mpsc::sync_channel(2);
    write_request(stdin, frame);
    read_output(stdout, events.clone());
    let (capture, stderr_done) = capture_stderr(stderr, limits.stderr_cap);
    watch_exit(group, events);
    Ok(Running {
        child,
        group,
        received,
        capture,
        stderr_done,
    })
}

impl Running {
    /// Stops the worker's group, reaps the worker and collects its standard error.
    fn finish(mut self) -> (std::io::Result<ExitStatus>, Capture) {
        stop(self.group, &mut self.child);
        let status = self.child.wait();
        let _ = self.stderr_done.recv_timeout(STDERR_GRACE);
        let capture =
            std::mem::take(&mut *self.capture.lock().unwrap_or_else(PoisonError::into_inner));
        (status, capture)
    }
}

/// Runs a started worker to its end: writes `frame`, reads the answer, enforces the deadline, stops the
/// worker's process group and reaps it. Never leaves a process of the group behind.
pub(crate) fn exchange(
    child: Child,
    frame: Vec<u8>,
    identity: &EngineIdentity,
    limits: HostLimits,
    started: Instant,
) -> Outcome {
    let cap = limits.max_frame;
    let mut running = match start(child, frame, limits, |stdout, events| {
        read_answer(stdout, cap, events);
    }) {
        Ok(running) => running,
        Err(failure) => return without_exchange(failure),
    };
    // A limit too far to represent is no limit.
    let deadline = started.checked_add(limits.timeout);
    let exchange = await_end(
        &running.received,
        running.group,
        &mut running.child,
        deadline,
    );
    let (status, capture) = running.finish();
    Outcome {
        answer: classify(exchange, status, identity),
        stderr: capture.bytes,
        stderr_truncated: capture.truncated,
    }
}

/// Runs a started extraction worker to its end (ADR-18): writes `frame`, hands each streamed entry to `sink`
/// under `budget`, enforces the deadline, stops the worker's process group and reaps it.
pub(crate) fn exchange_stream(
    child: Child,
    frame: Vec<u8>,
    identity: &EngineIdentity,
    limits: HostLimits,
    started: Instant,
    budget: &ExtractionBudget,
    sink: &mut dyn EntrySink,
) -> Outcome {
    let cap = limits.max_frame;
    let mut running = match start(child, frame, limits, |stdout, events| {
        read_stream(stdout, cap, events);
    }) {
        Ok(running) => running,
        Err(failure) => return without_exchange(failure),
    };
    let deadline = started.checked_add(limits.timeout);
    let mut stream = Stream {
        sink,
        budget,
        entries: 0,
        bytes: 0,
        current: None,
        done: None,
    };
    let exchange = await_stream(
        &running.received,
        running.group,
        &mut running.child,
        deadline,
        &mut stream,
    );
    let (status, capture) = running.finish();
    Outcome {
        answer: classify_stream(exchange, status, stream.done, identity),
        stderr: capture.bytes,
        stderr_truncated: capture.truncated,
    }
}

/// An extraction stream as the host checks it.
struct Stream<'a> {
    sink: &'a mut dyn EntrySink,
    budget: &'a ExtractionBudget,
    entries: u64,
    bytes: u64,
    /// Bytes still due for the current entry, if one is open.
    current: Option<u64>,
    done: Option<AnalyzeResponse>,
}

impl Stream<'_> {
    /// Applies one frame: the sizes and the budget are checked before the sink sees anything.
    fn on_frame(&mut self, frame: ExtractFrame) -> Result<(), Failure> {
        let sink_failure = |error: std::io::Error| Failure::Sink(error.to_string());
        match frame.frame {
            Some(Frame::Entry(entry)) => {
                if self.current.is_some() {
                    return Err(Failure::Stream(StreamFault::EntryCut));
                }
                self.entries = self.entries.saturating_add(1);
                if self.entries > self.budget.remaining_entries {
                    return Err(Failure::Stream(StreamFault::TooManyEntries));
                }
                self.sink.entry(&entry).map_err(sink_failure)?;
                if entry.size == 0 {
                    self.sink.end().map_err(sink_failure)?;
                } else {
                    self.current = Some(entry.size);
                }
            }
            Some(Frame::Data(bytes)) => {
                let left = self
                    .current
                    .ok_or(Failure::Stream(StreamFault::DataWithoutEntry))?;
                let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                if len > left {
                    return Err(Failure::Stream(StreamFault::DataBeyondSize));
                }
                self.bytes = self.bytes.saturating_add(len);
                if self.bytes > self.budget.remaining_bytes {
                    return Err(Failure::Stream(StreamFault::TooManyBytes));
                }
                self.sink.data(&bytes).map_err(sink_failure)?;
                if len == left {
                    self.sink.end().map_err(sink_failure)?;
                    self.current = None;
                } else {
                    self.current = Some(left - len);
                }
            }
            Some(Frame::Done(response)) => {
                // A worker stopping on a limit or a malformation abandons its current entry; an OK cannot.
                if self.current.is_some() && response.status == i32::from(Status::Ok) {
                    return Err(Failure::Stream(StreamFault::EntryCut));
                }
                self.done = Some(response);
            }
            None => {
                return Err(Failure::Protocol(ContractError::InvalidResponse("frame")));
            }
        }
        Ok(())
    }
}

/// How an extraction exchange ended, before the worker's exit status is read.
struct StreamExchange {
    ended: Option<Result<(), ContractError>>,
    fault: Option<Failure>,
    timed_out: bool,
}

/// Waits for the end of the stream and the worker's exit, or the deadline, applying each frame as it comes.
/// The worker's group is killed as soon as the worker exits, its stream is refused or a frame breaks the rules.
fn await_stream(
    received: &mpsc::Receiver<Event>,
    group: Pid,
    child: &mut Child,
    deadline: Option<Instant>,
    stream: &mut Stream<'_>,
) -> StreamExchange {
    let mut exchange = StreamExchange {
        ended: None,
        fault: None,
        timed_out: false,
    };
    let mut exited = false;
    while !(exited && exchange.ended.is_some()) {
        let event = match deadline {
            Some(deadline) => {
                received.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => received.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Event::Exited) => {
                exited = true;
                stop(group, child);
            }
            Ok(Event::Frame(frame)) => {
                if let Err(failure) = stream.on_frame(frame) {
                    exchange.fault = Some(failure);
                    break;
                }
            }
            Ok(Event::StreamEnd(end)) => {
                if end.is_err() {
                    stop(group, child);
                }
                exchange.ended = Some(end);
            }
            Ok(Event::Answer(_)) => {}
            Err(RecvTimeoutError::Timeout) => {
                exchange.timed_out = true;
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    exchange
}

/// The worker's final response, or the failure that replaces it.
fn classify_stream(
    exchange: StreamExchange,
    status: std::io::Result<ExitStatus>,
    done: Option<AnalyzeResponse>,
    identity: &EngineIdentity,
) -> Result<AnalyzeResponse, Failure> {
    if exchange.timed_out {
        return Err(Failure::Timeout);
    }
    if let Some(fault) = exchange.fault {
        return Err(fault);
    }
    if let Some(Err(error)) = exchange.ended {
        return Err(Failure::Protocol(error));
    }
    let status = status.map_err(|error| Failure::Protocol(ContractError::Io(error.kind())))?;
    if let Some(signal) = status.signal() {
        return Err(Failure::Signalled(signal));
    }
    match status.code() {
        Some(0) => {}
        Some(code) => return Err(Failure::Exited(code)),
        None => return Err(Failure::Protocol(ContractError::Io(ErrorKind::Other))),
    }
    if exchange.ended.is_none() {
        return Err(Failure::Protocol(ContractError::Io(ErrorKind::BrokenPipe)));
    }
    let response = done.ok_or(Failure::Stream(StreamFault::NoDone))?;
    if response.engine_id != identity.id {
        return Err(Failure::OtherEngine(response.engine_id));
    }
    Ok(response)
}

/// A launch the host does not run: the worker is killed and reaped, no answer is read.
fn refused(mut child: Child, reason: &str) -> Failure {
    let _ = child.kill();
    let _ = child.wait();
    Failure::Spawn(reason.into())
}

/// The outcome of a run that ended before any exchange.
fn without_exchange(failure: Failure) -> Outcome {
    Outcome {
        answer: Err(failure),
        stderr: Vec::new(),
        stderr_truncated: false,
    }
}

/// Waits for both the answer and the worker's exit, or the deadline. The worker's group is killed as soon as
/// the worker exits (a background process must not hold the output open) or its output is refused early.
fn await_end(
    received: &mpsc::Receiver<Event>,
    group: Pid,
    child: &mut Child,
    deadline: Option<Instant>,
) -> Exchange {
    let mut exchange = Exchange {
        answer: None,
        timed_out: false,
        cut_short: false,
    };
    let mut exited = false;
    while !(exited && exchange.answer.is_some()) {
        let event = match deadline {
            Some(deadline) => {
                received.recv_timeout(deadline.saturating_duration_since(Instant::now()))
            }
            None => received.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match event {
            Ok(Event::Exited) => {
                exited = true;
                stop(group, child);
            }
            Ok(Event::Frame(_) | Event::StreamEnd(_)) => {}
            Ok(Event::Answer(answer)) => {
                if matches!(
                    answer,
                    Err(ContractError::Empty
                        | ContractError::Oversized { .. }
                        | ContractError::TrailingBytes
                        | ContractError::Io(_))
                ) {
                    exchange.cut_short = true;
                    stop(group, child);
                }
                exchange.answer = Some(answer);
            }
            Err(RecvTimeoutError::Timeout) => {
                exchange.timed_out = true;
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    exchange
}

/// The worker's answer, or the failure that replaces it.
fn classify(
    exchange: Exchange,
    status: std::io::Result<ExitStatus>,
    identity: &EngineIdentity,
) -> Result<AnalyzeResponse, Failure> {
    if exchange.timed_out {
        return Err(Failure::Timeout);
    }
    if exchange.cut_short
        && let Some(Err(error)) = exchange.answer
    {
        return Err(Failure::Protocol(error));
    }
    let status = status.map_err(|error| Failure::Protocol(ContractError::Io(error.kind())))?;
    if let Some(signal) = status.signal() {
        return Err(Failure::Signalled(signal));
    }
    match status.code() {
        Some(0) => {}
        Some(code) => return Err(Failure::Exited(code)),
        None => return Err(Failure::Protocol(ContractError::Io(ErrorKind::Other))),
    }
    let body = exchange
        .answer
        .unwrap_or(Err(ContractError::Io(ErrorKind::BrokenPipe)))
        .map_err(Failure::Protocol)?;
    let response = decode_response(&body).map_err(Failure::Protocol)?;
    if response.engine_id != identity.id {
        return Err(Failure::OtherEngine(response.engine_id));
    }
    Ok(response)
}

/// Kills every process of the worker's group, and the worker itself should the group signal fail (a worker
/// under another user, say). The leader is never reaped before this, so its id still names this group; a
/// group already gone is not an error.
fn stop(group: Pid, child: &mut Child) {
    let _ = killpg(group, Signal::SIGKILL);
    let _ = child.kill();
}

/// Writes the request frame and closes the worker's standard input. A worker that does not read it makes the
/// write fail; its answer decides the run.
fn write_request(mut stdin: std::process::ChildStdin, frame: Vec<u8>) {
    std::thread::spawn(move || {
        let _ = stdin.write_all(&frame);
    });
}

/// Reads one frame's message from the worker's standard output, then expects the end of the output: the cap
/// is checked before the message is read, and any byte after it is refused.
fn read_answer(mut stdout: std::process::ChildStdout, cap: usize, events: mpsc::SyncSender<Event>) {
    std::thread::spawn(move || {
        let answer = read_frame(&mut stdout, cap).and_then(|body| {
            let mut extra = [0_u8; 1];
            loop {
                match stdout.read(&mut extra) {
                    Ok(0) => return Ok(body),
                    Ok(_) => return Err(ContractError::TrailingBytes),
                    Err(error) if error.kind() == ErrorKind::Interrupted => {}
                    Err(error) => return Err(ContractError::Io(error.kind())),
                }
            }
        });
        let _ = events.send(Event::Answer(answer));
    });
}

/// Reads the extraction worker's frames one by one and sends each, decoded and validated, to the run; after the
/// final response, expects the end of the output. An output ending before any byte of a frame ends the
/// stream (the run decides whether a final response came); a frame cut short or invalid refuses it.
fn read_stream(mut stdout: std::process::ChildStdout, cap: usize, events: mpsc::SyncSender<Event>) {
    std::thread::spawn(move || {
        let end = loop {
            let mut first = [0_u8; 1];
            match stdout.read(&mut first) {
                Ok(0) => break Ok(()),
                Ok(_) => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => break Err(ContractError::Io(error.kind())),
            }
            let frame = read_frame(&mut first.as_slice().chain(&mut stdout), cap)
                .and_then(|body| decode_extract_frame(&body));
            let frame = match frame {
                Ok(frame) => frame,
                Err(error) => break Err(error),
            };
            let finished = matches!(frame.frame, Some(Frame::Done(_)));
            if events.send(Event::Frame(frame)).is_err() {
                return;
            }
            if finished {
                break expect_end(&mut stdout);
            }
        };
        let _ = events.send(Event::StreamEnd(end));
    });
}

/// The end of the output: any further byte is refused.
fn expect_end(stdout: &mut std::process::ChildStdout) -> Result<(), ContractError> {
    let mut extra = [0_u8; 1];
    loop {
        match stdout.read(&mut extra) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(ContractError::TrailingBytes),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(ContractError::Io(error.kind())),
        }
    }
}

/// Keeps the first `cap` bytes of the worker's standard error and drains the rest.
fn capture_stderr(
    mut stderr: std::process::ChildStderr,
    cap: usize,
) -> (Arc<Mutex<Capture>>, mpsc::Receiver<()>) {
    let capture = Arc::new(Mutex::new(Capture::default()));
    let (done, finished) = mpsc::sync_channel(1);
    let shared = Arc::clone(&capture);
    std::thread::spawn(move || {
        let mut chunk = [0_u8; 8192];
        loop {
            let read = match stderr.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => read,
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            let mut kept = shared.lock().unwrap_or_else(PoisonError::into_inner);
            let room = cap.saturating_sub(kept.bytes.len());
            let bytes = chunk.get(..read).unwrap_or_default();
            kept.bytes
                .extend_from_slice(bytes.get(..room.min(read)).unwrap_or_default());
            if read > room {
                kept.truncated = true;
            }
        }
        let _ = done.send(());
    });
    (capture, finished)
}

/// Reports the leader's exit without reaping it (`WNOWAIT`), so the group can still be killed by its id.
fn watch_exit(group: Pid, events: mpsc::SyncSender<Event>) {
    std::thread::spawn(move || {
        while let Err(Errno::EINTR) =
            waitid(Id::Pid(group), WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT)
        {}
        let _ = events.send(Event::Exited);
    });
}
