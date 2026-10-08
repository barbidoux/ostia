//! Worker launch and limits (spec §19 `sandbox/`): the worker host.
//!
//! [`WorkerHost::run`] starts one throwaway worker per analysis through a [`Launcher`], gives it the object as
//! file descriptor 3 (read-only), writes one framed `AnalyzeRequest` on its standard input and reads one framed
//! `AnalyzeResponse` from its standard output (CTR-01, ADR-03). Whatever the worker does (crash, signal,
//! garbage, an answer from another engine, no answer within the time limit) the host returns a result and
//! keeps running (NFR-05): a failed run gets a synthesised response with the declared engine identity and
//! status `ERROR` or `TIMEOUT` (docs/contracts/cli.md, "Synthesised engine results").
//!
//! P1 launches workers without isolation ([`Unconfined`]); P2's sandbox replaces it behind [`Launcher`].

mod host;

use std::ffi::OsString;
use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use command_fds::{CommandFdExt, FdMapping};
use ostia_contracts::v1::{AnalyzeRequest, AnalyzeResponse};
use ostia_contracts::{ContractError, encode_frame};

/// The worker's descriptor holding the object (ADR-03).
const OBJECT_FD: i32 = 3;

/// Default cap on the captured standard error of one run: 64 KiB.
pub const DEFAULT_STDERR_CAP: usize = 64 * 1024;

/// The program and arguments of a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerCommand {
    program: OsString,
    args: Vec<OsString>,
}

impl WorkerCommand {
    /// A worker run as `program args…`.
    pub fn new(
        program: impl Into<OsString>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    /// The program.
    #[must_use]
    pub fn program(&self) -> &OsString {
        &self.program
    }

    /// The arguments.
    #[must_use]
    pub fn args(&self) -> &[OsString] {
        &self.args
    }
}

/// The identity an engine is declared with; it names every synthesised response (CTR-03).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineIdentity {
    /// Engine identifier; a response naming another engine is refused.
    pub id: String,
    /// Engine version.
    pub version: String,
    /// Version of the engine's rules, signatures or model.
    pub content_version: String,
}

/// Starts worker processes.
pub trait Launcher: Send + Sync {
    /// Starts `command` with `object` as its file descriptor 3, its standard input, output and error piped,
    /// as the leader of a new process group (the host stops the whole group at the end of the run).
    ///
    /// # Errors
    /// The process could not be started.
    fn launch(&self, command: &WorkerCommand, object: OwnedFd) -> std::io::Result<Child>;
}

/// Launches workers without isolation (P1); P2's sandbox adds namespaces, seccomp and limits.
#[derive(Debug, Clone, Copy, Default)]
pub struct Unconfined;

impl Launcher for Unconfined {
    fn launch(&self, command: &WorkerCommand, object: OwnedFd) -> std::io::Result<Child> {
        let mut process = Command::new(command.program());
        process
            .args(command.args())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .fd_mappings(vec![FdMapping {
                parent_fd: object,
                child_fd: OBJECT_FD,
            }])
            .map_err(std::io::Error::other)?;
        process.spawn()
    }
}

/// Limits of one run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostLimits {
    /// Wall-clock limit from launch to the worker's exit (the policy's `engine_timeout_seconds`).
    pub timeout: Duration,
    /// Cap on one frame's message, in both directions.
    pub max_frame: usize,
    /// Bytes of standard error kept; the rest is read and dropped.
    pub stderr_cap: usize,
}

impl HostLimits {
    /// `timeout`, with the default frame and standard error caps.
    #[must_use]
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            max_frame: ostia_contracts::DEFAULT_MAX_FRAME,
            stderr_cap: DEFAULT_STDERR_CAP,
        }
    }
}

/// Why a run did not produce the worker's own answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The object is not a readable regular file.
    Object(String),
    /// The request cannot be framed (larger than the frame cap).
    Request(ContractError),
    /// The worker could not be started.
    Spawn(String),
    /// No answer and exit within the time limit; the worker's process group was killed.
    Timeout,
    /// The worker exited with a non-zero code.
    Exited(i32),
    /// The worker was killed by a signal it did not get from the host.
    Signalled(i32),
    /// The worker's standard output is not exactly one valid response frame.
    Protocol(ContractError),
    /// The response names another engine.
    OtherEngine(String),
}

/// Result of one run.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkerRun {
    /// The worker's response, or the synthesised one when `failure` is set.
    pub response: AnalyzeResponse,
    /// Why the response was synthesised, if it was.
    pub failure: Option<Failure>,
    /// The start of the worker's standard error, at most the cap.
    pub stderr: Vec<u8>,
    /// The worker wrote more standard error than the cap.
    pub stderr_truncated: bool,
}

/// Runs workers, one process per analysis.
#[derive(Debug, Clone)]
pub struct WorkerHost<L: Launcher = Unconfined> {
    launcher: L,
    limits: HostLimits,
}

impl WorkerHost<Unconfined> {
    /// A host launching workers without isolation.
    #[must_use]
    pub fn unconfined(limits: HostLimits) -> Self {
        Self::new(Unconfined, limits)
    }
}

impl<L: Launcher> WorkerHost<L> {
    /// A host launching workers through `launcher`.
    #[must_use]
    pub fn new(launcher: L, limits: HostLimits) -> Self {
        Self { launcher, limits }
    }

    /// Runs `command` once on `object` with `request`; never fails, never panics on the worker's behaviour.
    #[must_use]
    pub fn run(
        &self,
        command: &WorkerCommand,
        identity: &EngineIdentity,
        request: &AnalyzeRequest,
        object: &Path,
    ) -> WorkerRun {
        let started = Instant::now();
        let outcome = encode_frame(request, self.limits.max_frame)
            .map_err(Failure::Request)
            .and_then(|frame| Ok((frame, host::open_object(object)?)))
            .and_then(|(frame, object)| {
                self.launcher
                    .launch(command, object.into())
                    .map(|child| (frame, child))
                    .map_err(|error| Failure::Spawn(error.to_string()))
            })
            .map(|(frame, child)| host::exchange(child, frame, identity, self.limits, started));
        let (answer, stderr, stderr_truncated) = match outcome {
            Ok(done) => (done.answer, done.stderr, done.stderr_truncated),
            Err(failure) => (Err(failure), Vec::new(), false),
        };
        match answer {
            Ok(response) => WorkerRun {
                response,
                failure: None,
                stderr,
                stderr_truncated,
            },
            Err(failure) => WorkerRun {
                response: host::synthesised(identity, &failure, started.elapsed()),
                failure: Some(failure),
                stderr,
                stderr_truncated,
            },
        }
    }
}
