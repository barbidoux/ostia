//! Clocks that tests and dev builds drive, behind `ostia_core_domain::clock::Clock`.
//!
//! - [`FakeClock`]: set and advanced by the test itself; clones share the same time.
//! - [`FileClock`]: reads the time (epoch milliseconds) from a file on every call, so a black-box test can
//!   move the time of a running dev build by rewriting the file. Dev builds select it with the
//!   `OSTIA_FAKE_CLOCK` environment variable (the path of the file), see [`FileClock::from_env_value`].
//!   Writers replace the file atomically (write a temporary file, then rename it): a reader could
//!   otherwise see a shorter number. A file that cannot be read or parsed keeps the last good time, so
//!   time freezes rather than failing. Release builds must never honour the variable (the CLI wires it
//!   in dev builds only).

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ostia_core_domain::clock::Clock;

/// Environment variable naming the file a dev build reads its time from.
pub const ENV_VAR: &str = "OSTIA_FAKE_CLOCK";

#[derive(Debug)]
struct FakeState {
    now: SystemTime,
    monotonic: Duration,
}

/// A clock moved only by the test.
#[derive(Debug, Clone)]
pub struct FakeClock {
    state: Arc<Mutex<FakeState>>,
}

impl FakeClock {
    /// A clock showing `now`, with monotonic time zero.
    #[must_use]
    pub fn at(now: SystemTime) -> Self {
        Self {
            state: Arc::new(Mutex::new(FakeState {
                now,
                monotonic: Duration::ZERO,
            })),
        }
    }

    /// Moves both the wall clock and the monotonic clock forward.
    pub fn advance(&self, by: Duration) {
        let mut state = self.lock();
        state.now += by;
        state.monotonic += by;
    }

    /// Sets the wall clock (it may jump back, as a real one can); the monotonic clock does not move.
    pub fn set(&self, now: SystemTime) {
        self.lock().now = now;
    }

    fn lock(&self) -> MutexGuard<'_, FakeState> {
        // A thread that panicked while holding the lock must not make every later read panic; the
        // state it left is used as is.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        self.lock().now
    }

    fn monotonic(&self) -> Duration {
        self.lock().monotonic
    }
}

/// Why a [`FileClock`] could not be created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClockError {
    /// The file could not be read.
    Unreadable(PathBuf),
    /// The file does not hold epoch milliseconds.
    NotEpochMillis(PathBuf),
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable(path) => {
                write!(f, "cannot read the fake clock file {}", path.display())
            }
            Self::NotEpochMillis(path) => {
                write!(f, "{} does not hold epoch milliseconds", path.display())
            }
        }
    }
}

impl std::error::Error for ClockError {}

#[derive(Debug)]
struct FileState {
    /// Last time read successfully, in epoch milliseconds.
    last: u64,
    /// Highest monotonic time reported, so it never goes back.
    monotonic: Duration,
}

/// A clock read from a file holding epoch milliseconds.
#[derive(Debug)]
pub struct FileClock {
    path: PathBuf,
    /// Epoch milliseconds when the clock was created: the monotonic origin.
    origin: u64,
    state: Mutex<FileState>,
}

impl FileClock {
    /// A clock reading `path`, which must hold epoch milliseconds now.
    ///
    /// # Errors
    /// The file is unreadable or does not hold epoch milliseconds.
    pub fn open(path: &Path) -> Result<Self, ClockError> {
        let origin = read_millis(path)?;
        Ok(Self {
            path: path.to_path_buf(),
            origin,
            state: Mutex::new(FileState {
                last: origin,
                monotonic: Duration::ZERO,
            }),
        })
    }

    /// The clock a dev build uses when [`ENV_VAR`] is set (`value` is that variable's value).
    ///
    /// # Errors
    /// As [`FileClock::open`].
    pub fn from_env_value(value: Option<OsString>) -> Result<Option<Self>, ClockError> {
        value.map(|path| Self::open(Path::new(&path))).transpose()
    }

    /// Reads the file and updates the state; a bad read keeps the last good time.
    fn read(&self) -> MutexGuard<'_, FileState> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if let Ok(millis) = read_millis(&self.path) {
            state.last = millis;
            let elapsed = Duration::from_millis(millis.saturating_sub(self.origin));
            state.monotonic = state.monotonic.max(elapsed);
        }
        state
    }
}

impl Clock for FileClock {
    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_millis(self.read().last)
    }

    fn monotonic(&self) -> Duration {
        self.read().monotonic
    }
}

fn read_millis(path: &Path) -> Result<u64, ClockError> {
    let text = fs::read_to_string(path).map_err(|_| ClockError::Unreadable(path.to_path_buf()))?;
    text.trim()
        .parse()
        .map_err(|_| ClockError::NotEpochMillis(path.to_path_buf()))
}
