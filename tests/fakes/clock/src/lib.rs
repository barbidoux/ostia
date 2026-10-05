//! Clocks that tests and dev builds drive, behind `ostia_core_domain::clock::Clock`.
//!
//! - [`FakeClock`]: set and advanced by the test itself; clones share the same time.
//! - [`FileClock`]: reads the time (epoch milliseconds) from a file on every call, so a black-box test can
//!   move the time of a running dev build by rewriting the file. Dev builds select it with the
//!   `OSTIA_FAKE_CLOCK` environment variable (the path of the file), see [`FileClock::from_env_value`].

use std::ffi::OsString;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use ostia_core_domain::clock::Clock;

/// Environment variable naming the file a dev build reads its time from.
pub const ENV_VAR: &str = "OSTIA_FAKE_CLOCK";

/// A clock moved only by the test.
#[derive(Debug, Clone)]
pub struct FakeClock;

impl FakeClock {
    /// A clock showing `now`, with monotonic time zero.
    #[must_use]
    pub fn at(_now: SystemTime) -> Self {
        todo!()
    }

    /// Moves both the wall clock and the monotonic clock forward.
    pub fn advance(&self, _by: Duration) {
        todo!()
    }

    /// Sets the wall clock (it may jump back, as a real one can); the monotonic clock does not move.
    pub fn set(&self, _now: SystemTime) {
        todo!()
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        todo!()
    }

    fn monotonic(&self) -> Duration {
        todo!()
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

/// A clock read from a file holding epoch milliseconds.
#[derive(Debug)]
pub struct FileClock;

impl FileClock {
    /// A clock reading `path`, which must hold epoch milliseconds now.
    ///
    /// # Errors
    /// The file is unreadable or does not hold epoch milliseconds.
    pub fn open(_path: &Path) -> Result<Self, ClockError> {
        todo!()
    }

    /// The clock a dev build uses when [`ENV_VAR`] is set (`value` is that variable's value).
    ///
    /// # Errors
    /// As [`FileClock::open`].
    pub fn from_env_value(_value: Option<OsString>) -> Result<Option<Self>, ClockError> {
        todo!()
    }
}

impl Clock for FileClock {
    fn now(&self) -> SystemTime {
        todo!()
    }

    fn monotonic(&self) -> Duration {
        todo!()
    }
}
