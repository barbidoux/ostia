//! The clock every component takes as a dependency: logic never reads `SystemTime::now()` directly, so
//! tests and dev builds can drive time (`tests/fakes/clock`).

use std::time::{Duration, Instant, SystemTime};

/// A source of time.
pub trait Clock: Send + Sync {
    /// Wall-clock time, for timestamps in reports and logs.
    fn now(&self) -> SystemTime;

    /// Time elapsed since an arbitrary origin on a clock that never goes back, for timeouts and
    /// durations.
    fn monotonic(&self) -> Duration;
}

/// The operating system's clocks.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    /// A system clock whose monotonic origin is now.
    #[must_use]
    pub fn new() -> Self {
        todo!()
    }
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        todo!()
    }

    fn monotonic(&self) -> Duration {
        let _ = self.origin;
        todo!()
    }
}
