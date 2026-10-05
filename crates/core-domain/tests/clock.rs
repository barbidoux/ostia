//! The system clock behind the `Clock` trait.

use std::sync::Arc;
use std::time::{Duration, SystemTime};

use ostia_core_domain::clock::{Clock, SystemClock};
use ostia_traceability::req;

#[req("TOOLING")]
#[test]
fn system_clock_follows_the_operating_system() {
    let clock = SystemClock::new();
    let before = SystemTime::now();
    let now = clock.now();
    let after = SystemTime::now();
    assert!(before <= now, "{before:?} <= {now:?}");
    assert!(now <= after, "{now:?} <= {after:?}");
}

#[req("TOOLING")]
#[test]
fn system_clock_monotonic_time_never_goes_back() {
    let clock = SystemClock::new();
    let mut previous = clock.monotonic();
    assert!(previous < Duration::from_secs(60), "origin at creation");
    for _ in 0..1000 {
        let next = clock.monotonic();
        assert!(next >= previous);
        previous = next;
    }
}

#[req("TOOLING")]
#[test]
fn a_clock_is_usable_as_a_shared_trait_object() {
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    let shared = Arc::clone(&clock);
    let elapsed = std::thread::spawn(move || shared.monotonic()).join();
    assert!(elapsed.is_ok());
}
