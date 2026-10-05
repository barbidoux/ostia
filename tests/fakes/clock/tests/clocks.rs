//! Behaviour of the fake clocks.

use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ostia_core_domain::clock::Clock;
use ostia_fake_clock::{ClockError, ENV_VAR, FakeClock, FileClock};
use ostia_traceability::req;

/// 2026-09-21T14:13:20Z.
const START_MS: u64 = 1_790_000_000_000;

fn at(millis: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(millis)
}

/// A file of this test in the system temporary directory, removed when dropped.
struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, content: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("ostia-fake-clock-{}-{name}", std::process::id()));
        fs::write(&path, content).unwrap();
        Self(path)
    }

    fn write(&self, content: &str) {
        fs::write(&self.0, content).unwrap();
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[req("TOOLING")]
#[test]
fn fake_clock_starts_where_it_is_told() {
    let clock = FakeClock::at(at(START_MS));
    assert_eq!(clock.now(), at(START_MS));
    assert_eq!(clock.monotonic(), Duration::ZERO);
}

#[req("TOOLING")]
#[test]
fn advancing_moves_wall_and_monotonic_time() {
    let clock = FakeClock::at(at(START_MS));
    clock.advance(Duration::from_millis(1500));
    assert_eq!(clock.now(), at(START_MS + 1500));
    assert_eq!(clock.monotonic(), Duration::from_millis(1500));
}

#[req("TOOLING")]
#[test]
fn setting_moves_only_the_wall_clock() {
    let clock = FakeClock::at(at(START_MS));
    clock.advance(Duration::from_secs(2));
    clock.set(at(START_MS - 3_600_000));
    assert_eq!(clock.now(), at(START_MS - 3_600_000));
    assert_eq!(clock.monotonic(), Duration::from_secs(2));
}

#[req("TOOLING")]
#[test]
fn clones_share_the_same_time_across_threads() {
    let clock = FakeClock::at(at(START_MS));
    let shared = clock.clone();
    std::thread::spawn(move || shared.advance(Duration::from_secs(30)))
        .join()
        .unwrap();
    assert_eq!(clock.now(), at(START_MS + 30_000));
    assert_eq!(clock.monotonic(), Duration::from_secs(30));
}

#[req("TOOLING")]
#[test]
fn file_clock_reads_the_file_on_every_call() {
    let file = TempFile::new("reads", "1790000000000\n");
    let clock = FileClock::open(&file.0).unwrap();
    assert_eq!(clock.now(), at(START_MS));
    assert_eq!(clock.monotonic(), Duration::ZERO);
    file.write("1790000004000");
    assert_eq!(clock.now(), at(START_MS + 4000));
    assert_eq!(clock.monotonic(), Duration::from_secs(4));
}

#[req("TOOLING")]
#[test]
fn file_clock_monotonic_time_never_goes_back() {
    let file = TempFile::new("back", "1790000010000");
    let clock = FileClock::open(&file.0).unwrap();
    file.write("1790000015000");
    assert_eq!(clock.monotonic(), Duration::from_secs(5));
    file.write("1790000000000");
    assert_eq!(clock.now(), at(START_MS));
    assert_eq!(clock.monotonic(), Duration::from_secs(5));
}

#[req("TOOLING")]
#[test]
fn file_clock_keeps_the_last_good_time_when_the_file_turns_bad() {
    let file = TempFile::new("bad", "1790000000000");
    let clock = FileClock::open(&file.0).unwrap();
    file.write("1790000002000");
    assert_eq!(clock.now(), at(START_MS + 2000));
    file.write("tomorrow");
    assert_eq!(clock.now(), at(START_MS + 2000));
    assert_eq!(clock.monotonic(), Duration::from_secs(2));
}

#[req("TOOLING")]
#[test]
fn file_clock_refuses_a_bad_file_at_creation() {
    let file = TempFile::new("refuse", "12:00");
    assert_eq!(
        FileClock::open(&file.0).unwrap_err(),
        ClockError::NotEpochMillis(file.0.clone())
    );
    let missing = std::env::temp_dir().join("ostia-fake-clock-does-not-exist");
    assert_eq!(
        FileClock::open(&missing).unwrap_err(),
        ClockError::Unreadable(missing.clone())
    );
}

#[req("TOOLING")]
#[test]
fn dev_builds_select_the_file_clock_through_the_environment() {
    assert_eq!(ENV_VAR, "OSTIA_FAKE_CLOCK");
    assert!(FileClock::from_env_value(None).unwrap().is_none());
    let file = TempFile::new("env", "1790000000000");
    let clock = FileClock::from_env_value(Some(OsString::from(&file.0)))
        .unwrap()
        .expect("a clock when the variable is set");
    assert_eq!(clock.now(), at(START_MS));
    let missing = std::env::temp_dir().join("ostia-fake-clock-env-missing");
    assert_eq!(
        FileClock::from_env_value(Some(missing.clone().into_os_string())).unwrap_err(),
        ClockError::Unreadable(missing)
    );
}
