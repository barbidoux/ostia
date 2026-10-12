//! Fuzz target: the triage worker's type rules and the name flags (FR-05).
#![no_main]

// Included by path, not through the crate's library: `crates/contracts/tests/fuzz_regressions.rs` includes
// that library, and the triage code needs crates the contracts tests do not have.
#[path = "../src/triage.rs"]
mod triage;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    triage::exercise_triage(data);
});
