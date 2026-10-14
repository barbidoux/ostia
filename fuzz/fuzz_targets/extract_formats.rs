//! Fuzz target: the extraction worker's formats, zip, tar and gzip, under a small budget (FR-06).
#![no_main]

// Included by path, not through the crate's library: `crates/contracts/tests/fuzz_regressions.rs` includes
// that library, and the extraction code needs crates the contracts tests do not have.
#[path = "../src/extract.rs"]
mod extract;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    extract::exercise_extract(data);
});
