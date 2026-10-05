//! Self-test of the fuzz harness: the real target plus a planted bug, compiled only with the
//! `fuzzing_selftest` feature. `fuzz/regressions/selftest/planted.bin` triggers it, and the fuzz suite
//! checks that libFuzzer reports the crash. The planted bug never exists in `ostia-contracts`.
#![no_main]

use libfuzzer_sys::fuzz_target;

const PLANTED: &[u8] = b"OSTIA-PLANTED-BUG";

fuzz_target!(|data: &[u8]| {
    assert!(
        !data.starts_with(PLANTED),
        "planted bug: the fuzz harness must catch this"
    );
    ostia_fuzz::exercise(data);
});
