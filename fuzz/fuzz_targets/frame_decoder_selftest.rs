//! Self-test of the fuzz harness: the real target's exercise plus two bugs planted after decoding,
//! compiled only with the `fuzzing_selftest` feature. A response named `OSTIA-PLANTED-BUG` panics and one
//! named `OSTIA-PLANTED-HANG` sleeps (`fuzz/regressions/selftest/`); the fuzz suite checks that libFuzzer
//! reports the crash and the timeout. Since the bugs sit behind the decoders, a target that skipped the
//! decoders would never trip them. The planted bugs never exist in `ostia-contracts`.
#![no_main]

use std::time::Duration;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ostia_fuzz::exercise_with(data, &|response| match response.engine_id.as_str() {
        "OSTIA-PLANTED-BUG" => panic!("planted bug: the fuzz harness must catch this"),
        "OSTIA-PLANTED-HANG" => std::thread::sleep(Duration::from_secs(10)),
        _ => {}
    });
});
