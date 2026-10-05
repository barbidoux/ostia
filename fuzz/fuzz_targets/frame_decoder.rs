//! Fuzz target: the `ostia.engine.v1` frame decoder and message validation.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    ostia_fuzz::exercise(data);
});
