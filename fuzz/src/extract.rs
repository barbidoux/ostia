//! What the extraction fuzz target does with one input: extract it as each format under a small budget,
//! checking the properties the stream must hold (FR-06). Any panic, a broken property included, is a finding.

/// Extracts `data` as a zip, a tar and a gzip file.
///
/// # Panics
/// When a property breaks: that is what the fuzzer looks for.
pub fn exercise_extract(data: &[u8]) {
    let _ = data;
    todo!("WP-1.8: exercise_extract")
}
