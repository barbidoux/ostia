//! The triage worker: one framed `AnalyzeRequest` on standard input, the object on descriptor 3, one framed
//! `AnalyzeResponse` carrying `detected_type` on standard output (FR-05, CTR-01).
//!
//! Exit 0 after answering: status OK with the type (`unknown` when no rule matches), or status ERROR with no
//! type when the object cannot be read or matches several rules (a polyglot, Q-55; never one of its types).
//! Exit 2, with nothing on standard output, when the request is not a valid frame; exit 1 when the answer
//! cannot be written.
//!
//! Descriptor 3 is opened again through `/proc/self/fd/3`, which needs no unsafe code; the sandbox of P2 must
//! give the worker `/proc` for it.

use std::fs::File;
use std::io::BufReader;
use std::process::ExitCode;
use std::time::Instant;

use ostia_contracts::v1::{AnalyzeResponse, Finding, Hint, Status};
use ostia_contracts::{
    DEFAULT_MAX_FRAME, current_version, decode_request, read_frame, write_frame,
};
use ostia_core_domain::types::DetectedType;
use ostia_workers::triage::matching_types;

/// Identity of this worker (CTR-03): the rule table is report.md's "Types", version 1.
const ENGINE_ID: &str = "ostia-triage";
const CONTENT_VERSION: &str = "magic-1";

/// The object's descriptor (ADR-03).
const OBJECT: &str = "/proc/self/fd/3";

/// The finding of an object matching several type rules: metadata only, the types it matched.
fn polyglot(types: &[DetectedType]) -> Finding {
    let names: Vec<_> = types.iter().map(|t| t.name()).collect();
    Finding {
        id: "triage.polyglot".into(),
        title: "content matches several type rules".into(),
        severity: 2,
        evidence: format!("types: {}", names.join(", ")),
        attack_ids: Vec::new(),
    }
}

fn main() -> ExitCode {
    let started = Instant::now();
    let request = read_frame(&mut std::io::stdin().lock(), DEFAULT_MAX_FRAME)
        .and_then(|body| decode_request(&body));
    if let Err(error) = request {
        eprintln!("ostia-triage: request refused: {error}");
        return ExitCode::from(2);
    }
    let found = File::open(OBJECT).and_then(|object| matching_types(&mut BufReader::new(object)));
    let (status, detected_type, findings) = match found.as_deref() {
        Ok([]) => (
            Status::Ok,
            DetectedType::Unknown.name().to_owned(),
            Vec::new(),
        ),
        Ok([detected]) => (Status::Ok, detected.name().to_owned(), Vec::new()),
        // A polyglot could not be typed (Q-55): never one of its types.
        Ok(several) => (Status::Error, String::new(), vec![polyglot(several)]),
        Err(error) => {
            eprintln!("ostia-triage: cannot read the object: {error}");
            (Status::Error, String::new(), Vec::new())
        }
    };
    let response = AnalyzeResponse {
        engine_id: ENGINE_ID.into(),
        engine_version: env!("CARGO_PKG_VERSION").into(),
        content_version: CONTENT_VERSION.into(),
        status: status.into(),
        hint: Hint::None.into(),
        score: None,
        findings,
        duration_ms: u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX),
        detected_type,
        version: Some(current_version()),
    };
    // write_frame flushes after the frame.
    match write_frame(&mut std::io::stdout().lock(), &response, DEFAULT_MAX_FRAME) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("ostia-triage: cannot answer: {error}");
            ExitCode::from(1)
        }
    }
}
