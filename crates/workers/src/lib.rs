//! Ostia's Rust workers (spec §19 `workers/`). Each runs as a throwaway process behind the worker host
//! (`ostia-sandbox`), reads the object from descriptor 3 and answers one framed message (CTR-01). The
//! orchestrator never links this crate: content is parsed here, in a worker, never there (SEC-05).

pub mod triage;
