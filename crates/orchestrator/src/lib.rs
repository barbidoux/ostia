//! The orchestrator (spec §19 `orchestrator/`): it drives the workers over a medium's objects and never reads
//! their content itself (SEC-05): typing and extraction happen in workers behind the worker host.

pub mod extraction;
