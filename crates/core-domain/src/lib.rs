//! Ostia domain model: sessions, media, the object tree and verdicts (WP-1.1). Pure Rust, no I/O.
//!
//! Verdict decisions belong to the signed policy (ADR-09); this crate holds the values, the worst-of order
//! (ADR-16) and the invariants of the object tree and of the report contract. The [`clock::Clock`] trait is
//! here from WP-0.7.

pub mod clock;
pub mod engine;
pub mod object;
pub mod session;
pub mod verdict;
