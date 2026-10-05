//! The Ostia engine contract (`ostia.engine.v1`, ADR-03) and its framing.
//!
//! Messages are generated from `proto/ostia/engine/v1/engine.proto` at build time (ADR-15).

/// Messages of the `ostia.engine.v1` contract.
// prost's generated helpers (`as_str_name`, `from_str_name`) lack `#[must_use]` and write "ProtoBuf"
// without backticks; approved by the owner for this generated module only (Q-21).
#[allow(clippy::must_use_candidate, clippy::doc_markdown)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/ostia.engine.v1.rs"));
}
