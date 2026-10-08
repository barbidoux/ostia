//! The signed, declarative verdict policy `ostia.policy.v1` (ADR-09, `docs/contracts/policy.md`).
//!
//! [`load`] verifies the Ed25519 signature over the exact bytes before anything is parsed, then refuses any
//! document the contract does not allow. [`Policy::evaluate`] applies the rules R1 to R7 in the order of the
//! specification; [`medium_verdict`] and [`transferable`] give the mode semantics of
//! `docs/contracts/report.md`. Verdicts come from here only.

use std::collections::{BTreeMap, BTreeSet};

use thiserror::Error;

use crate::engine::EngineResult;
use crate::object::Kind;
use crate::session::Mode;
use crate::verdict::Limit;

mod load;
mod medium;
mod rules;

pub use load::load;
pub use medium::{medium_verdict, transferable};

/// Largest policy file accepted, in bytes.
pub const MAX_POLICY_BYTES: usize = 1 << 20;
/// Size of a detached Ed25519 signature.
pub const SIGNATURE_BYTES: usize = 64;
/// Size of an Ed25519 public key.
pub const KEY_BYTES: usize = 32;

/// Why a policy is refused; the refusal codes of `docs/contracts/report.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The signature does not verify with the trusted key over the exact bytes, or a file is malformed.
    SignatureInvalid,
    /// The signature verifies but the content is refused.
    Invalid,
}

impl Refusal {
    /// `policy_signature_invalid` or `policy_invalid`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::SignatureInvalid => "policy_signature_invalid",
            Self::Invalid => "policy_invalid",
        }
    }
}

/// A refused policy: the refusal and a one-line detail (never the policy content).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{}: {detail}", refusal.code())]
pub struct PolicyError {
    /// Which refusal.
    pub refusal: Refusal,
    /// What was wrong.
    pub detail: String,
}

/// The role of an engine in the policy.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EngineRole {
    /// Hint MALICIOUS is a detection; `trusted_alone`: one is enough (R2).
    Detector {
        /// Whether one detection is enough.
        trusted_alone: bool,
    },
    /// Its score is compared with the thresholds (R4, R5); its hint is ignored.
    Scorer {
        /// Low threshold (R5).
        low: f64,
        /// High threshold (R4).
        high: f64,
    },
    /// Known-bad (R2) and known-good (R3) hashes.
    Reputation,
    /// Risky heuristics (R6).
    Heuristic,
}

/// An indicator of R6 (risky heuristic).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Indicator {
    /// Double extension ending in an executable one (triage).
    DoubleExtension,
    /// Type/extension mismatch (triage).
    ExtensionMismatch,
    /// One to K-1 detections by detectors that are not trusted alone.
    SingleDetection,
    /// A detector's SUSPICIOUS hint, or a heuristic's SUSPICIOUS or MALICIOUS hint.
    SuspiciousHint,
}

/// Extraction and engine limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Deepest object (1 to 64).
    pub max_depth: u32,
    /// Largest compression ratio.
    pub max_ratio: u64,
    /// Bytes extracted from one file's tree.
    pub max_total_bytes: u64,
    /// Entries extracted from one file's tree.
    pub max_entries: u64,
    /// Bytes of an entry path.
    pub max_path_length: u32,
    /// One engine run on one object.
    pub engine_timeout_seconds: u32,
}

/// A verified, valid policy.
#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    /// The policy's `version`.
    pub version: String,
    /// SHA-256 of the exact file bytes.
    pub sha256: [u8; 32],
    /// Engine id -> role.
    pub engines: BTreeMap<String, EngineRole>,
    /// `rules.R1.risky_types`.
    pub risky_types: BTreeSet<String>,
    /// `rules.R2.k`.
    pub k: u32,
    /// `rules.R2.critical_severity`.
    pub critical_severity: u32,
    /// The R6 indicators the policy enables (`rules.R6`).
    pub r6: BTreeSet<Indicator>,
    /// `limits`.
    pub limits: Limits,
}

/// Why an object could not be analysed before any rule looks at engines (R1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// A limit was reached on the object.
    Limit(Limit),
    /// The object could not be read.
    Unreadable,
    /// The object could not be typed or extracted (malformed, encrypted entry, sizes that do not match,
    /// entry path leaving its container).
    Malformed,
}

/// What the pipeline knows about one object when the policy decides.
#[derive(Debug, Clone, Copy)]
pub struct ObjectFacts<'a> {
    /// File, link or special file.
    pub kind: Kind,
    /// Type from content, if identified.
    pub detected_type: Option<&'a str>,
    /// The name's extension does not match the type.
    pub extension_mismatch: bool,
    /// The name has a double extension ending in an executable one.
    pub double_extension: bool,
    /// A failure before the engines, if any.
    pub failure: Option<Failure>,
    /// Every engine result for the object.
    pub results: &'a [EngineResult],
}

/// A device-level finding (D1 in P4, D2 in P5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediumFinding {
    /// D1: device rejected (non-storage interface, re-enumeration): the session is aborted.
    DeviceRejected,
    /// D2: executable content outside files: an alert; blocks only if the policy says so (default: no).
    HiddenPayload,
}

/// What the medium verdict depends on besides the object verdicts.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SessionState {
    /// Transfer mode.
    pub mode: Mode,
    /// The scan budget ran out (FR-14).
    pub expired: bool,
    /// The session stopped (expiry action `abort`, D1).
    pub aborted: bool,
    /// Device-level findings.
    pub findings: Vec<MediumFinding>,
}
