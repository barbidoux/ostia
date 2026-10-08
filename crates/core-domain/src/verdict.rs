//! Verdicts of objects and of the medium, and their worst-of ordering (ADR-16).
//!
//! Which verdict an object gets is decided by the signed policy (ADR-09, WP-1.2); this module holds the
//! values, the order and the invariants of the report contract (`docs/contracts/report.md`).

use thiserror::Error;

use crate::object::ObjectId;

/// The verdict of an object or of a medium (FR-09). The order of the variants is the worst-of order of
/// ADR-16: `Clean < Suspicious < Unscannable < Malicious`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Verdict {
    /// Nothing found.
    Clean,
    /// A risk indicator; blocks the object concerned in compliant mode.
    Suspicious,
    /// The object could not be analysed; blocks the medium in compliant mode.
    Unscannable,
    /// A detection; blocks the medium in compliant mode.
    Malicious,
}

impl Verdict {
    /// The name in the report contract: `CLEAN`, `SUSPICIOUS`, `UNSCANNABLE` or `MALICIOUS`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Clean => "CLEAN",
            Self::Suspicious => "SUSPICIOUS",
            Self::Unscannable => "UNSCANNABLE",
            Self::Malicious => "MALICIOUS",
        }
    }

    /// The worse of two verdicts: `Clean < Suspicious < Unscannable < Malicious` (ADR-16).
    #[must_use]
    pub fn worst(self, other: Self) -> Self {
        self.max(other)
    }
}

/// The worst verdict of a collection, or `None` when it is empty (the caller decides what an empty medium
/// means).
pub fn worst_of<I: IntoIterator<Item = Verdict>>(verdicts: I) -> Option<Verdict> {
    verdicts.into_iter().max()
}

/// The policy rule that decided an object verdict (spec §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rule {
    /// Failure, timeout, limit, unsupported risky type: UNSCANNABLE.
    R1,
    /// Known-bad hash, trusted detection, K-of-N, critical finding: MALICIOUS.
    R2,
    /// Exact known-good hash: CLEAN.
    R3,
    /// Score at or above the high threshold: MALICIOUS.
    R4,
    /// Score at or above the low threshold: SUSPICIOUS.
    R5,
    /// Risky heuristic: SUSPICIOUS.
    R6,
    /// None of the above: CLEAN.
    R7,
}

/// The verdict a rule gives (spec §8, `docs/contracts/policy.md`): fixed by the specification, so a
/// policy result that pairs a rule with another verdict is refused.
pub(crate) fn verdict_of(rule: Rule) -> Verdict {
    match rule {
        Rule::R1 => Verdict::Unscannable,
        Rule::R2 | Rule::R4 => Verdict::Malicious,
        Rule::R3 | Rule::R7 => Verdict::Clean,
        Rule::R5 | Rule::R6 => Verdict::Suspicious,
    }
}

/// The limit that made an object UNSCANNABLE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Limit {
    /// Nesting depth of extracted objects.
    Depth,
    /// Compression ratio.
    Ratio,
    /// Bytes extracted from one file's tree.
    TotalSize,
    /// Entries extracted from one file's tree.
    EntryCount,
    /// Length of an entry path.
    PathLength,
    /// Maximum scan time (FR-14).
    ScanTime,
}

impl Limit {
    /// The name in the report contract: `depth`, `ratio`, `total_size`, `entry_count`, `path_length` or
    /// `scan_time`.
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::Depth => "depth",
            Self::Ratio => "ratio",
            Self::TotalSize => "total_size",
            Self::EntryCount => "entry_count",
            Self::PathLength => "path_length",
            Self::ScanTime => "scan_time",
        }
    }
}

/// A score in `[0, 1]` (finite).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Score(f64);

impl Score {
    /// A score, refused when it is not a finite number in `[0, 1]`.
    ///
    /// # Errors
    /// [`VerdictError::ScoreOutOfRange`].
    pub fn new(value: f64) -> Result<Self, VerdictError> {
        if (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(VerdictError::ScoreOutOfRange(value))
        }
    }

    /// The value.
    #[must_use]
    pub fn value(self) -> f64 {
        self.0
    }
}

/// A value the report contract refuses.
#[derive(Debug, Clone, PartialEq, Error)]
pub enum VerdictError {
    /// A score that is not a finite number in `[0, 1]`.
    #[error("score {0} is not a finite number in [0, 1]")]
    ScoreOutOfRange(f64),
    /// An explanation that is empty or only white space.
    #[error("a verdict needs a non-empty explanation")]
    EmptyExplanation,
    /// A rule paired with another verdict than the one the specification gives it.
    #[error("{verdict:?} cannot come from rule {rule:?}")]
    RuleMismatch {
        /// The verdict given.
        verdict: Verdict,
        /// The rule given.
        rule: Rule,
    },
    /// An engine id that is empty.
    #[error("an engine id cannot be empty")]
    EmptyEngineId,
    /// A limit is reported only on an UNSCANNABLE object.
    #[error("a limit is reported only on an UNSCANNABLE verdict, not {0:?}")]
    LimitWithoutUnscannable(Verdict),
}

/// The decision for one object (FR-09): verdict, rule, score, contributing engines, explanation.
#[derive(Debug, Clone, PartialEq)]
pub struct ObjectVerdict {
    verdict: Verdict,
    rule: Rule,
    score: Option<Score>,
    contributing_engines: Vec<String>,
    explanation: String,
    limit: Option<Limit>,
}

impl ObjectVerdict {
    /// A verdict with its rule and explanation.
    ///
    /// # Errors
    /// [`VerdictError::EmptyExplanation`], [`VerdictError::RuleMismatch`].
    pub fn new(verdict: Verdict, rule: Rule, explanation: &str) -> Result<Self, VerdictError> {
        if explanation.trim().is_empty() {
            return Err(VerdictError::EmptyExplanation);
        }
        if verdict_of(rule) != verdict {
            return Err(VerdictError::RuleMismatch { verdict, rule });
        }
        Ok(Self {
            verdict,
            rule,
            score: None,
            contributing_engines: Vec::new(),
            explanation: explanation.to_owned(),
            limit: None,
        })
    }

    /// The same verdict with a score.
    #[must_use]
    pub fn with_score(mut self, score: Score) -> Self {
        self.score = Some(score);
        self
    }

    /// The same verdict with the engines whose results made the rule match (sorted, without duplicates).
    ///
    /// # Errors
    /// [`VerdictError::EmptyEngineId`].
    pub fn with_engines<I: IntoIterator<Item = S>, S: Into<String>>(
        mut self,
        engines: I,
    ) -> Result<Self, VerdictError> {
        let mut engines: Vec<String> = engines.into_iter().map(Into::into).collect();
        if engines.iter().any(String::is_empty) {
            return Err(VerdictError::EmptyEngineId);
        }
        engines.sort();
        engines.dedup();
        self.contributing_engines = engines;
        Ok(self)
    }

    /// The same verdict with the limit that was reached.
    ///
    /// # Errors
    /// [`VerdictError::LimitWithoutUnscannable`].
    pub fn with_limit(mut self, limit: Limit) -> Result<Self, VerdictError> {
        if self.verdict != Verdict::Unscannable {
            return Err(VerdictError::LimitWithoutUnscannable(self.verdict));
        }
        self.limit = Some(limit);
        Ok(self)
    }

    /// The verdict.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        self.verdict
    }

    /// The rule that decided it.
    #[must_use]
    pub fn rule(&self) -> Rule {
        self.rule
    }

    /// The score, if a scorer gave one.
    #[must_use]
    pub fn score(&self) -> Option<Score> {
        self.score
    }

    /// The contributing engines.
    #[must_use]
    pub fn contributing_engines(&self) -> &[String] {
        &self.contributing_engines
    }

    /// The explanation.
    #[must_use]
    pub fn explanation(&self) -> &str {
        &self.explanation
    }

    /// The limit reached, if any.
    #[must_use]
    pub fn limit(&self) -> Option<Limit> {
        self.limit
    }
}

/// The decision for the medium.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MediumVerdict {
    /// The worst verdict (ADR-16).
    pub verdict: Verdict,
    /// Whether the whole medium is blocked (decided by the policy and the mode).
    pub blocked: bool,
    /// The MALICIOUS and UNSCANNABLE objects.
    pub blocking_objects: Vec<ObjectId>,
    /// Device-level findings (D1, D2).
    pub findings: Vec<crate::policy::MediumFinding>,
}
