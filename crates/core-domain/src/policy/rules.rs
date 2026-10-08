//! The object rules R1 to R7 (spec §8, `docs/contracts/policy.md`, "Object rules"): the first that matches
//! decides, its rule id and contributing engines are recorded, and the explanation names both.

use std::collections::BTreeSet;

use ostia_contracts::v1::{Hint, Status};

use super::{EngineRole, Failure, Indicator, ObjectFacts, Policy};
use crate::engine::EngineResult;
use crate::object::Kind;
use crate::verdict::{Limit, ObjectVerdict, Rule, Score, VerdictError, verdict_of};

/// One engine result as the rules read it.
struct Read<'a> {
    id: &'a str,
    role: Option<EngineRole>,
    status: Option<Status>,
    hint: Hint,
    score: Option<f64>,
    max_severity: Option<u32>,
}

impl<'a> Read<'a> {
    fn new(policy: &Policy, result: &'a EngineResult) -> Self {
        let response = result.response();
        Self {
            id: result.engine_id(),
            role: policy.engines.get(result.engine_id()).copied(),
            status: Status::try_from(response.status).ok(),
            hint: Hint::try_from(response.hint).unwrap_or(Hint::Unspecified),
            score: response.score,
            max_severity: response.findings.iter().map(|f| f.severity).max(),
        }
    }

    fn ok(&self) -> bool {
        self.status == Some(Status::Ok)
    }

    /// A failure of this run (R1): status ERROR, TIMEOUT or unknown, a scorer answering OK without a
    /// score, or an engine the policy gives no role.
    fn failed(&self) -> bool {
        match (self.role, self.status) {
            (None, _) | (_, None | Some(Status::Error | Status::Timeout | Status::Unspecified)) => {
                true
            }
            (Some(EngineRole::Scorer { .. }), Some(Status::Ok)) => self.score.is_none(),
            _ => false,
        }
    }

    fn says(&self, hint: Hint) -> bool {
        self.ok() && self.hint == hint
    }

    fn detector(&self, trusted: bool) -> bool {
        self.role
            == Some(EngineRole::Detector {
                trusted_alone: trusted,
            })
    }
}

/// The verdict, rule, reason and engines of the first matching rule.
struct Decision<'a> {
    rule: Rule,
    reason: String,
    engines: BTreeSet<&'a str>,
    limit: Option<Limit>,
}

impl<'a> Decision<'a> {
    fn new(rule: Rule, reason: impl Into<String>, engines: BTreeSet<&'a str>) -> Self {
        Self {
            rule,
            reason: reason.into(),
            engines,
            limit: None,
        }
    }
}

impl Policy {
    /// The verdict of one object: the first rule of R1 to R7 that matches.
    ///
    /// # Errors
    /// [`VerdictError`] only if the policy built an inconsistent verdict (a bug, never a guess).
    pub fn evaluate(&self, facts: &ObjectFacts<'_>) -> Result<ObjectVerdict, VerdictError> {
        let reads: Vec<Read<'_>> = facts.results.iter().map(|r| Read::new(self, r)).collect();
        let decision = self
            .r1(facts, &reads)
            .or_else(|| self.r2(&reads))
            .or_else(|| r3(&reads))
            .or_else(|| r4_r5(&reads))
            .or_else(|| self.r6(facts, &reads))
            .unwrap_or_else(|| Decision::new(Rule::R7, "no rule matched", BTreeSet::new()));
        let verdict = verdict_of(decision.rule);
        let mut explanation = format!("{:?}: {verdict:?} — {}", decision.rule, decision.reason);
        if !decision.engines.is_empty() {
            let engines: Vec<&str> = decision.engines.iter().copied().collect();
            explanation.push_str(" (engines: ");
            explanation.push_str(&engines.join(", "));
            explanation.push(')');
        }
        let mut decided = ObjectVerdict::new(verdict, decision.rule, &explanation)?
            .with_engines(decision.engines)?;
        if let Some(score) = best_score(&reads) {
            decided = decided.with_score(Score::new(score)?);
        }
        if let Some(limit) = decision.limit {
            decided = decided.with_limit(limit)?;
        }
        Ok(decided)
    }

    /// R1: failure, timeout, limit, unreadable or malformed object, link, unsupported risky type.
    fn r1<'a>(&self, facts: &ObjectFacts<'_>, reads: &[Read<'a>]) -> Option<Decision<'a>> {
        let failed: BTreeSet<&str> = reads.iter().filter(|r| r.failed()).map(|r| r.id).collect();
        let reason = match (facts.kind, facts.failure) {
            (Kind::Symlink, _) => "a symbolic link is never followed or read".to_owned(),
            (Kind::Special, _) => "a special file is never opened".to_owned(),
            (Kind::File, Some(Failure::Limit(limit))) => {
                let mut decision =
                    Decision::new(Rule::R1, format!("limit {limit:?} reached"), failed);
                decision.limit = Some(limit);
                return Some(decision);
            }
            (Kind::File, Some(Failure::Unreadable)) => "the object could not be read".to_owned(),
            (Kind::File, Some(Failure::Malformed)) => {
                "the object could not be typed or extracted".to_owned()
            }
            (Kind::File, None) if !failed.is_empty() => {
                "an engine failed, timed out or has no role in the policy".to_owned()
            }
            (Kind::File, None) => {
                let risky = facts
                    .detected_type
                    .filter(|t| self.risky_types.contains(*t))?;
                if reads.iter().any(Read::ok) {
                    return None;
                }
                format!("no engine supports the risky type {risky}")
            }
        };
        Some(Decision::new(Rule::R1, reason, failed))
    }

    /// R2: known-bad hash, trusted detection, K-of-N detections, critical finding.
    fn r2<'a>(&self, reads: &[Read<'a>]) -> Option<Decision<'a>> {
        let mut engines = BTreeSet::new();
        for read in reads {
            let known_bad = read.role == Some(EngineRole::Reputation) && read.says(Hint::Malicious);
            let trusted = read.detector(true) && read.says(Hint::Malicious);
            let critical = read.ok() && read.max_severity >= Some(self.critical_severity);
            if known_bad || trusted || critical {
                engines.insert(read.id);
            }
        }
        let detections = untrusted_detections(reads);
        if u64::try_from(detections.len()).is_ok_and(|n| n >= self.k) {
            engines.extend(detections);
        }
        (!engines.is_empty()).then(|| {
            Decision::new(
                Rule::R2,
                "known-bad hash, trusted detection, K-of-N detections or critical finding",
                engines,
            )
        })
    }

    /// R6: the indicators the policy enables.
    fn r6<'a>(&self, facts: &ObjectFacts<'_>, reads: &[Read<'a>]) -> Option<Decision<'a>> {
        let mut matched = Vec::new();
        let mut engines = BTreeSet::new();
        if self.r6.contains(&Indicator::DoubleExtension) && facts.double_extension {
            matched.push("double extension");
        }
        if self.r6.contains(&Indicator::ExtensionMismatch) && facts.extension_mismatch {
            matched.push("type/extension mismatch");
        }
        let detections = untrusted_detections(reads);
        if self.r6.contains(&Indicator::SingleDetection) && !detections.is_empty() {
            matched.push("detection by an engine not trusted alone");
            engines.extend(detections);
        }
        if self.r6.contains(&Indicator::SuspiciousHint) {
            let hinted: Vec<&str> = reads
                .iter()
                .filter(|r| {
                    (r.detector(true) || r.detector(false)) && r.says(Hint::Suspicious)
                        || r.role == Some(EngineRole::Heuristic)
                            && (r.says(Hint::Suspicious) || r.says(Hint::Malicious))
                })
                .map(|r| r.id)
                .collect();
            if !hinted.is_empty() {
                matched.push("risky heuristic");
                engines.extend(hinted);
            }
        }
        (!matched.is_empty()).then(|| Decision::new(Rule::R6, matched.join(", "), engines))
    }
}

/// R3: a reputation engine knows the exact hash as good.
fn r3<'a>(reads: &[Read<'a>]) -> Option<Decision<'a>> {
    let engines: BTreeSet<&str> = reads
        .iter()
        .filter(|r| r.role == Some(EngineRole::Reputation) && r.says(Hint::Clean))
        .map(|r| r.id)
        .collect();
    (!engines.is_empty()).then(|| Decision::new(Rule::R3, "known-good hash", engines))
}

/// R4 then R5: a scorer's score at or above its high, then its low threshold.
fn r4_r5<'a>(reads: &[Read<'a>]) -> Option<Decision<'a>> {
    let scored = |above: fn(f64, f64, f64) -> bool| -> BTreeSet<&'a str> {
        reads
            .iter()
            .filter_map(|r| match (r.role, r.ok(), r.score) {
                (Some(EngineRole::Scorer { low, high }), true, Some(score))
                    if above(score, low, high) =>
                {
                    Some(r.id)
                }
                _ => None,
            })
            .collect()
    };
    let high = scored(|score, _, high| score >= high);
    if !high.is_empty() {
        return Some(Decision::new(
            Rule::R4,
            "score at or above the high threshold",
            high,
        ));
    }
    let low = scored(|score, low, _| score >= low);
    (!low.is_empty()).then(|| Decision::new(Rule::R5, "score at or above the low threshold", low))
}

/// Detectors that are not trusted alone and say MALICIOUS.
fn untrusted_detections<'a>(reads: &[Read<'a>]) -> Vec<&'a str> {
    reads
        .iter()
        .filter(|r| r.detector(false) && r.says(Hint::Malicious))
        .map(|r| r.id)
        .collect()
}

/// The highest score among the scorers' results with status OK.
fn best_score(reads: &[Read<'_>]) -> Option<f64> {
    reads
        .iter()
        .filter(|r| matches!(r.role, Some(EngineRole::Scorer { .. })) && r.ok())
        .filter_map(|r| r.score)
        .reduce(f64::max)
}
