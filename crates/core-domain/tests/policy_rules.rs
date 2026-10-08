//! The object rules R1 to R7 (spec §8, `docs/contracts/policy.md`): one row per rule condition and per
//! precedence pair. These tables are what mutation testing will score (NFR-14, P3).

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use ostia_contracts::v1::{AnalyzeResponse, Finding, Hint, Status};
use ostia_core_domain::engine::EngineResult;
use ostia_core_domain::object::Kind;
use ostia_core_domain::policy::{Failure, ObjectFacts, Policy, load};
use ostia_core_domain::verdict::{Limit, Rule, Score, Verdict};
use ostia_traceability::req;
use serde_json::{Value, json};

use Verdict::{Clean, Malicious, Suspicious, Unscannable};

const ENGINES: [&str; 6] = ["rep", "av-trusted", "av-a", "av-b", "ember", "heur"];
const DEFAULT_SCORE: f64 = 0.1;

fn document(r6: bool) -> Value {
    json!({
        "schema": "ostia.policy.v1",
        "version": "rules-1",
        "engines": {
            "rep": {"role": "reputation"},
            "av-trusted": {"role": "detector", "trusted_alone": true},
            "av-a": {"role": "detector", "trusted_alone": false},
            "av-b": {"role": "detector", "trusted_alone": false},
            "ember": {"role": "scorer", "thresholds": {"low": 0.5, "high": 0.9}},
            "heur": {"role": "heuristic"}
        },
        "rules": {
            "R1": {"risky_types": ["pe"]},
            "R2": {"k": 2, "critical_severity": 4},
            "R6": {
                "double_extension": r6,
                "extension_mismatch": r6,
                "single_detection": r6,
                "suspicious_hint": r6
            }
        },
        "limits": {
            "max_depth": 8,
            "max_ratio": 200,
            "max_total_bytes": 268_435_456,
            "max_entries": 10_000,
            "max_path_length": 1024,
            "engine_timeout_seconds": 30
        }
    })
}

fn policy(r6: bool) -> Policy {
    let key = SigningKey::from_bytes(&[7; 32]);
    let data = serde_json::to_vec(&document(r6)).expect("serialisable");
    load(
        &data,
        &key.sign(&data).to_bytes(),
        &key.verifying_key().to_bytes(),
    )
    .expect("valid policy")
}

/// One engine's answer for a row.
#[derive(Debug, Clone)]
struct Answer {
    status: Status,
    hint: Hint,
    score: Option<f64>,
    severity: Option<u32>,
}

fn ok(hint: Hint) -> Answer {
    Answer {
        status: Status::Ok,
        hint,
        score: None,
        severity: None,
    }
}

fn status(status: Status) -> Answer {
    Answer {
        status,
        hint: Hint::None,
        score: None,
        severity: None,
    }
}

fn score(value: f64) -> Answer {
    Answer {
        status: Status::Ok,
        hint: Hint::None,
        score: Some(value),
        severity: None,
    }
}

fn finding(severity: u32) -> Answer {
    Answer {
        status: Status::Ok,
        hint: Hint::None,
        score: None,
        severity: Some(severity),
    }
}

fn result(engine_id: &str, answer: &Answer) -> EngineResult {
    let mut response = AnalyzeResponse {
        engine_id: engine_id.into(),
        engine_version: "1.0.0".into(),
        content_version: "rules-1".into(),
        status: answer.status as i32,
        hint: answer.hint as i32,
        score: answer.score,
        duration_ms: 5,
        ..AnalyzeResponse::default()
    };
    if let Some(severity) = answer.severity {
        response.findings.push(Finding {
            id: format!("rule.severity{severity}"),
            title: format!("rule of severity {severity}"),
            severity,
            evidence: "offset 0".into(),
            attack_ids: Vec::new(),
        });
    }
    EngineResult::new(response)
}

/// A row of the table: what the object is, what each engine answers, and the expected decision.
struct Row {
    name: &'static str,
    kind: Kind,
    detected_type: Option<&'static str>,
    mismatch: bool,
    double: bool,
    failure: Option<Failure>,
    /// Engine id -> answer, over the default (OK, NONE; ember scores 0.1).
    answers: Vec<(&'static str, Answer)>,
    /// Engines that answered beyond the policy's.
    extra: Vec<(&'static str, Answer)>,
    verdict: Verdict,
    rule: Rule,
    engines: &'static [&'static str],
    score: Option<f64>,
    limit: Option<Limit>,
}

fn row(name: &'static str, verdict: Verdict, rule: Rule, engines: &'static [&'static str]) -> Row {
    Row {
        name,
        kind: Kind::File,
        detected_type: Some("unknown"),
        mismatch: false,
        double: false,
        failure: None,
        answers: Vec::new(),
        extra: Vec::new(),
        verdict,
        rule,
        engines,
        score: Some(DEFAULT_SCORE),
        limit: None,
    }
}

impl Row {
    fn answer(mut self, engine: &'static str, answer: Answer) -> Self {
        self.answers.push((engine, answer));
        self
    }

    fn every(mut self, answer: &Answer) -> Self {
        for engine in ENGINES {
            self.answers.push((engine, answer.clone()));
        }
        self
    }

    fn typed(mut self, detected_type: &'static str) -> Self {
        self.detected_type = Some(detected_type);
        self
    }

    fn score(mut self, score: Option<f64>) -> Self {
        self.score = score;
        self
    }

    fn results(&self) -> Vec<EngineResult> {
        let mut answers: BTreeMap<&str, Answer> = ENGINES
            .iter()
            .map(|&e| {
                let default = if e == "ember" {
                    score(DEFAULT_SCORE)
                } else {
                    ok(Hint::None)
                };
                (e, default)
            })
            .collect();
        for (engine, answer) in &self.answers {
            answers.insert(engine, answer.clone());
        }
        let mut results: Vec<EngineResult> = answers.iter().map(|(e, a)| result(e, a)).collect();
        results.extend(self.extra.iter().map(|(e, a)| result(e, a)));
        results
    }
}

const NONE: &[&str] = &[];

fn r1_rows() -> Vec<Row> {
    vec![
        // R1: failure, timeout, limit, unsupported risky type.
        row("engine error", Unscannable, Rule::R1, &["av-a"]).answer("av-a", status(Status::Error)),
        row("engine timeout", Unscannable, Rule::R1, &["av-b"])
            .answer("av-b", status(Status::Timeout)),
        row("status unspecified", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", status(Status::Unspecified)),
        row(
            "scorer error with a score",
            Unscannable,
            Rule::R1,
            &["ember"],
        )
        .answer(
            "ember",
            Answer {
                status: Status::Error,
                hint: Hint::None,
                score: Some(0.95),
                severity: None,
            },
        )
        .score(None),
        row(
            "scorer OK without a score",
            Unscannable,
            Rule::R1,
            &["ember"],
        )
        .answer("ember", ok(Hint::None))
        .score(None),
        Row {
            extra: vec![("av-x", ok(Hint::Malicious))],
            ..row(
                "engine without a role in the policy",
                Unscannable,
                Rule::R1,
                &["av-x"],
            )
        },
        Row {
            failure: Some(Failure::Limit(Limit::Depth)),
            limit: Some(Limit::Depth),
            ..row("depth limit", Unscannable, Rule::R1, NONE)
        },
        Row {
            failure: Some(Failure::Limit(Limit::ScanTime)),
            limit: Some(Limit::ScanTime),
            ..row("scan time", Unscannable, Rule::R1, NONE)
        },
        Row {
            failure: Some(Failure::Unreadable),
            ..row("unreadable", Unscannable, Rule::R1, NONE)
        },
        Row {
            failure: Some(Failure::Malformed),
            ..row("malformed archive", Unscannable, Rule::R1, NONE)
        },
        Row {
            kind: Kind::Symlink,
            ..row("symbolic link", Unscannable, Rule::R1, NONE)
        },
        Row {
            kind: Kind::Special,
            ..row("special file", Unscannable, Rule::R1, NONE)
        },
        row("risky type nobody supports", Unscannable, Rule::R1, NONE)
            .typed("pe")
            .every(&status(Status::Unsupported))
            .score(None),
        row("plain type nobody supports", Clean, Rule::R7, NONE)
            .typed("png")
            .every(&status(Status::Unsupported))
            .score(None),
        row("risky type one engine supports", Clean, Rule::R7, NONE)
            .typed("pe")
            .every(&status(Status::Unsupported))
            .answer("av-a", ok(Hint::None))
            .score(None),
    ]
}

fn r2_to_r7_rows() -> Vec<Row> {
    vec![
        // R2: known bad, trusted alone, K of N, critical finding.
        row("known-bad hash", Malicious, Rule::R2, &["rep"]).answer("rep", ok(Hint::Malicious)),
        row("trusted alone", Malicious, Rule::R2, &["av-trusted"])
            .answer("av-trusted", ok(Hint::Malicious)),
        row("K of N", Malicious, Rule::R2, &["av-a", "av-b"])
            .answer("av-a", ok(Hint::Malicious))
            .answer("av-b", ok(Hint::Malicious)),
        row(
            "critical finding of a heuristic",
            Malicious,
            Rule::R2,
            &["heur"],
        )
        .answer("heur", finding(4)),
        row(
            "critical finding of a detector",
            Malicious,
            Rule::R2,
            &["av-a"],
        )
        .answer("av-a", finding(4)),
        row("finding below critical", Clean, Rule::R7, NONE).answer("heur", finding(3)),
        // R3: known good.
        row("known-good hash", Clean, Rule::R3, &["rep"]).answer("rep", ok(Hint::Clean)),
        // R4, R5: scorer thresholds.
        row("score above high", Malicious, Rule::R4, &["ember"])
            .answer("ember", score(0.95))
            .score(Some(0.95)),
        row("score at high", Malicious, Rule::R4, &["ember"])
            .answer("ember", score(0.9))
            .score(Some(0.9)),
        row("score between", Suspicious, Rule::R5, &["ember"])
            .answer("ember", score(0.7))
            .score(Some(0.7)),
        row("score at low", Suspicious, Rule::R5, &["ember"])
            .answer("ember", score(0.5))
            .score(Some(0.5)),
        row("score below low", Clean, Rule::R7, NONE)
            .answer("ember", score(0.49))
            .score(Some(0.49)),
        row("scorer hint ignored", Clean, Rule::R7, NONE).answer(
            "ember",
            Answer {
                status: Status::Ok,
                hint: Hint::Malicious,
                score: Some(0.1),
                severity: None,
            },
        ),
        // R6: risky heuristics.
        row("single detection", Suspicious, Rule::R6, &["av-a"])
            .answer("av-a", ok(Hint::Malicious)),
        row(
            "heuristic not counted in K",
            Suspicious,
            Rule::R6,
            &["av-a", "heur"],
        )
        .answer("av-a", ok(Hint::Malicious))
        .answer("heur", ok(Hint::Malicious)),
        row("detector suspicious", Suspicious, Rule::R6, &["av-b"])
            .answer("av-b", ok(Hint::Suspicious)),
        row("heuristic suspicious", Suspicious, Rule::R6, &["heur"])
            .answer("heur", ok(Hint::Suspicious)),
        row("heuristic malicious", Suspicious, Rule::R6, &["heur"])
            .answer("heur", ok(Hint::Malicious)),
        Row {
            double: true,
            ..row("double extension", Suspicious, Rule::R6, NONE)
        },
        Row {
            mismatch: true,
            ..row("extension mismatch", Suspicious, Rule::R6, NONE)
        },
        // R7: nothing.
        row("nothing found", Clean, Rule::R7, NONE),
        row("detector clean hint", Clean, Rule::R7, NONE).answer("av-a", ok(Hint::Clean)),
    ]
}

fn error() -> Answer {
    status(Status::Error)
}

fn r1_precedence_rows() -> Vec<Row> {
    vec![
        row("R1 over R2", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("av-trusted", ok(Hint::Malicious)),
        Row {
            failure: Some(Failure::Limit(Limit::Ratio)),
            limit: Some(Limit::Ratio),
            ..row("limit over R2", Unscannable, Rule::R1, NONE)
                .answer("av-trusted", ok(Hint::Malicious))
        },
        row("R1 over R3", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("rep", ok(Hint::Clean)),
        row("R1 over R4", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("ember", score(0.95))
            .score(Some(0.95)),
        row("R1 over R5", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("ember", score(0.7))
            .score(Some(0.7)),
        Row {
            double: true,
            ..row("R1 over R6", Unscannable, Rule::R1, &["av-a"])
                .answer("av-a", error())
                .answer("heur", ok(Hint::Suspicious))
        },
    ]
}

fn later_precedence_rows() -> Vec<Row> {
    vec![
        row("R2 over R3", Malicious, Rule::R2, &["av-trusted"])
            .answer("av-trusted", ok(Hint::Malicious))
            .answer("rep", ok(Hint::Clean)),
        row("K of N over R3", Malicious, Rule::R2, &["av-a", "av-b"])
            .answer("av-a", ok(Hint::Malicious))
            .answer("av-b", ok(Hint::Malicious))
            .answer("rep", ok(Hint::Clean)),
        row("critical finding over R3", Malicious, Rule::R2, &["heur"])
            .answer("heur", finding(4))
            .answer("rep", ok(Hint::Clean)),
        row("R2 over R4", Malicious, Rule::R2, &["av-trusted"])
            .answer("av-trusted", ok(Hint::Malicious))
            .answer("ember", score(0.95))
            .score(Some(0.95)),
        row("R2 over R5", Malicious, Rule::R2, &["av-trusted"])
            .answer("av-trusted", ok(Hint::Malicious))
            .answer("ember", score(0.7))
            .score(Some(0.7)),
        Row {
            double: true,
            ..row("R2 over R6", Malicious, Rule::R2, &["av-trusted"])
                .answer("av-trusted", ok(Hint::Malicious))
                .answer("heur", ok(Hint::Suspicious))
        },
        row("R3 over R4", Clean, Rule::R3, &["rep"])
            .answer("rep", ok(Hint::Clean))
            .answer("ember", score(0.95))
            .score(Some(0.95)),
        row("R3 over R5", Clean, Rule::R3, &["rep"])
            .answer("rep", ok(Hint::Clean))
            .answer("ember", score(0.7))
            .score(Some(0.7)),
        Row {
            double: true,
            mismatch: true,
            ..row("R3 over R6", Clean, Rule::R3, &["rep"])
                .answer("rep", ok(Hint::Clean))
                .answer("heur", ok(Hint::Suspicious))
                .answer("av-a", ok(Hint::Malicious))
        },
        Row {
            double: true,
            ..row("R4 over R6", Malicious, Rule::R4, &["ember"])
                .answer("ember", score(0.95))
                .answer("heur", ok(Hint::Suspicious))
                .score(Some(0.95))
        },
        Row {
            mismatch: true,
            ..row("R5 over R6", Suspicious, Rule::R5, &["ember"])
                .answer("ember", score(0.7))
                .answer("av-a", ok(Hint::Malicious))
                .score(Some(0.7))
        },
    ]
}

fn check(policy: &Policy, row: &Row) {
    let results = row.results();
    let facts = ObjectFacts {
        kind: row.kind,
        detected_type: row.detected_type,
        extension_mismatch: row.mismatch,
        double_extension: row.double,
        failure: row.failure,
        results: &results,
    };
    let decided = policy.evaluate(&facts).expect("a consistent verdict");
    let name = row.name;
    assert_eq!(
        (decided.verdict(), decided.rule()),
        (row.verdict, row.rule),
        "{name}"
    );
    assert_eq!(decided.contributing_engines(), row.engines, "{name}");
    assert_eq!(decided.score().map(Score::value), row.score, "{name}");
    assert_eq!(decided.limit(), row.limit, "{name}");
    let explanation = decided.explanation();
    let rule = format!("{:?}", row.rule);
    assert!(explanation.contains(&rule), "{name}: {explanation:?}");
    for engine in row.engines {
        assert!(explanation.contains(engine), "{name}: {explanation:?}");
    }
}

#[req("FR-09")]
#[test]
fn each_rule_condition_decides_the_verdict() {
    let policy = policy(true);
    for row in r1_rows().into_iter().chain(r2_to_r7_rows()) {
        check(&policy, &row);
    }
}

#[req("FR-09")]
#[test]
fn earlier_rules_win_every_precedence_pair() {
    let policy = policy(true);
    for row in r1_precedence_rows()
        .into_iter()
        .chain(later_precedence_rows())
    {
        check(&policy, &row);
    }
}

#[req("FR-09")]
#[test]
fn r6_indicators_disabled_by_the_policy_do_not_decide() {
    let policy = policy(false);
    let rows = vec![
        Row {
            double: true,
            ..row("double extension, disabled", Clean, Rule::R7, NONE)
        },
        Row {
            mismatch: true,
            ..row("extension mismatch, disabled", Clean, Rule::R7, NONE)
        },
        row("single detection, disabled", Clean, Rule::R7, NONE)
            .answer("av-a", ok(Hint::Malicious)),
        row("suspicious hint, disabled", Clean, Rule::R7, NONE)
            .answer("heur", ok(Hint::Suspicious)),
        // R2 does not depend on R6 flags.
        row(
            "K of N with R6 disabled",
            Malicious,
            Rule::R2,
            &["av-a", "av-b"],
        )
        .answer("av-a", ok(Hint::Malicious))
        .answer("av-b", ok(Hint::Malicious)),
    ];
    for row in rows {
        check(&policy, &row);
    }
}
