//! The object rules R1 to R7 (spec §8, `docs/contracts/policy.md`): one row per rule condition and per
//! precedence pair, and tables over the policy's parameters (K, critical severity, each R6 indicator). These
//! tables are what mutation testing will score (NFR-14, P3).

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

const ENGINES: [&str; 8] = [
    "rep",
    "av-trusted",
    "av-a",
    "av-b",
    "av-c",
    "ember",
    "ember2",
    "heur",
];
const SCORERS: [&str; 2] = ["ember", "ember2"];
const DEFAULT_SCORE: f64 = 0.1;

/// The R6 indicators, by their policy key.
const R6_KEYS: [&str; 4] = [
    "double_extension",
    "extension_mismatch",
    "single_detection",
    "suspicious_hint",
];

/// The test policy: K = 2, critical severity 4, every R6 indicator on, unless changed.
fn document() -> Value {
    json!({
        "schema": "ostia.policy.v1",
        "version": "rules-1",
        "engines": {
            "rep": {"role": "reputation"},
            "av-trusted": {"role": "detector", "trusted_alone": true},
            "av-a": {"role": "detector", "trusted_alone": false},
            "av-b": {"role": "detector", "trusted_alone": false},
            "av-c": {"role": "detector", "trusted_alone": false},
            "ember": {"role": "scorer", "thresholds": {"low": 0.5, "high": 0.9}},
            "ember2": {"role": "scorer", "thresholds": {"low": 0.3, "high": 0.6}},
            "heur": {"role": "heuristic"}
        },
        "rules": {
            "R1": {"risky_types": ["pe"]},
            "R2": {"k": 2, "critical_severity": 4},
            "R6": {
                "double_extension": true,
                "extension_mismatch": true,
                "single_detection": true,
                "suspicious_hint": true
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

fn policy_from(document: &Value) -> Policy {
    let key = SigningKey::from_bytes(&[7; 32]);
    let data = serde_json::to_vec(document).expect("serialisable");
    load(
        &data,
        &key.sign(&data).to_bytes(),
        &key.verifying_key().to_bytes(),
    )
    .expect("valid policy")
}

fn policy() -> Policy {
    policy_from(&document())
}

/// The test policy with `value` at `rules.<rule>.<key>`.
fn policy_with(rule: &str, key: &str, value: Value) -> Policy {
    let mut document = document();
    document["rules"][rule][key] = value;
    policy_from(&document)
}

/// One engine's answer for a row. `status` is the raw protobuf value, so unknown values can be tested.
#[derive(Debug, Clone)]
struct Answer {
    status: i32,
    hint: Hint,
    score: Option<f64>,
    severity: Option<u32>,
}

fn answer(status: Status, hint: Hint) -> Answer {
    Answer {
        status: status as i32,
        hint,
        score: None,
        severity: None,
    }
}

fn ok(hint: Hint) -> Answer {
    answer(Status::Ok, hint)
}

fn status(status: Status) -> Answer {
    answer(status, Hint::None)
}

fn score(value: f64) -> Answer {
    Answer {
        score: Some(value),
        ..ok(Hint::None)
    }
}

fn finding(severity: u32) -> Answer {
    Answer {
        severity: Some(severity),
        ..ok(Hint::None)
    }
}

fn result(engine_id: &str, answer: &Answer) -> EngineResult {
    let mut response = AnalyzeResponse {
        engine_id: engine_id.into(),
        engine_version: "1.0.0".into(),
        content_version: "rules-1".into(),
        status: answer.status,
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
    /// Engine id -> answer, over the default (OK, NONE; scorers score 0.1).
    answers: Vec<(&'static str, Answer)>,
    /// Results beyond one per policy engine.
    extra: Vec<(&'static str, Answer)>,
    verdict: Verdict,
    rule: Rule,
    engines: &'static [&'static str],
    score: Option<f64>,
    limit: Option<Limit>,
    /// Text the explanation must contain besides the rule and the engines.
    mentions: &'static [&'static str],
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
        mentions: &[],
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

    fn extra(mut self, engine: &'static str, answer: Answer) -> Self {
        self.extra.push((engine, answer));
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

    fn failure(mut self, failure: Failure) -> Self {
        self.failure = Some(failure);
        if let Failure::Limit(limit) = failure {
            self.limit = Some(limit);
        }
        self
    }

    fn kind(mut self, kind: Kind) -> Self {
        self.kind = kind;
        self
    }

    fn double(mut self) -> Self {
        self.double = true;
        self
    }

    fn mismatch(mut self) -> Self {
        self.mismatch = true;
        self
    }

    fn mentions(mut self, mentions: &'static [&'static str]) -> Self {
        self.mentions = mentions;
        self
    }

    fn results(&self) -> Vec<EngineResult> {
        let mut answers: BTreeMap<&str, Answer> = ENGINES
            .iter()
            .map(|&e| {
                let default = if SCORERS.contains(&e) {
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
    let verdict = format!("{:?}", row.verdict).to_uppercase();
    for expected in [rule.as_str(), verdict.as_str()]
        .into_iter()
        .chain(row.engines.iter().copied())
        .chain(row.mentions.iter().copied())
    {
        assert!(
            explanation.contains(expected),
            "{name}: {expected:?} not in {explanation:?}"
        );
    }
}

fn check_all(policy: &Policy, rows: Vec<Row>) {
    for row in rows {
        check(policy, &row);
    }
}

fn r1_rows() -> Vec<Row> {
    vec![
        row("engine error", Unscannable, Rule::R1, &["av-a"]).answer("av-a", status(Status::Error)),
        row("engine timeout", Unscannable, Rule::R1, &["av-b"])
            .answer("av-b", status(Status::Timeout)),
        row("status unspecified", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", status(Status::Unspecified)),
        row("unknown status value", Unscannable, Rule::R1, &["av-a"]).answer(
            "av-a",
            Answer {
                status: 7,
                ..ok(Hint::None)
            },
        ),
        row(
            "scorer error with a score",
            Unscannable,
            Rule::R1,
            &["ember"],
        )
        .answer(
            "ember",
            Answer {
                score: Some(0.95),
                ..status(Status::Error)
            },
        )
        .score(Some(DEFAULT_SCORE)),
        row(
            "scorer OK without a score",
            Unscannable,
            Rule::R1,
            &["ember"],
        )
        .answer("ember", ok(Hint::None)),
        row(
            "scorer score not a number",
            Unscannable,
            Rule::R1,
            &["ember"],
        )
        .answer("ember", score(f64::NAN)),
        row("scorer score below 0", Unscannable, Rule::R1, &["ember"]).answer("ember", score(-0.1)),
        row("scorer score above 1", Unscannable, Rule::R1, &["ember"]).answer("ember", score(1.5)),
        row(
            "engine without a role in the policy",
            Unscannable,
            Rule::R1,
            &["av-x"],
        )
        .extra("av-x", ok(Hint::Malicious)),
        row(
            "two results of one engine",
            Unscannable,
            Rule::R1,
            &["av-a"],
        )
        .extra("av-a", ok(Hint::None)),
        row("engine result without an id", Unscannable, Rule::R1, NONE)
            .extra("", ok(Hint::Malicious)),
        row(
            "unsupported with a hint",
            Unscannable,
            Rule::R1,
            &["av-trusted"],
        )
        .answer("av-trusted", answer(Status::Unsupported, Hint::Malicious)),
        row(
            "unsupported with a finding",
            Unscannable,
            Rule::R1,
            &["heur"],
        )
        .answer(
            "heur",
            Answer {
                severity: Some(4),
                ..status(Status::Unsupported)
            },
        ),
        row(
            "unsupported with a score",
            Unscannable,
            Rule::R1,
            &["ember"],
        )
        .answer(
            "ember",
            Answer {
                score: Some(0.2),
                ..status(Status::Unsupported)
            },
        )
        .score(Some(DEFAULT_SCORE)),
    ]
}

fn r1_object_rows() -> Vec<Row> {
    vec![
        row("depth limit", Unscannable, Rule::R1, NONE)
            .failure(Failure::Limit(Limit::Depth))
            .mentions(&["depth"]),
        row("total size limit", Unscannable, Rule::R1, NONE)
            .failure(Failure::Limit(Limit::TotalSize))
            .mentions(&["total_size"]),
        row("scan time", Unscannable, Rule::R1, NONE)
            .failure(Failure::Limit(Limit::ScanTime))
            .mentions(&["scan_time"]),
        row("unreadable", Unscannable, Rule::R1, NONE).failure(Failure::Unreadable),
        row("malformed archive", Unscannable, Rule::R1, NONE).failure(Failure::Malformed),
        row("symbolic link", Unscannable, Rule::R1, NONE).kind(Kind::Symlink),
        row("special file", Unscannable, Rule::R1, NONE).kind(Kind::Special),
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

fn r2_r3_rows() -> Vec<Row> {
    vec![
        row("known-bad hash", Malicious, Rule::R2, &["rep"]).answer("rep", ok(Hint::Malicious)),
        row("trusted alone", Malicious, Rule::R2, &["av-trusted"])
            .answer("av-trusted", ok(Hint::Malicious)),
        row("K of N, K = 2", Malicious, Rule::R2, &["av-a", "av-b"])
            .answer("av-a", ok(Hint::Malicious))
            .answer("av-b", ok(Hint::Malicious)),
        row(
            "more than K",
            Malicious,
            Rule::R2,
            &["av-a", "av-b", "av-c"],
        )
        .answer("av-a", ok(Hint::Malicious))
        .answer("av-b", ok(Hint::Malicious))
        .answer("av-c", ok(Hint::Malicious)),
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
        row("known-good hash", Clean, Rule::R3, &["rep"]).answer("rep", ok(Hint::Clean)),
    ]
}

fn scorer_rows() -> Vec<Row> {
    vec![
        row("score above high", Malicious, Rule::R4, &["ember"])
            .answer("ember", score(0.95))
            .score(Some(0.95))
            .mentions(&["0.95", "0.9"]),
        row("score at high", Malicious, Rule::R4, &["ember"])
            .answer("ember", score(0.9))
            .score(Some(0.9)),
        row("score between", Suspicious, Rule::R5, &["ember"])
            .answer("ember", score(0.7))
            .score(Some(0.7))
            .mentions(&["0.7", "0.5"]),
        row("score at low", Suspicious, Rule::R5, &["ember"])
            .answer("ember", score(0.5))
            .score(Some(0.5)),
        row("score below low", Clean, Rule::R7, NONE)
            .answer("ember", score(0.49))
            .score(Some(0.49)),
        row("scorer hint ignored", Clean, Rule::R7, NONE).answer(
            "ember",
            Answer {
                score: Some(0.1),
                ..ok(Hint::Malicious)
            },
        ),
        row("scorer suspicious hint ignored", Clean, Rule::R7, NONE).answer(
            "ember",
            Answer {
                score: Some(0.1),
                ..ok(Hint::Suspicious)
            },
        ),
        // Each scorer is compared with its own thresholds; the score is the highest.
        row(
            "second scorer above its high",
            Malicious,
            Rule::R4,
            &["ember2"],
        )
        .answer("ember", score(0.7))
        .answer("ember2", score(0.65))
        .score(Some(0.7)),
        row(
            "first scorer above its high",
            Malicious,
            Rule::R4,
            &["ember"],
        )
        .answer("ember", score(0.95))
        .answer("ember2", score(0.4))
        .score(Some(0.95)),
        row("second scorer between", Suspicious, Rule::R5, &["ember2"])
            .answer("ember", score(0.1))
            .answer("ember2", score(0.35))
            .score(Some(0.35)),
        row(
            "bad score of one scorer among two",
            Unscannable,
            Rule::R1,
            &["ember"],
        )
        .answer("ember", score(f64::NAN))
        .answer("ember2", score(0.1)),
    ]
}

fn r6_r7_rows() -> Vec<Row> {
    vec![
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
        row(
            "trusted detector suspicious",
            Suspicious,
            Rule::R6,
            &["av-trusted"],
        )
        .answer("av-trusted", ok(Hint::Suspicious)),
        row("heuristic suspicious", Suspicious, Rule::R6, &["heur"])
            .answer("heur", ok(Hint::Suspicious)),
        row("heuristic malicious", Suspicious, Rule::R6, &["heur"])
            .answer("heur", ok(Hint::Malicious)),
        row("reputation suspicious ignored", Clean, Rule::R7, NONE)
            .answer("rep", ok(Hint::Suspicious)),
        row("double extension", Suspicious, Rule::R6, NONE)
            .double()
            .mentions(&["double extension"]),
        row("extension mismatch", Suspicious, Rule::R6, NONE)
            .mismatch()
            .mentions(&["mismatch"]),
        row("nothing found", Clean, Rule::R7, NONE),
        row("detector clean hint", Clean, Rule::R7, NONE).answer("av-a", ok(Hint::Clean)),
    ]
}

fn r1_precedence_rows() -> Vec<Row> {
    let error = || status(Status::Error);
    vec![
        row("R1 over R2", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("av-trusted", ok(Hint::Malicious)),
        row("limit over R2", Unscannable, Rule::R1, NONE)
            .failure(Failure::Limit(Limit::Ratio))
            .answer("av-trusted", ok(Hint::Malicious)),
        row("R1 over R3", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("rep", ok(Hint::Clean)),
        row("limit over R3", Unscannable, Rule::R1, NONE)
            .failure(Failure::Limit(Limit::Ratio))
            .answer("rep", ok(Hint::Clean)),
        row("malformed over R3", Unscannable, Rule::R1, NONE)
            .failure(Failure::Malformed)
            .answer("rep", ok(Hint::Clean)),
        row("link over R3", Unscannable, Rule::R1, NONE)
            .kind(Kind::Symlink)
            .answer("rep", ok(Hint::Clean)),
        row("R1 over R4", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("ember", score(0.95))
            .score(Some(0.95)),
        row("R1 over R5", Unscannable, Rule::R1, &["av-a"])
            .answer("av-a", error())
            .answer("ember", score(0.7))
            .score(Some(0.7)),
        row("R1 over R6", Unscannable, Rule::R1, &["av-a"])
            .double()
            .answer("av-a", error())
            .answer("heur", ok(Hint::Suspicious)),
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
        row("R2 over R6", Malicious, Rule::R2, &["av-trusted"])
            .double()
            .answer("av-trusted", ok(Hint::Malicious))
            .answer("heur", ok(Hint::Suspicious)),
        row("R3 over R4", Clean, Rule::R3, &["rep"])
            .answer("rep", ok(Hint::Clean))
            .answer("ember", score(0.95))
            .score(Some(0.95)),
        row("R3 over R5", Clean, Rule::R3, &["rep"])
            .answer("rep", ok(Hint::Clean))
            .answer("ember", score(0.7))
            .score(Some(0.7)),
        row("R3 over R6", Clean, Rule::R3, &["rep"])
            .double()
            .mismatch()
            .answer("rep", ok(Hint::Clean))
            .answer("heur", ok(Hint::Suspicious))
            .answer("av-a", ok(Hint::Malicious)),
        row("R4 over R5", Malicious, Rule::R4, &["ember2"])
            .answer("ember", score(0.7))
            .answer("ember2", score(0.65))
            .score(Some(0.7)),
        row("R4 over R6", Malicious, Rule::R4, &["ember"])
            .double()
            .answer("ember", score(0.95))
            .answer("heur", ok(Hint::Suspicious))
            .score(Some(0.95)),
        row("R5 over R6", Suspicious, Rule::R5, &["ember"])
            .mismatch()
            .answer("ember", score(0.7))
            .answer("av-a", ok(Hint::Malicious))
            .score(Some(0.7)),
    ]
}

#[req("FR-09")]
#[test]
fn r1_conditions_make_the_object_unscannable() {
    check_all(&policy(), r1_rows());
    check_all(&policy(), r1_object_rows());
}

#[req("FR-09")]
#[test]
fn r2_and_r3_conditions_decide_the_verdict() {
    check_all(&policy(), r2_r3_rows());
}

#[req("FR-09")]
#[test]
fn scorers_are_compared_with_their_own_thresholds() {
    check_all(&policy(), scorer_rows());
}

#[req("FR-09")]
#[test]
fn r6_and_r7_conditions_decide_the_verdict() {
    check_all(&policy(), r6_r7_rows());
}

#[req("FR-09")]
#[test]
fn earlier_rules_win_every_precedence_pair() {
    let policy = policy();
    check_all(&policy, r1_precedence_rows());
    check_all(&policy, later_precedence_rows());
}

#[req("FR-09")]
#[test]
fn k_comes_from_the_policy() {
    let detections = |n: usize| {
        let ids: &[&'static str] = &["av-a", "av-b", "av-c"];
        let engines: &'static [&'static str] = match n {
            2 => &["av-a", "av-b"],
            _ => &["av-a", "av-b", "av-c"],
        };
        let (verdict, rule) = if n >= 3 {
            (Malicious, Rule::R2)
        } else {
            (Suspicious, Rule::R6)
        };
        ids.iter()
            .take(n)
            .fold(row("detections, K = 3", verdict, rule, engines), |r, id| {
                r.answer(id, ok(Hint::Malicious))
            })
    };
    check_all(
        &policy_with("R2", "k", json!(3)),
        vec![detections(2), detections(3)],
    );
}

#[req("FR-09")]
#[test]
fn critical_severity_comes_from_the_policy() {
    let policy = policy_with("R2", "critical_severity", json!(3));
    check_all(
        &policy,
        vec![
            row("severity 4 over 3", Malicious, Rule::R2, &["heur"]).answer("heur", finding(4)),
            row("severity 3 at 3", Malicious, Rule::R2, &["heur"]).answer("heur", finding(3)),
            row("severity 2 below 3", Clean, Rule::R7, NONE).answer("heur", finding(2)),
        ],
    );
}

/// One row per R6 indicator, and the key that disables it.
fn indicator_rows() -> Vec<(&'static str, Vec<Row>)> {
    let on = |name| row(name, Suspicious, Rule::R6, NONE);
    vec![
        ("double_extension", vec![on("double extension").double()]),
        (
            "extension_mismatch",
            vec![on("extension mismatch").mismatch()],
        ),
        (
            "single_detection",
            vec![
                row("single detection", Suspicious, Rule::R6, &["av-a"])
                    .answer("av-a", ok(Hint::Malicious)),
            ],
        ),
        (
            "suspicious_hint",
            vec![
                row("detector suspicious", Suspicious, Rule::R6, &["av-b"])
                    .answer("av-b", ok(Hint::Suspicious)),
                row("heuristic suspicious", Suspicious, Rule::R6, &["heur"])
                    .answer("heur", ok(Hint::Suspicious)),
                row("heuristic malicious", Suspicious, Rule::R6, &["heur"])
                    .answer("heur", ok(Hint::Malicious)),
            ],
        ),
    ]
}

#[req("FR-09")]
#[test]
fn each_r6_indicator_is_switched_by_its_own_key() {
    for disabled in R6_KEYS {
        let policy = policy_with("R6", disabled, json!(false));
        for (key, rows) in indicator_rows() {
            for mut row in rows {
                if key == disabled {
                    (row.verdict, row.rule, row.engines) = (Clean, Rule::R7, NONE);
                    row.mentions = &[];
                }
                check(&policy, &row);
            }
        }
    }
}

#[req("FR-09")]
#[test]
fn r2_does_not_depend_on_the_r6_indicators() {
    let mut document = document();
    for key in R6_KEYS {
        document["rules"]["R6"][key] = json!(false);
    }
    check(
        &policy_from(&document),
        &row("K of N with R6 off", Malicious, Rule::R2, &["av-a", "av-b"])
            .answer("av-a", ok(Hint::Malicious))
            .answer("av-b", ok(Hint::Malicious)),
    );
}
