//! Verdicts, their worst-of ordering (ADR-16) and the object-verdict invariants of the report and policy
//! contracts (`docs/contracts/report.md`, `docs/contracts/policy.md`).

use ostia_core_domain::verdict::{
    Limit, ObjectVerdict, Rule, Score, Verdict, VerdictError, worst_of,
};
use ostia_traceability::req;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

use Verdict::{Clean, Malicious, Suspicious, Unscannable};

/// Every verdict, from best to worst (ADR-16): the literal oracle of these tests.
const ORDER: [Verdict; 4] = [Clean, Suspicious, Unscannable, Malicious];

/// The verdict each rule gives (spec §8).
const RULES: [(Rule, Verdict); 7] = [
    (Rule::R1, Unscannable),
    (Rule::R2, Malicious),
    (Rule::R3, Clean),
    (Rule::R4, Malicious),
    (Rule::R5, Suspicious),
    (Rule::R6, Suspicious),
    (Rule::R7, Clean),
];

fn fixed_seed() -> Config {
    Config {
        cases: 256,
        rng_seed: RngSeed::Fixed(0x0a_d1_60_16),
        // A fixed seed replays every case; no regression file is written.
        failure_persistence: None,
        ..Config::default()
    }
}

/// Position in ADR-16's order, from the literal table (never from the code under test).
fn rank(v: Verdict) -> usize {
    ORDER
        .iter()
        .position(|&x| x == v)
        .expect("every verdict is in ORDER")
}

fn verdict() -> impl Strategy<Value = Verdict> {
    prop::sample::select(ORDER.to_vec())
}

#[req("FR-09")]
#[test]
fn worst_of_two_follows_clean_suspicious_unscannable_malicious() {
    for (i, &better) in ORDER.iter().enumerate() {
        for &worse in &ORDER[i..] {
            assert_eq!(better.worst(worse), worse, "{better:?} vs {worse:?}");
            assert_eq!(worse.worst(better), worse, "{worse:?} vs {better:?}");
        }
    }
}

#[req("FR-09")]
#[test]
fn malicious_ranks_above_unscannable() {
    assert_eq!(Unscannable.worst(Malicious), Malicious);
    assert_eq!(
        worst_of([Unscannable, Clean, Malicious, Suspicious]),
        Some(Malicious)
    );
}

#[req("FR-09")]
#[test]
fn worst_of_nothing_is_none() {
    assert_eq!(worst_of([]), None);
}

#[req("FR-09")]
#[test]
fn worst_of_one_is_itself() {
    for v in ORDER {
        assert_eq!(worst_of([v]), Some(v));
    }
}

#[req("FR-09")]
#[test]
fn worst_is_the_higher_rank_for_every_pair() {
    // Exhaustive over the 16 pairs: commutative, idempotent, and the ADR-16 rank.
    for a in ORDER {
        for b in ORDER {
            assert_eq!(rank(a.worst(b)), rank(a).max(rank(b)), "{a:?} vs {b:?}");
            assert_eq!(a.worst(b), b.worst(a), "{a:?} vs {b:?}");
        }
        assert_eq!(a.worst(a), a);
    }
}

#[req("FR-09")]
#[test]
fn worst_is_associative_for_every_triple() {
    for a in ORDER {
        for b in ORDER {
            for c in ORDER {
                assert_eq!(
                    a.worst(b).worst(c),
                    a.worst(b.worst(c)),
                    "{a:?} {b:?} {c:?}"
                );
            }
        }
    }
}

proptest! {
    #![proptest_config(fixed_seed())]

    #[req("FR-09")]
    #[test]
    fn worst_of_is_the_highest_rank(verdicts in prop::collection::vec(verdict(), 1..16)) {
        let expected = verdicts.iter().copied().map(rank).max();
        prop_assert_eq!(worst_of(verdicts).map(rank), expected);
    }

    #[req("FR-09")]
    #[test]
    fn adding_an_object_never_improves_the_verdict(
        verdicts in prop::collection::vec(verdict(), 1..16),
        added in verdict(),
    ) {
        let before = worst_of(verdicts.clone()).map(rank);
        let mut more = verdicts;
        more.push(added);
        let after = worst_of(more).map(rank);
        prop_assert!(after >= before, "{after:?} < {before:?}");
        prop_assert!(after >= Some(rank(added)));
    }

    #[req("FR-09")]
    #[test]
    fn worst_of_does_not_depend_on_order(
        (verdicts, shuffled) in prop::collection::vec(verdict(), 1..16)
            .prop_flat_map(|v| (Just(v.clone()), Just(v).prop_shuffle())),
    ) {
        prop_assert_eq!(worst_of(verdicts), worst_of(shuffled));
    }
}

#[req("FR-09")]
#[test]
fn object_verdict_carries_rule_score_engines_and_explanation() {
    let decided = ObjectVerdict::new(
        Suspicious,
        Rule::R5,
        "R5: ember scored 0.7 (low 0.5, high 0.9)",
    )
    .expect("valid")
    .with_score(Score::new(0.7).expect("in range"))
    .with_engines(["ember"])
    .expect("engine ids");
    assert_eq!(decided.verdict(), Suspicious);
    assert_eq!(decided.rule(), Rule::R5);
    assert_eq!(decided.score().map(Score::value), Some(0.7));
    assert_eq!(decided.contributing_engines(), ["ember".to_owned()]);
    assert_eq!(
        decided.explanation(),
        "R5: ember scored 0.7 (low 0.5, high 0.9)"
    );
    assert_eq!(decided.limit(), None);
}

#[req("FR-09")]
#[test]
fn contributing_engines_are_sorted_without_duplicates() {
    let decided = ObjectVerdict::new(Malicious, Rule::R2, "R2: av-b and av-a detected it")
        .expect("valid")
        .with_engines(["av-b", "av-a", "av-b"])
        .expect("engine ids");
    assert_eq!(
        decided.contributing_engines(),
        ["av-a".to_owned(), "av-b".to_owned()]
    );
}

#[req("FR-09")]
#[test]
fn empty_engine_id_is_refused() {
    let decided = ObjectVerdict::new(Malicious, Rule::R2, "R2: detected").expect("valid");
    assert_eq!(
        decided.with_engines(["av-a", ""]),
        Err(VerdictError::EmptyEngineId)
    );
}

#[req("FR-09")]
#[test]
fn verdict_without_explanation_is_refused() {
    for explanation in ["", "   ", "\n\t"] {
        assert_eq!(
            ObjectVerdict::new(Clean, Rule::R7, explanation),
            Err(VerdictError::EmptyExplanation),
            "{explanation:?}"
        );
    }
}

#[req("FR-09")]
#[test]
fn each_rule_gives_only_its_verdict() {
    // All 28 pairs: a policy bug writing "CLEAN by R2" (a detection reported as clean) is refused.
    for (rule, expected) in RULES {
        for verdict in ORDER {
            let result = ObjectVerdict::new(verdict, rule, "explained");
            if verdict == expected {
                assert!(result.is_ok(), "{verdict:?} by {rule:?}: {result:?}");
            } else {
                assert_eq!(
                    result,
                    Err(VerdictError::RuleMismatch { verdict, rule }),
                    "{verdict:?} by {rule:?}"
                );
            }
        }
    }
}

#[req("FR-09")]
#[test]
fn limit_is_reported_only_on_unscannable() {
    let unscannable = ObjectVerdict::new(Unscannable, Rule::R1, "R1: depth limit 3 reached")
        .expect("valid")
        .with_limit(Limit::Depth)
        .expect("limit on UNSCANNABLE");
    assert_eq!(unscannable.limit(), Some(Limit::Depth));
    for (verdict, rule) in [
        (Clean, Rule::R7),
        (Suspicious, Rule::R5),
        (Malicious, Rule::R2),
    ] {
        let decided = ObjectVerdict::new(verdict, rule, "explained").expect("valid");
        assert_eq!(
            decided.with_limit(Limit::Ratio),
            Err(VerdictError::LimitWithoutUnscannable(verdict))
        );
    }
}

#[req("FR-09")]
#[test]
fn score_is_a_finite_number_between_0_and_1() {
    for value in [0.0, -0.0, 0.5, 1.0] {
        assert_eq!(Score::new(value).map(Score::value), Ok(value));
    }
    for value in [
        -f64::MIN_POSITIVE,
        -0.01,
        1.0 + f64::EPSILON,
        1.01,
        f64::NAN,
        f64::INFINITY,
        f64::NEG_INFINITY,
    ] {
        assert!(
            matches!(Score::new(value), Err(VerdictError::ScoreOutOfRange(_))),
            "{value}"
        );
    }
}
