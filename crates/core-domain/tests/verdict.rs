//! Verdicts, their worst-of ordering (ADR-16) and the object-verdict invariants of the report contract.

use ostia_core_domain::verdict::{
    Limit, ObjectVerdict, Rule, Score, Verdict, VerdictError, worst_of,
};
use ostia_traceability::req;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

use Verdict::{Clean, Malicious, Suspicious, Unscannable};

/// Every verdict, from best to worst (ADR-16).
const ORDER: [Verdict; 4] = [Clean, Suspicious, Unscannable, Malicious];

fn fixed_seed() -> Config {
    Config {
        rng_seed: RngSeed::Fixed(0x0a_d1_60_16),
        ..Config::default()
    }
}

fn verdict() -> impl Strategy<Value = Verdict> {
    prop::sample::select(ORDER.to_vec())
}

/// `a` is at most as bad as `b`, read only through `worst`.
fn at_most(a: Verdict, b: Verdict) -> bool {
    a.worst(b) == b
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

#[req("FR-09", "FR-10")]
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

proptest! {
    #![proptest_config(fixed_seed())]

    #[req("FR-09")]
    #[test]
    fn worst_is_commutative(a in verdict(), b in verdict()) {
        prop_assert_eq!(a.worst(b), b.worst(a));
    }

    #[req("FR-09")]
    #[test]
    fn worst_is_associative(a in verdict(), b in verdict(), c in verdict()) {
        prop_assert_eq!(a.worst(b).worst(c), a.worst(b.worst(c)));
    }

    #[req("FR-09")]
    #[test]
    fn worst_is_idempotent(a in verdict()) {
        prop_assert_eq!(a.worst(a), a);
    }

    #[req("FR-09")]
    #[test]
    fn worst_is_monotonic(a in verdict(), b in verdict(), c in verdict()) {
        if at_most(a, b) {
            prop_assert!(at_most(a.worst(c), b.worst(c)));
        }
    }

    #[req("FR-09")]
    #[test]
    fn worst_of_does_not_depend_on_order(
        verdicts in prop::collection::vec(verdict(), 1..12),
        rotation in 0usize..12,
    ) {
        let mut reordered = verdicts.clone();
        reordered.rotate_left(rotation % verdicts.len());
        reordered.reverse();
        prop_assert_eq!(worst_of(verdicts.clone()), worst_of(reordered));
    }

    #[req("FR-09")]
    #[test]
    fn worst_of_is_one_of_them_and_bounds_them(verdicts in prop::collection::vec(verdict(), 1..12)) {
        let worst = worst_of(verdicts.clone()).expect("non-empty");
        prop_assert!(verdicts.contains(&worst));
        for v in verdicts {
            prop_assert!(at_most(v, worst));
        }
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
    .with_engines(["ember"]);
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
        .with_engines(["av-b", "av-a", "av-b"]);
    assert_eq!(
        decided.contributing_engines(),
        ["av-a".to_owned(), "av-b".to_owned()]
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
fn unscannable_comes_only_from_r1() {
    assert!(ObjectVerdict::new(Unscannable, Rule::R1, "R1: av-a crashed").is_ok());
    for rule in [Rule::R2, Rule::R3, Rule::R4, Rule::R5, Rule::R6, Rule::R7] {
        assert_eq!(
            ObjectVerdict::new(Unscannable, rule, "explained"),
            Err(VerdictError::RuleMismatch {
                verdict: Unscannable,
                rule
            })
        );
    }
    for verdict in [Clean, Suspicious, Malicious] {
        assert_eq!(
            ObjectVerdict::new(verdict, Rule::R1, "explained"),
            Err(VerdictError::RuleMismatch {
                verdict,
                rule: Rule::R1
            })
        );
    }
}

#[req("FR-09", "FR-06")]
#[test]
fn limit_is_reported_only_on_unscannable() {
    let unscannable = ObjectVerdict::new(Unscannable, Rule::R1, "R1: depth limit 3 reached")
        .expect("valid")
        .with_limit(Limit::Depth)
        .expect("limit on UNSCANNABLE");
    assert_eq!(unscannable.limit(), Some(Limit::Depth));
    let clean = ObjectVerdict::new(Clean, Rule::R7, "R7: nothing found").expect("valid");
    assert_eq!(
        clean.with_limit(Limit::Ratio),
        Err(VerdictError::LimitWithoutUnscannable(Clean))
    );
}

#[req("FR-09")]
#[test]
fn score_is_a_finite_number_between_0_and_1() {
    for value in [0.0, 0.5, 1.0] {
        assert_eq!(Score::new(value).map(Score::value), Ok(value));
    }
    for value in [-0.01, 1.01, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert!(
            matches!(Score::new(value), Err(VerdictError::ScoreOutOfRange(_))),
            "{value}"
        );
    }
}
