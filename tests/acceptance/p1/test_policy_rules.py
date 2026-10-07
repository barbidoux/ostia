"""FR-09 and the verdict policy (spec §8, ADR-09, docs/contracts/policy.md): one row per rule R1-R7 and per
precedence pair that can be exercised black-box, through fake engines answering per object. Each row is a file
of one generated image; one scan answers every row. Smaller scans show that the parameters come from the
signed policy."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from common import (
    Planted,
    Scan,
    SignedPolicy,
    build_image,
    fake_engine_config,
    on_sha256,
    pe_bytes,
    png_bytes,
    policy_document,
    scan,
    sha256,
    text_bytes,
    write_signed_policy,
    zip_bytes,
)

ENGINES: dict[str, dict[str, Any]] = {
    "rep": {"role": "reputation"},
    "av-trusted": {"role": "detector", "trusted_alone": True},
    "av-a": {"role": "detector", "trusted_alone": False},
    "av-b": {"role": "detector", "trusted_alone": False},
    "ember": {"role": "scorer", "thresholds": {"low": 0.5, "high": 0.9}},
    "heur": {"role": "heuristic"},
}
DEFAULT_SCORE = 0.1  # every ember answer carries it unless the row says otherwise

ERROR = {"status": "ERROR", "hint": "NONE"}
TIMEOUT = {"status": "TIMEOUT", "hint": "NONE"}
UNSUPPORTED = {"status": "UNSUPPORTED", "hint": "NONE"}
MALICIOUS = {"status": "OK", "hint": "MALICIOUS"}
SUSPICIOUS = {"status": "OK", "hint": "SUSPICIOUS"}
CLEAN = {"status": "OK", "hint": "CLEAN"}


def score(value: float, hint: str = "NONE", status: str = "OK") -> dict[str, Any]:
    return {"status": status, "hint": hint, "score": value}


def finding(severity: int) -> dict[str, Any]:
    return {
        "status": "OK",
        "hint": "NONE",
        "findings": [
            {
                "id": f"rule.severity{severity}",
                "title": f"rule of severity {severity}",
                "severity": severity,
                "evidence": "offset 0",
                "attack_ids": [],
            }
        ],
    }


@dataclass(frozen=True)
class Row:
    name: str
    answers: dict[str, dict[str, Any]]
    verdict: str
    rule: str
    contributing: frozenset[str]
    content: bytes = field(default=b"")

    def data(self) -> bytes:
        return self.content or text_bytes(f"policy row {self.name}")

    def expected_score(self) -> float | None:
        # The fake engine merges a rule's answer over its default, so ember always sends a score; only a
        # result with status OK counts (report.md).
        answer = {"status": "OK", "score": DEFAULT_SCORE, **self.answers.get("ember", {})}
        if answer["status"] != "OK":
            return None
        value: float = answer.get("score", DEFAULT_SCORE)
        return value


def every(answer: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {engine_id: answer for engine_id in ENGINES}


def only(*ids: str) -> frozenset[str]:
    return frozenset(ids)


R1, R2, R3, R4, R5, R6, R7 = "R1", "R2", "R3", "R4", "R5", "R6", "R7"
UNSCANNABLE, MAL, SUS, OK = "UNSCANNABLE", "MALICIOUS", "SUSPICIOUS", "CLEAN"

RULE_ROWS = [
    Row("r1-engine-error.txt", {"av-a": ERROR}, UNSCANNABLE, R1, only("av-a")),
    Row("r1-engine-timeout.txt", {"av-b": TIMEOUT}, UNSCANNABLE, R1, only("av-b")),
    Row(
        "r1-scorer-error-with-score.txt",
        {"ember": score(0.95, status="ERROR")},
        UNSCANNABLE,
        R1,
        only("ember"),
    ),
    Row(
        "r1-risky-type-unsupported.exe",
        every(UNSUPPORTED),
        UNSCANNABLE,
        R1,
        only(),
        pe_bytes("risky type nobody supports"),
    ),
    Row(
        "r7-plain-type-unsupported.png",
        every(UNSUPPORTED),
        OK,
        R7,
        only(),
        png_bytes("plain type nobody supports"),
    ),
    Row("r2-known-bad.txt", {"rep": MALICIOUS}, MAL, R2, only("rep")),
    Row("r2-trusted-alone.txt", {"av-trusted": MALICIOUS}, MAL, R2, only("av-trusted")),
    Row("r2-k-of-n.txt", {"av-a": MALICIOUS, "av-b": MALICIOUS}, MAL, R2, only("av-a", "av-b")),
    Row("r2-critical-finding.txt", {"heur": finding(4)}, MAL, R2, only("heur")),
    Row("r7-finding-below-critical.txt", {"heur": finding(3)}, OK, R7, only()),
    Row("r3-known-good.txt", {"rep": CLEAN}, OK, R3, only("rep")),
    Row("r3-every-engine-clean.txt", every(CLEAN) | {"ember": score(0.2)}, OK, R3, only("rep")),
    Row("r4-score-above-high.txt", {"ember": score(0.95)}, MAL, R4, only("ember")),
    Row("r4-score-at-high.txt", {"ember": score(0.9)}, MAL, R4, only("ember")),
    Row("r5-score-between.txt", {"ember": score(0.7)}, SUS, R5, only("ember")),
    Row("r5-score-at-low.txt", {"ember": score(0.5)}, SUS, R5, only("ember")),
    Row("r7-score-below-low.txt", {"ember": score(0.49)}, OK, R7, only()),
    Row("r7-scorer-hint-ignored.txt", {"ember": score(0.1, hint="MALICIOUS")}, OK, R7, only()),
    Row("r6-single-detection.txt", {"av-a": MALICIOUS}, SUS, R6, only("av-a")),
    Row(
        "r6-heuristic-not-counted-in-k.txt",
        {"av-a": MALICIOUS, "heur": MALICIOUS},
        SUS,
        R6,
        only("av-a", "heur"),
    ),
    Row("r6-detector-suspicious.txt", {"av-b": SUSPICIOUS}, SUS, R6, only("av-b")),
    Row("r6-heuristic-suspicious.txt", {"heur": SUSPICIOUS}, SUS, R6, only("heur")),
    Row("r6-heuristic-malicious.txt", {"heur": MALICIOUS}, SUS, R6, only("heur")),
    Row("r7-nothing-found.txt", {}, OK, R7, only()),
]

PRECEDENCE_ROWS = [
    Row(
        "p-r1-over-r2.txt", {"av-a": ERROR, "av-trusted": MALICIOUS}, UNSCANNABLE, R1, only("av-a")
    ),
    Row("p-r1-over-r3.txt", {"av-a": ERROR, "rep": CLEAN}, UNSCANNABLE, R1, only("av-a")),
    Row("p-r1-over-r4.txt", {"av-a": ERROR, "ember": score(0.95)}, UNSCANNABLE, R1, only("av-a")),
    Row("p-r1-over-r5.txt", {"av-a": ERROR, "ember": score(0.7)}, UNSCANNABLE, R1, only("av-a")),
    Row("p-r1-over-r6.txt", {"av-a": ERROR, "heur": SUSPICIOUS}, UNSCANNABLE, R1, only("av-a")),
    Row(
        "p-r1-over-mismatch.pdf",
        {"av-a": ERROR},
        UNSCANNABLE,
        R1,
        only("av-a"),
        png_bytes("image named as a document, engine failed"),
    ),
    Row("p-r2-over-r3.txt", {"av-trusted": MALICIOUS, "rep": CLEAN}, MAL, R2, only("av-trusted")),
    Row(
        "p-r2-k-of-n-over-r3.txt",
        {"av-a": MALICIOUS, "av-b": MALICIOUS, "rep": CLEAN},
        MAL,
        R2,
        only("av-a", "av-b"),
    ),
    Row("p-r2-critical-over-r3.txt", {"heur": finding(4), "rep": CLEAN}, MAL, R2, only("heur")),
    Row(
        "p-r2-over-r4.txt",
        {"av-trusted": MALICIOUS, "ember": score(0.95)},
        MAL,
        R2,
        only("av-trusted"),
    ),
    Row(
        "p-r2-over-r5.txt",
        {"av-trusted": MALICIOUS, "ember": score(0.7)},
        MAL,
        R2,
        only("av-trusted"),
    ),
    Row(
        "p-r2-over-r6.txt",
        {"av-trusted": MALICIOUS, "heur": SUSPICIOUS},
        MAL,
        R2,
        only("av-trusted"),
    ),
    Row(
        "p-r2-over-double.pdf.exe",
        {"av-trusted": MALICIOUS},
        MAL,
        R2,
        only("av-trusted"),
        pe_bytes("detected with a double extension"),
    ),
    Row("p-r3-over-r4.txt", {"rep": CLEAN, "ember": score(0.95)}, OK, R3, only("rep")),
    Row("p-r3-over-r5.txt", {"rep": CLEAN, "ember": score(0.7)}, OK, R3, only("rep")),
    Row("p-r3-over-r6.txt", {"rep": CLEAN, "heur": SUSPICIOUS}, OK, R3, only("rep")),
    Row(
        "p-r3-over-double.pdf.exe",
        {"rep": CLEAN},
        OK,
        R3,
        only("rep"),
        pe_bytes("known good with a double extension"),
    ),
    Row("p-r4-over-r6.txt", {"ember": score(0.95), "heur": SUSPICIOUS}, MAL, R4, only("ember")),
    Row(
        "p-r4-over-double.pdf.exe",
        {"ember": score(0.95)},
        MAL,
        R4,
        only("ember"),
        pe_bytes("high score with a double extension"),
    ),
    Row("p-r5-over-r6.txt", {"ember": score(0.7), "heur": SUSPICIOUS}, SUS, R5, only("ember")),
]

ROWS = RULE_ROWS + PRECEDENCE_ROWS


def engine_rules(rows: list[Row], engine_id: str) -> list[dict[str, Any]]:
    return [
        on_sha256(sha256(row.data()), **row.answers[engine_id])
        for row in rows
        if engine_id in row.answers
    ]


def run(
    work: Path,
    rows: list[Row],
    engines: Mapping[str, Mapping[str, object]],
    *,
    defaults: Mapping[str, dict[str, Any]] | None = None,
    document: dict[str, Any] | None = None,
) -> tuple[Scan, SignedPolicy]:
    """Scan one image holding a file per row, with one fake engine per policy engine; the policy is
    `document`, else the default document for `engines`."""
    image = build_image("ext4", [Planted(row.name, row.data()) for row in rows])
    configs = [
        fake_engine_config(
            work,
            engine_id,
            default=(defaults or {}).get(engine_id, {"status": "OK", "hint": "NONE"}),
            rules=engine_rules(rows, engine_id),
            version=f"{engine_id}-2.1.0",
            content_version=f"{engine_id}-content-7",
        )
        for engine_id in engines
    ]
    signed = write_signed_policy(work / "policy", document or policy_document(engines))
    return scan(work / "scan", image, signed, configs), signed


@dataclass
class RulesScan:
    scan: Scan
    policy: SignedPolicy


@pytest.fixture(scope="module")
def rules(tmp_path_factory: pytest.TempPathFactory) -> RulesScan:
    found, signed = run(
        tmp_path_factory.mktemp("policy-rules"),
        ROWS,
        ENGINES,
        defaults={"ember": {"status": "OK", "hint": "NONE", "score": DEFAULT_SCORE}},
        document=policy_document(
            ENGINES, version="p1-rules", risky_types=("pe",), k=2, critical_severity=4
        ),
    )
    return RulesScan(found, signed)


def name(row: Row) -> str:
    return row.name


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("row", ROWS, ids=name)
def test_first_matching_rule_decides_the_verdict(rules: RulesScan, row: Row) -> None:
    listed = rules.scan.file(row.name)
    assert (listed["verdict"], listed["rule"]) == (row.verdict, row.rule)


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("row", ROWS, ids=name)
def test_contributing_engines_are_reported(rules: RulesScan, row: Row) -> None:
    assert frozenset(rules.scan.file(row.name)["contributing_engines"]) == row.contributing


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("row", ROWS, ids=name)
def test_score_is_the_scorer_score(rules: RulesScan, row: Row) -> None:
    assert rules.scan.file(row.name)["score"] == row.expected_score()


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("row", ROWS, ids=name)
def test_explanation_names_the_rule_and_the_engines(rules: RulesScan, row: Row) -> None:
    explanation = rules.scan.file(row.name)["explanation"]
    assert row.rule in explanation
    for engine_id in row.contributing:
        assert engine_id in explanation


@pytest.mark.req("FR-09")
def test_engine_results_carry_each_engine_identity(rules: RulesScan) -> None:
    expected = sorted((e, f"{e}-2.1.0", f"{e}-content-7") for e in ENGINES)
    assert len(rules.scan.files()) == len(ROWS)
    for listed in rules.scan.files():
        identities = sorted(
            (r["engine_id"], r["engine_version"], r["content_version"])
            for r in listed["engine_results"]
        )
        assert identities == expected, listed["path"]


@pytest.mark.req("FR-09")
def test_report_records_the_policy_version_and_hash(rules: RulesScan) -> None:
    assert rules.scan.report["policy"] == {
        "version": "p1-rules",
        "sha256": sha256(rules.policy.data),
    }


# --- parameters come from the signed policy ----------------------------------------------------------

SMALL_ENGINES: dict[str, dict[str, Any]] = {
    "av-a": {"role": "detector", "trusted_alone": False},
    "av-b": {"role": "detector", "trusted_alone": False},
    "heur": {"role": "heuristic"},
}
PARAMETER_ROWS = [
    # K = 3: two detections are a single detection.
    Row("k-three.txt", {"av-a": MALICIOUS, "av-b": MALICIOUS}, SUS, R6, only("av-a", "av-b")),
    # critical_severity = 3.
    Row("severity-three.txt", {"heur": finding(3)}, MAL, R2, only("heur")),
    # risky_types = png only.
    Row(
        "nobody-png.png",
        {e: UNSUPPORTED for e in SMALL_ENGINES},
        UNSCANNABLE,
        R1,
        only(),
        png_bytes("risky by this policy"),
    ),
    Row(
        "nobody-pe.exe",
        {e: UNSUPPORTED for e in SMALL_ENGINES},
        OK,
        R7,
        only(),
        pe_bytes("not risky by this policy"),
    ),
]
DISABLED_ROWS = [
    Row("lone-detection.txt", {"av-a": MALICIOUS}, OK, R7, only()),
    Row("suspicious-hint.txt", {"heur": SUSPICIOUS}, OK, R7, only()),
]


@pytest.fixture(scope="module")
def parameters(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    work = tmp_path_factory.mktemp("policy-parameters")
    document = policy_document(SMALL_ENGINES, k=3, critical_severity=3, risky_types=("png",))
    found, _ = run(work, PARAMETER_ROWS, SMALL_ENGINES, document=document)
    return found


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("row", PARAMETER_ROWS, ids=name)
def test_rule_parameters_come_from_the_policy(parameters: Scan, row: Row) -> None:
    listed = parameters.file(row.name)
    assert (listed["verdict"], listed["rule"]) == (row.verdict, row.rule)


@pytest.mark.req("FR-09")
@pytest.mark.parametrize("row", DISABLED_ROWS, ids=name)
def test_disabled_r6_indicators_do_not_decide(tmp_path: Path, row: Row) -> None:
    r6 = {"single_detection": False, "suspicious_hint": False}
    found, _ = run(tmp_path, [row], SMALL_ENGINES, document=policy_document(SMALL_ENGINES, r6=r6))
    listed = found.file(row.name)
    assert (listed["verdict"], listed["rule"]) == (row.verdict, row.rule)


@pytest.mark.req("FR-09")
def test_scorer_answering_without_a_score_is_a_failure(tmp_path: Path) -> None:
    row = Row("no-score.txt", {}, UNSCANNABLE, R1, only("ember"))
    found, _ = run(tmp_path, [row], {"ember": ENGINES["ember"]})
    listed = found.file(row.name)
    assert (listed["verdict"], listed["rule"], listed["score"]) == (UNSCANNABLE, R1, None)
    assert listed["contributing_engines"] == ["ember"]


def nest(levels: int) -> bytes:
    archive = zip_bytes([("leaf.txt", text_bytes("leaf of a known-good archive"))])
    for level in range(levels - 1, 0, -1):
        archive = zip_bytes([(f"l{level}.zip", archive)])
    return archive


@pytest.mark.req("FR-09", "FR-06")
def test_known_good_archive_is_still_extracted_under_limits(tmp_path: Path) -> None:
    # R3 never beats R1: a known-good hash does not skip extraction or its limits.
    deep = Row("known-good-deep.zip", {"rep": CLEAN}, OK, R3, only("rep"), nest(5))
    engines = {"rep": ENGINES["rep"], "av-a": ENGINES["av-a"]}
    document = policy_document(engines, limits={"max_depth": 3})
    found, _ = run(tmp_path, [deep], engines, document=document)
    level = found.file(deep.name)
    for entry in ("l1.zip", "l2.zip", "l3.zip"):
        level = found.child(level, entry)
    assert (level["verdict"], level["rule"], level["limit"]) == (UNSCANNABLE, R1, "depth")
    assert found.file(deep.name)["transferable"] is False
    assert found.report["medium_verdict"]["blocked"] is True
