"""FR-05: the type comes from the content, never from the name; a type/extension mismatch and a double
extension are risk indicators that make the file SUSPICIOUS through R6 (spec §8, §20)."""

from dataclasses import dataclass
from pathlib import Path

import pytest
from common import (
    Planted,
    Scan,
    build_image,
    fake_engine_config,
    gzip_bytes,
    pdf_bytes,
    pe_bytes,
    png_bytes,
    policy_document,
    scan,
    sha256,
    tar_bytes,
    text_bytes,
    write_signed_policy,
    zip_bytes,
)


@dataclass(frozen=True)
class Case:
    name: str
    content: bytes
    detected_type: str
    mismatch: bool
    double: bool
    verdict: str
    rule: str


INSIDE = text_bytes("inside a disguised archive")
CASES = [
    Case("photo.png", png_bytes("photo"), "png", False, False, "CLEAN", "R7"),
    Case("report.pdf", png_bytes("renamed image"), "png", True, False, "SUSPICIOUS", "R6"),
    Case("notes.txt", pdf_bytes("notes"), "pdf", True, False, "SUSPICIOUS", "R6"),
    Case("invoice.pdf.exe", pe_bytes("invoice"), "pe", False, True, "SUSPICIOUS", "R6"),
    Case("setup.exe", pe_bytes("setup"), "pe", False, False, "CLEAN", "R7"),
    Case(
        "holiday.jpg", zip_bytes([("inside.txt", INSIDE)]), "zip", True, False, "SUSPICIOUS", "R6"
    ),
    Case(
        "backup.tar.gz",
        gzip_bytes("backup.tar", tar_bytes([("saved.txt", text_bytes("saved"))])),
        "gzip",
        False,
        False,
        "CLEAN",
        "R7",
    ),
]
ENGINES = {"fake-av": {"role": "detector", "trusted_alone": False}}


def run(work: Path, r6: dict[str, bool] | None = None) -> Scan:
    image = build_image("ext4", [Planted(case.name, case.content) for case in CASES])
    engine = fake_engine_config(work, "fake-av")
    policy = write_signed_policy(work / "policy", policy_document(ENGINES, r6=r6))
    return scan(work / "scan", image, policy, [engine])


@pytest.fixture(scope="module")
def triage(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("triage"))


def ids(case: Case) -> str:
    return case.name


@pytest.mark.req("FR-05")
@pytest.mark.parametrize("case", CASES, ids=ids)
def test_type_is_identified_from_content(triage: Scan, case: Case) -> None:
    assert triage.file(case.name)["detected_type"] == case.detected_type


@pytest.mark.req("FR-05")
@pytest.mark.parametrize("case", CASES, ids=ids)
def test_extension_mismatch_is_flagged(triage: Scan, case: Case) -> None:
    assert triage.file(case.name)["extension_mismatch"] is case.mismatch


@pytest.mark.req("FR-05")
@pytest.mark.parametrize("case", CASES, ids=ids)
def test_double_extension_is_flagged(triage: Scan, case: Case) -> None:
    assert triage.file(case.name)["double_extension"] is case.double


@pytest.mark.req("FR-05", "FR-09")
@pytest.mark.parametrize("case", CASES, ids=ids)
def test_risk_indicators_make_the_file_suspicious(triage: Scan, case: Case) -> None:
    listed = triage.file(case.name)
    assert (listed["verdict"], listed["rule"]) == (case.verdict, case.rule)


@pytest.mark.req("FR-05", "FR-06")
def test_disguised_archive_is_extracted_by_content(triage: Scan) -> None:
    entry = triage.child(triage.file("holiday.jpg"), "inside.txt")
    assert entry["sha256"] == sha256(INSIDE)


@pytest.mark.req("FR-05", "FR-09")
def test_indicators_disabled_in_the_policy_do_not_decide(tmp_path: Path) -> None:
    lenient = run(tmp_path, r6={"double_extension": False, "extension_mismatch": False})
    for name in ("report.pdf", "invoice.pdf.exe"):
        listed = lenient.file(name)
        assert (listed["verdict"], listed["rule"]) == ("CLEAN", "R7"), name
