"""FR-10: in compliant mode (the default) a MALICIOUS or UNSCANNABLE object blocks the whole medium and
nothing is transferred; a SUSPICIOUS object blocks only itself (spec §8). Selective mode, flagged
non-compliant, transfers the CLEAN files only (spec §5)."""

from pathlib import Path

import pytest
from common import (
    Planted,
    Scan,
    build_image,
    fake_engine_config,
    on_sha256,
    policy_document,
    scan,
    sha256,
    text_bytes,
    write_signed_policy,
    zip_bytes,
)

ENGINES: dict[str, dict[str, object]] = {
    "av": {"role": "detector", "trusted_alone": True},
    "heur": {"role": "heuristic"},
}
A = Planted("a.txt", text_bytes("clean a"))
B = Planted("b.txt", text_bytes("clean b"))
SUS = Planted("sus.txt", text_bytes("suspicious"))
MAL = Planted("mal.txt", text_bytes("malicious"))
BROKEN = Planted("broken.txt", text_bytes("the engine crashes on this one"))
SUS_INSIDE = text_bytes("suspicious inside an archive")
BOX = Planted("box.zip", zip_bytes([("sus-inside.txt", SUS_INSIDE), ("ok.txt", text_bytes("ok"))]))

AV_RULES = [
    on_sha256(sha256(MAL.content), hint="MALICIOUS"),
    on_sha256(sha256(BROKEN.content), crash={"exit_code": 3}),
]
HEUR_RULES = [
    on_sha256(sha256(SUS.content), hint="SUSPICIOUS"),
    on_sha256(sha256(SUS_INSIDE), hint="SUSPICIOUS"),
]


def run(work: Path, files: list[Planted], mode: str | None = None) -> Scan:
    image = build_image("ext4", files)
    engines = [
        fake_engine_config(work, "av", rules=AV_RULES),
        fake_engine_config(work, "heur", rules=HEUR_RULES),
    ]
    policy = write_signed_policy(work / "policy", policy_document(ENGINES))
    return scan(work / "scan", image, policy, engines, mode=mode)


def content(*files: Planted) -> dict[str, bytes]:
    return {f.path: f.content for f in files}


@pytest.fixture(scope="module")
def clean(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("clean"), [A, B])


@pytest.fixture(scope="module")
def suspicious(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("suspicious"), [A, B, SUS])


@pytest.fixture(scope="module")
def malicious(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("malicious"), [A, B, MAL])


@pytest.fixture(scope="module")
def unscannable(tmp_path_factory: pytest.TempPathFactory) -> Scan:
    return run(tmp_path_factory.mktemp("unscannable"), [A, B, BROKEN])


@pytest.mark.req("FR-10")
def test_compliant_mode_is_the_default(malicious: Scan) -> None:
    assert malicious.report["session"]["mode"] == "compliant"
    assert malicious.report["session"]["compliant"] is True


@pytest.mark.req("FR-10")
def test_clean_medium_transfers_every_file(clean: Scan) -> None:
    verdict = clean.report["medium_verdict"]
    assert (verdict["verdict"], verdict["blocked"], verdict["blocking_objects"]) == (
        "CLEAN",
        False,
        [],
    )
    assert clean.output_files() == content(A, B)


@pytest.mark.req("FR-10")
def test_suspicious_file_blocks_only_itself(suspicious: Scan) -> None:
    verdict = suspicious.report["medium_verdict"]
    assert (verdict["verdict"], verdict["blocked"]) == ("SUSPICIOUS", False)
    assert suspicious.file("sus.txt")["transferable"] is False
    assert suspicious.output_files() == content(A, B)


@pytest.mark.req("FR-10")
def test_malicious_file_blocks_the_medium(malicious: Scan) -> None:
    verdict = malicious.report["medium_verdict"]
    assert (verdict["verdict"], verdict["blocked"]) == ("MALICIOUS", True)
    assert verdict["blocking_objects"] == [malicious.file("mal.txt")["id"]]


@pytest.mark.req("FR-10")
def test_blocked_medium_transfers_nothing(malicious: Scan) -> None:
    assert [o["path"] for o in malicious.objects if o["transferable"]] == []
    assert malicious.output_files() == {}


@pytest.mark.req("FR-10", "NFR-05")
def test_unscannable_file_blocks_the_medium(unscannable: Scan) -> None:
    verdict = unscannable.report["medium_verdict"]
    assert (verdict["verdict"], verdict["blocked"]) == ("UNSCANNABLE", True)
    assert verdict["blocking_objects"] == [unscannable.file("broken.txt")["id"]]
    assert unscannable.output_files() == {}


@pytest.mark.req("FR-10", "FR-06")
def test_archive_with_a_suspicious_entry_is_not_transferred(tmp_path: Path) -> None:
    found = run(tmp_path, [BOX, A])
    assert found.child(found.file("box.zip"), "sus-inside.txt")["verdict"] == "SUSPICIOUS"
    assert found.file("box.zip")["transferable"] is False
    assert found.output_files() == content(A)


@pytest.mark.req("FR-10")
def test_selective_mode_transfers_clean_files_and_is_flagged(tmp_path: Path) -> None:
    found = run(tmp_path, [A, B, MAL], mode="selective")
    assert found.report["session"]["mode"] == "selective"
    assert found.report["session"]["compliant"] is False
    verdict = found.report["medium_verdict"]
    assert (verdict["verdict"], verdict["blocked"]) == ("MALICIOUS", False)
    assert verdict["blocking_objects"] == [found.file("mal.txt")["id"]]
    assert found.file("mal.txt")["transferable"] is False
    assert found.output_files() == content(A, B)


@pytest.mark.req("FR-10")
def test_scan_only_mode_transfers_nothing(tmp_path: Path) -> None:
    found = run(tmp_path, [A, B], mode="scan-only")
    assert found.report["session"]["mode"] == "scan-only"
    assert found.report["medium_verdict"]["verdict"] == "CLEAN"
    assert [o["path"] for o in found.objects if o["transferable"]] == []
    assert found.output_files() == {}
