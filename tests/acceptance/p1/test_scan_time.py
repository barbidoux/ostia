"""FR-14: a maximum scan time, 10 minutes by default, configurable; when it expires the administrator's action
applies and the report says so. The budget (10 s) is far below the fake engine's delay (120 s) so that the
outcome never depends on scheduling; the elapsed time is part of the requirement."""

import time
from dataclasses import dataclass
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
)

ENGINES = {"av": {"role": "detector", "trusted_alone": False}}
FAST = Planted("fast.txt", text_bytes("answered at once"))
SLOW = Planted("slow.txt", text_bytes("answered after two minutes"))
DELAY_MS = 120_000
BUDGET = 10  # mount and inventory included; slow.txt is listed well before it runs out
# Far below the engine delay; the engine timeout is not what stops the scan.
ELAPSED_BOUND = 60


@dataclass
class Timed:
    scan: Scan
    elapsed: float


def run(
    work: Path,
    files: list[Planted],
    *,
    max_scan_time: int | None = None,
    on_expiry: str | None = None,
    mode: str | None = None,
) -> Timed:
    image = build_image("ext4", files)
    rules = [on_sha256(sha256(SLOW.content), delay_ms=DELAY_MS, status="OK", hint="NONE")]
    engine = fake_engine_config(work, "av", rules=rules)
    document = policy_document(ENGINES, limits={"engine_timeout_seconds": 600})
    policy = write_signed_policy(work / "policy", document)
    started = time.monotonic()
    found = scan(
        work / "scan",
        image,
        policy,
        [engine],
        mode=mode,
        max_scan_time=max_scan_time,
        on_expiry=on_expiry,
        timeout=300,
    )
    return Timed(found, time.monotonic() - started)


@pytest.mark.req("FR-14")
def test_default_budget_is_ten_minutes_with_block_on_expiry(tmp_path: Path) -> None:
    timing = run(tmp_path, [FAST]).scan.report["timing"]
    assert timing["max_scan_time_seconds"] == 600
    assert timing["on_expiry"] == "block"
    assert (timing["expired"], timing["aborted"]) == (False, False)


@pytest.fixture(scope="module")
def blocked(tmp_path_factory: pytest.TempPathFactory) -> Timed:
    work = tmp_path_factory.mktemp("expiry-block")
    return run(work, [FAST, SLOW], max_scan_time=BUDGET, on_expiry="block")


@pytest.mark.req("FR-14")
def test_expiry_stops_the_scan_long_before_the_slow_engine_answers(blocked: Timed) -> None:
    assert blocked.scan.result.returncode == 0, blocked.scan.result.stderr
    assert blocked.elapsed < ELAPSED_BOUND


@pytest.mark.req("FR-14")
def test_expiry_is_reported_with_its_action(blocked: Timed) -> None:
    timing = blocked.scan.report["timing"]
    assert timing["max_scan_time_seconds"] == BUDGET
    assert (timing["expired"], timing["on_expiry"], timing["aborted"]) == (True, "block", False)


@pytest.mark.req("FR-14")
def test_object_left_unfinished_at_expiry_is_unscannable(blocked: Timed) -> None:
    slow = blocked.scan.file("slow.txt")
    assert (slow["verdict"], slow["rule"], slow["limit"]) == ("UNSCANNABLE", "R1", "scan_time")


@pytest.mark.req("FR-14", "FR-10")
def test_block_on_expiry_blocks_the_medium(blocked: Timed) -> None:
    assert blocked.scan.report["medium_verdict"]["blocked"] is True
    assert blocked.scan.output_files() == {}


@pytest.fixture(scope="module")
def aborted(tmp_path_factory: pytest.TempPathFactory) -> Timed:
    work = tmp_path_factory.mktemp("expiry-abort")
    return run(work, [FAST, SLOW], max_scan_time=BUDGET, on_expiry="abort")


@pytest.mark.req("FR-14")
def test_abort_on_expiry_stops_the_session(aborted: Timed) -> None:
    assert aborted.elapsed < ELAPSED_BOUND
    timing = aborted.scan.report["timing"]
    assert (timing["expired"], timing["on_expiry"], timing["aborted"]) == (True, "abort", True)


@pytest.mark.req("FR-14", "FR-10")
def test_abort_on_expiry_transfers_nothing(aborted: Timed) -> None:
    assert aborted.scan.report["medium_verdict"]["blocked"] is True
    assert [o["path"] for o in aborted.scan.objects if o["transferable"]] == []
    assert aborted.scan.output_files() == {}


@pytest.mark.req("FR-14")
def test_abort_on_expiry_transfers_nothing_even_in_selective_mode(tmp_path: Path) -> None:
    # Selective mode would transfer fast.txt after a `block` expiry; `abort` stops the session.
    timed = run(tmp_path, [FAST, SLOW], max_scan_time=BUDGET, on_expiry="abort", mode="selective")
    assert timed.scan.report["timing"]["aborted"] is True
    assert timed.scan.report["medium_verdict"]["blocked"] is True
    assert timed.scan.file("fast.txt")["transferable"] is False
    assert timed.scan.output_files() == {}
