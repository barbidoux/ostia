"""CI acceptance policy: closed phases gate, the current phase is informational, future phases are not run."""

import json
import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

PLAN = str(REPO / "tools" / "ci" / "acceptance_plan.py")


def layout(tmp_path: Path, status: str, locked: list[str], unlocked: list[str]) -> tuple[Path, Path]:
    status_file = tmp_path / "phase-status.md"
    status_file.write_text(status)
    acceptance = tmp_path / "acceptance"
    acceptance.mkdir()
    for name in locked:
        (acceptance / name).mkdir()
        (acceptance / name / "LOCK.sha256").write_text("# locked\n")
    for name in unlocked:
        (acceptance / name).mkdir()
    return status_file, acceptance


def plan(status_file: Path, acceptance: Path) -> tuple[int, str, str]:
    cmd = [sys.executable, PLAN, "--status", str(status_file), "--acceptance", str(acceptance)]
    result = run(cmd, cwd=REPO)
    return result.returncode, result.stdout, result.stderr


@pytest.mark.req("TOOLING")
def test_phase_zero_runs_nothing(tmp_path: Path) -> None:
    status_file, acceptance = layout(tmp_path, "# Status\n\nCurrent phase: P0 · Foundations\n", [], [])
    code, out, err = plan(status_file, acceptance)
    assert code == 0, err
    assert json.loads(out) == {"current": "p0", "gate": [], "informational": [], "not_run": []}


@pytest.mark.req("TOOLING")
def test_dirs_are_classified_against_the_current_phase(tmp_path: Path) -> None:
    status_file, acceptance = layout(
        tmp_path,
        "Current phase: P2 · EMBER engine\n",
        locked=["p1", "p2", "p3", "common", "p10"],
        unlocked=["p4"],
    )
    code, out, err = plan(status_file, acceptance)
    assert code == 0, err
    assert json.loads(out) == {
        "current": "p2",
        "gate": ["p1"],
        "informational": ["p2"],
        "not_run": ["p3", "p4", "p10"],
    }


@pytest.mark.req("TOOLING")
def test_double_digit_phases_sort_numerically(tmp_path: Path) -> None:
    status_file, acceptance = layout(tmp_path, "Current phase: P11 · Later\n", ["p2", "p10", "p11"], [])
    code, out, err = plan(status_file, acceptance)
    assert code == 0, err
    assert json.loads(out)["gate"] == ["p2", "p10"]


@pytest.mark.req("TOOLING")
def test_unlocked_closed_phase_fails_closed(tmp_path: Path) -> None:
    status_file, acceptance = layout(tmp_path, "Current phase: P2 · EMBER engine\n", ["p2"], ["p1"])
    code, _, err = plan(status_file, acceptance)
    assert code == 1
    assert "tests/acceptance/p1 belongs to a closed phase but is not locked" in err


@pytest.mark.req("TOOLING")
def test_unlocked_current_phase_fails_closed(tmp_path: Path) -> None:
    status_file, acceptance = layout(tmp_path, "Current phase: P1 · Pipeline\n", [], ["p1"])
    code, _, err = plan(status_file, acceptance)
    assert code == 1
    assert "tests/acceptance/p1 belongs to the current phase but is not locked" in err


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "status",
    [
        "# no phase line\n",
        "Current phase: Foundations\n",
        "Current phase: P1 · Pipeline\nCurrent phase: P2 · EMBER engine\n",
    ],
)
def test_missing_or_ambiguous_current_phase_fails_closed(tmp_path: Path, status: str) -> None:
    status_file, acceptance = layout(tmp_path, status, [], [])
    code, _, err = plan(status_file, acceptance)
    assert code == 1
    assert "exactly one 'Current phase: P<n>' line" in err


@pytest.mark.req("TOOLING")
def test_missing_acceptance_directory_means_nothing_to_run(tmp_path: Path) -> None:
    status_file = tmp_path / "phase-status.md"
    status_file.write_text("Current phase: P0 · Foundations\n")
    code, out, err = plan(status_file, tmp_path / "absent")
    assert code == 0, err
    assert json.loads(out) == {"current": "p0", "gate": [], "informational": [], "not_run": []}


@pytest.mark.req("TOOLING")
def test_repository_status_is_readable() -> None:
    cmd = [sys.executable, PLAN, "--status", "docs/phase-status.md", "--acceptance", "tests/acceptance"]
    result = run(cmd, cwd=REPO)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["current"].startswith("p")
