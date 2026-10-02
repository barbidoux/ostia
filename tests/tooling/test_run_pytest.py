"""Empty suites pass: pytest exit code 5 counts as success only when the directories hold no tests."""

import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

RUNNER = str(REPO / "tools" / "ci" / "run_pytest.py")
ISOLATED = ["-c", "/dev/null", "-p", "no:cacheprovider", "-q"]

PASSING = "def test_passes() -> None:\n    assert 1 + 1 == 2\n"
FAILING = "def test_fails() -> None:\n    assert 1 + 1 == 3\n"
EMPTY_REPORT = '<?xml version="1.0" encoding="utf-8"?>\n<testsuites tests="0" />\n'


def runner(tmp_path: Path, *pytest_args: str) -> tuple[int, str]:
    cmd = [sys.executable, RUNNER, str(tmp_path), "--", *ISOLATED, *pytest_args]
    result = run(cmd, cwd=tmp_path)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_directory_without_tests_passes(tmp_path: Path) -> None:
    (tmp_path / "helper.py").write_text("VALUE = 1\n")
    code, output = runner(tmp_path)
    assert code == 0, output
    assert "no tests in" in output


@pytest.mark.req("TOOLING")
def test_nothing_collected_from_existing_tests_fails(tmp_path: Path) -> None:
    (tmp_path / "test_sample.py").write_text(PASSING)
    code, output = runner(tmp_path, "-m", "bench")
    assert code == 5
    assert "1 deselected" in output


@pytest.mark.req("TOOLING")
def test_passing_suite_passes(tmp_path: Path) -> None:
    (tmp_path / "test_sample.py").write_text(PASSING)
    code, output = runner(tmp_path)
    assert code == 0, output
    assert "1 passed" in output


@pytest.mark.req("TOOLING")
def test_failing_suite_fails(tmp_path: Path) -> None:
    (tmp_path / "test_sample.py").write_text(FAILING)
    code, output = runner(tmp_path)
    assert code == 1
    assert "1 failed" in output


@pytest.mark.req("TOOLING")
def test_empty_suite_writes_an_empty_junit_report(tmp_path: Path) -> None:
    report = tmp_path / "out" / "pytest.xml"
    code, output = runner(tmp_path, f"--junitxml={report}")
    assert code == 0, output
    assert report.read_text() == EMPTY_REPORT


@pytest.mark.req("TOOLING")
def test_tests_in_any_directory_make_the_suite_non_empty(tmp_path: Path) -> None:
    empty, full = tmp_path / "empty", tmp_path / "full"
    empty.mkdir()
    full.mkdir()
    (full / "test_sample.py").write_text(PASSING)
    cmd = [sys.executable, RUNNER, str(empty), str(full), "--", *ISOLATED]
    result = run(cmd, cwd=tmp_path)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "1 passed" in result.stdout


@pytest.mark.req("TOOLING")
def test_no_directory_is_a_usage_error(tmp_path: Path) -> None:
    result = run([sys.executable, RUNNER, "--", *ISOLATED], cwd=tmp_path)
    assert result.returncode == 2
    assert "usage" in result.stderr


@pytest.mark.req("TOOLING")
def test_missing_directory_fails(tmp_path: Path) -> None:
    result = run([sys.executable, RUNNER, str(tmp_path / "absent"), "--", *ISOLATED], cwd=tmp_path)
    assert result.returncode == 2
    assert "not a directory" in result.stderr
