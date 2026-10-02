"""A non-bench run with any skipped test fails: the JUnit reports are checked after every test run."""

import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

CHECK = str(REPO / "tools" / "ci" / "junit_no_skips.py")

PYTEST_CLEAN = """<?xml version="1.0" encoding="utf-8"?>
<testsuites name="pytest tests"><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="2">
<testcase classname="tests.tooling.test_a" name="test_one" time="0.01"/>
<testcase classname="tests.tooling.test_a" name="test_two" time="0.01"/>
</testsuite></testsuites>
"""

PYTEST_ONE_SKIPPED = """<?xml version="1.0" encoding="utf-8"?>
<testsuites name="pytest tests"><testsuite name="pytest" errors="0" failures="0" skipped="1" tests="2">
<testcase classname="tests.tooling.test_a" name="test_one" time="0.01"/>
<testcase classname="tests.tooling.test_a" name="test_two" time="0.00">
<skipped type="pytest.skip" message="no hardware">no hardware</skipped></testcase>
</testsuite></testsuites>
"""

NEXTEST_CLEAN = """<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="1" failures="0" errors="0" uuid="0" timestamp="2026-10-02T00:00:00Z" time="0.1">
<testsuite name="core-domain" tests="1" disabled="0" errors="0" failures="0">
<testcase name="tests::it_works" classname="core-domain" timestamp="2026-10-02T00:00:00Z" time="0.01"/>
</testsuite></testsuites>
"""

EMPTY_RUN = """<?xml version="1.0" encoding="utf-8"?>
<testsuites name="pytest tests"><testsuite name="pytest" errors="0" failures="0" skipped="0" tests="0"/></testsuites>
"""


def check(tmp_path: Path, *reports: str) -> tuple[int, str]:
    paths = []
    for i, text in enumerate(reports):
        path = tmp_path / f"report{i}.xml"
        path.write_text(text)
        paths.append(str(path))
    result = run([sys.executable, CHECK, *paths], cwd=REPO)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_reports_without_skips_pass(tmp_path: Path) -> None:
    code, output = check(tmp_path, PYTEST_CLEAN, NEXTEST_CLEAN)
    assert code == 0, output
    assert "no skipped tests in 2 report(s)" in output


@pytest.mark.req("TOOLING")
def test_empty_run_passes(tmp_path: Path) -> None:
    code, output = check(tmp_path, EMPTY_RUN)
    assert code == 0, output


@pytest.mark.req("TOOLING")
def test_skipped_test_fails_and_is_named(tmp_path: Path) -> None:
    code, output = check(tmp_path, NEXTEST_CLEAN, PYTEST_ONE_SKIPPED)
    assert code == 1
    assert "1 skipped test(s)" in output
    assert "tests.tooling.test_a::test_two" in output


@pytest.mark.req("TOOLING")
def test_skipped_attribute_without_element_fails(tmp_path: Path) -> None:
    code, output = check(tmp_path, PYTEST_CLEAN.replace('skipped="0"', 'skipped="3"'))
    assert code == 1
    assert "3 skipped test(s)" in output


@pytest.mark.req("TOOLING")
def test_malformed_report_fails_closed(tmp_path: Path) -> None:
    code, output = check(tmp_path, "<testsuites><testsuite")
    assert code == 1
    assert "cannot parse" in output


@pytest.mark.req("TOOLING")
def test_missing_report_fails_closed(tmp_path: Path) -> None:
    result = run([sys.executable, CHECK, str(tmp_path / "absent.xml")], cwd=REPO)
    assert result.returncode == 1
    assert "cannot parse" in result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_no_report_argument_fails_closed() -> None:
    result = run([sys.executable, CHECK], cwd=REPO)
    assert result.returncode == 2
    assert "usage" in result.stderr
