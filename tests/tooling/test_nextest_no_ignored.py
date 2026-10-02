"""A Rust `#[ignore]` test fails the fast suite.

cargo-nextest leaves ignored tests out of its JUnit report (checked with nextest 0.9.146: a crate
with one ignored test reports tests="1" skipped="0"), so the test list is checked instead.
"""

import json
import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

CHECK = str(REPO / "tools" / "ci" / "nextest_no_ignored.py")


def listing(cases: dict[str, dict[str, bool]]) -> str:
    """A `cargo nextest list --message-format json` document with one suite."""
    testcases = {
        name: {"kind": "test", "ignored": flags["ignored"], "filter-match": {"status": "matches"}}
        for name, flags in cases.items()
    }
    suites = {"ostia-core-domain": {"binary-id": "ostia-core-domain", "testcases": testcases}}
    return json.dumps({"rust-build-meta": {}, "test-count": len(cases), "rust-suites": suites})


def check(tmp_path: Path, text: str) -> tuple[int, str]:
    path = tmp_path / "list.json"
    path.write_text(text)
    result = run([sys.executable, CHECK, str(path)], cwd=REPO)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_list_without_ignored_tests_passes(tmp_path: Path) -> None:
    code, output = check(tmp_path, listing({"tests::a": {"ignored": False}}))
    assert code == 0, output
    assert "no ignored Rust tests (1 listed)" in output


@pytest.mark.req("TOOLING")
def test_empty_workspace_passes(tmp_path: Path) -> None:
    text = json.dumps({"rust-build-meta": {}, "test-count": 0, "rust-suites": {}})
    code, output = check(tmp_path, text)
    assert code == 0, output
    assert "no ignored Rust tests (0 listed)" in output


@pytest.mark.req("TOOLING")
def test_ignored_test_fails_and_is_named(tmp_path: Path) -> None:
    cases = {"tests::a": {"ignored": False}, "tests::slow": {"ignored": True}}
    code, output = check(tmp_path, listing(cases))
    assert code == 1
    assert "1 ignored Rust test(s)" in output
    assert "ostia-core-domain::tests::slow" in output


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        "[]",
        '{"test-count": 1}',
        '{"rust-suites": {"x": {"testcases": {"t": {"kind": "test"}}}}}',
    ],
)
def test_malformed_list_fails_closed(tmp_path: Path, text: str) -> None:
    code, output = check(tmp_path, text)
    assert code == 1
    assert "cannot read nextest list" in output


@pytest.mark.req("TOOLING")
def test_missing_list_fails_closed(tmp_path: Path) -> None:
    result = run([sys.executable, CHECK, str(tmp_path / "absent.json")], cwd=REPO)
    assert result.returncode == 1
    assert "cannot read nextest list" in result.stderr
