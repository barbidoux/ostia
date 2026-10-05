"""Traceability matrix (tools/traceability/matrix.py) on a fixture mini-repository.

tests/tooling/fixtures/trace/complete/ is a complete repository: registry, plan, phase status, a Rust crate
with #[req] tests, and the nextest and pytest JUnit reports of a run. Each test copies it and changes one
thing. Rules (docs/questions.md Q-14): unknown ids always fail; a requirement cited by a ticked work package
without a passing test always fails; `--gate P<n>` / `--gate all` fail on a MUST without a passing test.
"""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

MATRIX = str(REPO / "tools" / "traceability" / "matrix.py")
COMPLETE = Path(__file__).parent / "fixtures" / "trace" / "complete"
PYTEST_REPORT = Path("target/junit/pytest.xml")
NEXTEST_REPORT = Path("target/nextest/ci/junit.xml")
REPORT_TIME = 1_790_000_000
MEDIUM_MARKER = "ostia-req: FR-01\n"


def repository(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(COMPLETE, root)
    # The reports of a run are newer than the sources they were produced from.
    for source in (root / "crates").rglob("*.rs"):
        os.utime(source, (REPORT_TIME - 60, REPORT_TIME - 60))
    for report in (NEXTEST_REPORT, PYTEST_REPORT):
        os.utime(root / report, (REPORT_TIME, REPORT_TIME))
    return root


def matrix(root: Path, *args: str) -> tuple[int, list[str]]:
    result = run([sys.executable, MATRIX, "--root", str(root), *args], cwd=REPO)
    return result.returncode, (result.stdout + result.stderr).splitlines()


def replace(root: Path, relative: Path | str, old: str, new: str) -> None:
    """Edit a file of the fixture repository, keeping its modification time."""
    path = root / relative
    text = path.read_text()
    assert old in text, f"{old!r} not in {relative}"
    times = path.stat()
    path.write_text(text.replace(old, new))
    os.utime(path, ns=(times.st_atime_ns, times.st_mtime_ns))


@pytest.mark.req("TOOLING")
def test_complete_repository_passes_and_writes_the_matrix(tmp_path: Path) -> None:
    root = repository(tmp_path)
    code, lines = matrix(root)
    assert code == 0, "\n".join(lines)
    assert lines[-1] == "traceability OK: 3 of 5 requirements have a passing test"
    data = json.loads((root / "target" / "traceability.json").read_text())
    assert data == {
        "version": 1,
        "requirements": {
            "FR-01": {
                "level": "MUST",
                "phases": ["P1"],
                "passing": True,
                "tests": [
                    {"kind": "rust", "name": "demo::tests::medium_is_read_only", "status": "passed"}
                ],
            },
            "FR-02": {
                "level": "MUST",
                "phases": ["P1"],
                "passing": True,
                "tests": [
                    {
                        "kind": "python",
                        "name": "tests.test_hashes::test_every_object_is_hashed",
                        "status": "passed",
                    }
                ],
            },
            "FR-03": {"level": "SHOULD", "phases": ["P1"], "passing": False, "tests": []},
            "NFR-01": {"level": "MUST", "phases": ["P2"], "passing": False, "tests": []},
            "TOOLING": {
                "level": "n/a",
                "phases": [],
                "passing": True,
                "tests": [
                    {"kind": "rust", "name": "demo::tests::helper_works", "status": "passed"},
                    {
                        "kind": "python",
                        "name": "tests.test_hashes::test_every_object_is_hashed",
                        "status": "passed",
                    },
                    {
                        "kind": "python",
                        "name": "tests.test_hashes::test_summary_header",
                        "status": "passed",
                    },
                ],
            },
        },
    }
    markdown = (root / "target" / "traceability.md").read_text()
    assert "| FR-01 | MUST | P1 | yes | demo::tests::medium_is_read_only (passed) |" in markdown
    assert "| NFR-01 | MUST | P2 | no |  |" in markdown


@pytest.mark.req("TOOLING")
def test_missing_test_for_a_ticked_work_package_fails(tmp_path: Path) -> None:
    root = repository(tmp_path)
    replace(root, PYTEST_REPORT, 'value="FR-02,TOOLING"', 'value="TOOLING"')
    code, lines = matrix(root)
    assert code == 1
    assert "trace: FR-02 (cited by ticked WP-1.2) has no passing test" in lines
    assert lines[-1] == "traceability FAILED"


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("child", "status"),
    [
        ('<failure message="assert False">boom</failure>', "failed"),
        ('<error message="fixture">boom</error>', "failed"),
        ('<skipped message="later">later</skipped>', "skipped"),
    ],
    ids=["failure", "error", "skipped"],
)
def test_a_test_that_did_not_pass_does_not_cover(tmp_path: Path, child: str, status: str) -> None:
    root = repository(tmp_path)
    replace(
        root,
        PYTEST_REPORT,
        '<properties><property name="req" value="FR-02,TOOLING"/></properties>',
        f'<properties><property name="req" value="FR-02,TOOLING"/></properties>{child}',
    )
    code, lines = matrix(root)
    assert code == 1
    assert "trace: FR-02 (cited by ticked WP-1.2) has no passing test" in lines
    data = json.loads((root / "target" / "traceability.json").read_text())
    assert data["requirements"]["FR-02"]["tests"][0]["status"] == status


@pytest.mark.req("TOOLING")
def test_rust_test_absent_from_the_nextest_report_does_not_cover(tmp_path: Path) -> None:
    # The #[req("FR-01")] attribute is still in the source: only the report proves a test ran.
    root = repository(tmp_path)
    report = (root / NEXTEST_REPORT).read_text()
    start = report.index('<testcase name="tests::medium_is_read_only"')
    end = report.index("</testcase>", start) + len("</testcase>")
    (root / NEXTEST_REPORT).write_text(report[:start] + report[end:])
    code, lines = matrix(root)
    assert code == 1
    assert "trace: FR-01 (cited by ticked WP-1.1) has no passing test" in lines
    data = json.loads((root / "target" / "traceability.json").read_text())
    assert data["requirements"]["FR-01"]["tests"] == []


@pytest.mark.req("TOOLING")
def test_a_passing_test_with_the_same_name_does_not_cover_a_failing_one(tmp_path: Path) -> None:
    # tests::medium_is_read_only (FR-01) fails; other::medium_is_read_only (TOOLING) passes.
    root = repository(tmp_path)
    replace(
        root,
        NEXTEST_REPORT,
        '<testcase name="tests::helper_works" classname="demo" time="0.001">',
        '<testcase name="other::medium_is_read_only" classname="demo" time="0.001">',
    )
    replace(
        root,
        NEXTEST_REPORT,
        '<testcase name="tests::medium_is_read_only" classname="demo" time="0.001">',
        '<testcase name="tests::medium_is_read_only" classname="demo" time="0.001">'
        '<failure message="panicked">boom</failure>',
    )
    code, lines = matrix(root)
    assert code == 1
    assert "trace: FR-01 (cited by ticked WP-1.1) has no passing test" in lines
    data = json.loads((root / "target" / "traceability.json").read_text())
    assert data["requirements"]["FR-01"]["tests"] == [
        {"kind": "rust", "name": "demo::tests::medium_is_read_only", "status": "failed"}
    ]


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("relative", "old", "new", "message"),
    [
        (
            NEXTEST_REPORT,
            "ostia-req: TOOLING\n",
            "",
            "trace: Rust test demo::tests::helper_works has no #[req] marker in the nextest report",
        ),
        (
            NEXTEST_REPORT,
            MEDIUM_MARKER,
            MEDIUM_MARKER + MEDIUM_MARKER,
            "trace: Rust test demo::tests::medium_is_read_only has 2 #[req] markers",
        ),
        (
            PYTEST_REPORT,
            '<properties><property name="req" value="TOOLING"/></properties>',
            "",
            "trace: Python test tests.test_hashes::test_summary_header has no req property",
        ),
    ],
    ids=["rust without marker", "rust with two markers", "python without property"],
)
def test_every_reported_test_carries_exactly_one_tag(
    tmp_path: Path, relative: Path, old: str, new: str, message: str
) -> None:
    root = repository(tmp_path)
    replace(root, relative, old, new)
    code, lines = matrix(root)
    assert code == 1
    assert message in lines


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("relative", "old", "new", "message"),
    [
        (
            NEXTEST_REPORT,
            MEDIUM_MARKER,
            "ostia-req: FR-01,FR-09\n",
            "trace: unknown requirement id 'FR-09' in demo::tests::medium_is_read_only",
        ),
        (
            "crates/demo/src/lib.rs",
            '#[req("FR-01")]',
            '#[req("FR-01", "FR-09")]',
            "trace: unknown requirement id 'FR-09' in crates/demo/src/lib.rs",
        ),
        (
            "crates/demo/src/lib.rs",
            '#[req("TOOLING")]',
            '// #[req("SEC-77")]\n    #[req("TOOLING")]',
            "trace: unknown requirement id 'SEC-77' in crates/demo/src/lib.rs",
        ),
        (
            PYTEST_REPORT,
            'value="FR-02,TOOLING"',
            'value="FR-02,SEC-99"',
            "trace: unknown requirement id 'SEC-99' in tests.test_hashes::test_every_object_is_hashed",
        ),
    ],
    ids=["rust report", "rust source of a test that did not run", "rust comment", "python"],
)
def test_unknown_ids_fail(
    tmp_path: Path, relative: Path | str, old: str, new: str, message: str
) -> None:
    root = repository(tmp_path)
    replace(root, relative, old, new)
    code, lines = matrix(root)
    assert code == 1
    assert message in lines


@pytest.mark.req("TOOLING")
def test_reports_older_than_the_sources_are_refused(tmp_path: Path) -> None:
    root = repository(tmp_path)
    source = root / "crates" / "demo" / "src" / "lib.rs"
    os.utime(source, (REPORT_TIME + 1, REPORT_TIME + 1))
    code, lines = matrix(root)
    assert code == 1
    assert (
        f"trace: {NEXTEST_REPORT} is older than crates/demo/src/lib.rs: run `just test` first"
        in lines
    )
    assert lines[-1] == "traceability FAILED"


@pytest.mark.req("TOOLING")
def test_gate_of_the_phase_requires_every_must(tmp_path: Path) -> None:
    root = repository(tmp_path)
    code, lines = matrix(root, "--gate", "P1")
    assert code == 0, "\n".join(lines)
    replace(root, "docs/phase-status.md", "- [x] WP-1.2", "- [ ] WP-1.2")
    replace(root, PYTEST_REPORT, 'value="FR-02,TOOLING"', 'value="TOOLING"')
    code, lines = matrix(root)
    assert code == 0, "rule 1 only covers ticked work packages:\n" + "\n".join(lines)
    code, lines = matrix(root, "--gate", "P1")
    assert code == 1
    assert "trace: FR-02 (MUST, P1) has no passing test" in lines
    assert not any("FR-03" in line for line in lines), "a SHOULD is not gated"


@pytest.mark.req("TOOLING")
def test_gate_all_requires_every_must_of_the_spec(tmp_path: Path) -> None:
    code, lines = matrix(repository(tmp_path), "--gate", "all")
    assert code == 1
    assert "trace: NFR-01 (MUST, P2) has no passing test" in lines
    assert not any("FR-03" in line for line in lines), "a SHOULD is not gated"


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("delete nextest", f"trace: cannot read JUnit report {NEXTEST_REPORT}"),
        ("delete pytest", f"trace: cannot read JUnit report {PYTEST_REPORT}"),
        ("garble nextest", f"trace: cannot read JUnit report {NEXTEST_REPORT}"),
        ("garble pytest", f"trace: cannot read JUnit report {PYTEST_REPORT}"),
        ("not junit", f"trace: {NEXTEST_REPORT} is not a JUnit report (root element <html>)"),
        ("delete registry", "trace: cannot read requirements.yaml"),
        ("registry without requirements", "trace: cannot read requirements.yaml"),
        ("delete plan", "trace: cannot read the plan or the phase status"),
        ("delete phase status", "trace: cannot read the plan or the phase status"),
    ],
)
def test_missing_or_malformed_inputs_fail_closed(tmp_path: Path, change: str, message: str) -> None:
    root = repository(tmp_path)
    if change == "delete nextest":
        (root / NEXTEST_REPORT).unlink()
    elif change == "delete pytest":
        (root / PYTEST_REPORT).unlink()
    elif change == "garble nextest":
        (root / NEXTEST_REPORT).write_text("<testsuites><testsuite")
    elif change == "garble pytest":
        (root / PYTEST_REPORT).write_text("<testsuites><testsuite")
    elif change == "not junit":
        (root / NEXTEST_REPORT).write_text("<html/>")
    elif change == "delete registry":
        (root / "requirements.yaml").unlink()
    elif change == "registry without requirements":
        (root / "requirements.yaml").write_text("version: 1\n")
    elif change == "delete plan":
        (root / "docs" / "plan.md").unlink()
    elif change == "delete phase status":
        (root / "docs" / "phase-status.md").unlink()
    code, lines = matrix(root)
    assert code == 1
    assert any(line.startswith(message) for line in lines), "\n".join(lines)


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("gate", ["P10", "p1", "everything"])
def test_unknown_gate_is_a_usage_error(tmp_path: Path, gate: str) -> None:
    code, lines = matrix(repository(tmp_path), "--gate", gate)
    assert code == 2
    assert any("--gate must be P0 to P9 or all" in line for line in lines)
