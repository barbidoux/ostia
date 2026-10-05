"""The pytest `req` plugin (tools/traceability/pytest_plugin.py): every test names requirement ids that exist
in the registry, checked at collection, and the ids are recorded in the JUnit report.

Each test runs pytest in a subprocess on a temporary test file and a temporary registry.
"""

import sys
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from tooling_support import REPO, run

REGISTRY = """version: 1
requirements:
- id: FR-06
  level: MUST
  phases: [P1]
  phase_source: spec
  anssi: [FS3]
  section: 5. Functional requirements
  text: Extract archives within limits
- id: SEC-10
  level: MUST
  phases: [P1]
  phase_source: spec
  anssi: []
  section: 13. Isolation and hardening
  text: Hash the copy
- id: TOOLING
  level: n/a
  phases: []
  phase_source: reserved
  anssi: []
  section: reserved
  text: Tests of helpers, fixtures and tooling that prove no product requirement
"""


def pytest_run(tmp_path: Path, body: str, registry: str | None = REGISTRY) -> tuple[int, str, Path]:
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_sample.py").write_text("import pytest\n\n\n" + body)
    registry_path = tmp_path / "requirements.yaml"
    if registry is not None:
        registry_path.write_text(registry)
    junit = tmp_path / "junit.xml"
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-c",
        "/dev/null",
        "-p",
        "no:cacheprovider",
        "-p",
        "tools.traceability.pytest_plugin",
        "-o",
        f"req_registry={registry_path}",
        f"--rootdir={tmp_path}",
        f"--junitxml={junit}",
        str(tests),
    ]
    env_path = f"{REPO}"
    result = run(cmd, cwd=tmp_path, env={"PYTHONPATH": env_path, "PATH": "/usr/bin:/bin"})
    return result.returncode, result.stdout + result.stderr, junit


def properties(junit: Path) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for case in ET.parse(junit).getroot().iter("testcase"):
        values = [p.get("value", "") for p in case.iter("property") if p.get("name") == "req"]
        found[case.get("name", "")] = values
    return found


@pytest.mark.req("TOOLING")
def test_known_ids_pass_and_are_recorded_in_junit(tmp_path: Path) -> None:
    body = (
        '@pytest.mark.req("FR-06")\ndef test_one() -> None:\n    assert True\n\n\n'
        '@pytest.mark.req("FR-06", "SEC-10")\ndef test_two() -> None:\n    assert True\n'
    )
    code, output, junit = pytest_run(tmp_path, body)
    assert code == 0, output
    assert properties(junit) == {"test_one": ["FR-06"], "test_two": ["FR-06,SEC-10"]}


@pytest.mark.req("TOOLING")
def test_ids_from_several_markers_are_merged(tmp_path: Path) -> None:
    body = (
        '@pytest.mark.req("SEC-10")\n@pytest.mark.req("FR-06")\n'
        "def test_one() -> None:\n    assert True\n"
    )
    code, output, junit = pytest_run(tmp_path, body)
    assert code == 0, output
    assert properties(junit) == {"test_one": ["FR-06,SEC-10"]}


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("body", "message"),
    [
        (
            '@pytest.mark.req("FR-99")\ndef test_one() -> None:\n    assert True\n',
            "test_one: unknown requirement id 'FR-99'",
        ),
        ("def test_one() -> None:\n    assert True\n", "test_one: has no req marker"),
        (
            "@pytest.mark.req()\ndef test_one() -> None:\n    assert True\n",
            "test_one: req marker without an id",
        ),
        (
            "@pytest.mark.req(6)\ndef test_one() -> None:\n    assert True\n",
            "test_one: requirement ids must be strings, got 6",
        ),
    ],
    ids=["unknown id", "no marker", "marker without id", "not a string"],
)
def test_bad_tags_refuse_the_collection(tmp_path: Path, body: str, message: str) -> None:
    code, output, _ = pytest_run(tmp_path, body)
    assert code != 0
    assert message in output
    assert "1 passed" not in output


@pytest.mark.req("TOOLING")
def test_the_project_test_suite_loads_the_plugin() -> None:
    with (REPO / "pyproject.toml").open("rb") as f:
        options = tomllib.load(f)["tool"]["pytest"]["ini_options"]
    addopts = options["addopts"]
    assert "tools.traceability.pytest_plugin" in addopts
    assert addopts[addopts.index("tools.traceability.pytest_plugin") - 1] == "-p"
    assert "." in options["pythonpath"]


@pytest.mark.req("TOOLING")
def test_missing_registry_refuses_the_collection(tmp_path: Path) -> None:
    body = '@pytest.mark.req("FR-06")\ndef test_one() -> None:\n    assert True\n'
    code, output, _ = pytest_run(tmp_path, body, registry=None)
    assert code != 0
    assert f"cannot read the requirements registry {tmp_path / 'requirements.yaml'}" in output
