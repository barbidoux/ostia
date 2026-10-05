"""Traceability matrix: requirements → tests → results, and the CI rules on it.

Usage: matrix.py [--root .] [--gate P<n>|all]

Inputs (under --root): requirements.yaml, docs/plan.md, docs/phase-status.md, the nextest report
target/nextest/ci/junit.xml (each tagged test prints one `ostia-req: <ids>` line, kept in its system-out:
see crates/traceability) and the pytest report target/junit/pytest.xml (each testcase carries the `req`
property written by the pytest plugin). The ids of every `#[req(...)]` under crates/ (comments included) are
checked against the registry, but only the reports say which tests ran and passed.
Outputs: target/traceability.json and target/traceability.md.

Rules (docs/questions.md Q-14):
- always: an id that is not in the registry fails; a requirement cited by a ticked work package
  (docs/phase-status.md) without a passing test fails;
- --gate P<n>: every MUST of phase P<n> without a passing test fails; --gate all: every MUST of the spec.
A test passes only if its report shows it ran without failure, error or skip. Every reported test carries
exactly one tag. Missing or malformed inputs fail, and so do reports older than the sources (the reports
come from `just test`; a stale run cannot vouch for the current tree).
"""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from registry import RegistryError, plan_citations

REQ_ATTRIBUTE = re.compile(r"\breq\(([^)]*)\)")
MARKER = "ostia-req: "
STRING = re.compile(r'"([^"]*)"')
TICKED = re.compile(r"^- \[x\] (WP-\d+\.\d+)\b", re.MULTILINE)
GATE = re.compile(r"^(P[0-9]|all)$")
NEXTEST_REPORT = Path("target/nextest/ci/junit.xml")
PYTEST_REPORT = Path("target/junit/pytest.xml")
# Sources whose changes make the reports stale (relative to --root, file pattern).
SOURCES = [("crates", "*.rs"), ("tests", "*.py"), ("tools", "*.py"), ("workers-py", "*.py")]
IGNORED_PARTS = {"target", ".venv", "__pycache__", "node_modules"}


class TraceError(Exception):
    """An input cannot be read: the matrix cannot be trusted."""


@dataclass
class TestRecord:
    kind: str
    name: str
    status: str
    ids: list[str]
    location: str


@dataclass
class Case:
    classname: str
    name: str
    status: str
    ids: list[str]
    output: str


def read_registry(root: Path) -> list[dict[str, Any]]:
    try:
        document = yaml.safe_load((root / "requirements.yaml").read_text(encoding="utf-8"))
        entries: list[dict[str, Any]] = document["requirements"]
        return entries
    except (OSError, yaml.YAMLError, KeyError, TypeError) as exc:
        raise TraceError(f"cannot read requirements.yaml: {exc}") from exc


def read_cases(root: Path, report: Path) -> list[Case]:
    try:
        tree = ET.parse(root / report)
    except (OSError, ET.ParseError) as exc:
        raise TraceError(f"cannot read JUnit report {report}: {exc}") from exc
    if tree.getroot().tag not in ("testsuites", "testsuite"):
        raise TraceError(f"{report} is not a JUnit report (root element <{tree.getroot().tag}>)")
    cases = []
    for case in tree.getroot().iter("testcase"):
        if case.find("failure") is not None or case.find("error") is not None:
            status = "failed"
        elif case.find("skipped") is not None:
            status = "skipped"
        else:
            status = "passed"
        ids = [
            rid.strip()
            for prop in case.iter("property")
            if prop.get("name") == "req"
            for rid in prop.get("value", "").split(",")
            if rid.strip()
        ]
        output = case.findtext("system-out", "")
        cases.append(Case(case.get("classname", ""), case.get("name", ""), status, ids, output))
    return cases


def sources(root: Path) -> list[Path]:
    found = []
    for directory, pattern in SOURCES:
        for path in (root / directory).rglob(pattern):
            if not IGNORED_PARTS.intersection(path.relative_to(root).parts):
                found.append(path)
    return sorted(found)


def check_fresh(root: Path, files: list[Path]) -> None:
    """Refuse reports older than the newest source."""
    if not files:
        return
    newest = max(files, key=lambda path: path.stat().st_mtime_ns)
    for report in (NEXTEST_REPORT, PYTEST_REPORT):
        if (root / report).stat().st_mtime_ns < newest.stat().st_mtime_ns:
            relative = newest.relative_to(root).as_posix()
            raise TraceError(f"{report} is older than {relative}: run `just test` first")


def source_tags(root: Path, files: list[Path]) -> list[tuple[str, list[str]]]:
    """(file, ids) of every `req(...)` in the Rust sources, comments included."""
    tags = []
    for source in files:
        if source.suffix != ".rs":
            continue
        try:
            text = source.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise TraceError(f"cannot read {source}: {exc}") from exc
        location = source.relative_to(root).as_posix()
        tags += [(location, STRING.findall(m.group(1))) for m in REQ_ATTRIBUTE.finditer(text)]
    return tags


def rust_tests(cases: list[Case], failures: list[str]) -> list[TestRecord]:
    records = []
    for case in cases:
        name = f"{case.classname}::{case.name}"
        markers = [
            line.strip()[len(MARKER) :]
            for line in case.output.splitlines()
            if line.strip().startswith(MARKER)
        ]
        if not markers:
            failures.append(f"Rust test {name} has no #[req] marker in the nextest report")
        elif len(markers) > 1:
            failures.append(f"Rust test {name} has {len(markers)} #[req] markers")
        else:
            ids = [rid.strip() for rid in markers[0].split(",") if rid.strip()]
            records.append(TestRecord("rust", name, case.status, ids, name))
    return records


def python_tests(cases: list[Case], failures: list[str]) -> list[TestRecord]:
    records = []
    for case in cases:
        name = f"{case.classname}::{case.name}"
        if case.ids:
            records.append(TestRecord("python", name, case.status, case.ids, name))
        else:
            failures.append(f"Python test {name} has no req property")
    return records


def build(root: Path, gate: str | None) -> tuple[dict[str, Any], list[str]]:
    registry = read_registry(root)
    known = {str(entry["id"]) for entry in registry}
    nextest_cases = read_cases(root, NEXTEST_REPORT)
    pytest_cases = read_cases(root, PYTEST_REPORT)
    files = sources(root)
    check_fresh(root, files)
    failures: list[str] = []
    tests = rust_tests(nextest_cases, failures)
    tests += python_tests(pytest_cases, failures)
    failures += [
        f"unknown requirement id {rid!r} in {test.location}"
        for test in tests
        for rid in test.ids
        if rid not in known
    ]
    failures += [
        f"unknown requirement id {rid!r} in {location}"
        for location, ids in source_tags(root, files)
        for rid in ids
        if rid not in known
    ]
    matrix: dict[str, Any] = {}
    for entry in registry:
        rid = str(entry["id"])
        covering = [test for test in tests if rid in test.ids]
        matrix[rid] = {
            "level": entry["level"],
            "phases": entry["phases"],
            "passing": any(test.status == "passed" for test in covering),
            "tests": [{"kind": t.kind, "name": t.name, "status": t.status} for t in covering],
        }
    try:
        plan = (root / "docs" / "plan.md").read_text(encoding="utf-8")
        status = (root / "docs" / "phase-status.md").read_text(encoding="utf-8")
        citations = plan_citations(plan)
    except (OSError, RegistryError) as exc:
        raise TraceError(f"cannot read the plan or the phase status: {exc}") from exc
    for wid in TICKED.findall(status):
        for rid in citations.get(wid, []):
            if rid in matrix and not matrix[rid]["passing"]:
                failures.append(f"{rid} (cited by ticked {wid}) has no passing test")
    if gate:
        for rid, row in matrix.items():
            in_gate = gate == "all" or gate in row["phases"]
            if row["level"] == "MUST" and in_gate and not row["passing"]:
                phases = ", ".join(row["phases"]) or "no phase"
                failures.append(f"{rid} (MUST, {phases}) has no passing test")
    return {"version": 1, "requirements": matrix}, list(dict.fromkeys(failures))


def markdown(document: dict[str, Any]) -> str:
    lines = [
        "# Traceability matrix",
        "",
        "| Requirement | Level | Phases | Passing | Tests |",
        "|---|---|---|---|---|",
    ]
    for rid, row in document["requirements"].items():
        tests = ", ".join(f"{t['name']} ({t['status']})" for t in row["tests"])
        passing = "yes" if row["passing"] else "no"
        lines.append(
            f"| {rid} | {row['level']} | {', '.join(row['phases'])} | {passing} | {tests} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Ostia traceability matrix")
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--gate")
    args = parser.parse_args(argv)
    if args.gate is not None and not GATE.match(args.gate):
        parser.error("--gate must be P0 to P9 or all")
    root: Path = args.root
    try:
        document, failures = build(root, args.gate)
    except TraceError as exc:
        print(f"trace: {exc}")
        print("traceability FAILED")
        return 1
    target = root / "target"
    target.mkdir(parents=True, exist_ok=True)
    (target / "traceability.json").write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8"
    )
    (target / "traceability.md").write_text(markdown(document), encoding="utf-8")
    for failure in failures:
        print(f"trace: {failure}")
    if failures:
        print("traceability FAILED")
        return 1
    rows = document["requirements"].values()
    passing = sum(1 for row in rows if row["passing"])
    print(f"traceability OK: {passing} of {len(rows)} requirements have a passing test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
