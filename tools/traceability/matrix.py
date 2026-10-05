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
exactly one tag. Missing or malformed inputs fail. Each report must sit next to a fingerprint of the sources
it was produced from (`sources.sha256`, written by `just test-rust` / `just test-py` with
`--write-fingerprint` before the suite runs); a report of other sources is refused, since a stale run cannot
vouch for the current tree.
"""

import argparse
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from registry import RegistryError, plan_citations

# `#[req(...)]` or `#[path::req(...)]`, up to the closing `)]`, across lines.
REQ_ATTRIBUTE = re.compile(r"#\s*\[\s*(?:\w+\s*::\s*)*req\s*\((.*?)\)\s*\]", re.DOTALL)
MARKER = "ostia-req: "
STRING = re.compile(r'"([^"]*)"')
TICKED = re.compile(r"^- \[x\] (WP-\d+\.\d+)\b", re.MULTILINE)
GATE = re.compile(r"^(P[0-9]|all)$")
NEXTEST_REPORT = Path("target/nextest/ci/junit.xml")
PYTEST_REPORT = Path("target/junit/pytest.xml")
FINGERPRINT = "sources.sha256"
# What a test run depends on: every file under these directories, and these files (relative to --root).
# fuzz/regressions only: the corpus and artifacts change while fuzzing and no test reads them.
SOURCE_DIRECTORIES = ["crates", "fuzz/regressions", "proto", "tests", "tools", "workers-py"]
SOURCE_FILES = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "pyproject.toml",
    "uv.lock",
    ".config/nextest.toml",
]
IGNORED_PARTS = {
    "target",
    ".venv",
    "__pycache__",
    "node_modules",
    ".hypothesis",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
}


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
    tags: int
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
        values = [
            prop.get("value", "") for prop in case.iter("property") if prop.get("name") == "req"
        ]
        ids = [rid.strip() for value in values for rid in value.split(",") if rid.strip()]
        output = case.findtext("system-out", "")
        name = case.get("name", "")
        cases.append(Case(case.get("classname", ""), name, status, ids, len(values), output))
    return cases


def sources(root: Path) -> list[Path]:
    found = [root / name for name in SOURCE_FILES if (root / name).is_file()]
    for directory in SOURCE_DIRECTORIES:
        for path in (root / directory).rglob("*"):
            parts = path.relative_to(root).parts
            if path.is_file() and path.suffix != ".pyc" and not IGNORED_PARTS.intersection(parts):
                found.append(path)
    return sorted(found)


def fingerprint(root: Path, files: list[Path]) -> str:
    """SHA-256 over the relative path and the content hash of every source."""
    digest = hashlib.sha256()
    for path in files:
        try:
            content = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as exc:
            raise TraceError(f"cannot read {path}: {exc}") from exc
        digest.update(f"{path.relative_to(root).as_posix()}\0{content}\n".encode())
    return digest.hexdigest()


def check_fresh(root: Path, files: list[Path]) -> None:
    """Refuse a report whose fingerprint is missing or differs from the current sources."""
    current = fingerprint(root, files)
    for report in (NEXTEST_REPORT, PYTEST_REPORT):
        try:
            recorded = (root / report.parent / FINGERPRINT).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise TraceError(f"{report} has no source fingerprint: run `just test` first") from exc
        if recorded != current:
            raise TraceError(f"{report} was produced from other sources: run `just test` first")


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
        if case.tags == 0:
            failures.append(f"Python test {name} has no req property")
        elif case.tags > 1:
            failures.append(f"Python test {name} has {case.tags} req properties")
        else:
            records.append(TestRecord("python", name, case.status, case.ids, name))
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
    parser.add_argument(
        "--write-fingerprint",
        type=Path,
        metavar="PATH",
        help="write the fingerprint of the current sources to PATH (under --root) and exit",
    )
    args = parser.parse_args(argv)
    if args.gate is not None and not GATE.match(args.gate):
        parser.error("--gate must be P0 to P9 or all")
    root: Path = args.root
    if args.write_fingerprint is not None:
        try:
            value = fingerprint(root, sources(root))
            destination = root / args.write_fingerprint
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(value + "\n", encoding="utf-8")
        except (TraceError, OSError) as exc:
            print(f"trace: {exc}")
            return 1
        return 0
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
