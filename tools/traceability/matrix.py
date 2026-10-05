"""Traceability matrix: requirements → tests → results, and the CI rules on it.

Usage: matrix.py [--root .] [--gate P<n>|all]

Inputs (under --root): requirements.yaml, docs/plan.md, docs/phase-status.md, the `#[req(...)]` attributes
of Rust functions under crates/, the nextest report target/nextest/ci/junit.xml and the pytest report
target/junit/pytest.xml (whose testcases carry the `req` property written by the pytest plugin).
Outputs: target/traceability.json and target/traceability.md.

Rules (docs/questions.md Q-14):
- always: an id that is not in the registry fails; a requirement cited by a ticked work package
  (docs/phase-status.md) without a passing test fails;
- --gate P<n>: every MUST of phase P<n> without a passing test fails; --gate all: every MUST of the spec.
A test passes only if its report shows it ran without failure, error or skip. A Rust test absent from the
nextest report did not run. Missing or malformed inputs fail.
"""

import argparse
import json
import re
import sys
import tomllib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from registry import RegistryError, plan_citations

REQ_ATTRIBUTE = re.compile(r"#\[req\(([^)]*)\)\]")
FUNCTION = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)")
OTHER_ATTRIBUTES = re.compile(r"#\[[^\]]*\]")
STRING = re.compile(r'"([^"]*)"')
TICKED = re.compile(r"^- \[x\] (WP-\d+\.\d+)\b", re.MULTILINE)
GATE = re.compile(r"^(P[0-9]|all)$")
NEXTEST_REPORT = Path("target/nextest/ci/junit.xml")
PYTEST_REPORT = Path("target/junit/pytest.xml")


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
        cases.append(Case(case.get("classname", ""), case.get("name", ""), status, ids))
    return cases


def crate_name(source: Path) -> str:
    for directory in source.parents:
        manifest = directory / "Cargo.toml"
        if manifest.is_file():
            with manifest.open("rb") as f:
                package = tomllib.load(f).get("package", {})
            if "name" in package:
                return str(package["name"])
    raise TraceError(f"no Cargo package for {source}")


def rust_tests(root: Path, cases: list[Case]) -> list[TestRecord]:
    records = []
    for source in sorted((root / "crates").rglob("*.rs")):
        text = source.read_text(encoding="utf-8")
        location = source.relative_to(root).as_posix()
        for attribute in REQ_ATTRIBUTE.finditer(text):
            function = FUNCTION.search(text, attribute.end())
            if not function:
                continue
            between = OTHER_ATTRIBUTES.sub("", text[attribute.end() : function.start()]).split()
            if any(word not in ("pub", "async") for word in between):
                continue  # the attribute does not decorate this function
            name, crate = function.group(1), crate_name(source)
            ids = STRING.findall(attribute.group(1))
            matches = [
                case
                for case in cases
                if (case.classname == crate or case.classname.startswith(f"{crate}::"))
                and case.name.split("::")[-1] == name
            ]
            for case in matches:
                full_name = f"{case.classname}::{case.name}"
                records.append(
                    TestRecord("rust", full_name, case.status, ids, f"{location} ({name})")
                )
            if not matches:
                records.append(
                    TestRecord("rust", f"{crate}::{name}", "not run", ids, f"{location} ({name})")
                )
    return records


def python_tests(cases: list[Case]) -> list[TestRecord]:
    return [
        TestRecord(
            "python", f"{c.classname}::{c.name}", c.status, c.ids, f"{c.classname}::{c.name}"
        )
        for c in cases
        if c.ids
    ]


def build(root: Path, gate: str | None) -> tuple[dict[str, Any], list[str]]:
    registry = read_registry(root)
    known = {str(entry["id"]) for entry in registry}
    tests = rust_tests(root, read_cases(root, NEXTEST_REPORT))
    tests += python_tests(read_cases(root, PYTEST_REPORT))
    failures = [
        f"unknown requirement id {rid!r} in {test.location}"
        for test in tests
        for rid in test.ids
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
        print(f"trace: {exc}", file=sys.stderr)
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
