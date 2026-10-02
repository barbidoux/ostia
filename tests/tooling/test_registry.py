"""Requirements registry: requirements.yaml generated from docs/spec.md and docs/plan.md, validated.

The CLI is driven on small spec and plan documents written by each test, so expected values are the
literal content of those documents.
"""

import sys
from pathlib import Path

import pytest
import yaml

from tooling_support import REPO, run

REGISTRY = str(REPO / "tools" / "traceability" / "registry.py")
SCHEMA = str(REPO / "schemas" / "requirements.schema.json")

SPEC = """# Spec

## 2. Goals

| ID | Goal | Success measure |
| --- | --- | --- |
| G1 | Compliance | Tests pass |

## 5. Functional requirements

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| FR-01 | Mount the medium read-only (`ro`) | MUST | FS4, FS9 | P1 |
| FR-02 | Show a summary | SHOULD | — | P2–P3 |
| FR-03 | Network airlock | MAY | FS15 | after 1.0 |

## 6. Non-functional requirements

| ID | Area | Requirement | Level | Verification |
| --- | --- | --- | --- | --- |
| NFR-01 | Performance | Scan a medium in 10 minutes | MUST | Bench |
| NFR-02 | Determinism | Same versions give the same verdict | MUST | Test |

## 9. Engines

| ID | Requirement | Level | Phase |
| --- | --- | --- | --- |
| ENG-01 | Adapters for third-party engines | MUST | P3 |
"""

PLAN = """# Plan

| WP | Scope | Requirements | Tests written first | Size | After |
| --- | --- | --- | --- | --- | --- |
| WP-1.2 | Policy | FR-01, NFR-01, ADR-09 | Tables | M | 1.1 |
| WP-3.4 | ICAP | NFR-01, ENG-01 | Fake server | M | 3.1 |
"""

EXPECTED = [
    {
        "id": "FR-01",
        "level": "MUST",
        "phases": ["P1"],
        "phase_source": "spec",
        "anssi": ["FS4", "FS9"],
        "section": "5. Functional requirements",
        "text": "Mount the medium read-only (`ro`)",
    },
    {
        "id": "FR-02",
        "level": "SHOULD",
        "phases": ["P2", "P3"],
        "phase_source": "spec",
        "anssi": [],
        "section": "5. Functional requirements",
        "text": "Show a summary",
    },
    {
        "id": "FR-03",
        "level": "MAY",
        "phases": ["post-1.0"],
        "phase_source": "spec",
        "anssi": ["FS15"],
        "section": "5. Functional requirements",
        "text": "Network airlock",
    },
    {
        "id": "NFR-01",
        "level": "MUST",
        "phases": ["P1", "P3"],
        "phase_source": "plan",
        "anssi": [],
        "section": "6. Non-functional requirements",
        "area": "Performance",
        "text": "Scan a medium in 10 minutes",
    },
    {
        "id": "NFR-02",
        "level": "MUST",
        "phases": [],
        "phase_source": "none",
        "anssi": [],
        "section": "6. Non-functional requirements",
        "area": "Determinism",
        "text": "Same versions give the same verdict",
    },
    {
        "id": "ENG-01",
        "level": "MUST",
        "phases": ["P3"],
        "phase_source": "spec",
        "anssi": [],
        "section": "9. Engines",
        "text": "Adapters for third-party engines",
    },
    {
        "id": "TOOLING",
        "level": "n/a",
        "phases": [],
        "phase_source": "reserved",
        "anssi": [],
        "section": "reserved",
        "text": "Tests of helpers, fixtures and tooling that prove no product requirement",
    },
]


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def generate(tmp_path: Path, spec: str = SPEC, plan: str = PLAN) -> tuple[int, str, Path]:
    out = tmp_path / "requirements.yaml"
    cmd = [
        sys.executable,
        REGISTRY,
        "generate",
        "--spec",
        str(write(tmp_path, "spec.md", spec)),
        "--plan",
        str(write(tmp_path, "plan.md", plan)),
        "--out",
        str(out),
    ]
    result = run(cmd, cwd=REPO)
    return result.returncode, result.stdout + result.stderr, out


def validate(registry: Path) -> tuple[int, str]:
    cmd = [sys.executable, REGISTRY, "validate", "--registry", str(registry), "--schema", SCHEMA]
    result = run(cmd, cwd=REPO)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_generate_extracts_every_requirement_row(tmp_path: Path) -> None:
    code, output, out = generate(tmp_path)
    assert code == 0, output
    document = yaml.safe_load(out.read_text(encoding="utf-8"))
    assert document == {"version": 1, "requirements": EXPECTED}


@pytest.mark.req("TOOLING")
def test_generated_registry_passes_its_schema(tmp_path: Path) -> None:
    code, output, out = generate(tmp_path)
    assert code == 0, output
    code, output = validate(out)
    assert code == 0, output
    assert "registry valid: 7 entries" in output


@pytest.mark.req("TOOLING")
def test_output_is_deterministic(tmp_path: Path) -> None:
    first_dir, second_dir = tmp_path / "a", tmp_path / "b"
    first_dir.mkdir()
    second_dir.mkdir()
    code_a, output_a, first = generate(first_dir)
    code_b, output_b, second = generate(second_dir)
    assert (code_a, code_b) == (0, 0), output_a + output_b
    assert first.read_bytes() == second.read_bytes()
    header = "# Generated by tools/traceability/registry.py"
    assert first.read_text(encoding="utf-8").startswith(header)


@pytest.mark.req("TOOLING")
def test_plan_ranges_are_expanded(tmp_path: Path) -> None:
    spec = SPEC.replace(
        "| ENG-01 | Adapters for third-party engines | MUST | P3 |",
        "| ENG-01 | Adapters for third-party engines | MUST | P3 |\n"
        "| ENG-02 | Manifest | MUST | P3 |\n"
        "| ENG-03 | Loopback only | MUST | P3 |",
    ).replace(
        "| NFR-02 | Determinism | Same versions give the same verdict | MUST | Test |",
        "| NFR-02 | Determinism | Same versions give the same verdict | MUST | Test |\n"
        "| NFR-03 | Memory | Under 4 GiB | MUST | Bench |",
    )
    plan = PLAN + "| WP-2.1 | Sandbox | NFR-01 to NFR-03, ENG-01 to 03 | Escape tests | M | 1.6 |\n"
    code, output, out = generate(tmp_path, spec, plan)
    assert code == 0, output
    entries = {e["id"]: e for e in yaml.safe_load(out.read_text(encoding="utf-8"))["requirements"]}
    assert entries["NFR-02"]["phases"] == ["P2"]
    assert entries["NFR-03"]["phases"] == ["P2"]
    assert entries["NFR-01"]["phases"] == ["P1", "P2", "P3"]


@pytest.mark.req("TOOLING")
def test_duplicate_id_in_spec_fails(tmp_path: Path) -> None:
    spec = SPEC.replace(
        "| FR-03 | Network airlock | MAY | FS15 | after 1.0 |",
        "| FR-03 | Network airlock | MAY | FS15 | after 1.0 |\n| FR-01 | Again | MUST | — | P1 |",
    )
    code, output, out = generate(tmp_path, spec)
    assert code == 1
    assert "duplicate requirement id FR-01" in output
    assert not out.exists()


@pytest.mark.req("TOOLING")
def test_plan_citing_an_unknown_id_fails(tmp_path: Path) -> None:
    code, output, out = generate(tmp_path, plan=PLAN.replace("FR-01, NFR-01", "FR-99, NFR-01"))
    assert code == 1
    assert "WP-1.2 cites FR-99, which is not in the spec" in output
    assert not out.exists()


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        ("| SHOULD | — | P2–P3 |", "| SHOULD | — | soon |", "FR-02: unknown phase 'soon'"),
        ("| SHOULD | — | P2–P3 |", "| SHOULD | — |  |", "FR-02: unknown phase ''"),
        ("| SHOULD | — | P2–P3 |", "| OPTIONAL | — | P2–P3 |", "FR-02: unknown level 'OPTIONAL'"),
        ("| SHOULD | — | P2–P3 |", "| SHOULD | FS16 | P2–P3 |", "FR-02: unknown ANSSI 'FS16'"),
        ("| Show a summary |", "|  |", "FR-02: empty requirement text"),
    ],
)
def test_malformed_row_fails_closed(tmp_path: Path, old: str, new: str, message: str) -> None:
    code, output, out = generate(tmp_path, SPEC.replace(old, new))
    assert code == 1
    assert message in output
    assert not out.exists()


@pytest.mark.req("TOOLING")
def test_spec_without_requirements_fails(tmp_path: Path) -> None:
    code, output, _ = generate(tmp_path, "# Empty\n")
    assert code == 1
    assert "no requirement rows found" in output


def tamper(tmp_path: Path, change: str) -> Path:
    code, output, out = generate(tmp_path)
    assert code == 0, output
    document = yaml.safe_load(out.read_text(encoding="utf-8"))
    first = document["requirements"][0]
    if change == "extra field":
        first["owner"] = "someone"
    elif change == "bad id":
        first["id"] = "FR-1"
    elif change == "missing field":
        del first["level"]
    elif change == "bad level":
        first["level"] = "MUSTN'T"
    elif change == "bad phase":
        first["phases"] = ["P10"]
    elif change == "duplicate id":
        document["requirements"][1]["id"] = "FR-01"
    elif change == "wrong version":
        document["version"] = 2
    out.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return out


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "change",
    ["extra field", "bad id", "missing field", "bad level", "bad phase", "wrong version"],
)
def test_schema_rejects_a_malformed_registry(tmp_path: Path, change: str) -> None:
    code, output = validate(tamper(tmp_path, change))
    assert code == 1
    assert "registry invalid" in output


@pytest.mark.req("TOOLING")
def test_duplicate_id_in_registry_is_rejected(tmp_path: Path) -> None:
    code, output = validate(tamper(tmp_path, "duplicate id"))
    assert code == 1
    assert "registry invalid: duplicate id FR-01" in output


@pytest.mark.req("TOOLING")
def test_registry_that_is_not_yaml_is_rejected(tmp_path: Path) -> None:
    code, output = validate(write(tmp_path, "requirements.yaml", "requirements: [unclosed\n"))
    assert code == 1
    assert "registry invalid" in output


def committed_registry() -> str:
    path = REPO / "requirements.yaml"
    assert path.is_file(), "requirements.yaml is not generated and committed yet"
    return path.read_text(encoding="utf-8")


def check(registry: Path) -> tuple[int, str]:
    cmd = [sys.executable, REGISTRY, "check", "--registry", str(registry)]
    result = run(cmd, cwd=REPO)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_committed_registry_is_up_to_date() -> None:
    code, output = check(REPO / "requirements.yaml")
    assert code == 0, output
    assert "registry up to date: 131 entries" in output


@pytest.mark.req("TOOLING")
def test_stale_registry_is_reported(tmp_path: Path) -> None:
    stale = tmp_path / "requirements.yaml"
    text = committed_registry()
    stale.write_text(text.replace("level: SHOULD", "level: MUST", 1), encoding="utf-8")
    code, output = check(stale)
    assert code == 1
    assert "requirements.yaml is out of date: run `just registry`" in output


@pytest.mark.req("TOOLING")
def test_repository_registry_lists_every_spec_requirement() -> None:
    document = yaml.safe_load(committed_registry())
    entries = {e["id"]: e for e in document["requirements"]}
    families: dict[str, int] = {}
    for rid in entries:
        family = rid.split("-")[0]
        families[family] = families.get(family, 0) + 1
    assert families == {
        "FR": 25,
        "NFR": 19,
        "ENG": 8,
        "USB": 8,
        "DEEP": 9,
        "ENR": 13,
        "SEC": 14,
        "CTR": 7,
        "LOG": 10,
        "UI": 9,
        "UPD": 8,
        "TOOLING": 1,
    }
    assert entries["FR-03"] == {
        "id": "FR-03",
        "level": "MUST",
        "phases": ["P1"],
        "phase_source": "spec",
        "anssi": ["FS1"],
        "section": "5. Functional requirements",
        "text": "Support FAT12/16/32, exFAT, NTFS and ext2/3/4; reject any other file system cleanly "
        "with a clear message",
    }
    assert entries["FR-25"]["level"] == "SHOULD"
    assert entries["FR-25"]["anssi"] == []
    assert entries["FR-08"]["phases"] == ["P2", "P3"]
    assert entries["LOG-10"]["phases"] == ["post-1.0"]
    assert entries["NFR-09"]["phases"] == ["P0"]
    assert entries["NFR-09"]["phase_source"] == "plan"
