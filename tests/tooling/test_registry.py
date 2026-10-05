"""Requirements registry: requirements.yaml generated from docs/spec.md and docs/plan.md, validated.

The CLI is driven on small spec and plan documents written by each test, so expected values are the
literal content of those documents.
"""

import json
import os
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


EARLY_TABLE = (
    "| ID | Requirement | Level | Phase |\n"
    "| --- | --- | --- | --- |\n"
    "| ENG-09 | Early | MUST | P3 |\n"
)


def with_fr02_phase(cell: str) -> str:
    return SPEC.replace("| SHOULD | — | P2–P3 |", f"| SHOULD | — | {cell} |")


def write(tmp_path: Path, name: str, text: str) -> Path:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


def generate(
    tmp_path: Path, spec: str = SPEC, plan: str = PLAN, env: dict[str, str] | None = None
) -> tuple[int, str, Path]:
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
    result = run(cmd, cwd=REPO, env=env)
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
    # Different hash seeds: an iteration over an unordered set would change the output.
    code_a, output_a, first = generate(first_dir, env={**os.environ, "PYTHONHASHSEED": "1"})
    code_b, output_b, second = generate(second_dir, env={**os.environ, "PYTHONHASHSEED": "2"})
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
    plan = (
        PLAN
        + "| WP-2.1 | Sandbox | NFR-01 to 03, ENG-01 to 03 | Escape tests | M | 1.6 |\n"
        + "| WP-4.1 | Media | NFR-02 to NFR-03 | Images | M | 2.1 |\n"
    )
    code, output, out = generate(tmp_path, spec, plan)
    assert code == 0, output
    entries = {e["id"]: e for e in yaml.safe_load(out.read_text(encoding="utf-8"))["requirements"]}
    assert entries["NFR-01"]["phases"] == ["P1", "P2", "P3"]
    assert entries["NFR-02"]["phases"] == ["P2", "P4"]
    assert entries["NFR-03"]["phases"] == ["P2", "P4"]


@pytest.mark.req("TOOLING")
def test_short_form_range_citing_an_unknown_id_fails(tmp_path: Path) -> None:
    plan = PLAN + "| WP-3.1 | Manifest | ENG-01 to 02 | Schema | S | 2.3 |\n"
    code, output, out = generate(tmp_path, plan=plan)
    assert code == 1
    assert "WP-3.1 cites ENG-02, which is not in the spec" in output
    assert not out.exists()


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
    code, output, out = generate(tmp_path, "# Empty\n")
    assert code == 1
    assert "no requirement rows found" in output
    assert not out.exists()


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("spec", "plan", "message"),
    [
        (
            SPEC.replace("| FR-03 | Network airlock |", "| FR-3 | Network airlock |"),
            PLAN,
            "malformed requirement id 'FR-3'",
        ),
        (
            SPEC.replace("| ENG-01 | Adapters", "| ENG-001 | Adapters"),
            PLAN.replace("NFR-01, ENG-01", "NFR-01"),
            "malformed requirement id 'ENG-001'",
        ),
        (SPEC, PLAN.replace("FR-01, NFR-01", "FR-01, NFR-1"), "WP-1.2 cites malformed id 'NFR-1'"),
        (
            SPEC,
            PLAN + "| WP-2.1 | Sandbox |\n",
            "WP-2.1: expected at least 3 cells, found 2",
        ),
        (
            SPEC,
            PLAN + "| WP-1.2 | Again | FR-01 | x | S | — |\n",
            "duplicate work package WP-1.2",
        ),
        (
            SPEC,
            PLAN + "\nThresholds of NFR-41 are measured in WP-9.6.\n",
            "plan line 8 mentions NFR-41, which is not in the spec",
        ),
        (
            SPEC.replace("| Show a summary | SHOULD |", "| Show `a|b` | SHOULD |"),
            PLAN,
            "FR-02: expected 5 cells, found 6",
        ),
        (
            SPEC.replace("# Spec\n", "# Spec\n\n" + EARLY_TABLE),
            PLAN,
            "ENG-09: requirement table outside any section",
        ),
    ],
    ids=[
        "spec id with one digit",
        "spec id with three digits",
        "plan cites a malformed id",
        "short plan row",
        "duplicate work package",
        "unknown id in plan prose",
        "pipe inside a cell",
        "table before any section",
    ],
)
def test_malformed_sources_fail_closed(tmp_path: Path, spec: str, plan: str, message: str) -> None:
    code, output, out = generate(tmp_path, spec, plan)
    assert code == 1
    assert message in output
    assert not out.exists()


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("cell", "phases"),
    [("P2-P3", ["P2", "P3"]), ("P1, P3", ["P1", "P3"]), ("P3, P1, P3", ["P1", "P3"])],
)
def test_phase_cell_forms(tmp_path: Path, cell: str, phases: list[str]) -> None:
    code, output, out = generate(tmp_path, with_fr02_phase(cell))
    assert code == 0, output
    entries = {e["id"]: e for e in yaml.safe_load(out.read_text(encoding="utf-8"))["requirements"]}
    assert entries["FR-02"]["phases"] == phases


@pytest.mark.req("TOOLING")
def test_reversed_phase_range_fails(tmp_path: Path) -> None:
    code, output, out = generate(tmp_path, with_fr02_phase("P3–P2"))
    assert code == 1
    assert "FR-02: unknown phase 'P3–P2'" in output
    assert not out.exists()


@pytest.mark.req("TOOLING")
def test_table_without_id_header_is_not_read_as_requirements(tmp_path: Path) -> None:
    other_table = (
        "| ENG-01 | Adapters for third-party engines | MUST | P3 |\n\n"
        "| Engine | Kind | Level | Phase |\n| --- | --- | --- | --- |\n| ENG-02 | Native | MUST | P3 |\n"
    )
    spec = SPEC.replace("| ENG-01 | Adapters for third-party engines | MUST | P3 |\n", other_table)
    code, output, out = generate(tmp_path, spec)
    assert code == 0, output
    ids = [e["id"] for e in yaml.safe_load(out.read_text(encoding="utf-8"))["requirements"]]
    assert "ENG-02" not in ids


def tamper(tmp_path: Path, change: str) -> Path:
    code, output, out = generate(tmp_path)
    assert code == 0, output
    document = yaml.safe_load(out.read_text(encoding="utf-8"))
    requirements = document["requirements"]
    first, nfr, tooling = requirements[0], requirements[3], requirements[-1]
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
    elif change == "repeated phase":
        first["phases"] = ["P1", "P1"]
    elif change == "bad anssi":
        first["anssi"] = ["FS16"]
    elif change == "bad phase source":
        first["phase_source"] = "guess"
    elif change == "empty text":
        first["text"] = ""
    elif change == "n/a level on a requirement":
        first["level"] = "n/a"
    elif change == "phases without a source":
        nfr["phase_source"] = "none"
    elif change == "tooling with a phase":
        tooling["phases"] = ["P1"]
    elif change == "duplicate id":
        requirements[1]["id"] = "FR-01"
    elif change == "wrong version":
        document["version"] = 2
    elif change == "no requirements":
        document["requirements"] = []
    elif change == "not a mapping":
        document = ["FR-01"]
    out.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return out


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("change", "location"),
    [
        ("extra field", "requirements/0:"),
        ("bad id", "requirements/0/id:"),
        ("missing field", "requirements/0:"),
        ("bad level", "requirements/0/level:"),
        ("bad phase", "requirements/0/phases/0:"),
        ("repeated phase", "requirements/0/phases:"),
        ("bad anssi", "requirements/0/anssi/0:"),
        ("bad phase source", "requirements/0/phase_source:"),
        ("empty text", "requirements/0/text:"),
        ("n/a level on a requirement", "requirements/0"),
        ("phases without a source", "requirements/3"),
        ("tooling with a phase", "requirements/6"),
        ("wrong version", "version:"),
        ("no requirements", "requirements:"),
        ("not a mapping", "document:"),
    ],
)
def test_schema_rejects_a_malformed_registry(tmp_path: Path, change: str, location: str) -> None:
    code, output = validate(tamper(tmp_path, change))
    assert code == 1
    assert f"registry invalid: {location}" in output


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


@pytest.mark.req("TOOLING")
def test_schema_examples_are_valid_registries(tmp_path: Path) -> None:
    examples = json.loads(Path(SCHEMA).read_text(encoding="utf-8"))["examples"]
    assert len(examples) == 1
    for index, example in enumerate(examples):
        path = write(tmp_path, f"example{index}.yaml", yaml.safe_dump(example, sort_keys=False))
        code, output = validate(path)
        assert code == 0, output


def committed_registry() -> str:
    path = REPO / "requirements.yaml"
    assert path.is_file(), "requirements.yaml is not generated and committed yet"
    return path.read_text(encoding="utf-8")


def check(registry: Path) -> tuple[int, str]:
    cmd = [sys.executable, REGISTRY, "check", "--registry", str(registry)]
    result = run(cmd, cwd=REPO)
    return result.returncode, result.stdout + result.stderr


def check_sources(tmp_path: Path, registry: Path, plan: str = PLAN) -> tuple[int, str]:
    cmd = [
        sys.executable,
        REGISTRY,
        "check",
        "--spec",
        str(write(tmp_path, "check-spec.md", SPEC)),
        "--plan",
        str(write(tmp_path, "check-plan.md", plan)),
        "--registry",
        str(registry),
    ]
    result = run(cmd, cwd=REPO)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_check_passes_on_a_fresh_registry(tmp_path: Path) -> None:
    code, output, out = generate(tmp_path)
    assert code == 0, output
    code, output = check_sources(tmp_path, out)
    assert code == 0, output
    assert "registry up to date: 7 entries" in output


@pytest.mark.req("TOOLING")
def test_check_fails_when_the_plan_cites_an_unknown_id(tmp_path: Path) -> None:
    code, output, out = generate(tmp_path)
    assert code == 0, output
    code, output = check_sources(tmp_path, out, PLAN.replace("FR-01, NFR-01", "FR-99, NFR-01"))
    assert code == 1
    assert "WP-1.2 cites FR-99, which is not in the spec" in output


@pytest.mark.req("TOOLING")
def test_check_fails_on_a_schema_invalid_registry(tmp_path: Path) -> None:
    code, output = check_sources(tmp_path, tamper(tmp_path, "bad level"))
    assert code == 1
    assert "registry invalid: requirements/0/level" in output


@pytest.mark.req("TOOLING")
def test_check_fails_on_a_missing_registry(tmp_path: Path) -> None:
    code, output = check_sources(tmp_path, tmp_path / "absent.yaml")
    assert code == 1
    assert "registry invalid: cannot read" in output


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
    # Cited by no work package (docs/questions.md Q-10).
    for rid in ("NFR-07", "NFR-19"):
        assert entries[rid]["phases"] == []
        assert entries[rid]["phase_source"] == "none"
