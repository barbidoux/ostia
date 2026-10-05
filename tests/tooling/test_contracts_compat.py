"""CTR-04: within major 1, ostia.engine.v1 only grows (tools/contracts/compat.py).

proto/ostia/engine/v1/compat.json freezes every v1 field (number, name, type, label) and enum value. The
check compares it with the descriptors of the generated code (a removed, renumbered, renamed or retyped field
or enum value fails; every current one must be frozen) and with the snapshot of the base branch (entries
can only be added, so a field cannot be removed from the .proto and the snapshot in one change).
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

COMPAT_TOOL = str(REPO / "tools" / "contracts" / "compat.py")
SNAPSHOT = REPO / "proto" / "ostia" / "engine" / "v1" / "compat.json"


def compat(*args: str) -> tuple[int, list[str]]:
    result = run([sys.executable, COMPAT_TOOL, *args], cwd=REPO)
    return result.returncode, (result.stdout + result.stderr).splitlines()


def edited_snapshot(tmp_path: Path, edit: str) -> Path:
    path = tmp_path / "compat.json"
    shutil.copyfile(SNAPSHOT, path)
    data = json.loads(path.read_text())
    response = data["messages"]["AnalyzeResponse"]
    if edit == "unknown field":
        response["9"] = ["verdict", "string", ""]
    elif edit == "renamed field":
        response["1"] = ["engine", "string", ""]
    elif edit == "retyped field":
        response["8"] = ["duration_ms", "uint64", ""]
    elif edit == "label":
        response["6"] = ["score", "double", ""]
    elif edit == "enum value":
        data["enums"]["Hint"]["5"] = "BENIGN"
    elif edit == "renamed enum value":
        data["enums"]["Status"]["2"] = "FAILED"
    elif edit == "unknown message":
        data["messages"]["Verdict"] = {"1": ["value", "string", ""]}
    elif edit == "package":
        data["package"] = "ostia.engine.v2"
    elif edit == "fewer fields":
        del response["8"]
    path.write_text(json.dumps(data))
    return path


@pytest.mark.req("CTR-04")
def test_the_generated_contract_matches_its_v1_snapshot() -> None:
    # Default base: origin/main (CI checks out the full history).
    code, lines = compat()
    assert code == 0, "\n".join(lines)
    assert lines[-1] == "ostia.engine.v1 is compatible with compat.json (5 messages, 3 enums)"
    code, lines = compat("--base", "HEAD")
    assert code == 0, "\n".join(lines)


@pytest.mark.req("CTR-04")
@pytest.mark.parametrize(
    ("edit", "message"),
    [
        ("unknown field", "AnalyzeResponse field 9 (verdict) is missing"),
        ("renamed field", "AnalyzeResponse field 1 is engine_id, string; v1 has engine, string"),
        (
            "retyped field",
            "AnalyzeResponse field 8 is duration_ms, uint32; v1 has duration_ms, uint64",
        ),
        ("label", "AnalyzeResponse field 6 is score, double, optional; v1 has score, double"),
        ("enum value", "Hint value 5 (BENIGN) is missing"),
        ("renamed enum value", "Status value 2 is ERROR; v1 has FAILED"),
        ("unknown message", "message Verdict is missing"),
        ("package", "package is ostia.engine.v1; the snapshot is for ostia.engine.v2"),
    ],
)
def test_a_breaking_change_is_refused(tmp_path: Path, edit: str, message: str) -> None:
    # Editing the snapshot stands for the opposite edit of the .proto.
    snapshot = edited_snapshot(tmp_path, edit)
    code, lines = compat("--snapshot", str(snapshot), "--base-snapshot", str(SNAPSHOT))
    assert code == 1
    assert f"compat: {message}" in lines
    assert lines[-1] == "ostia.engine.v1 breaks compat.json: a breaking change needs a new major"


@pytest.mark.req("CTR-04")
def test_every_current_field_must_be_frozen(tmp_path: Path) -> None:
    snapshot = edited_snapshot(tmp_path, "fewer fields")
    code, lines = compat("--snapshot", str(snapshot), "--base-snapshot", str(snapshot))
    assert code == 1
    assert "compat: AnalyzeResponse field 8 (duration_ms) is not frozen in compat.json" in lines


@pytest.mark.req("CTR-04")
def test_an_added_field_is_compatible(tmp_path: Path) -> None:
    # A base snapshot without duration_ms stands for an older v1: this change added the field.
    base = edited_snapshot(tmp_path, "fewer fields")
    code, lines = compat("--snapshot", str(SNAPSHOT), "--base-snapshot", str(base))
    assert code == 0, "\n".join(lines)


@pytest.mark.req("CTR-04")
def test_removing_a_field_from_the_proto_and_the_snapshot_together_is_refused(
    tmp_path: Path,
) -> None:
    # The base froze field 9; this change dropped it from both the .proto and compat.json.
    base = edited_snapshot(tmp_path, "unknown field")
    code, lines = compat("--snapshot", str(SNAPSHOT), "--base-snapshot", str(base))
    assert code == 1
    assert "compat: compat.json drops AnalyzeResponse field 9 (verdict) frozen on the base" in lines


@pytest.mark.req("CTR-04")
def test_a_base_without_a_snapshot_is_the_first_version() -> None:
    root = run(["git", "rev-list", "--max-parents=0", "HEAD"], cwd=REPO).stdout.split()[0]
    code, lines = compat("--base", root)
    assert code == 0, "\n".join(lines)
    assert f"compat: no compat.json at the base ({root[:12]}) yet: first version" in lines


@pytest.mark.req("CTR-04")
def test_an_unreadable_base_fails_closed() -> None:
    code, lines = compat("--base", "no-such-ref")
    assert code == 1
    expected = "compat: cannot read the base snapshot at no-such-ref"
    assert any(line.startswith(expected) for line in lines), "\n".join(lines)
