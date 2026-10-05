"""Golden vectors of ostia.engine.v1 (tools/contracts/gen_vectors.py).

The generator writes proto/testdata/vectors.json and one `<name>.bin` frame per vector, with the Python
encoder; the Rust and Python test suites consume them. `--check` fails when the committed set differs from
what the generator writes.
"""

import json
import shutil
import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

GEN = str(REPO / "tools" / "contracts" / "gen_vectors.py")
TESTDATA = REPO / "proto" / "testdata"


def gen(*args: str) -> tuple[int, str]:
    result = run([sys.executable, GEN, *args], cwd=REPO)
    return result.returncode, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_committed_vectors_match_the_generator() -> None:
    code, output = gen("--check")
    assert code == 0, output
    assert "golden vectors are up to date (32 vectors)" in output


@pytest.mark.req("TOOLING")
def test_the_manifest_describes_every_vector(tmp_path: Path) -> None:
    code, output = gen("--out", str(tmp_path))
    assert code == 0, output
    manifest = json.loads((tmp_path / "vectors.json").read_text())
    names = [vector["name"] for vector in manifest["vectors"]]
    assert sorted(p.stem for p in tmp_path.glob("*.bin")) == sorted(names)
    by_name = {vector["name"]: vector for vector in manifest["vectors"]}
    assert by_name["response_clean"]["expect"] == "ok"
    assert by_name["response_clean"]["message"] == "AnalyzeResponse"
    assert by_name["response_clean"]["fields"]["engine_id"] == "clamav"
    assert by_name["frame_empty"]["expect"] == "empty"
    assert by_name["frame_empty"]["fields"] is None
    assert (tmp_path / "frame_empty.bin").read_bytes() == b"\x00\x00\x00\x00"
    assert (tmp_path / "frame_oversized.bin").read_bytes() == b"\x01\x00\x00\x01"


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("change", "message"),
    [
        ("edit a frame", "response_clean.bin is out of date: run `just vectors`"),
        ("delete a frame", "request_pdf.bin is missing: run `just vectors`"),
        ("extra frame", "stray.bin is not a vector: run `just vectors`"),
    ],
)
def test_check_detects_a_stale_set(tmp_path: Path, change: str, message: str) -> None:
    copy = tmp_path / "testdata"
    assert TESTDATA.is_dir(), "proto/testdata is not committed"
    shutil.copytree(TESTDATA, copy)
    if change == "edit a frame":
        (copy / "response_clean.bin").write_bytes(b"\x00\x00\x00\x01\x00")
    elif change == "delete a frame":
        (copy / "request_pdf.bin").unlink()
    else:
        (copy / "stray.bin").write_bytes(b"\x00")
    code, output = gen("--check", "--out", str(copy))
    assert code == 1
    assert message in output
