"""The fuzz targets of fuzz/ (cargo-fuzz, pinned nightly) run and catch crashes (NFR-06).

Run by `just test-fuzz` (CI job `fuzz` on every push and pull request, and the nightly workflow), not by
`just test`: they need the nightly toolchain and cargo-fuzz from tools/dev/versions.env. FUZZ_SECONDS sets
how long the frame decoder target runs (default 60); FUZZ_CORPUS, when set, is the corpus directory the run
grows (the nightly workflow caches it). A missing toolchain or cargo-fuzz fails, never skips.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FUZZ = REPO / "fuzz"
REGRESSIONS = FUZZ / "regressions"
PLANTED = REGRESSIONS / "selftest" / "planted.bin"  # ASCII: "OSTIA-PLANTED-BUG"
VERSIONS = dict(
    line.split("=", 1)
    for line in (REPO / "tools" / "dev" / "versions.env").read_text().splitlines()
    if "=" in line
)
SECONDS = int(os.environ.get("FUZZ_SECONDS", "60"))


def cargo_fuzz(*args: str) -> subprocess.CompletedProcess[str]:
    toolchain = VERSIONS.get("NIGHTLY_TOOLCHAIN")
    assert toolchain, "NIGHTLY_TOOLCHAIN is not pinned in tools/dev/versions.env"
    assert shutil.which("cargo-fuzz"), "cargo-fuzz is not installed (see docs/dev-setup.md)"
    env = {**os.environ, "CARGO_TERM_COLOR": "never"}
    command = ["cargo", f"+{toolchain}", "fuzz", *args]
    return subprocess.run(command, cwd=REPO, capture_output=True, text=True, env=env, check=False)


@pytest.mark.req("NFR-06")
def test_the_frame_decoder_target_runs_for_a_fixed_time_without_crashing(tmp_path: Path) -> None:
    corpus = Path(os.environ.get("FUZZ_CORPUS", tmp_path / "corpus"))
    corpus.mkdir(parents=True, exist_ok=True)
    result = cargo_fuzz(
        "run",
        "frame_decoder",
        str(corpus),
        str(REPO / "proto" / "testdata"),
        "--",
        f"-max_total_time={SECONDS}",
        f"-artifact_prefix={tmp_path}/",
    )
    assert result.returncode == 0, result.stderr[-4000:]
    assert "Done " in result.stderr
    assert list(tmp_path.glob("crash-*")) == []


@pytest.mark.req("NFR-06")
def test_a_planted_crash_is_caught(tmp_path: Path) -> None:
    # The self-test target wraps the real decoders with a bug planted behind the fuzzing_selftest
    # feature (fuzz/fuzz_targets/frame_decoder_selftest.rs); the real decoder never contains it.
    assert PLANTED.is_file(), f"{PLANTED} is missing"
    result = cargo_fuzz(
        "run",
        "frame_decoder_selftest",
        "--features",
        "fuzzing_selftest",
        str(PLANTED),
        "--",
        f"-artifact_prefix={tmp_path}/",
    )
    assert result.returncode != 0, "the planted crash was not detected"
    assert "planted bug: the fuzz harness must catch this" in result.stderr
    assert "deadly signal" in result.stderr


def unhex(path: Path) -> bytes:
    """A regression input: hex digits and whitespace, `#` starts a comment line."""
    lines = path.read_text().splitlines()
    return bytes.fromhex("".join(line for line in lines if not line.lstrip().startswith("#")))


@pytest.mark.req("NFR-06")
def test_the_real_target_survives_every_regression_input(tmp_path: Path) -> None:
    sources = sorted(REGRESSIONS.glob("*.hex"))
    assert sources, f"no regression input in {REGRESSIONS}"
    inputs = []
    for source in sources:
        binary = tmp_path / f"{source.stem}.bin"
        binary.write_bytes(unhex(source))
        inputs.append(str(binary))
    result = cargo_fuzz("run", "frame_decoder", *inputs, "--", f"-artifact_prefix={tmp_path}/")
    assert result.returncode == 0, result.stderr[-4000:]
    assert f"Executed {inputs[-1]}" in result.stderr
