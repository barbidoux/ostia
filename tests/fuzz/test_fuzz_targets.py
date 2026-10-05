"""The fuzz targets of fuzz/ (cargo-fuzz, pinned nightly) reach the decoders and catch crashes and hangs
(NFR-06).

Run by `just test-fuzz` (CI job `fuzz` on every push and pull request, and the nightly workflow), not by
`just test`: they need the nightly toolchain and cargo-fuzz from tools/dev/versions.env. Nothing is
downloaded here: rustup may not install a toolchain, and fuzz/Cargo.lock must be current.

Environment: FUZZ_SECONDS (> 0, default 60) is how long the frame decoder target runs; FUZZ_CORPUS, when set,
is the corpus directory the run grows (the nightly workflow caches it); FUZZ_ARTIFACTS, when set, receives
crash and timeout inputs (the nightly workflow uploads it on failure).
"""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
FUZZ = REPO / "fuzz"
REGRESSIONS = FUZZ / "regressions"
SELFTEST = REGRESSIONS / "selftest"
VERSIONS = dict(
    line.split("=", 1)
    for line in (REPO / "tools" / "dev" / "versions.env").read_text().splitlines()
    if "=" in line
)
SECONDS = int(os.environ.get("FUZZ_SECONDS", "60"))
# Per-input limit: a decoder taking longer than this on one input is a finding.
INPUT_TIMEOUT = 5
# Generous allowance for building the targets with sanitizers.
BUILD_ALLOWANCE = 1200
# Coverage the frame decoder target reaches within seconds on nightly-2026-10-04 (607 measured in 15 s);
# a target that never reaches the decoders stays far below.
MIN_COVERAGE = 400


def unhex(path: Path) -> bytes:
    """An input file: hex digits and whitespace, `#` starts a comment line."""
    lines = path.read_text().splitlines()
    return bytes.fromhex("".join(line for line in lines if not line.lstrip().startswith("#")))


def artifacts(tmp_path: Path) -> Path:
    directory = Path(os.environ.get("FUZZ_ARTIFACTS", tmp_path / "artifacts"))
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def cargo_fuzz(*args: str, seconds: int = 0) -> subprocess.CompletedProcess[str]:
    toolchain = VERSIONS.get("NIGHTLY_TOOLCHAIN")
    assert toolchain, "NIGHTLY_TOOLCHAIN is not pinned in tools/dev/versions.env"
    assert shutil.which("cargo-fuzz"), "cargo-fuzz is not installed (see docs/dev-setup.md)"
    installed = subprocess.run(
        ["rustup", "toolchain", "list"], capture_output=True, text=True, check=False
    )
    assert toolchain in installed.stdout, f"{toolchain} is not installed (see docs/dev-setup.md)"
    env = {**os.environ, "CARGO_TERM_COLOR": "never", "RUSTUP_AUTO_INSTALL": "0"}
    command = ["cargo", f"+{toolchain}", "fuzz", *args]
    return subprocess.run(
        command,
        cwd=REPO,
        capture_output=True,
        text=True,
        env=env,
        check=False,
        timeout=seconds + BUILD_ALLOWANCE,
    )


def report(result: subprocess.CompletedProcess[str]) -> str:
    """The start of the log (libFuzzer's seed) and its end (the finding)."""
    return result.stderr[:1500] + "\n...\n" + result.stderr[-4000:]


@pytest.mark.req("NFR-06")
def test_the_fuzz_lockfile_is_current() -> None:
    toolchain = VERSIONS["NIGHTLY_TOOLCHAIN"]
    command = [
        "cargo",
        f"+{toolchain}",
        "metadata",
        "--locked",
        "--format-version",
        "1",
        "--manifest-path",
        str(FUZZ / "Cargo.toml"),
    ]
    env = {**os.environ, "RUSTUP_AUTO_INSTALL": "0"}
    result = subprocess.run(command, capture_output=True, text=True, env=env, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.req("NFR-06")
def test_the_frame_decoder_target_reaches_the_decoders_without_crashing(tmp_path: Path) -> None:
    assert SECONDS > 0, "FUZZ_SECONDS must be positive (0 means no limit to libFuzzer)"
    corpus = Path(os.environ.get("FUZZ_CORPUS", tmp_path / "corpus"))
    corpus.mkdir(parents=True, exist_ok=True)
    result = cargo_fuzz(
        "run",
        "frame_decoder",
        str(corpus),
        str(REPO / "proto" / "testdata"),
        "--",
        f"-max_total_time={SECONDS}",
        f"-timeout={INPUT_TIMEOUT}",
        f"-artifact_prefix={artifacts(tmp_path)}/",
        seconds=SECONDS,
    )
    assert result.returncode == 0, report(result)
    runs = re.search(r"^Done (\d+) runs", result.stderr, re.MULTILINE)
    assert runs and int(runs.group(1)) > 0, report(result)
    coverage = [int(value) for value in re.findall(r"\bcov: (\d+)", result.stderr)]
    assert coverage and max(coverage) >= MIN_COVERAGE, f"coverage {coverage[-1:]}\n{report(result)}"


@pytest.mark.req("NFR-06")
def test_a_crash_after_decoding_is_caught(tmp_path: Path) -> None:
    # The self-test target runs the same exercise as the real one, with a check planted behind the
    # fuzzing_selftest feature that panics on a response the decoders accepted (never in ostia-contracts).
    planted = tmp_path / "planted_crash.bin"
    planted.write_bytes(unhex(SELFTEST / "planted_crash.hex"))
    result = cargo_fuzz(
        "run",
        "frame_decoder_selftest",
        "--features",
        "fuzzing_selftest",
        str(planted),
        "--",
        f"-artifact_prefix={tmp_path}/",
    )
    assert result.returncode != 0, "the planted crash was not detected"
    assert "planted bug: the fuzz harness must catch this" in result.stderr, report(result)
    assert "deadly signal" in result.stderr, report(result)


@pytest.mark.req("NFR-06")
def test_a_slow_input_is_reported_as_a_timeout(tmp_path: Path) -> None:
    planted = tmp_path / "planted_hang.bin"
    planted.write_bytes(unhex(SELFTEST / "planted_hang.hex"))
    result = cargo_fuzz(
        "run",
        "frame_decoder_selftest",
        "--features",
        "fuzzing_selftest",
        str(planted),
        "--",
        "-timeout=2",
        f"-artifact_prefix={tmp_path}/",
    )
    assert result.returncode != 0, "the planted hang was not detected"
    assert "ERROR: libFuzzer: timeout after" in result.stderr, report(result)


@pytest.mark.req("NFR-06")
def test_the_real_target_survives_every_regression_input(tmp_path: Path) -> None:
    sources = sorted(REGRESSIONS.glob("*.hex"))
    assert sources, f"no regression input in {REGRESSIONS}"
    inputs = []
    for source in sources:
        binary = tmp_path / f"{source.stem}.bin"
        binary.write_bytes(unhex(source))
        inputs.append(str(binary))
    result = cargo_fuzz(
        "run",
        "frame_decoder",
        *inputs,
        "--",
        f"-timeout={INPUT_TIMEOUT}",
        f"-artifact_prefix={artifacts(tmp_path)}/",
    )
    assert result.returncode == 0, report(result)
    assert f"Executed {inputs[-1]}" in result.stderr
