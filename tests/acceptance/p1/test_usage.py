"""Usage errors of `ostia scan` (docs/contracts/cli.md, exit 2): they are refused before the medium is opened
and nothing is written. The engine checks make sure a scan never runs with fewer engines than the signed policy
declares (FR-08) and that no engine without a role in the policy contributes (FR-09)."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from common import (
    blank_image,
    fake_engine_config,
    policy_document,
    run_ostia,
    write_signed_policy,
)

DETECTOR = {"role": "detector", "trusted_alone": False}


@dataclass
class Setup:
    work: Path
    report: Path
    output: Path

    def args(
        self, engines: dict[str, dict[str, object]], dev_engines: list[Path]
    ) -> list[str | Path]:
        policy = write_signed_policy(self.work / "policy", policy_document(engines))
        args: list[str | Path] = ["scan", "--image", blank_image(), "--report", self.report]
        args += ["--output", self.output, *policy.args()]
        for engine in dev_engines:
            args += ["--dev-engine", engine]
        return args


def engine(work: Path, engine_id: str, sub: str = "") -> Path:
    return fake_engine_config(work / f"engines{sub}", engine_id)


def no_engine(s: Setup) -> list[str | Path]:
    return s.args({"fake-av": DETECTOR}, [])


def undeclared_engine(s: Setup) -> list[str | Path]:
    return s.args({"fake-av": DETECTOR}, [engine(s.work, "fake-av"), engine(s.work, "av-x")])


def missing_policy_engine(s: Setup) -> list[str | Path]:
    return s.args({"fake-av": DETECTOR, "av-b": DETECTOR}, [engine(s.work, "fake-av")])


def duplicate_engine_id(s: Setup) -> list[str | Path]:
    twice = [engine(s.work, "fake-av", "-1"), engine(s.work, "fake-av", "-2")]
    return s.args({"fake-av": DETECTOR}, twice)


def extra(flags: list[str]) -> Callable[[Setup], list[str | Path]]:
    def make(s: Setup) -> list[str | Path]:
        return [*s.args({"fake-av": DETECTOR}, [engine(s.work, "fake-av")]), *flags]

    return make


def missing_image(s: Setup) -> list[str | Path]:
    args = s.args({"fake-av": DETECTOR}, [engine(s.work, "fake-av")])
    args[args.index("--image") + 1] = s.work / "absent.img"
    return args


CASES: dict[str, Callable[[Setup], list[str | Path]]] = {
    "no-engine": no_engine,
    "policy-engine-missing": missing_policy_engine,
    "engine-not-in-policy": undeclared_engine,
    "duplicate-engine-id": duplicate_engine_id,
    "max-scan-time-zero": extra(["--max-scan-time", "0"]),
    "unknown-expiry-action": extra(["--on-expiry", "later"]),
    "unknown-mode": extra(["--mode", "lenient"]),
    "missing-image": missing_image,
}


@pytest.mark.req("FR-08", "FR-09", "FR-10", "FR-14")
@pytest.mark.parametrize("case", sorted(CASES))
def test_usage_error_exits_2_and_writes_nothing(tmp_path: Path, case: str) -> None:
    setup = Setup(tmp_path, tmp_path / "report.json", tmp_path / "output")
    result = run_ostia(*CASES[case](setup))
    assert result.returncode == 2, result.stderr
    assert result.stderr.startswith("ostia: ")
    assert not setup.report.exists()
    assert not setup.output.exists() or not any(setup.output.iterdir())


@pytest.mark.req("FR-10")
def test_non_empty_output_directory_is_refused_untouched(tmp_path: Path) -> None:
    setup = Setup(tmp_path, tmp_path / "report.json", tmp_path / "output")
    setup.output.mkdir()
    (setup.output / "already-here.txt").write_bytes(b"kept")
    result = run_ostia(*extra([])(setup))
    assert result.returncode == 2, result.stderr
    assert not setup.report.exists()
    assert [p.name for p in setup.output.iterdir()] == ["already-here.txt"]
    assert (setup.output / "already-here.txt").read_bytes() == b"kept"
