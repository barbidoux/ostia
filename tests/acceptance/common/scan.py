"""One `ostia scan` run and what it produced: exit status, report, transferred files."""

import subprocess
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from common.ostia import load_report, run_ostia
from common.policy import SignedPolicy


@dataclass
class Scan:
    result: subprocess.CompletedProcess[str]
    report_path: Path
    output: Path
    _report: dict[str, Any] | None = None

    @property
    def report(self) -> dict[str, Any]:
        """The validated report of a scan that completed (exit 0)."""
        if self._report is None:
            assert self.result.returncode == 0, (
                f"ostia scan exited {self.result.returncode}: {self.result.stderr.strip()}"
            )
            self._report = load_report(self.report_path)
        return self._report

    @property
    def objects(self) -> list[dict[str, Any]]:
        objects: list[dict[str, Any]] = self.report["objects"]
        return objects

    def files(self) -> list[dict[str, Any]]:
        """Objects of origin FILE (the medium's files)."""
        return [o for o in self.objects if o["origin"] == "FILE"]

    def file(self, path: str) -> dict[str, Any]:
        """The medium file at `path`; exactly one must exist."""
        found = [o for o in self.files() if o["path"] == path]
        assert len(found) == 1, f"{len(found)} FILE objects with path {path!r}"
        return found[0]

    def stream(self, path: str, name: str, origin: str) -> dict[str, Any]:
        """The ALT_STREAM or XATTR object `name` of the file at `path`; exactly one must exist."""
        found = [
            o
            for o in self.objects
            if o["origin"] == origin and o["path"] == path and o["stream"] == name
        ]
        assert len(found) == 1, f"{len(found)} {origin} objects {path!r} / {name!r}"
        return found[0]

    def by_id(self, object_id: str) -> dict[str, Any]:
        found = [o for o in self.objects if o["id"] == object_id]
        assert len(found) == 1, f"{len(found)} objects with id {object_id!r}"
        return found[0]

    def children(self, parent: dict[str, Any], origin: str = "EXTRACTED") -> list[dict[str, Any]]:
        return [o for o in self.objects if o["parent_id"] == parent["id"] and o["origin"] == origin]

    def child(self, parent: dict[str, Any], path: str) -> dict[str, Any]:
        """The extracted entry `path` of `parent`; exactly one must exist."""
        found = [o for o in self.children(parent) if o["path"] == path]
        assert len(found) == 1, f"{len(found)} entries {path!r} in {parent['path']!r}"
        return found[0]

    def descendants(self, parent: dict[str, Any]) -> list[dict[str, Any]]:
        """Every EXTRACTED object below `parent`, all levels."""
        found = []
        pending = [parent]
        while pending:
            current = pending.pop()
            for child in self.children(current):
                found.append(child)
                pending.append(child)
        return found

    def output_files(self) -> dict[str, bytes]:
        """What `--output` received from a scan that completed: relative `/`-separated path -> bytes."""
        assert self.report is not None
        if not self.output.exists():
            return {}
        return {
            path.relative_to(self.output).as_posix(): path.read_bytes()
            for path in sorted(self.output.rglob("*"))
            if path.is_file()
        }

    def engine_result(self, obj: dict[str, Any], engine_id: str) -> dict[str, Any]:
        results: list[dict[str, Any]] = obj["engine_results"]
        found = [r for r in results if r["engine_id"] == engine_id]
        assert len(found) == 1, f"{len(found)} results of {engine_id!r} for {obj['path']!r}"
        return found[0]


def scan(
    workdir: Path,
    image: Path,
    policy: SignedPolicy,
    engines: Sequence[Path] = (),
    *,
    mode: str | None = None,
    max_scan_time: int | None = None,
    on_expiry: str | None = None,
    timeout: float = 600,
) -> Scan:
    """Run `ostia scan` on `image` with a report and an `--output` directory under `workdir`."""
    workdir.mkdir(parents=True, exist_ok=True)
    report = workdir / "report.json"
    output = workdir / "output"
    args: list[str | Path] = ["scan", "--image", image, "--report", report, "--output", output]
    args += policy.args()
    if mode is not None:
        args += ["--mode", mode]
    if max_scan_time is not None:
        args += ["--max-scan-time", str(max_scan_time)]
    if on_expiry is not None:
        args += ["--on-expiry", on_expiry]
    for engine in engines:
        args += ["--dev-engine", engine]
    return Scan(run_ostia(*args, timeout=timeout), report, output)
