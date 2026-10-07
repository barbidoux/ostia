"""Run the `ostia` binary and read its report (docs/contracts/cli.md, docs/contracts/report.md)."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import jsonschema

REPO = Path(__file__).resolve().parents[3]
REPORT_SCHEMA = REPO / "schemas" / "report.schema.json"
FAKE_ENGINE = REPO / "tests" / "fakes" / "fake_engine.py"
BUILD_HINT = "cargo build --workspace --locked --features ostia-cli/dev"


def ostia_bin() -> Path:
    """The binary under test: `OSTIA_BIN`, else the debug build of the workspace."""
    configured = os.environ.get("OSTIA_BIN")
    return Path(configured) if configured else REPO / "target" / "debug" / "ostia"


def run_ostia(*args: str | Path, timeout: float = 600) -> subprocess.CompletedProcess[str]:
    """Run `ostia <args>` from the repository root; the dev engine runs the repository's fake engine
    with this interpreter."""
    binary = ostia_bin()
    assert binary.is_file(), f"{binary} is missing: build it with `{BUILD_HINT}`"
    env = dict(os.environ)
    env["OSTIA_DEV_PYTHON"] = sys.executable
    env["OSTIA_DEV_FAKE_ENGINE"] = str(FAKE_ENGINE)
    return subprocess.run(
        [str(binary), *map(str, args)],
        cwd=REPO,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def load_report(path: Path) -> dict[str, Any]:
    """The report at `path`, validated against schemas/report.schema.json."""
    assert path.is_file(), f"no report was written at {path}"
    report: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    schema = json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator(schema).validate(report)
    return report
