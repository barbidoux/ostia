"""Which acceptance directories CI runs, and how, given the current phase.

Usage: acceptance_plan.py --status docs/phase-status.md --acceptance tests/acceptance
Prints JSON: {"current": "p<n>", "gate": [...], "informational": [...], "not_run": [...]}
- gate: directories of closed phases (n < current), run with `ostia_lock.py gate`, blocking;
- informational: the current phase's directory, run with `just test-acceptance`, reported as N/M green;
- not_run: directories of future phases.
Only `p<n>` directories are phase directories (`common` is a helper package). A closed or current
phase directory that is not locked is an error: CI fails closed.
"""

import argparse
import json
import re
import sys
from pathlib import Path

CURRENT = re.compile(r"^Current phase:\s*P(\d+)\b", re.MULTILINE)
PHASE_DIR = re.compile(r"^p(\d+)$")
LOCK_NAME = "LOCK.sha256"


class PlanError(Exception):
    """The repository state does not allow a safe plan."""


def current_phase(status: str) -> int:
    found = CURRENT.findall(status)
    if len(found) != 1:
        raise PlanError("phase status must hold exactly one 'Current phase: P<n>' line")
    return int(found[0])


def plan(status: str, acceptance: Path) -> dict[str, object]:
    current = current_phase(status)
    phases: list[tuple[int, Path]] = []
    if acceptance.is_dir():
        for entry in acceptance.iterdir():
            match = PHASE_DIR.match(entry.name)
            if entry.is_dir() and match:
                phases.append((int(match.group(1)), entry))
    phases.sort()
    result: dict[str, list[str]] = {"gate": [], "informational": [], "not_run": []}
    for number, path in phases:
        locked = (path / LOCK_NAME).is_file()
        if number < current:
            if not locked:
                raise PlanError(
                    f"tests/acceptance/{path.name} belongs to a closed phase but is not locked"
                )
            result["gate"].append(path.name)
        elif number == current:
            if not locked:
                raise PlanError(
                    f"tests/acceptance/{path.name} belongs to the current phase but is not locked"
                )
            result["informational"].append(path.name)
        else:
            result["not_run"].append(path.name)
    return {"current": f"p{current}", **result}


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("--status", type=Path, required=True)
    parser.add_argument("--acceptance", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        status = args.status.read_text(encoding="utf-8")
        print(json.dumps(plan(status, args.acceptance)))
    except (OSError, PlanError) as exc:
        print(f"acceptance plan: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
