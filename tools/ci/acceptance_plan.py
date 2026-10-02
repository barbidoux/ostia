"""Which acceptance directories CI runs, and how, given the current phase.

Usage: acceptance_plan.py --status docs/phase-status.md --acceptance tests/acceptance
Prints JSON: {"current": "p<n>", "gate": [...], "informational": [...], "not_run": [...]}
- gate: directories of closed phases (n < current), run with `ostia_lock.py gate`, blocking;
- informational: the current phase's directory, run with `just test-acceptance`, reported as N/M green;
- not_run: directories of future phases.
Only `p<n>` directories are phase directories (`common` is a helper package). CI fails closed when
a closed or current phase directory (P1 to the current phase) is missing or not locked, or when a
directory name is not canonical (`p01`).
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


def phase_dirs(acceptance: Path) -> dict[int, Path]:
    """Phase directories by number; a name like `p01` is refused rather than guessed."""
    found: dict[int, Path] = {}
    if acceptance.is_dir():
        for entry in acceptance.iterdir():
            match = PHASE_DIR.match(entry.name)
            if not (entry.is_dir() and match):
                continue
            number = int(match.group(1))
            if entry.name != f"p{number}":
                raise PlanError(
                    f"tests/acceptance/{entry.name} is not a valid phase directory name"
                )
            found[number] = entry
    return found


def plan(status: str, acceptance: Path) -> dict[str, object]:
    current = current_phase(status)
    phases = phase_dirs(acceptance)
    # Every phase from P1 to the current one has a locked directory: P0 locks p1, P1 locks p2, ...
    required = set(range(1, current + 1))
    result: dict[str, list[str]] = {"gate": [], "informational": [], "not_run": []}
    for number in sorted(required | phases.keys()):
        path = phases.get(number)
        if path is None:
            raise PlanError(
                f"tests/acceptance/p{number} is missing: phase {number} is closed or current"
            )
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
