"""Fail when a JUnit report records any skipped test (a non-bench run must skip nothing).

Usage: junit_no_skips.py <report.xml> [<report.xml> ...]
Reads pytest and cargo-nextest reports. A report that is missing or cannot be parsed fails.
"""

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


def skipped_in(report: Path) -> tuple[int, list[str]]:
    """Number of skipped tests in a report and the names of those carrying a <skipped> element."""
    root = ET.parse(report).getroot()
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    total = 0
    names: list[str] = []
    for suite in suites:
        marked = [
            f"{case.get('classname', '')}::{case.get('name', '')}"
            for case in suite.iter("testcase")
            if case.find("skipped") is not None
        ]
        declared = int(suite.get("skipped", "0") or "0")
        total += max(declared, len(marked))
        names.extend(marked)
    return total, names


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: junit_no_skips.py <report.xml> [<report.xml> ...]", file=sys.stderr)
        return 2
    total = 0
    names: list[str] = []
    for arg in argv:
        try:
            count, skipped = skipped_in(Path(arg))
        except (OSError, ET.ParseError, ValueError) as exc:
            print(f"cannot parse JUnit report {arg}: {exc}", file=sys.stderr)
            return 1
        total += count
        names.extend(skipped)
    if total:
        print(f"{total} skipped test(s) in a non-bench run:", file=sys.stderr)
        for name in names:
            print(f"  {name}", file=sys.stderr)
        return 1
    print(f"no skipped tests in {len(argv)} report(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
