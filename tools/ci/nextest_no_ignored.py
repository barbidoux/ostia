"""Fail when the Rust workspace holds any `#[ignore]` test (a non-bench run must skip nothing).

Usage: nextest_no_ignored.py <list.json>
The input is `cargo nextest list --message-format json`. cargo-nextest leaves ignored tests out of
its JUnit report, so they are found here instead. A missing or malformed list fails.
"""

import json
import sys
from pathlib import Path


class ListError(Exception):
    """The nextest list is not in the expected shape."""


def ignored_tests(document: object) -> tuple[int, list[str]]:
    """Number of listed tests and the names of the ignored ones."""
    if not isinstance(document, dict) or not isinstance(document.get("rust-suites"), dict):
        raise ListError("no 'rust-suites' object")
    listed = 0
    ignored: list[str] = []
    for suite_name, suite in document["rust-suites"].items():
        cases = suite.get("testcases") if isinstance(suite, dict) else None
        if not isinstance(cases, dict):
            raise ListError(f"suite {suite_name!r} has no 'testcases' object")
        for case_name, case in cases.items():
            flag = case.get("ignored") if isinstance(case, dict) else None
            if not isinstance(flag, bool):
                raise ListError(f"test {suite_name}::{case_name} has no boolean 'ignored'")
            listed += 1
            if flag:
                ignored.append(f"{suite_name}::{case_name}")
    return listed, ignored


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: nextest_no_ignored.py <list.json>", file=sys.stderr)
        return 2
    try:
        listed, ignored = ignored_tests(json.loads(Path(argv[0]).read_text(encoding="utf-8")))
    except (OSError, ValueError, ListError) as exc:
        print(f"cannot read nextest list {argv[0]}: {exc}", file=sys.stderr)
        return 1
    if ignored:
        print(f"{len(ignored)} ignored Rust test(s) in a non-bench run:", file=sys.stderr)
        for name in ignored:
            print(f"  {name}", file=sys.stderr)
        return 1
    print(f"no ignored Rust tests ({listed} listed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
