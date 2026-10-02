"""Commit-msg hook: the subject line follows the commit discipline of AGENTS.md.

Usage: commit_msg.py <message file>   (called by pre-commit at the commit-msg stage)
"""

import re
import sys
from pathlib import Path

SUBJECT = re.compile(
    r"^(test|feat|fix|refactor|docs|chore|contract|build|ci|perf)(\([A-Za-z0-9][A-Za-z0-9.,\- ]*\))?: \S"
)


def subject(message: str) -> str:
    """The first line that is not a git comment."""
    for line in message.splitlines():
        if not line.startswith("#"):
            return line
    return ""


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: commit_msg.py <message file>", file=sys.stderr)
        return 2
    try:
        message = Path(argv[0]).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"invalid commit message: cannot read {argv[0]}: {exc}", file=sys.stderr)
        return 1
    first = subject(message)
    if SUBJECT.match(first):
        return 0
    print(
        f"invalid commit message: {first!r}\n"
        "expected '<type>(<ids>): <what>' with type in "
        "test|feat|fix|refactor|docs|chore|contract|build|ci|perf, e.g. 'test(FR-06): ...'",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
