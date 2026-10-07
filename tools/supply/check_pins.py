"""Checks that every Python dependency is pinned exactly and installed only with verified hashes (UPD-07).

Usage: check_pins.py [--pyproject pyproject.toml] [--requirements requirements.txt]

--pyproject: every requirement of `project.dependencies`, `project.optional-dependencies.*`,
`dependency-groups.*` and `tool.uv.dev-dependencies` is `name[extras]==version` (markers allowed);
`{include-group = ...}` entries are not requirements.
--requirements: a file exported from uv.lock (`uv export --format requirements-txt`, hashes on by default)
in which every requirement is pinned with == and carries at least one sha256 hash; any other line
(options, editable or local paths, URLs) is refused, so pip-audit and pip install see only hashed pins.

Exit codes: 0 everything pinned, 1 findings (one line each on stderr), 2 usage error or unreadable file.
"""

import argparse
import re
import sys
import tomllib
from collections.abc import Iterator
from pathlib import Path

NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
PINNED = re.compile(rf"({NAME})\s*(?:\[[^\]]*\])?\s*==\s*[A-Za-z0-9][A-Za-z0-9.+!_-]*")
STARTS_WITH_NAME = re.compile(rf"{NAME}(?:\s|\[|[=<>!~;@]|$)")
OPTION = re.compile(r"\s--")
HASH = re.compile(r"--hash=(\w+):(\S+)")
SHA256 = re.compile(r"[0-9a-f]{64}")


class UsageError(Exception):
    """The input cannot be checked."""


def is_pinned(requirement: str) -> bool:
    """`name[extras]==version`, optionally followed by `; markers`."""
    return PINNED.fullmatch(requirement.split(";", 1)[0].strip()) is not None


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as error:
        raise UsageError(f"cannot read {path}: {error}") from error


def declared(path: Path) -> Iterator[tuple[str, object]]:
    """(table, entry) for every dependency declared in a pyproject.toml."""
    try:
        project = tomllib.loads(read(path))
    except tomllib.TOMLDecodeError as error:
        raise UsageError(f"{path} is not valid TOML: {error}") from error
    tables: list[tuple[str, object]] = [
        ("project.dependencies", project.get("project", {}).get("dependencies", []))
    ]
    optional = project.get("project", {}).get("optional-dependencies", {})
    tables += [(f"project.optional-dependencies.{k}", v) for k, v in optional.items()]
    groups = project.get("dependency-groups", {})
    tables += [(f"dependency-groups.{k}", v) for k, v in groups.items()]
    legacy = project.get("tool", {}).get("uv", {}).get("dev-dependencies")
    if legacy is not None:
        tables.append(("tool.uv.dev-dependencies", legacy))
    for table, entries in tables:
        if not isinstance(entries, list):
            raise UsageError(f"{path}: {table} is not a list")
        for entry in entries:
            yield table, entry


def check_pyproject(path: Path) -> tuple[int, list[str]]:
    count, findings = 0, []
    for table, entry in declared(path):
        if isinstance(entry, dict) and set(entry) == {"include-group"}:
            continue
        count += 1
        if not isinstance(entry, str):
            findings.append(f"{path}: {table}: unsupported entry {entry!r}")
        elif not is_pinned(entry):
            findings.append(f"{path}: {table}: {entry!r} is not pinned with ==")
    return count, findings


def logical_lines(text: str) -> Iterator[tuple[int, str]]:
    """(first line number, text) of each requirement line, continuations joined, comments removed."""
    start, parts = 0, list[str]()
    for number, raw in enumerate(text.splitlines(), start=1):
        line = re.sub(r"(^|\s)#.*$", "", raw).rstrip()
        if not parts:
            start = number
        continued = line.endswith("\\")
        parts.append(line[:-1] if continued else line)
        if not continued:
            joined = " ".join(part.strip() for part in parts).strip()
            parts = []
            if joined:
                yield start, joined
    if parts:
        joined = " ".join(part.strip() for part in parts).strip()
        if joined:
            yield start, joined


def check_requirements(path: Path) -> tuple[int, list[str]]:
    count, findings = 0, []
    for number, line in logical_lines(read(path)):
        where = f"{path}:{number}"
        option = OPTION.search(line)
        requirement = (line[: option.start()] if option else line).strip()
        options = (line[option.start() :] if option else "").split()
        if not STARTS_WITH_NAME.match(requirement) or "://" in requirement.split(";", 1)[0]:
            findings.append(f"{where}: unsupported line {line!r}")
            continue
        hashes = [HASH.fullmatch(item) for item in options]
        if not all(hashes):
            findings.append(f"{where}: unsupported line {line!r}")
            continue
        count += 1
        if not is_pinned(requirement):
            findings.append(f"{where}: {requirement!r} is not pinned with ==")
        elif not any(
            found and found.group(1) == "sha256" and SHA256.fullmatch(found.group(2))
            for found in hashes
        ):
            findings.append(f"{where}: {requirement!r} has no sha256 hash")
    if count == 0 and not findings:
        findings.append(f"{path}: no requirements")
    return count, findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Python dependencies are pinned and hashed")
    parser.add_argument("--pyproject", type=Path)
    parser.add_argument("--requirements", type=Path)
    args = parser.parse_args(argv)
    if args.pyproject is None and args.requirements is None:
        print(
            "check_pins: nothing to check: give --pyproject, --requirements or both",
            file=sys.stderr,
        )
        return 2
    findings: list[str] = []
    summary = []
    try:
        if args.pyproject is not None:
            count, found = check_pyproject(args.pyproject)
            findings += found
            summary.append(f"{count} declared")
        if args.requirements is not None:
            count, found = check_requirements(args.requirements)
            findings += found
            summary.append(f"{count} locked")
    except UsageError as error:
        print(f"check_pins: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        return 1
    print(f"pins OK: {', '.join(summary)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
