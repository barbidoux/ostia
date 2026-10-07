"""Checks the licences of the Python dependencies against the allowlist of deny.toml (NFR-11).

Usage: python_licences.py --sbom env.cdx.json [--deny deny.toml] [--config tools/supply/python-licences.toml]

The SBOM is a CycloneDX JSON document of the Python environment (`cyclonedx-py environment`). Every
licence entry of every component must be allowed: an SPDX id in the allowlist, or an SPDX expression
that the allowlist satisfies (`OR`: one side, `AND`: both, `X WITH exception`: X). Non-SPDX names (trove
classifiers) count only through the `[aliases]` table of the config, reviewed by hand. A package whose
metadata carries no usable licence needs a `[packages]` override pinned to its exact version
(`"name==version" = "<SPDX expression>"`), so a new version is reviewed again. A component without any
licence fails: fail closed.

Exit codes: 0 all allowed, 1 findings (one line each on stderr), 2 usage error or unreadable input.
"""

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]
TOKEN = re.compile(r"\(|\)|[^\s()]+")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+:-]*")
OPERATORS = {"AND", "OR", "WITH"}


class UsageError(Exception):
    """The input cannot be checked."""


class ExpressionError(Exception):
    """A licence expression that is not valid SPDX."""


class Expression:
    """A recursive-descent evaluator of SPDX licence expressions against an allowlist."""

    def __init__(self, text: str, allowed: set[str]) -> None:
        self.tokens = TOKEN.findall(text)
        self.position = 0
        self.allowed = allowed

    def satisfied(self) -> bool:
        if not self.tokens:
            raise ExpressionError("empty")
        result = self.disjunction()
        if self.position != len(self.tokens):
            raise ExpressionError(f"unexpected {self.tokens[self.position]!r}")
        return result

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise ExpressionError("unexpected end")
        self.position += 1
        return token

    def disjunction(self) -> bool:
        result = self.conjunction()
        while self.peek() == "OR":
            self.take()
            # Evaluate both sides so a malformed right side is always reported.
            right = self.conjunction()
            result = result or right
        return result

    def conjunction(self) -> bool:
        result = self.atom()
        while self.peek() == "AND":
            self.take()
            right = self.atom()
            result = result and right
        return result

    def atom(self) -> bool:
        token = self.take()
        if token == "(":
            result = self.disjunction()
            if self.take() != ")":
                raise ExpressionError("missing )")
            return result
        licence = self.identifier(token)
        if self.peek() == "WITH":
            self.take()
            # An exception only adds permissions to the licence it modifies.
            self.identifier(self.take())
        return licence in self.allowed

    @staticmethod
    def identifier(token: str) -> str:
        if token in OPERATORS or not IDENTIFIER.fullmatch(token):
            raise ExpressionError(f"unexpected {token!r}")
        return token


def load_toml(path: Path) -> dict[str, Any]:
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise UsageError(f"cannot read {path}: {error}") from error


def load_sbom(path: Path) -> list[dict[str, Any]]:
    problem = f"{path} is not a CycloneDX JSON document with components"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise UsageError(f"cannot read {path}: {error}") from error
    except ValueError as error:
        raise UsageError(problem) from error
    if (
        not isinstance(document, dict)
        or document.get("bomFormat") != "CycloneDX"
        or not isinstance(document.get("components"), list)
    ):
        raise UsageError(problem)
    components: list[dict[str, Any]] = document["components"]
    return components


def allowlist(path: Path) -> set[str]:
    allow = load_toml(path).get("licenses", {}).get("allow")
    if not isinstance(allow, list) or not all(isinstance(item, str) for item in allow):
        raise UsageError(f"{path}: [licenses] allow is not a list of licence ids")
    return set(allow)


def string_table(config: dict[str, Any], name: str, path: Path) -> dict[str, str]:
    table = config.get(name, {})
    if not isinstance(table, dict) or not all(isinstance(v, str) for v in table.values()):
        raise UsageError(f"{path}: [{name}] must map strings to strings")
    return table


def licence_entries(
    component: dict[str, Any], aliases: dict[str, str], packages: dict[str, str]
) -> list[tuple[str, str | None]]:
    """(shown text, SPDX expression or None when the text is an unknown name) per licence entry."""
    key = f"{component.get('name')}=={component.get('version')}"
    if key in packages:
        return [(packages[key], packages[key])]
    entries: list[tuple[str, str | None]] = []
    for entry in component.get("licenses") or []:
        if not isinstance(entry, dict):
            entries.append((repr(entry), None))
        elif "expression" in entry:
            entries.append((str(entry["expression"]), str(entry["expression"])))
        else:
            licence = entry.get("license", {})
            if "id" in licence:
                entries.append((str(licence["id"]), str(licence["id"])))
            else:
                name = str(licence.get("name", ""))
                entries.append((name, aliases.get(name)))
    return entries


def check(
    components: list[dict[str, Any]],
    allowed: set[str],
    aliases: dict[str, str],
    packages: dict[str, str],
) -> list[str]:
    findings = []
    for component in components:
        label = f"{component.get('name')} {component.get('version')}"
        entries = licence_entries(component, aliases, packages)
        if not entries:
            findings.append(f"{label}: no licence")
        for shown, expression in entries:
            if expression is None:
                if shown not in allowed:
                    findings.append(f"{label}: {shown!r} is not allowed")
                continue
            try:
                ok = Expression(expression, allowed).satisfied()
            except ExpressionError as error:
                findings.append(
                    f"{label}: cannot parse licence expression {expression!r} ({error})"
                )
                continue
            if not ok:
                findings.append(f"{label}: {shown!r} is not allowed")
    return findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Licences of the Python dependencies")
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--deny", type=Path, default=REPO / "deny.toml")
    parser.add_argument(
        "--config", type=Path, default=REPO / "tools" / "supply" / "python-licences.toml"
    )
    args = parser.parse_args(argv)
    try:
        components = load_sbom(args.sbom)
        allowed = allowlist(args.deny)
        config = load_toml(args.config)
        aliases = string_table(config, "aliases", args.config)
        packages = string_table(config, "packages", args.config)
    except UsageError as error:
        print(f"python_licences: {error}", file=sys.stderr)
        return 2
    findings = check(components, allowed, aliases, packages)
    for finding in findings:
        print(finding, file=sys.stderr)
    if findings:
        return 1
    print(f"licences OK: {len(components)} Python packages")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
