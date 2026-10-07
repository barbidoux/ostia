"""Checks the licences of the Python dependencies against the allowlist of deny.toml (NFR-11).

Usage: python_licences.py --sbom env.cdx.json [--deny deny.toml] [--config tools/supply/python-licences.toml]

The SBOM is a CycloneDX JSON document of the Python environment (`cyclonedx-py environment`); nested
components are checked too. The allowlist is `[licenses] allow` of deny.toml plus `[allow] python-only`
of the config. Every licence entry of every component must be allowed: an SPDX id in the allowlist, or
an SPDX expression that the allowlist satisfies (`OR`: one side, `AND`: both, `X WITH exception`: X).
Non-SPDX names (trove classifiers) count only through the `[aliases]` table of the config, reviewed by
hand. A `[packages]` override, pinned to an exact version (`"name==version" = "<SPDX expression>"`),
replaces the metadata of that version, so a new version is reviewed again. A component without any
licence, or with an entry CycloneDX does not allow, fails: fail closed.

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
    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise UsageError(problem)
    components: list[dict[str, Any]] = []
    pending = [document]
    while pending:
        nested = pending.pop().get("components", [])
        if not isinstance(nested, list) or not all(isinstance(c, dict) for c in nested):
            raise UsageError(problem)
        components += nested
        pending += nested
    if "components" not in document:
        raise UsageError(problem)
    return components


def allowlist(path: Path) -> set[str]:
    allow = load_toml(path).get("licenses", {}).get("allow")
    if not isinstance(allow, list) or not all(isinstance(item, str) for item in allow):
        raise UsageError(f"{path}: [licenses] allow is not a list of licence ids")
    return set(allow)


def python_only(config: dict[str, Any], path: Path) -> set[str]:
    extra = config.get("allow", {}).get("python-only", [])
    if not isinstance(extra, list) or not all(isinstance(item, str) for item in extra):
        raise UsageError(f"{path}: [allow] python-only is not a list of licence ids")
    return set(extra)


def string_table(config: dict[str, Any], name: str, path: Path) -> dict[str, str]:
    table = config.get(name, {})
    if not isinstance(table, dict) or not all(isinstance(v, str) for v in table.values()):
        raise UsageError(f"{path}: [{name}] must map strings to strings")
    return table


# One licence entry: ("expression", shown, SPDX expression), ("name", shown, None) for a name without an
# alias, or ("unsupported", shown, None) for a shape CycloneDX does not allow.
Entry = tuple[str, str, str | None]


def parse_entry(entry: object, aliases: dict[str, str]) -> Entry:
    unsupported: Entry = ("unsupported", f"unsupported licence entry {entry!r}", None)
    if not isinstance(entry, dict) or len({"expression", "license"} & set(entry)) != 1:
        return unsupported
    if "expression" in entry:
        text = entry["expression"]
        return ("expression", text, text) if isinstance(text, str) else unsupported
    licence = entry["license"]
    if not isinstance(licence, dict):
        return unsupported
    if isinstance(licence.get("id"), str):
        return ("expression", licence["id"], licence["id"])
    if isinstance(licence.get("name"), str):
        name = licence["name"]
        return ("expression", name, aliases[name]) if name in aliases else ("name", name, None)
    return unsupported


def licence_entries(
    component: dict[str, Any], aliases: dict[str, str], packages: dict[str, str]
) -> list[Entry]:
    key = f"{component.get('name')}=={component.get('version')}"
    if key in packages:
        return [("expression", packages[key], packages[key])]
    licences = component.get("licenses") or []
    if not isinstance(licences, list):
        return [("unsupported", f"unsupported licence entry {licences!r}", None)]
    return [parse_entry(entry, aliases) for entry in licences]


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
        for kind, shown, expression in entries:
            if kind == "unsupported":
                findings.append(f"{label}: {shown}")
                continue
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
        config = load_toml(args.config)
        allowed = allowlist(args.deny) | python_only(config, args.config)
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
