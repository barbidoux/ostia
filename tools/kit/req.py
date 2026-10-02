#!/usr/bin/env python3
"""Look up work packages and requirements in docs/plan.md and docs/spec.md.

Kit tool (owner-managed, protected from agent edits). Standard library only.

Usage:
  req.py WP-1.8          work package row + full text of every requirement it cites
  req.py FR-06           requirement row + the work packages that cite it
  req.py phase P1        work packages of a phase + requirements whose phase is P1
  req.py rules           verdict policy rules (R1-R7, E1, D1, D2)
  req.py check           every id cited in the plan exists in the spec (exit 1 if not)
"""

from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

PREFIXES = ("FR", "NFR", "ENG", "USB", "DEEP", "ENR", "SEC", "CTR", "LOG", "UI", "UPD")
_ALT = "|".join(PREFIXES)
REQ_ID = re.compile(rf"\b(?:{_ALT})-\d{{2}}\b")
REQ_RANGE = re.compile(rf"\b((?:{_ALT}))-(\d{{2}}) to (?:\1-)?(\d{{2}})\b")
WP_ID = re.compile(r"^WP-(\d+)\.(\d+)$")
RULE_ID = re.compile(r"^(R[1-7]|E1|D[12])$")


def repo_root() -> Path:
    env = os.environ.get("CLAUDE_PROJECT_DIR")
    if env:
        return Path(env)
    here = Path(__file__).resolve()
    return here.parents[2]


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


@dataclass
class Requirement:
    rid: str
    section: str
    columns: dict[str, str]
    line: int

    @property
    def level(self) -> str:
        return self.columns.get("Level", "?")

    def phases(self) -> set[str]:
        cell = self.phase
        out = set(re.findall(r"P\d", cell))
        for a, b in re.findall(r"P(\d)\s*[–-]\s*P(\d)", cell):
            out |= {f"P{n}" for n in range(int(a), int(b) + 1)}
        return out

    @property
    def phase(self) -> str:
        if "Phase" in self.columns:
            return self.columns["Phase"]
        m = re.search(r"phase (\d)", self.columns.get("Verification", ""), re.I)
        return f"P{m.group(1)}" if m else "?"


@dataclass
class WorkPackage:
    wid: str
    phase: str
    scope: str
    requirements: str
    tests_first: str
    size: str
    after: str
    line: int
    req_ids: list[str] = field(default_factory=list)


def expand_ids(text: str) -> list[str]:
    ids: list[str] = []
    for m in REQ_RANGE.finditer(text):
        prefix, start, end = m.group(1), int(m.group(2)), int(m.group(3))
        ids.extend(f"{prefix}-{n:02d}" for n in range(start, end + 1))
    ids.extend(REQ_ID.findall(text))
    seen: set[str] = set()
    out = []
    for i in ids:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def load_spec(root: Path) -> tuple[dict[str, Requirement], dict[str, str]]:
    reqs: dict[str, Requirement] = {}
    rules: dict[str, str] = {}
    section = ""
    header: list[str] = []
    for n, line in enumerate((root / "docs/spec.md").read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("## "):
            section = line[3:].strip()
        if not line.startswith("|"):
            continue
        row = cells(line)
        if row and row[0] in ("ID", "Rule"):
            header = row
            continue
        if not row or not header or set(row[0]) <= {"-", ":", " "}:
            continue
        if REQ_ID.fullmatch(row[0]):
            reqs[row[0]] = Requirement(row[0], section, dict(zip(header, row, strict=False)), n)
        elif RULE_ID.match(row[0]) and header and header[0] == "Rule":
            rules[row[0]] = " | ".join(row[1:])
    # D1/D2 are bullet points, not table rows
    text = (root / "docs/spec.md").read_text(encoding="utf-8")
    for m in re.finditer(r"\*\*(D[12]), ([^*]+)\*\*\s*([^\n]+)", text):
        rules[m.group(1)] = f"{m.group(2).strip()}: {m.group(3).strip()}"
    return reqs, rules


def load_plan(root: Path) -> dict[str, WorkPackage]:
    wps: dict[str, WorkPackage] = {}
    for n, line in enumerate((root / "docs/plan.md").read_text(encoding="utf-8").splitlines(), 1):
        if not line.startswith("| WP-"):
            continue
        row = cells(line)
        if len(row) < 6 or not WP_ID.match(row[0]):
            continue
        phase = "P" + WP_ID.match(row[0]).group(1)
        wp = WorkPackage(row[0], phase, row[1], row[2], row[3], row[4], row[5], n)
        wp.req_ids = expand_ids(row[2])
        wps[row[0]] = wp
    return wps


def show_req(r: Requirement) -> str:
    body = " | ".join(f"{k}: {v}" for k, v in r.columns.items() if k != "ID")
    return f"{r.rid}  [{r.level}, {r.phase}]  (spec § {r.section}, line {r.line})\n    {body}"


def cmd_wp(wid: str, reqs: dict[str, Requirement], wps: dict[str, WorkPackage]) -> int:
    wp = wps.get(wid)
    if not wp:
        print(f"unknown work package {wid}", file=sys.stderr)
        return 1
    print(f"{wp.wid}  ({wp.phase}, size {wp.size}, plan line {wp.line})")
    print(f"  Scope:               {wp.scope}")
    print(f"  Requirements:        {wp.requirements}")
    print(f"  Tests written first: {wp.tests_first}")
    print(f"  After:               {wp.after}")
    if wp.req_ids:
        print("\nCited requirements (full text):")
        for rid in wp.req_ids:
            print(show_req(reqs[rid]) if rid in reqs else f"{rid}  !! NOT FOUND IN SPEC — stop and ask the owner")
    other = [w for w in re.findall(r"(?:ADR-\d{2}|Spec §\d+|P\d scope)", wp.requirements)]
    if other:
        print("\nOther references: " + ", ".join(other) + " (read them in docs/spec.md)")
    if wp.size == "L":
        print("\n!! Size L: split this package with the owner before starting.")
    return 0


def cmd_req(rid: str, reqs: dict[str, Requirement], wps: dict[str, WorkPackage]) -> int:
    r = reqs.get(rid)
    if not r:
        print(f"unknown requirement {rid}", file=sys.stderr)
        return 1
    print(show_req(r))
    citing = [w.wid for w in wps.values() if rid in w.req_ids]
    print("\nCited by: " + (", ".join(citing) if citing else "no work package (check the phase lock package)"))
    return 0


def cmd_phase(phase: str, reqs: dict[str, Requirement], wps: dict[str, WorkPackage]) -> int:
    phase = phase.upper()
    rows = [w for w in wps.values() if w.phase == phase]
    if not rows:
        print(f"no work packages for {phase}", file=sys.stderr)
        return 1
    print(f"Work packages of {phase}:")
    for w in rows:
        print(f"  {w.wid:8} [{w.size}] after {w.after:12} {w.scope[:90]}")
    cited = {rid for w in rows for rid in w.req_ids}
    in_phase = [r for r in reqs.values() if phase in r.phases() or r.rid in cited]
    print(
        f"\nRequirements of {phase}: phase column says {phase} (P) and/or cited by a {phase} package (C) "
        f"— {len(in_phase)} total, {sum(r.level == 'MUST' for r in in_phase)} MUST:"
    )
    for r in in_phase:
        src = ("P" if phase in r.phases() else " ") + ("C" if r.rid in cited else " ")
        text = r.columns.get("Requirement", "")
        print(f"  {r.rid:8} {r.level:6} {src}  {text[:95]}")
    orphans = [r.rid for r in in_phase if phase in r.phases() and r.rid not in cited]
    if orphans:
        print(
            f"\nIn {phase} by the spec but cited by no {phase} package (cover them in the lock tests or ask): "
            + ", ".join(orphans)
        )
    return 0


def cmd_check(reqs: dict[str, Requirement], wps: dict[str, WorkPackage]) -> int:
    missing = sorted({(w.wid, rid) for w in wps.values() for rid in w.req_ids if rid not in reqs})
    for wid, rid in missing:
        print(f"{wid} cites {rid}, which is not in the spec")
    print(f"{len(reqs)} requirements, {len(wps)} work packages, {len(missing)} dangling references")
    return 1 if missing else 0


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__)
        return 2
    root = repo_root()
    reqs, rules = load_spec(root)
    wps = load_plan(root)
    arg = argv[0]
    if arg == "check":
        return cmd_check(reqs, wps)
    if arg == "rules":
        for k in sorted(rules, key=lambda s: (s[0] != "R", s)):
            print(f"{k}: {rules[k]}")
        return 0
    if arg == "phase" and len(argv) > 1:
        return cmd_phase(argv[1], reqs, wps)
    if WP_ID.match(arg):
        return cmd_wp(arg, reqs, wps)
    if REQ_ID.fullmatch(arg):
        return cmd_req(arg, reqs, wps)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
