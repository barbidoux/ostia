#!/usr/bin/env python3
"""Lock and verify the acceptance tests of each phase (tests/acceptance/<dir>/).

Kit tool (owner-managed, protected from agent edits). Standard library only.

A locked directory holds LOCK.sha256: one "<sha256>  <relative path>" line per file,
plus a header recording when, by whom and how many tests were collected. Once a
directory is locked, any added, removed or changed file makes `verify` fail.

The owner commits the LOCK file and tags the commit `lock-<dir>` (for example
`lock-p1`). When that tag exists, `verify` also checks that the LOCK file in the
working tree is byte-identical to the one in the tag, so re-locking without the
owner's tag is caught as well.

Commands (owner only for lock/relock; anyone for verify/status/gate):
  ostia_lock.py lock <dir>                      e.g. lock p1, lock common
  ostia_lock.py relock <dir> --reason "<why>"   logs the reason in tests/acceptance/LOCKLOG.md
  ostia_lock.py verify [--require-tags]         every locked dir matches its manifest
  ostia_lock.py status                          locked / unlocked / tag present
  ostia_lock.py gate <dir> [-- <pytest args>]   run the locked tests: all pass, none skipped,
                                                same number of tests as at lock time
  ostia_lock.py collect <dir>                   hardened collect-only of a directory (locked or not)
  ostia_lock.py dry-run <dir> [-- <pytest args>] hardened run of a directory, summary only, no pass requirement
  ostia_lock.py rails-verify                    the rails files match tools/lock/RAILS.sha256
  ostia_lock.py rails-update                    owner only: record the current rails files

Locked tests run in a hardened pytest: no ini file (-c /dev/null), conftest lookup cut at the locked
directory, entry-point plugins disabled (PYTEST_DISABLE_PLUGIN_AUTOLOAD=1), PYTEST_ADDOPTS ignored.
Plugins a phase needs are listed, one module per line, in its locked GATE_PLUGINS file.
"""

from __future__ import annotations

import datetime as _dt
import getpass
import hashlib
import os
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

LOCK_NAME = "LOCK.sha256"
IGNORED_DIRS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules", ".hypothesis"}
IGNORED_SUFFIXES = {".pyc", ".pyo"}


def repo_root() -> Path:
    env = os.environ.get("OSTIA_REPO_ROOT") or os.environ.get("CLAUDE_PROJECT_DIR")
    top = None
    try:
        out = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True)
        top = Path(out.stdout.strip()).resolve()
    except (OSError, subprocess.CalledProcessError):
        pass
    if env and top and Path(env).resolve() != top:
        print(
            f"refusing: OSTIA_REPO_ROOT/CLAUDE_PROJECT_DIR ({env}) is not this git repository ({top})", file=sys.stderr
        )
        sys.exit(2)
    if top:
        return top
    if env:
        return Path(env).resolve()
    return Path(__file__).resolve().parents[2]


def acceptance_dir(root: Path) -> Path:
    return root / "tests" / "acceptance"


def tracked_files(d: Path) -> list[Path]:
    files = []
    for p in sorted(d.rglob("*")):
        if not p.is_file() or p.name == LOCK_NAME:
            continue
        rel = p.relative_to(d)
        if any(part in IGNORED_DIRS for part in rel.parts) or p.suffix in IGNORED_SUFFIXES:
            continue
        files.append(p)
    return files


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(d: Path) -> dict[str, str]:
    return {p.relative_to(d).as_posix(): sha256(p) for p in tracked_files(d)}


def read_lock(lock: Path) -> tuple[dict[str, str], dict[str, str]]:
    entries: dict[str, str] = {}
    header: dict[str, str] = {}
    for line in lock.read_text(encoding="utf-8").splitlines():
        if line.startswith("#"):
            m = re.match(r"#\s*([\w-]+):\s*(.*)", line)
            if m:
                header[m.group(1)] = m.group(2).strip()
            continue
        if not line.strip():
            continue
        digest, _, rel = line.partition("  ")
        entries[rel] = digest
    return entries, header


def pytest_invocation(root: Path, d: Path, args: list[str]) -> tuple[list[str], dict[str, str]]:
    """Command and environment for running a locked directory, isolated from unlocked configuration."""
    base = ["pytest", str(d), "-c", os.devnull, f"--rootdir={root}", f"--confcutdir={d}", "-p", "no:cacheprovider"]
    plugins = d / "GATE_PLUGINS"
    if plugins.exists():
        for line in plugins.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                base += ["-p", line]
    base += args
    if (root / "pyproject.toml").exists() and _which("uv"):
        cmd = ["uv", "run", "--frozen", *base]
    else:
        cmd = [sys.executable, "-m", *base]
    env = dict(os.environ)
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    for k in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS"):
        env.pop(k, None)
    paths = [str(root), str(root / "tests" / "acceptance")]
    if env.get("PYTHONPATH"):
        paths.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(paths)
    return cmd, env


def collect_count(root: Path, d: Path) -> int | None:
    """Number of tests pytest collects in d, or None if pytest is unavailable.

    Raises CollectionError when pytest reports collection errors.
    """
    cmd, env = pytest_invocation(root, d, ["--collect-only", "-q"])
    try:
        out = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=600, env=env)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if "No module named pytest" in out.stderr:
        return None
    if re.search(r"\b\d+ errors?\b", out.stdout) or "ERROR collecting" in out.stdout:
        raise CollectionError(out.stdout[-2000:])
    m = re.search(r"(\d+) tests? collected", out.stdout) or re.search(r"collected (\d+) items?", out.stdout)
    if m:
        return int(m.group(1))
    lines = [x for x in out.stdout.splitlines() if "::" in x]
    return len(lines) if lines else None


class CollectionError(Exception):
    """pytest could not collect every test of the directory."""


def _which(name: str) -> bool:
    from shutil import which

    return which(name) is not None


def write_lock(root: Path, name: str, reason: str | None) -> int:
    d = acceptance_dir(root) / name
    if not d.is_dir():
        print(f"no such directory: {d}", file=sys.stderr)
        return 1
    files = manifest(d)
    if not files:
        print(f"{d} is empty; write the acceptance tests first", file=sys.stderr)
        return 1
    try:
        count = collect_count(root, d) if name != "common" else None
    except CollectionError as exc:
        print(f"refusing to lock: pytest reports collection errors in {d}\n{exc}", file=sys.stderr)
        return 1
    lines = [
        f"# dir: tests/acceptance/{name}",
        f"# locked-at: {_dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()}",
        f"# locked-by: {os.environ.get('GIT_AUTHOR_NAME') or getpass.getuser()}",
        f"# tests-collected: {count if count is not None else 'unknown'}",
    ]
    if reason:
        lines.append(f"# relock-reason: {reason}")
    lines += [f"{digest}  {rel}" for rel, digest in sorted(files.items())]
    (d / LOCK_NAME).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"locked tests/acceptance/{name}: {len(files)} files, tests collected: {count}")
    print(
        f"next: commit the LOCK file on the lock branch, tag that commit and push the tag BEFORE merging:\n"
        f"  git commit -m 'chore(lock): lock {name}'\n"
        f"  git tag -s lock-{name} -m 'lock {name}' && git push origin lock-{name}"
    )
    return 0


def cmd_lock(root: Path, name: str) -> int:
    if (acceptance_dir(root) / name / LOCK_NAME).exists():
        print(f"tests/acceptance/{name} is already locked; use relock with --reason", file=sys.stderr)
        return 1
    return write_lock(root, name, None)


def cmd_relock(root: Path, name: str, reason: str) -> int:
    if not reason.strip():
        print("relock needs a non-empty --reason", file=sys.stderr)
        return 1
    rc = write_lock(root, name, reason)
    if rc == 0:
        log = acceptance_dir(root) / "LOCKLOG.md"
        stamp = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
        with log.open("a", encoding="utf-8") as f:
            f.write(f"- {stamp} relock {name}: {reason}\n")
        print(
            f"next: commit, move the tag and push it before merging:  git tag -f -s lock-{name} -m 'relock {name}' "
            f"&& git push -f origin lock-{name}"
        )
    return rc


def tag_lock_content(root: Path, name: str) -> bytes | None:
    path = f"tests/acceptance/{name}/{LOCK_NAME}"
    try:
        out = subprocess.run(["git", "show", f"lock-{name}:{path}"], cwd=root, capture_output=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    return out.stdout


def locked_dirs(root: Path) -> list[Path]:
    a = acceptance_dir(root)
    if not a.is_dir():
        return []
    return sorted(p.parent for p in a.glob(f"*/{LOCK_NAME}"))


def cmd_verify(root: Path, require_tags: bool) -> int:
    problems: list[str] = []
    dirs = locked_dirs(root)
    for d in dirs:
        name = d.name
        expected, _ = read_lock(d / LOCK_NAME)
        actual = manifest(d)
        for rel in sorted(set(expected) - set(actual)):
            problems.append(f"{name}: locked file removed: {rel}")
        for rel in sorted(set(actual) - set(expected)):
            problems.append(f"{name}: file added after lock: {rel}")
        for rel in sorted(set(expected) & set(actual)):
            if expected[rel] != actual[rel]:
                problems.append(f"{name}: locked file changed: {rel}")
        tagged = tag_lock_content(root, name)
        if tagged is None:
            if require_tags:
                problems.append(f"{name}: tag lock-{name} missing (owner must tag the lock commit)")
            else:
                print(f"warning: {name}: no tag lock-{name} yet", file=sys.stderr)
        elif tagged != (d / LOCK_NAME).read_bytes():
            problems.append(
                f"{name}: {LOCK_NAME} differs from the one in tag lock-{name} (re-locked without the owner)"
            )
    for p in problems:
        print(f"LOCK VIOLATION  {p}")
    if not problems:
        print(f"locks OK ({len(dirs)} locked director{'y' if len(dirs) == 1 else 'ies'})")
    return 1 if problems else 0


def cmd_status(root: Path) -> int:
    a = acceptance_dir(root)
    if not a.is_dir():
        print("no tests/acceptance directory yet")
        return 0
    for d in sorted(p for p in a.iterdir() if p.is_dir() and p.name not in IGNORED_DIRS):
        lock = d / LOCK_NAME
        if lock.exists():
            _, header = read_lock(lock)
            tag = "tagged" if tag_lock_content(root, d.name) is not None else "NOT TAGGED"
            print(
                f"{d.name:8} LOCKED  {header.get('locked-at', '?')}  tests={header.get('tests-collected', '?')}  {tag}"
            )
        else:
            print(f"{d.name:8} open    ({len(tracked_files(d))} files)")
    return 0


def cmd_gate(root: Path, name: str, extra: list[str]) -> int:
    d = acceptance_dir(root) / name
    lock = d / LOCK_NAME
    if not lock.exists():
        print(f"tests/acceptance/{name} is not locked", file=sys.stderr)
        return 1
    if cmd_verify(root, require_tags=False) != 0:
        return 1
    _, header = read_lock(lock)
    junit = root / "target" / f"gate-{name}.xml"
    junit.parent.mkdir(parents=True, exist_ok=True)
    if junit.exists():
        junit.unlink()
    cmd, env = pytest_invocation(root, d, ["-rA", f"--junitxml={junit}", *extra])
    rc = subprocess.run(cmd, cwd=root, env=env).returncode
    if not junit.exists():
        print("GATE FAIL: no junit report produced")
        return 1
    suites = ET.parse(junit).getroot()
    suite_list = [suites] if suites.tag == "testsuite" else list(suites)
    tests = sum(int(s.get("tests", 0)) for s in suite_list)
    failures = sum(int(s.get("failures", 0)) for s in suite_list)
    errors = sum(int(s.get("errors", 0)) for s in suite_list)
    skipped = sum(int(s.get("skipped", 0)) for s in suite_list)
    expected = header.get("tests-collected", "unknown")
    print(f"gate {name}: tests={tests} failures={failures} errors={errors} skipped={skipped} expected={expected}")
    bad = []
    if tests == 0:
        bad.append("no tests ran")
    if failures or errors:
        bad.append("failing tests")
    if skipped:
        bad.append("skipped or xfailed tests are not allowed at a gate")
    if expected.isdigit() and int(expected) != tests:
        bad.append(f"test count {tests} differs from {expected} collected at lock time (deselection?)")
    if rc != 0 and not bad:
        bad.append(f"pytest exited with {rc}")
    for b in bad:
        print(f"GATE FAIL: {b}")
    if not bad:
        print(f"GATE OK: tests/acceptance/{name}")
    return 1 if bad else 0


def cmd_collect(root: Path, name: str) -> int:
    d = acceptance_dir(root) / name
    if not d.is_dir():
        print(f"no such directory: {d}", file=sys.stderr)
        return 1
    try:
        count = collect_count(root, d)
    except CollectionError as exc:
        print(f"COLLECTION ERRORS in tests/acceptance/{name} (the directory cannot be locked):\n{exc}")
        return 1
    print(f"tests/acceptance/{name}: {count if count is not None else 'unknown (pytest missing?)'} tests collected")
    return 0 if count else 1


def cmd_dry_run(root: Path, name: str, extra: list[str]) -> int:
    d = acceptance_dir(root) / name
    if not d.is_dir():
        print(f"no such directory: {d}", file=sys.stderr)
        return 1
    cmd, env = pytest_invocation(root, d, ["-rA", "-q", *extra])
    rc = subprocess.run(cmd, cwd=root, env=env).returncode
    print(f"dry-run of tests/acceptance/{name} finished with pytest exit code {rc} (informational)")
    return 0


RAILS_FILES = [
    "CLAUDE.md",
    "AGENTS.md",
    "GUIDE-FR.md",
    "docs/spec.md",
    "docs/plan.md",
    "docs/unsafe-allowlist.md",
    ".github/CODEOWNERS",
    ".github/workflows/rails.yml",
    "deny.toml",
]
RAILS_DIRS = [".claude", "prompts", "tools/kit", "tools/lock"]
RAILS_EXCLUDE = {".claude/settings.local.json", "tools/lock/RAILS.sha256"}
RAILS_MANIFEST = "tools/lock/RAILS.sha256"


def rails_current(root: Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for f in RAILS_FILES:
        if (root / f).is_file():
            found[f] = sha256(root / f)
    for d in RAILS_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            rel = p.relative_to(root).as_posix()
            if (
                not p.is_file()
                or rel in RAILS_EXCLUDE
                or p.suffix in IGNORED_SUFFIXES
                or any(part in IGNORED_DIRS for part in p.relative_to(root).parts)
            ):
                continue
            found[rel] = sha256(p)
    return found


def cmd_rails_update(root: Path) -> int:
    files = rails_current(root)
    lines = [
        f"# rails manifest, updated {_dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()}",
        f"# by {os.environ.get('GIT_AUTHOR_NAME') or getpass.getuser()}",
    ]
    lines += [f"{digest}  {rel}" for rel, digest in sorted(files.items())]
    (root / RAILS_MANIFEST).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"rails manifest updated: {len(files)} files. Commit it with the rails change.")
    return 0


def cmd_rails_verify(root: Path) -> int:
    manifest_path = root / RAILS_MANIFEST
    if not manifest_path.exists():
        print(f"RAILS VIOLATION  {RAILS_MANIFEST} is missing")
        return 1
    expected, _ = read_lock(manifest_path)
    actual = rails_current(root)
    problems = []
    for rel in sorted(set(expected) - set(actual)):
        problems.append(f"rails file removed: {rel}")
    for rel in sorted(set(actual) - set(expected)):
        if rel == "deny.toml":
            print(
                "warning: deny.toml is not in the rails manifest yet (owner: run rails-update after WP-0.8)",
                file=sys.stderr,
            )
            continue
        problems.append(f"rails file added without the owner: {rel}")
    for rel in sorted(set(expected) & set(actual)):
        if expected[rel] != actual[rel]:
            problems.append(f"rails file changed without the owner: {rel}")
    for p in problems:
        print(f"RAILS VIOLATION  {p}")
    if not problems:
        print(f"rails OK ({len(expected)} files)")
    return 1 if problems else 0


def main(argv: list[str]) -> int:
    root = repo_root()
    if not argv:
        print(__doc__)
        return 2
    cmd, rest = argv[0], argv[1:]
    if cmd == "lock" and len(rest) == 1:
        return cmd_lock(root, rest[0])
    if cmd == "relock" and len(rest) == 3 and rest[1] == "--reason":
        return cmd_relock(root, rest[0], rest[2])
    if cmd == "verify":
        return cmd_verify(root, "--require-tags" in rest)
    if cmd == "status":
        return cmd_status(root)
    if cmd == "rails-verify":
        return cmd_rails_verify(root)
    if cmd == "collect" and len(rest) == 1:
        return cmd_collect(root, rest[0])
    if cmd == "dry-run" and rest:
        extra = rest[2:] if len(rest) > 1 and rest[1] == "--" else []
        return cmd_dry_run(root, rest[0], extra)
    if cmd == "rails-update":
        return cmd_rails_update(root)
    if cmd == "gate" and rest:
        extra = rest[2:] if len(rest) > 1 and rest[1] == "--" else []
        return cmd_gate(root, rest[0], extra)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
