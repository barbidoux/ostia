"""Red-first check of a pull request's commits (spec §18 cycle rule 3, WP-0.9).

Usage: red_first.py --base <ref> [--head HEAD] [--pytest-cmd "uv run --frozen python -m pytest"]

For every `test(<ID>)` commit of `<base>..<head>` (merge commits left out):
- the tests it adds or changes are found: Python test functions (and `Test*` methods) whose source, or a
  module-level name they use (constant, helper, fixture by parameter name), changed in that commit; Rust
  `#[test]` functions whose source changed. Acceptance tests (`tests/acceptance/`) are left to the lock
  tool, and the fuzz workspace (`fuzz/`) to the fuzz suite;
- the commit is checked out in a temporary worktree and those tests run there: each must fail for a valid
  reason. A collection error (Python) or a compile error (Rust) is not a valid red; a skip is not red.
  Tests named on a `Pins: <test ids>` line of the commit message are exempt: they pin behaviour that is
  already correct (owner decision, 2026-10-07);
- each id of its scope needs a later `feat`, `fix`, `build` or `ci` commit for the same id, unless every
  test of the commit is pinned. Phase scopes (`test(P1)`, the lock work package) need none.

Exit codes: 0 every test commit is red first, 1 findings (one line each on stdout), 2 usage error.
"""

import argparse
import ast
import copy
import os
import re
import shlex
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

SUBJECT = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?!?: ")
IMPLEMENTATION = {"feat", "fix", "build", "ci"}
PHASE = re.compile(r"^P\d+$")
PINS = re.compile(r"^Pins:\s*(?P<ids>.+)$", re.MULTILINE)
PYTHON_TEST_FILE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test)\.py$")
RUST_TEST_ATTR = re.compile(r"#\[test\]")
RUST_FN = re.compile(r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(")
LEFT_OUT = ("tests/acceptance/", "fuzz/")
NEXTEST_FAILED = 100
NEXTEST_NO_TESTS = 4


class UsageError(Exception):
    """The check cannot run."""


@dataclass
class Commit:
    sha: str
    subject: str
    body: str
    kind: str = ""
    ids: list[str] = field(default_factory=list)

    @property
    def short(self) -> str:
        return self.sha[:7]

    @property
    def label(self) -> str:
        return f"{self.short} {self.subject.split(':', 1)[0]}"


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise UsageError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def commits(repo: Path, base: str, head: str) -> list[Commit]:
    for ref in (base, head):
        probe = subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"],
            cwd=repo,
            capture_output=True,
            text=True,
            check=False,
        )
        if probe.returncode != 0:
            raise UsageError(f"unknown {'base' if ref == base else 'head'} {ref}")
    log = git(
        repo, "log", "--reverse", "--no-merges", "--format=%H%x00%s%x00%b%x1e", f"{base}..{head}"
    )
    found = []
    for record in log.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, subject, body = record.split("\x00", 2)
        commit = Commit(sha, subject, body)
        match = SUBJECT.match(subject)
        if match:
            commit.kind = match.group("type")
            commit.ids = [i.strip() for i in (match.group("scope") or "").split(",") if i.strip()]
        found.append(commit)
    return found


def changed_files(repo: Path, sha: str) -> list[str]:
    out = git(
        repo, "diff-tree", "--root", "--no-commit-id", "-r", "--name-only", "--diff-filter=AM", sha
    )
    return [p for p in out.splitlines() if p and not p.startswith(LEFT_OUT)]


def file_at(repo: Path, rev: str, path: str) -> str | None:
    result = subprocess.run(
        ["git", "show", f"{rev}:{path}"], cwd=repo, capture_output=True, text=True, check=False
    )
    return result.stdout if result.returncode == 0 else None


def parent(repo: Path, sha: str) -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "--verify", "--quiet", f"{sha}^"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else None


# --- Python: which tests a commit adds or changes -------------------------------------------------


@dataclass
class Definition:
    """A top-level name of a test module (a function, a class, a `Test*` method or an assignment)."""

    body: str
    decorators: str
    uses: set[str]
    decorator_uses: set[str]
    is_test: bool
    is_function: bool


def names_used(nodes: Iterable[ast.AST]) -> set[str]:
    used = set()
    for node in nodes:
        used |= {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        for function in ast.walk(node):
            if isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
                # pytest fixtures arrive by parameter name.
                used |= {a.arg for a in [*function.args.args, *function.args.kwonlyargs]}
    return used


def function_definition(node: ast.FunctionDef | ast.AsyncFunctionDef, is_test: bool) -> Definition:
    undecorated = copy.copy(node)
    undecorated.decorator_list = []
    return Definition(
        body=ast.dump(undecorated),
        decorators=repr([ast.dump(d) for d in node.decorator_list]),
        uses=names_used([undecorated]),
        decorator_uses=names_used(node.decorator_list),
        is_test=is_test,
        is_function=True,
    )


def definitions(source: str) -> dict[str, Definition]:
    tree = ast.parse(source)
    found: dict[str, Definition] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found[node.name] = function_definition(node, node.name.startswith("test"))
        elif isinstance(node, ast.ClassDef):
            found[node.name] = Definition(
                ast.dump(node), "", names_used([node]), set(), False, True
            )
            if node.name.startswith("Test"):
                for item in node.body:
                    if isinstance(item, ast.FunctionDef) and item.name.startswith("test"):
                        found[f"{node.name}::{item.name}"] = function_definition(item, True)
        elif isinstance(node, ast.Assign | ast.AnnAssign):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value if node.value is not None else node
            for target in targets:
                for name in ast.walk(target):
                    if isinstance(name, ast.Name):
                        found[name.id] = Definition(
                            ast.dump(node), "", names_used([value]), set(), False, False
                        )
    return found


@dataclass
class PythonChanges:
    whole: list[str]
    """Tests whose every case must fail: their own code, a helper or fixture they reach, or a constant
    they use directly changed."""
    new_cases: list[str]
    """Tests whose decorators alone changed (rows added to a parametrize list): only their new cases."""


def changed_python_tests(old: str | None, new: str) -> PythonChanges:
    before = definitions(old) if old is not None else {}
    after = definitions(new)

    def body_changed(name: str) -> bool:
        return name not in before or before[name].body != after[name].body

    def decorators_changed(name: str) -> bool:
        return name not in before or before[name].decorators != after[name].decorators

    # Helpers and fixtures whose code changed reach every test that uses them, transitively. A changed
    # constant counts only for the definitions that use it directly: a table that grows does not change
    # the tests that only reach it through an unchanged helper.
    functions = {
        n
        for n, d in after.items()
        if d.is_function and not d.is_test and (body_changed(n) or decorators_changed(n))
    }
    grew = True
    while grew:
        grew = False
        for name, d in after.items():
            if d.is_function and not d.is_test and name not in functions and d.uses & functions:
                functions.add(name)
                grew = True
    constants = {
        n for n, d in after.items() if not d.is_function and (body_changed(n) or d.uses & functions)
    }
    whole, new_cases = [], []
    for name, d in after.items():
        if not d.is_test:
            continue
        if body_changed(name) or d.uses & (functions | constants):
            whole.append(name)
        elif decorators_changed(name) or d.decorator_uses & (functions | constants):
            new_cases.append(name)
    return PythonChanges(sorted(whole), sorted(new_cases))


# --- Rust: which tests a commit adds or changes ---------------------------------------------------


def rust_tests(source: str) -> dict[str, str]:
    """`#[test]` function name -> its source text (from the attribute to the closing brace)."""
    found = {}
    for attribute in RUST_TEST_ATTR.finditer(source):
        function = RUST_FN.search(source, attribute.end())
        if function is None:
            continue
        opening = source.find("{", function.end())
        depth, position = 0, opening
        while position < len(source):
            if source[position] == "{":
                depth += 1
            elif source[position] == "}":
                depth -= 1
                if depth == 0:
                    break
            position += 1
        found[function.group("name")] = source[attribute.start() : position + 1]
    return found


def changed_rust_tests(old: str | None, new: str) -> list[str]:
    before = rust_tests(old) if old is not None else {}
    return sorted(name for name, text in rust_tests(new).items() if before.get(name) != text)


# --- running the tests at the commit --------------------------------------------------------------


@dataclass
class Outcome:
    failed: bool = False
    skipped: bool = False


def junit_outcomes(report: Path) -> dict[tuple[str, str], Outcome]:
    outcomes = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        outcome = Outcome(
            failed=case.find("failure") is not None or case.find("error") is not None,
            skipped=case.find("skipped") is not None,
        )
        outcomes[(case.get("classname", ""), case.get("name", ""))] = outcome
    return outcomes


def collected(worktree: Path, pytest_cmd: list[str], tests: list[str]) -> set[str]:
    """Node ids pytest collects for these tests in the worktree (empty when they do not collect)."""
    cmd = [
        *pytest_cmd,
        "--collect-only",
        "-q",
        "-p",
        "no:cacheprovider",
        f"--rootdir={worktree}",
        *tests,
    ]
    result = subprocess.run(cmd, cwd=worktree, capture_output=True, text=True, check=False)
    return (
        {line.strip() for line in result.stdout.splitlines() if "::" in line}
        if result.returncode == 0
        else set()
    )


def run_python(
    worktree: Path, pytest_cmd: list[str], tests: list[str], label: str, old_cases: set[str]
) -> list[str]:
    """Findings for the tests run at the commit; cases in `old_cases` existed before and are left out."""
    report = worktree / ".red-first-junit.xml"
    cmd = [
        *pytest_cmd,
        "-q",
        "-p",
        "no:cacheprovider",
        f"--rootdir={worktree}",
        f"--junitxml={report}",
        *tests,
    ]
    result = subprocess.run(cmd, cwd=worktree, capture_output=True, text=True, check=False)
    # 0 all passed, 1 some failed; anything else (collection errors, no tests found) is not a valid red.
    if result.returncode not in (0, 1) or not report.is_file():
        return [f"{label}: the tests do not collect (an import or syntax error is not a valid red)"]
    outcomes = junit_outcomes(report)
    findings = []
    for test in tests:
        path, _, name = test.partition("::")
        module = path.removesuffix(".py").replace("/", ".")
        cls, _, function = name.rpartition("::")
        classname = f"{module}.{cls}" if cls else module
        cases = {
            case: outcome
            for (owner, case), outcome in outcomes.items()
            if owner == classname and (case == function or case.startswith(f"{function}["))
        }
        if not cases:
            findings.append(
                f"{label}: the tests do not collect (an import or syntax error is not a valid red)"
            )
            continue
        for case, outcome in sorted(cases.items()):
            case_id = f"{path}::{f'{cls}::' if cls else ''}{case}"
            if case_id in old_cases:
                continue
            if outcome.skipped:
                findings.append(f"{label}: {case_id} was skipped")
            elif not outcome.failed:
                findings.append(f"{label}: {case_id} passes before its implementation")
    return sorted(set(findings), key=findings.index)


def run_rust(worktree: Path, tests: dict[str, str], label: str, env: dict[str, str]) -> list[str]:
    locked = ["--locked"] if (worktree / "Cargo.lock").is_file() else []
    base = ["cargo", "nextest", "run", "--workspace", *locked]
    build = subprocess.run(
        [*base, "--no-run"], cwd=worktree, capture_output=True, text=True, env=env, check=False
    )
    if build.returncode != 0:
        return [
            f"{label}: the Rust tests do not compile (commit a stub that returns todo!() with the tests)"
        ]
    findings = []
    for name, path in tests.items():
        result = subprocess.run(
            [*base, "--no-fail-fast", "--no-tests=fail", "-E", f"test(/(^|::){re.escape(name)}$/)"],
            cwd=worktree,
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )
        if result.returncode == 0:
            findings.append(f"{label}: {path}::{name} passes before its implementation")
        elif result.returncode == NEXTEST_NO_TESTS:
            findings.append(f"{label}: {path}::{name} was not found by cargo-nextest")
        elif result.returncode != NEXTEST_FAILED:
            findings.append(
                f"{label}: {path}::{name} could not run (cargo-nextest exit {result.returncode})"
            )
    return findings


@dataclass
class TestsOfCommit:
    python: list[str] = field(default_factory=list)
    python_new_cases: list[str] = field(default_factory=list)
    rust: dict[str, str] = field(default_factory=dict)

    def ids(self) -> set[str]:
        rust = {f"{path}::{name}" for name, path in self.rust.items()}
        return {*self.python, *self.python_new_cases, *rust}


def tests_of(repo: Path, commit: Commit) -> TestsOfCommit:
    before = parent(repo, commit.sha)
    found = TestsOfCommit()
    for path in changed_files(repo, commit.sha):
        new = file_at(repo, commit.sha, path)
        old = file_at(repo, before, path) if before else None
        if new is None:
            continue
        if PYTHON_TEST_FILE.search(path):
            try:
                changes = changed_python_tests(old, new)
            except SyntaxError:
                found.python.append(f"{path}::<syntax error>")
                continue
            found.python += [f"{path}::{name}" for name in changes.whole]
            found.python_new_cases += [f"{path}::{name}" for name in changes.new_cases]
        elif path.endswith(".rs"):
            for name in changed_rust_tests(old, new):
                found.rust[name] = path
    return found


def pins(commit: Commit) -> set[str]:
    return {
        pin
        for match in PINS.finditer(commit.body)
        for pin in re.split(r"[,\s]+", match.group("ids"))
        if pin
    }


def is_pinned(test: str, pinned: set[str]) -> bool:
    # A pin on a function covers its parametrized cases.
    return test in pinned or test.split("[", 1)[0] in pinned


def check_commit(
    repo: Path, commit: Commit, pytest_cmd: list[str], env: dict[str, str]
) -> tuple[list[str], bool]:
    """Findings for one test commit, and whether it has tests that are not pinned."""
    tests = tests_of(repo, commit)
    pinned = pins(commit)
    findings = [
        f"{commit.label}: Pins names {pin}, which this commit does not add or change"
        for pin in sorted(pinned - tests.ids())
    ]
    if not tests.ids():
        if not all(PHASE.match(i) for i in commit.ids) or not commit.ids:
            findings.append(f"{commit.label}: adds or changes no test")
        return findings, False
    if any(t.endswith("<syntax error>") for t in tests.python):
        findings.append(
            f"{commit.label}: the tests do not collect (an import or syntax error is not a valid red)"
        )
        return findings, True
    python = [t for t in tests.python if not is_pinned(t, pinned)]
    new_cases = [t for t in tests.python_new_cases if not is_pinned(t, pinned)]
    rust = {n: p for n, p in tests.rust.items() if not is_pinned(f"{p}::{n}", pinned)}
    if not python and not new_cases and not rust:
        return findings, False
    with tempfile.TemporaryDirectory(prefix="red-first-") as scratch:
        trees = []
        try:
            old_cases: set[str] = set()
            before = parent(repo, commit.sha)
            if new_cases and before:
                # The cases that existed at the parent are left out: only rows the commit adds count.
                previous = Path(scratch) / "parent"
                git(repo, "worktree", "add", "--quiet", "--detach", str(previous), before)
                trees.append(previous)
                old_cases = collected(previous, pytest_cmd, new_cases)
            worktree = Path(scratch) / "tree"
            git(repo, "worktree", "add", "--quiet", "--detach", str(worktree), commit.sha)
            trees.append(worktree)
            if python or new_cases:
                found = run_python(
                    worktree, pytest_cmd, python + new_cases, commit.label, old_cases
                )
                findings += [
                    f for f in found if not is_pinned(f.split(": ", 1)[1].split(" ", 1)[0], pinned)
                ]
            if rust:
                findings += run_rust(worktree, rust, commit.label, env)
        finally:
            for tree in trees:
                git(repo, "worktree", "remove", "--force", str(tree))
    return findings, True


def implementations(later: Iterable[Commit]) -> set[str]:
    return {i for c in later if c.kind in IMPLEMENTATION for i in c.ids}


def check(repo: Path, base: str, head: str, pytest_cmd: list[str]) -> tuple[int, list[str]]:
    history = commits(repo, base, head)
    env = {**os.environ, "CARGO_TERM_COLOR": "never"}
    env.setdefault("CARGO_TARGET_DIR", str(repo / "target"))
    findings: list[str] = []
    checked = 0
    for index, commit in enumerate(history):
        if commit.kind != "test":
            continue
        checked += 1
        if not commit.ids:
            findings.append(f"{commit.short} test: no requirement id in the scope")
            continue
        found, needs_implementation = check_commit(repo, commit, pytest_cmd, env)
        findings += found
        if needs_implementation:
            done = implementations(history[index + 1 :])
            findings += [
                f"{commit.label}: no later feat, fix, build or ci commit for {i}"
                for i in commit.ids
                if not PHASE.match(i) and i not in done
            ]
    return checked, findings


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Each test(...) commit fails before its implementation"
    )
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--pytest-cmd", default="uv run --frozen python -m pytest")
    args = parser.parse_args(argv)
    repo = Path.cwd()
    try:
        checked, findings = check(repo, args.base, args.head, shlex.split(args.pytest_cmd))
    except UsageError as error:
        print(f"red_first: {error}", file=sys.stderr)
        return 2
    for finding in findings:
        print(finding)
    if findings:
        return 1
    print(f"red-first OK: {checked} test commit{'' if checked == 1 else 's'} checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
