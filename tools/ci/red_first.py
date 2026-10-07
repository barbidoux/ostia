"""Red-first check of a pull request's commits (spec §18 cycle rules 1 and 3, WP-0.9).

Usage: red_first.py --base <ref> [--head HEAD] [--pytest-cmd "uv run --frozen python -m pytest"]
                    [--timeout 1800]

Every commit of `<base>..<head>` (merge commits left out) must follow the commit convention of
tools/ci/commit_msg.py, and only `test(<ID>)` commits may add, change or remove tests (owner decision,
2026-10-07). For every `test(<ID>)` commit:
- the tests it adds or changes are found:
  - Python test functions and `Test*` methods whose code changed, or that use a helper or fixture whose
    code changed (transitively, `conftest.py` included), or a module-level constant that changed;
  - when only a test's `parametrize` rows changed, only the rows the commit adds or changes, compared by
    content;
  - Rust `#[test]`, `#[tokio::test]` and `#[rstest]` functions whose code changed, per file.
  Acceptance tests (`tests/acceptance/`) are left to the lock tool, the fuzz workspace (`fuzz/`) to the
  fuzz suite;
- the commit is checked out in a temporary worktree and those tests run there. Each must fail for a valid
  reason. These are not valid reds:
  - a collection, setup or fixture error, or a NameError or a missing import (Python);
  - a compile error (Rust);
  - a skip;
  - a run that does not finish within --timeout.
  Two kinds of test are not run:
  - tests named on a `Pins: <test ids>` line of the commit message (regression guards that pin behaviour
    already correct; a pin may name one parametrized case). They are printed;
  - bench tests (the `bench` marker, Rust targets that require the `bench` feature): their red evidence
    comes from the bench run. They are printed as not checked;
- each id of its scope needs a later commit (a descendant) `feat`, `fix`, `build` or `ci` for the same
  id, unless every test of the commit is pinned. Phase scopes (`test(P1)`, the lock work package) need
  none, and may add no test when they only touch acceptance tests.

Exit codes: 0 every test commit is red first, 1 findings (one line each on stdout), 2 usage error.
"""

import argparse
import ast
import copy
import os
import re
import shlex
import signal
import subprocess
import sys
import tempfile
import tomllib
import xml.etree.ElementTree as ET
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from commit_msg import SUBJECT as CONVENTION

SUBJECT = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]*)\))?: ")
IMPLEMENTATION = {"feat", "fix", "build", "ci"}
PHASE = re.compile(r"^P\d+$")
PINS = re.compile(r"^Pins:\s*(?P<ids>.+)$", re.MULTILINE)
PYTHON_TEST_FILE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test)\.py$")
ACCEPTANCE = "tests/acceptance/"
LEFT_OUT = (ACCEPTANCE, "fuzz/")
INVALID_EXCEPTIONS = {
    "NameError",
    "ImportError",
    "ModuleNotFoundError",
    "SyntaxError",
    "IndentationError",
}
RUST_TEST_ATTR = re.compile(r"#\[\s*(?:[A-Za-z_]\w*\s*::\s*)*(?:test|rstest)\b[^\]]*\]")
RUST_FN = re.compile(r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*[<(]")
NEXTEST_FAILED = 100
NEXTEST_NO_TESTS = 4
DO_NOT_COLLECT = "the tests do not collect (an import or syntax error is not a valid red)"


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


@dataclass
class Finding:
    message: str
    test: str | None = None


def git(repo: Path, *args: str) -> str:
    result = subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise UsageError(f"git {' '.join(args)}: {result.stderr.strip()}")
    return result.stdout


def succeeds(repo: Path, *args: str) -> bool:
    return (
        subprocess.run(["git", *args], cwd=repo, capture_output=True, check=False).returncode == 0
    )


def commits(repo: Path, base: str, head: str) -> list[Commit]:
    for ref, what in ((base, "base"), (head, "head")):
        if not succeeds(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"):
            raise UsageError(f"unknown {what} {ref}")
    log = git(
        repo,
        "log",
        "--reverse",
        "--topo-order",
        "--no-merges",
        "--format=%H%x00%s%x00%b%x1e",
        f"{base}..{head}",
    )
    found = []
    for record in log.split("\x1e"):
        record = record.strip("\n")
        if not record:
            continue
        sha, subject, body = record.split("\x00", 2)
        commit = Commit(sha, subject, body)
        match = SUBJECT.match(subject)
        if match and CONVENTION.match(subject):
            commit.kind = match.group("type")
            commit.ids = [i.strip() for i in (match.group("scope") or "").split(",") if i.strip()]
        found.append(commit)
    return found


@dataclass
class Change:
    status: str
    old: str | None
    new: str | None


def changes(repo: Path, sha: str) -> list[Change]:
    out = git(repo, "diff-tree", "--root", "--no-commit-id", "-r", "-M", "--name-status", sha)
    found = []
    for line in out.splitlines():
        parts = line.split("\t")
        status = parts[0][:1]
        if status == "R":
            found.append(Change("R", parts[1], parts[2]))
        elif status == "D":
            found.append(Change("D", parts[1], None))
        elif status in ("A", "M", "C", "T"):
            found.append(Change(status, None if status == "A" else parts[-1], parts[-1]))
    return found


def file_at(repo: Path, rev: str | None, path: str | None) -> str | None:
    if rev is None or path is None:
        return None
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


# --- Python: which tests a commit adds, changes or removes ----------------------------------------


@dataclass
class Definition:
    """A top-level name of a test module (a function, a class, a `Test*` method or an assignment)."""

    body: str
    decorators: str
    uses: set[str]
    decorator_uses: set[str]
    is_test: bool
    is_function: bool
    rows: list[str] | None = None
    """The `parametrize` rows (dumped) when the test has exactly one parametrize with literal rows."""
    other_decorators: str = ""
    is_bench: bool = False


def names_used(nodes: Iterable[ast.AST]) -> set[str]:
    used = set()
    for node in nodes:
        used |= {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
        for function in ast.walk(node):
            if isinstance(function, ast.FunctionDef | ast.AsyncFunctionDef):
                # pytest fixtures arrive by parameter name.
                used |= {a.arg for a in [*function.args.args, *function.args.kwonlyargs]}
    return used


def is_mark(node: ast.AST, mark: str) -> bool:
    """`pytest.mark.<mark>` or `mark.<mark>`, called or not."""
    target = node.func if isinstance(node, ast.Call) else node
    return (
        isinstance(target, ast.Attribute)
        and target.attr == mark
        and isinstance(target.value, ast.Attribute | ast.Name)
        and (target.value.attr if isinstance(target.value, ast.Attribute) else target.value.id)
        == "mark"
    )


def has_bench_mark(nodes: Iterable[ast.AST]) -> bool:
    return any(is_mark(n, "bench") for node in nodes for n in ast.walk(node))


def parametrize_rows(
    decorators: list[ast.expr], assignments: dict[str, ast.expr]
) -> tuple[list[str] | None, str]:
    """(rows of the single parametrize decorator, dump of the other decorators)."""
    marks = [d for d in decorators if isinstance(d, ast.Call) and is_mark(d, "parametrize")]
    others = repr([ast.dump(d) for d in decorators if d not in marks])
    if len(marks) != 1:
        return None, others
    call = marks[0]
    values = call.args[1] if len(call.args) > 1 else None
    for keyword in call.keywords:
        if keyword.arg == "argvalues":
            values = keyword.value
    if isinstance(values, ast.Name):
        values = assignments.get(values.id)
    if not isinstance(values, ast.List | ast.Tuple):
        return None, others
    return [ast.dump(v) for v in values.elts], others


def function_definition(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    is_test: bool,
    assignments: dict[str, ast.expr],
    bench_scope: bool,
) -> Definition:
    undecorated = copy.copy(node)
    undecorated.decorator_list = []
    rows, others = parametrize_rows(node.decorator_list, assignments)
    return Definition(
        body=ast.dump(undecorated),
        decorators=repr([ast.dump(d) for d in node.decorator_list]),
        uses=names_used([undecorated]),
        decorator_uses=names_used(node.decorator_list),
        is_test=is_test,
        is_function=True,
        rows=rows,
        other_decorators=others,
        is_bench=bench_scope or has_bench_mark(node.decorator_list),
    )


def definitions(source: str) -> dict[str, Definition]:
    tree = ast.parse(source)
    assignments: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    assignments[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value:
            assignments[node.target.id] = node.value
    module_bench = "pytestmark" in assignments and has_bench_mark([assignments["pytestmark"]])
    found: dict[str, Definition] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            found[node.name] = function_definition(
                node, node.name.startswith("test"), assignments, module_bench
            )
        elif isinstance(node, ast.ClassDef):
            found[node.name] = Definition(
                ast.dump(node), "", names_used([node]), set(), False, True
            )
            if node.name.startswith("Test"):
                class_bench = module_bench or has_bench_mark(node.decorator_list)
                for item in node.body:
                    if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) and (
                        item.name.startswith("test")
                    ):
                        found[f"{node.name}::{item.name}"] = function_definition(
                            item, True, assignments, class_bench
                        )
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


def changed_helpers(before: dict[str, Definition], after: dict[str, Definition]) -> set[str]:
    """Helpers and fixtures whose code changed, and those that use them, transitively."""

    def changed(name: str) -> bool:
        old = before.get(name)
        return old is None or (old.body, old.decorators) != (
            after[name].body,
            after[name].decorators,
        )

    functions = {n for n, d in after.items() if d.is_function and not d.is_test and changed(n)}
    grew = True
    while grew:
        grew = False
        for name, d in after.items():
            if d.is_function and not d.is_test and name not in functions and d.uses & functions:
                functions.add(name)
                grew = True
    return functions


@dataclass
class PythonChanges:
    whole: list[str] = field(default_factory=list)
    """Tests whose every case must fail."""
    rows: dict[str, tuple[list[int], int]] = field(default_factory=dict)
    """Tests whose parametrize rows alone changed: (indices of the rows added or changed, row count)."""
    removed: list[str] = field(default_factory=list)
    bench: set[str] = field(default_factory=set)


def changed_python_tests(
    old: str | None, new: str, outside: set[str] | None = None
) -> PythonChanges:
    """Tests of a module that changed; `outside` holds changed fixture names from a conftest."""
    before = definitions(old) if old is not None else {}
    after = definitions(new)
    functions = changed_helpers(before, after) | (outside or set())
    # A changed constant counts only for the definitions that use it directly: a table that grows
    # does not change the tests that only reach it through an unchanged helper.
    constants = {
        n
        for n, d in after.items()
        if not d.is_function and (n not in before or before[n].body != d.body or d.uses & functions)
    }
    result = PythonChanges(
        removed=sorted(n for n, d in before.items() if d.is_test and n not in after)
    )
    for name, d in after.items():
        if not d.is_test:
            continue
        if d.is_bench:
            result.bench.add(name)
        previous = before.get(name)
        if previous is None or previous.body != d.body or d.uses & (functions | constants):
            result.whole.append(name)
            continue
        if previous.decorators == d.decorators and not d.decorator_uses & (functions | constants):
            continue
        if (
            d.rows is None
            or previous.rows is None
            or d.other_decorators != previous.other_decorators
        ):
            result.whole.append(name)
            continue
        available = Counter(previous.rows)
        fresh = []
        for index, row in enumerate(d.rows):
            if available[row]:
                available[row] -= 1
            else:
                fresh.append(index)
        if fresh:
            result.rows[name] = (fresh, len(d.rows))
    result.whole.sort()
    return result


# --- Rust: which tests a commit adds, changes or removes ------------------------------------------


def blank_literals(source: str) -> str:
    """The source with comments, strings and char literals replaced by spaces (newlines kept)."""
    out = list(source)
    i, n = 0, len(source)

    def blank(start: int, end: int) -> None:
        for k in range(start, min(end, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        if source.startswith("//", i):
            end = source.find("\n", i)
            end = n if end < 0 else end
            blank(i, end)
            i = end
        elif source.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if source.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif source.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif (raw := re.match(r'r(#*)"', source[i:])) is not None:
            closing = '"' + raw.group(1)
            end = source.find(closing, i + len(raw.group(0)))
            end = n if end < 0 else end + len(closing)
            blank(i, end)
            i = end
        elif source[i] == '"':
            j = i + 1
            while j < n and source[j] != '"':
                j += 2 if source[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
        elif source[i] == "'" and (char := re.match(r"'(\\.[^']*|[^'\\\n])'", source[i:])):
            blank(i, i + len(char.group(0)))
            i += len(char.group(0))
        else:
            i += 1
    return "".join(out)


def rust_tests(source: str) -> dict[str, str]:
    """Test function name -> its source text (from the attribute to the closing brace)."""
    plain = blank_literals(source)
    found = {}
    for attribute in RUST_TEST_ATTR.finditer(plain):
        function = RUST_FN.search(plain, attribute.end())
        if function is None:
            continue
        opening = plain.find("{", function.end())
        if opening < 0:
            continue
        depth, position = 0, opening
        while position < len(plain):
            if plain[position] == "{":
                depth += 1
            elif plain[position] == "}":
                depth -= 1
                if depth == 0:
                    break
            position += 1
        found[function.group("name")] = source[attribute.start() : position + 1]
    return found


# --- what a commit does to the tests --------------------------------------------------------------


@dataclass
class TestsOfCommit:
    python: list[str] = field(default_factory=list)
    python_rows: dict[str, tuple[list[int], int]] = field(default_factory=dict)
    rust: list[tuple[str, str]] = field(default_factory=list)
    """(path, name) of the Rust tests added or changed."""
    removed: list[str] = field(default_factory=list)
    bench: set[str] = field(default_factory=set)
    syntax_errors: list[str] = field(default_factory=list)

    def ids(self) -> set[str]:
        return {*self.python, *self.python_rows, *(f"{p}::{n}" for p, n in self.rust)}


def conftest_fixtures(repo: Path, commit: Commit, before: str | None) -> dict[str, set[str]]:
    """Directory -> changed helper and fixture names of each conftest.py the commit changes."""
    found = {}
    for change in changes(repo, commit.sha):
        if change.new is None or Path(change.new).name != "conftest.py":
            continue
        if change.new.startswith(LEFT_OUT):
            continue
        new = file_at(repo, commit.sha, change.new)
        old = file_at(repo, before, change.old)
        try:
            names = changed_helpers(definitions(old) if old else {}, definitions(new or ""))
        except SyntaxError:
            continue
        if names:
            found[str(Path(change.new).parent)] = names
    return found


def tests_of(repo: Path, commit: Commit) -> TestsOfCommit:
    before = parent(repo, commit.sha)
    found = TestsOfCommit()
    fixtures = conftest_fixtures(repo, commit, before)
    paths: dict[str, str | None] = {}
    for change in changes(repo, commit.sha):
        if change.new is not None and not change.new.startswith(LEFT_OUT):
            paths[change.new] = change.old
        elif change.new is None and change.old and not change.old.startswith(LEFT_OUT):
            paths.setdefault(f"\0deleted\0{change.old}", change.old)
    if fixtures:
        listing = git(repo, "ls-tree", "-r", "--name-only", commit.sha).splitlines()
        for path in listing:
            directory = next((d for d in fixtures if d == "." or path.startswith(f"{d}/")), None)
            if (
                directory is not None
                and PYTHON_TEST_FILE.search(path)
                and path not in paths
                and not path.startswith(LEFT_OUT)
            ):
                paths[path] = path
    for path, old_path in paths.items():
        deleted = path.startswith("\0deleted\0")
        new = None if deleted else file_at(repo, commit.sha, path)
        old = file_at(repo, before, old_path)
        shown = old_path if deleted else path
        outside = {
            name
            for directory, names in fixtures.items()
            if directory == "." or (shown or "").startswith(f"{directory}/")
            for name in names
        }
        if shown is not None and PYTHON_TEST_FILE.search(shown):
            try:
                result = changed_python_tests(old, new or "", outside)
            except SyntaxError:
                found.syntax_errors.append(shown)
                continue
            found.python += [f"{shown}::{n}" for n in result.whole]
            found.python_rows.update({f"{shown}::{n}": rows for n, rows in result.rows.items()})
            found.removed += [f"{(old_path or shown)}::{n}" for n in result.removed]
            found.bench |= {f"{shown}::{n}" for n in result.bench}
        elif shown is not None and shown.endswith(".rs"):
            old_tests = rust_tests(old) if old else {}
            new_tests = rust_tests(new) if new else {}
            found.rust += [(shown, n) for n, t in new_tests.items() if old_tests.get(n) != t]
            found.removed += [f"{old_path}::{n}" for n in old_tests if n not in new_tests]
    found.python = sorted(set(found.python))
    return found


# --- running the tests at the commit --------------------------------------------------------------


class Timeout(Exception):
    """A run did not finish in time."""


def run_limited(
    cmd: list[str], cwd: Path, timeout: float, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a command in its own process group, killed whole when it overruns."""
    with subprocess.Popen(
        cmd,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    ) as process:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise Timeout from error
        return subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)


@dataclass
class Outcome:
    kind: str
    """passed, failed, error or skipped."""
    exception: str = ""


def junit_outcomes(report: Path) -> dict[tuple[str, str], Outcome]:
    outcomes = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        outcome = Outcome("passed")
        if case.find("error") is not None:
            outcome = Outcome("error")
        elif (failure := case.find("failure")) is not None:
            match = re.match(r"([A-Za-z_][\w.]*)(?::|$)", failure.get("message", ""))
            outcome = Outcome("failed", match.group(1).rsplit(".", 1)[-1] if match else "")
        elif case.find("skipped") is not None:
            outcome = Outcome("skipped")
        outcomes[(case.get("classname", ""), case.get("name", ""))] = outcome
    return outcomes


def collected(worktree: Path, pytest_cmd: list[str], tests: list[str], timeout: float) -> list[str]:
    """Node ids pytest collects for these tests, in collection order (empty when they do not collect)."""
    cmd = [*pytest_cmd, "--collect-only", "-q", "-p", "no:cacheprovider", f"--rootdir={worktree}"]
    result = run_limited([*cmd, *tests], worktree, timeout)
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if "::" in line]


def run_python(
    worktree: Path,
    pytest_cmd: list[str],
    tests: list[str],
    rows: dict[str, tuple[list[int], int]],
    label: str,
    timeout: float,
) -> list[Finding]:
    """Findings for the tests run at the commit; for `rows` tests, only the given row indices count."""
    selected_rows: dict[str, set[str]] = {}
    if rows:
        order = collected(worktree, pytest_cmd, list(rows), timeout)
        for test, (indices, count) in rows.items():
            ordered = [c for c in order if c.startswith(f"{test}[")]
            # Cases follow the rows in order; if they do not map one to one, every case counts.
            selected_rows[test] = (
                {ordered[i] for i in indices} if len(ordered) == count else set(ordered)
            )
    report = worktree / ".red-first-junit.xml"
    cmd = [
        *pytest_cmd,
        "-q",
        "-p",
        "no:cacheprovider",
        f"--rootdir={worktree}",
        f"--junitxml={report}",
    ]
    result = run_limited([*cmd, *tests, *rows], worktree, timeout)
    # 0 all passed, 1 some failed; anything else (collection errors, no tests found) is not a valid red.
    if result.returncode not in (0, 1) or not report.is_file():
        return [Finding(f"{label}: {DO_NOT_COLLECT}")]
    outcomes = junit_outcomes(report)
    findings: list[Finding] = []
    for test in [*tests, *rows]:
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
            findings.append(Finding(f"{label}: {DO_NOT_COLLECT}"))
            continue
        for case, outcome in sorted(cases.items()):
            case_id = f"{path}::{f'{cls}::' if cls else ''}{case}"
            if test in rows and case_id not in selected_rows.get(test, set()):
                continue
            message = None
            if outcome.kind == "skipped":
                message = f"{case_id} was skipped"
            elif outcome.kind == "passed":
                message = f"{case_id} passes before its implementation"
            elif outcome.kind == "error":
                message = (
                    f"{case_id} errors outside the test body (a broken fixture is not a valid red)"
                )
            elif outcome.exception in INVALID_EXCEPTIONS:
                message = (
                    f"{case_id} fails with {outcome.exception} "
                    "(a typo or a missing import is not a valid red)"
                )
            if message:
                findings.append(Finding(f"{label}: {message}", case_id))
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.message, finding)
    return list(unique.values())


@dataclass
class RustTarget:
    package: str
    selector: str
    """A nextest filterset selecting the test binary of the file."""
    bench: bool


def rust_target(repo: Path, sha: str, path: str) -> RustTarget | None:
    """The package and test binary of a Rust file, from the nearest Cargo.toml with a [package]."""
    directory = Path(path).parent
    manifest: dict[str, Any] = {}
    while True:
        text = file_at(repo, sha, (directory / "Cargo.toml").as_posix())
        if text is not None:
            try:
                parsed = tomllib.loads(text)
            except tomllib.TOMLDecodeError:
                return None
            if "package" in parsed:
                manifest = parsed
                break
        if directory == Path("."):
            return None
        directory = directory.parent
    package = str(manifest["package"]["name"])
    relative = Path(path).relative_to(directory).as_posix()
    targets = manifest.get("test", [])
    for target in targets:
        target_path = target.get("path", f"tests/{target.get('name')}.rs")
        if target_path == relative:
            bench = "bench" in target.get("required-features", [])
            return RustTarget(package, f"binary({target['name']})", bench)
    parts = relative.split("/")
    if parts[0] == "tests" and len(parts) == 2:
        return RustTarget(package, f"binary({Path(parts[1]).stem})", False)
    if parts[0] == "tests" and len(parts) > 2:
        return RustTarget(package, f"binary({parts[1]})", False)
    if relative.startswith("src/bin/") or relative == "src/main.rs":
        return RustTarget(package, "kind(bin)", False)
    return RustTarget(package, "kind(lib)", False)


def run_rust(
    repo: Path,
    commit: Commit,
    worktree: Path,
    tests: list[tuple[str, str]],
    env: dict[str, str],
    timeout: float,
) -> list[Finding]:
    label = commit.label
    locked = ["--locked"] if (worktree / "Cargo.lock").is_file() else []
    base = ["cargo", "nextest", "run", "--workspace", *locked]
    build = run_limited([*base, "--no-run"], worktree, timeout, env)
    if build.returncode != 0:
        return [
            Finding(
                f"{label}: the Rust tests do not compile "
                "(commit a stub that returns todo!() with the tests)"
            )
        ]
    findings = []
    for path, name in tests:
        target = rust_target(repo, commit.sha, path)
        test_id = f"{path}::{name}"
        name_filter = f"test(/(^|::){re.escape(name)}$/)"
        expression = (
            f"package({target.package}) & {target.selector} & {name_filter}"
            if target
            else name_filter
        )
        result = run_limited(
            [*base, "--no-fail-fast", "--no-tests=fail", "-E", expression], worktree, timeout, env
        )
        if result.returncode == 0:
            findings.append(
                Finding(f"{label}: {test_id} passes before its implementation", test_id)
            )
        elif result.returncode == NEXTEST_NO_TESTS:
            findings.append(Finding(f"{label}: {test_id} was not found by cargo-nextest", test_id))
        elif result.returncode != NEXTEST_FAILED:
            findings.append(
                Finding(
                    f"{label}: {test_id} could not run (cargo-nextest exit {result.returncode})",
                    test_id,
                )
            )
    return findings


def pins(commit: Commit) -> set[str]:
    return {
        pin
        for match in PINS.finditer(commit.body)
        for pin in re.split(r"[,\s]+", match.group("ids"))
        if pin
    }


def is_pinned(test: str | None, pinned: set[str]) -> bool:
    # A pin on a function covers its parametrized cases; a pin on a case covers that case only.
    return test is not None and (test in pinned or test.split("[", 1)[0] in pinned)


def rust_bench(repo: Path, commit: Commit, tests: list[tuple[str, str]]) -> set[str]:
    """Rust tests of the commit that belong to a target requiring the `bench` feature."""
    return {
        f"{path}::{name}"
        for path, name in tests
        if (target := rust_target(repo, commit.sha, path)) is not None and target.bench
    }


@dataclass
class Report:
    findings: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def remove_worktrees(repo: Path, trees: list[Path]) -> None:
    for tree in trees:
        try:
            git(repo, "worktree", "remove", "--force", str(tree))
        except UsageError:
            pass
    subprocess.run(["git", "worktree", "prune"], cwd=repo, capture_output=True, check=False)


def check_test_commit(
    repo: Path,
    commit: Commit,
    tests: TestsOfCommit,
    pytest_cmd: list[str],
    env: dict[str, str],
    timeout: float,
    report: Report,
) -> bool:
    """Check one test commit; returns whether it has tests that are not pinned (needing an
    implementation)."""
    pinned = pins(commit)
    known = tests.ids()
    for pin in sorted(pinned):
        if pin in known or ("[" in pin and pin.split("[", 1)[0] in known):
            report.notes.append(f"pinned {commit.short}: {pin}")
        else:
            report.findings.append(
                f"{commit.label}: Pins names {pin}, which this commit does not add or change"
            )
    if not known and not tests.syntax_errors:
        only_acceptance = all(
            (c.new or c.old or "").startswith(ACCEPTANCE) for c in changes(repo, commit.sha)
        )
        if not (commit.ids and all(PHASE.match(i) for i in commit.ids) and only_acceptance):
            report.findings.append(f"{commit.label}: adds or changes no test")
        return False
    if tests.syntax_errors:
        report.findings.append(f"{commit.label}: {DO_NOT_COLLECT}")
        return True
    bench = tests.bench | rust_bench(repo, commit, tests.rust)
    for test in sorted(known & bench):
        report.notes.append(f"not checked (bench) {commit.short}: {test}")
    python = [t for t in tests.python if not is_pinned(t, pinned) and t not in bench]
    rows = {
        t: r for t, r in tests.python_rows.items() if not is_pinned(t, pinned) and t not in bench
    }
    rust = [
        (p, n)
        for p, n in tests.rust
        if not is_pinned(f"{p}::{n}", pinned) and f"{p}::{n}" not in bench
    ]
    unpinned = {t for t in known if not is_pinned(t, pinned)}
    if not python and not rows and not rust:
        return bool(unpinned)
    with tempfile.TemporaryDirectory(prefix="red-first-") as scratch:
        worktree = Path(scratch) / "tree"
        trees = [worktree]
        try:
            git(repo, "worktree", "add", "--quiet", "--detach", str(worktree), commit.sha)
            found: list[Finding] = []
            if python or rows:
                found += run_python(worktree, pytest_cmd, python, rows, commit.label, timeout)
            if rust:
                found += run_rust(repo, commit, worktree, rust, env, timeout)
            report.findings += [f.message for f in found if not is_pinned(f.test, pinned)]
        except Timeout:
            report.findings.append(f"{commit.label}: the tests did not finish within {timeout:g} s")
        finally:
            remove_worktrees(repo, trees)
    return True


def check(
    repo: Path, base: str, head: str, pytest_cmd: list[str], timeout: float
) -> tuple[int, Report]:
    history = commits(repo, base, head)
    env = {**os.environ, "CARGO_TERM_COLOR": "never"}
    # Not the developer's target directory: older commits would leave stale binaries there.
    env.setdefault("CARGO_TARGET_DIR", str(repo / "target" / "red-first"))
    report = Report()
    checked = 0
    for commit in history:
        if not commit.kind:
            report.findings.append(
                f"{commit.short} subject does not follow the commit convention: {commit.subject!r}"
            )
            continue
        tests = tests_of(repo, commit)
        if commit.kind != "test":
            report.findings += [
                f"{commit.label}: adds or changes {test} outside a test(...) commit"
                for test in sorted(tests.ids())
            ]
            report.findings += [
                f"{commit.label}: removes {test} outside a test(...) commit"
                for test in tests.removed
            ]
            continue
        checked += 1
        if not commit.ids:
            report.findings.append(f"{commit.short} test: no requirement id in the scope")
            continue
        if not check_test_commit(repo, commit, tests, pytest_cmd, env, timeout, report):
            continue
        for requirement in commit.ids:
            if PHASE.match(requirement):
                continue
            implemented = any(
                later.kind in IMPLEMENTATION
                and requirement in later.ids
                and later.sha != commit.sha
                and succeeds(repo, "merge-base", "--is-ancestor", commit.sha, later.sha)
                for later in history
            )
            if not implemented:
                report.findings.append(
                    f"{commit.label}: no later feat, fix, build or ci commit for {requirement}"
                )
    return checked, report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description="Each test(...) commit fails before its implementation"
    )
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--pytest-cmd", default="uv run --frozen python -m pytest")
    parser.add_argument("--timeout", type=float, default=1800, help="seconds per test run")
    args = parser.parse_args(argv)
    repo = Path.cwd()
    try:
        checked, report = check(
            repo, args.base, args.head, shlex.split(args.pytest_cmd), args.timeout
        )
    except UsageError as error:
        print(f"red_first: {error}", file=sys.stderr)
        return 2
    for line in [*report.notes, *report.findings]:
        print(line)
    if report.findings:
        return 1
    print(f"red-first OK: {checked} test commit{'' if checked == 1 else 's'} checked")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
