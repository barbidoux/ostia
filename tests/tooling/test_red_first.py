"""Red-first check of a pull request's commits (WP-0.9, spec §18 cycle rule 3).

`tools/ci/red_first.py --base <ref>` walks the commits of `<ref>..HEAD` (merges left out). For every
`test(<ID>)` commit it checks the commit out in a worktree and runs the tests that commit adds or changes:
each must fail there, for a valid reason (an assertion or a stub, not a collection or compile error),
unless the commit lists it on a `Pins: <test ids>` line (a regression guard that pins correct behaviour,
owner decision 2026-10-07). Each id of a `test(<ID>)` commit with non-pinned tests needs a later commit
`feat`, `fix`, `build` or `ci` for the same id. Phase scopes (`test(P1)`, the lock WP) need none, and
acceptance tests are left to the lock tool.

Each test builds a throwaway git repository. Python tests there run with this interpreter's pytest
(`--pytest-cmd`); Rust tests with cargo-nextest.
"""

import os
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

RED_FIRST = REPO / "tools" / "ci" / "red_first.py"
PYTEST_CMD = shlex.join([sys.executable, "-m", "pytest"])

FEATURE_STUB = "def answer() -> int:\n    raise NotImplementedError\n"
FEATURE_DONE = "def answer() -> int:\n    return 42\n"
TEST_ANSWER = (
    "from feature import answer\n\n\ndef test_answer() -> None:\n    assert answer() == 42\n"
)
TEST_ALWAYS_TRUE = "def test_new() -> None:\n    assert True\n"


class Repo:
    """A throwaway git repository with one commit per call to `commit`."""

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir()
        self.git("init", "-q", "-b", "main")
        self.commit("chore: start", {"README.md": "sample\n", "feature.py": FEATURE_STUB})
        self.base = self.head()

    def git(self, *args: str) -> str:
        identity = ["-c", "user.name=Ostia Tests", "-c", "user.email=tests@ostia.invalid"]
        result = run(["git", *identity, *args], cwd=self.root)
        assert result.returncode == 0, result.stderr
        return result.stdout

    def commit(self, message: str, files: dict[str, str | None]) -> str:
        for name, text in files.items():
            path = self.root / name
            if text is None:
                path.unlink()
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text)
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", message)
        return self.head()

    def head(self) -> str:
        return self.git("rev-parse", "HEAD").strip()

    def short(self, sha: str) -> str:
        return sha[:7]


def red_first(repo: Repo, *extra: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "CARGO_TERM_COLOR": "never"}
    cmd = [sys.executable, str(RED_FIRST), "--base", repo.base, "--pytest-cmd", PYTEST_CMD, *extra]
    return run(cmd, cwd=repo.root, env=env)


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path / "repo")


# --- the usual cycle ------------------------------------------------------------------------------


@pytest.mark.req("TOOLING")
def test_red_test_then_feat_passes(repo: Repo) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "red-first OK: 1 test commit checked" in result.stdout


@pytest.mark.req("TOOLING")
def test_nothing_to_check_passes(repo: Repo) -> None:
    repo.commit("docs: readme", {"README.md": "more\n"})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "red-first OK: 0 test commits checked" in result.stdout


@pytest.mark.req("TOOLING")
def test_test_passing_before_its_implementation_fails(repo: Repo) -> None:
    sha = repo.commit("test(FR-01): vacuous", {"tests/test_feature.py": TEST_ALWAYS_TRUE})
    repo.commit("feat(FR-01): nothing", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    expected = f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_new passes before its implementation"
    assert expected in result.stdout


@pytest.mark.req("TOOLING")
def test_pinned_test_may_pass(repo: Repo) -> None:
    repo.commit(
        "test(FR-01): pin the readme\n\nPins: tests/test_feature.py::test_new",
        {"tests/test_feature.py": TEST_ALWAYS_TRUE},
    )
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "red-first OK: 1 test commit checked" in result.stdout


@pytest.mark.req("TOOLING")
def test_every_exemption_is_printed(repo: Repo) -> None:
    # The CI log shows each pinned test, so an exemption is visible without reading every message.
    sha = repo.commit(
        "test(FR-01): pin the readme\n\nPins: tests/test_feature.py::test_new",
        {"tests/test_feature.py": TEST_ALWAYS_TRUE},
    )
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"pinned {repo.short(sha)}: tests/test_feature.py::test_new" in result.stdout


@pytest.mark.req("TOOLING")
def test_a_pin_may_name_one_parametrized_case(repo: Repo) -> None:
    cases = (
        "import pytest\n\nfrom feature import answer\n\n\n"
        "@pytest.mark.parametrize('value', [42, 7])\n"
        "def test_cases(value: int) -> None:\n"
        "    assert value == 7 or answer() == value\n"
    )
    sha = repo.commit(
        "test(FR-01): cases\n\nPins: tests/test_feature.py::test_cases[7], other::id",
        {"tests/test_feature.py": cases},
    )
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    # Only the unknown pin is a finding: the pinned case may pass, the other case is red.
    short = repo.short(sha)
    assert result.returncode == 1
    assert result.stdout.splitlines() == [
        f"pinned {short}: tests/test_feature.py::test_cases[7]",
        f"{short} test(FR-01): Pins names other::id, which this commit does not add or change",
    ]


@pytest.mark.req("TOOLING")
def test_pins_only_apply_to_the_tests_they_name(repo: Repo) -> None:
    both = TEST_ALWAYS_TRUE + "\n\ndef test_other() -> None:\n    assert True\n"
    sha = repo.commit(
        "test(FR-01): two guards\n\nPins: tests/test_feature.py::test_new",
        {"tests/test_feature.py": both},
    )
    repo.commit("feat(FR-01): nothing", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_other passes" in result.stdout
    )
    assert "test_new passes" not in result.stdout


@pytest.mark.req("TOOLING")
def test_pins_naming_a_test_the_commit_does_not_touch_fail(repo: Repo) -> None:
    sha = repo.commit(
        "test(FR-01): the answer\n\nPins: tests/test_feature.py::test_elsewhere",
        {"tests/test_feature.py": TEST_ANSWER},
    )
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): Pins names tests/test_feature.py::test_elsewhere, "
        "which this commit does not add or change"
    ) in result.stdout


# --- the implementation commit --------------------------------------------------------------------


@pytest.mark.req("TOOLING")
def test_red_test_without_implementation_fails(repo: Repo) -> None:
    sha = repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("docs(FR-01): explain", {"README.md": "answer\n"})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): no later feat, fix, build or ci commit for FR-01"
    ) in result.stdout


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("kind", ["feat", "fix", "build", "ci"])
def test_implementation_types_are_accepted(repo: Repo, kind: str) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit(f"{kind}(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("kind", ["docs", "refactor", "chore", "test", "perf", "contract"])
def test_other_types_are_not_an_implementation(repo: Repo, kind: str) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit(f"{kind}(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert "no later feat, fix, build or ci commit for FR-01" in result.stdout


@pytest.mark.req("TOOLING")
def test_implementation_before_the_test_does_not_count(repo: Repo) -> None:
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE.replace("42", "41")})
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    result = red_first(repo)
    assert result.returncode == 1
    assert "no later feat, fix, build or ci commit for FR-01" in result.stdout


@pytest.mark.req("TOOLING")
def test_every_id_of_the_scope_needs_its_implementation(repo: Repo) -> None:
    repo.commit("test(FR-01, FR-02): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert "no later feat, fix, build or ci commit for FR-02" in result.stdout
    assert "commit for FR-01" not in result.stdout


@pytest.mark.req("TOOLING")
def test_implementation_scope_may_hold_several_ids(repo: Repo) -> None:
    repo.commit("test(FR-01,FR-02): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("feat(FR-02,FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_test_commit_without_requirement_id_fails(repo: Repo) -> None:
    sha = repo.commit("test: the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("feat: the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert f"{repo.short(sha)} test: no requirement id in the scope" in result.stdout


@pytest.mark.req("TOOLING")
def test_phase_lock_commit_needs_no_implementation(repo: Repo) -> None:
    acceptance = "def test_kiosk() -> None:\n    raise AssertionError('not built yet')\n"
    repo.commit("test(P1): acceptance tests", {"tests/acceptance/p1/test_kiosk.py": acceptance})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr


# --- what counts as a valid red -------------------------------------------------------------------


@pytest.mark.req("TOOLING")
def test_collection_error_is_not_a_valid_red(repo: Repo) -> None:
    broken = (
        "from feature import missing_name\n\n\ndef test_x() -> None:\n    assert missing_name()\n"
    )
    sha = repo.commit("test(FR-01): broken import", {"tests/test_feature.py": broken})
    repo.commit(
        "feat(FR-01): add it",
        {"feature.py": FEATURE_DONE + "\n\ndef missing_name() -> bool:\n    return True\n"},
    )
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): the tests do not collect "
        "(an import or syntax error is not a valid red)"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_skipped_test_is_not_red(repo: Repo) -> None:
    skipping = "import pytest\n\n\ndef test_x() -> None:\n    pytest." + "skip('later')\n"
    sha = repo.commit("test(FR-01): skipped", {"tests/test_feature.py": skipping})
    repo.commit("feat(FR-01): nothing", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_x was skipped" in result.stdout
    )


@pytest.mark.req("TOOLING")
def test_every_parametrized_case_must_fail(repo: Repo) -> None:
    cases = (
        "import pytest\n\nfrom feature import answer\n\n\n"
        "@pytest.mark.parametrize('value', [42, 7])\n"
        "def test_cases(value: int) -> None:\n"
        "    assert value == 7 or answer() == value\n"
    )
    sha = repo.commit("test(FR-01): cases", {"tests/test_feature.py": cases})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_cases[7] passes"
        in result.stdout
    )
    assert "test_cases[42]" not in result.stdout


@pytest.mark.req("TOOLING")
def test_test_class_methods_are_checked(repo: Repo) -> None:
    in_class = "class TestAnswer:\n    def test_value(self) -> None:\n        assert True\n"
    sha = repo.commit("test(FR-01): class", {"tests/test_feature.py": in_class})
    repo.commit("feat(FR-01): nothing", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::TestAnswer::test_value passes"
        in result.stdout
    )


# --- which tests a commit adds or changes ---------------------------------------------------------


@pytest.mark.req("TOOLING")
def test_changed_existing_test_must_fail_too(repo: Repo) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    loosened = TEST_ANSWER.replace("== 42", "> 0")
    sha = repo.commit("test(FR-01): any positive answer", {"tests/test_feature.py": loosened})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_answer passes" in result.stdout
    )


@pytest.mark.req("TOOLING")
def test_unchanged_tests_of_the_file_are_not_run(repo: Repo) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    more = TEST_ANSWER + "\n\ndef test_double() -> None:\n    assert answer() * 2 == 85\n"
    repo.commit("test(FR-02): the double", {"tests/test_feature.py": more})
    repo.commit("feat(FR-02): nothing to do", {"README.md": "double\n"})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "test_answer" not in result.stdout


@pytest.mark.req("TOOLING")
def test_changed_constant_marks_the_tests_using_it(repo: Repo) -> None:
    with_constant = (
        "from feature import answer\n\nEXPECTED = 42\n\n\n"
        "def test_answer() -> None:\n    assert answer() == EXPECTED\n\n\n"
        "def test_other() -> None:\n    assert answer() != 0\n"
    )
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": with_constant})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    sha = repo.commit(
        "test(FR-01): any answer",
        {"tests/test_feature.py": with_constant.replace("EXPECTED = 42", "EXPECTED = answer()")},
    )
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_answer passes" in result.stdout
    )
    assert "test_other" not in result.stdout


@pytest.mark.req("TOOLING")
def test_changed_helper_or_fixture_marks_the_tests_using_it(repo: Repo) -> None:
    with_fixture = (
        "import pytest\n\nfrom feature import answer\n\n\n"
        "def expected() -> int:\n    return 42\n\n\n"
        "@pytest.fixture\ndef target() -> int:\n    return expected()\n\n\n"
        "def test_answer(target: int) -> None:\n    assert answer() == target\n"
    )
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": with_fixture})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    sha = repo.commit(
        "test(FR-01): helper changed",
        {"tests/test_feature.py": with_fixture.replace("return 42", "return answer()")},
    )
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_answer passes" in result.stdout
    )


CASES_42 = (
    "import pytest\n\nfrom feature import answer\n\n\n"
    "@pytest.mark.parametrize('value', [42])\n"
    "def test_cases(value: int) -> None:\n"
    "    assert answer() == value or value > 100\n"
)


@pytest.mark.req("TOOLING")
def test_only_the_rows_a_commit_adds_to_a_parametrize_list_must_fail(repo: Repo) -> None:
    repo.commit("test(FR-01): cases", {"tests/test_feature.py": CASES_42})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    # The old row (42) still passes; the new one (85) fails until a feat changes nothing here.
    repo.commit(
        "test(FR-02): one more row", {"tests/test_feature.py": CASES_42.replace("[42]", "[42, 85]")}
    )
    repo.commit("feat(FR-02): accept it", {"README.md": "85\n"})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_added_parametrize_row_that_passes_is_reported_alone(repo: Repo) -> None:
    repo.commit("test(FR-01): cases", {"tests/test_feature.py": CASES_42})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    sha = repo.commit(
        "test(FR-02): a row that passes",
        {"tests/test_feature.py": CASES_42.replace("[42]", "[42, 101]")},
    )
    repo.commit("feat(FR-02): nothing", {"README.md": "101\n"})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-02): tests/test_feature.py::test_cases[101] passes"
        in result.stdout
    )
    assert "test_cases[42]" not in result.stdout


@pytest.mark.req("TOOLING")
def test_table_grown_behind_an_unchanged_helper_does_not_mark_its_users(repo: Repo) -> None:
    table = (
        "from feature import answer\n\nKNOWN = {'answer': 42}\n\n\n"
        "def lookup(name: str) -> int:\n    return KNOWN[name]\n\n\n"
        "def test_lookup() -> None:\n    assert answer() == lookup('answer')\n"
    )
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": table})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    grown = table.replace("{'answer': 42}", "{'answer': 42, 'double': 84}") + (
        "\n\ndef test_double() -> None:\n    assert answer() * 2 == KNOWN['double'] + 1\n"
    )
    repo.commit("test(FR-02): the double", {"tests/test_feature.py": grown})
    repo.commit("feat(FR-02): nothing yet", {"README.md": "double\n"})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "test_lookup" not in result.stdout


@pytest.mark.req("TOOLING")
def test_test_commit_that_adds_or_changes_no_test_fails(repo: Repo) -> None:
    sha = repo.commit("test(FR-01): nothing really", {"tests/helpers.py": "VALUE = 1\n"})
    repo.commit("feat(FR-01): nothing", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert f"{repo.short(sha)} test(FR-01): adds or changes no test" in result.stdout


@pytest.mark.req("TOOLING")
def test_commits_before_the_base_and_merges_are_ignored(repo: Repo) -> None:
    repo.commit("test(FR-09): vacuous, before the base", {"tests/test_old.py": TEST_ALWAYS_TRUE})
    repo.base = repo.head()
    repo.git("switch", "-q", "-c", "side")
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.git("switch", "-q", "main")
    repo.commit("docs: main moves", {"README.md": "main\n"})
    repo.git("merge", "-q", "--no-edit", "side")
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "red-first OK: 1 test commit checked" in result.stdout
    assert "FR-09" not in result.stdout


@pytest.mark.req("TOOLING")
def test_worktrees_are_removed_afterwards(repo: Repo) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    assert red_first(repo).returncode == 0
    assert repo.git("worktree", "list").count("\n") == 1


@pytest.mark.req("TOOLING")
def test_bad_base_is_a_usage_error(repo: Repo) -> None:
    result = run(
        [sys.executable, str(RED_FIRST), "--base", "no-such-ref", "--pytest-cmd", PYTEST_CMD],
        cwd=repo.root,
    )
    assert result.returncode == 2
    assert "red_first: unknown base no-such-ref" in result.stderr


# --- review findings: the commit convention and tests outside test(...) commits -------------------


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "subject",
    ["Test(FR-01): vacuous", "tests(FR-01): vacuous", "test(FR-01) : vacuous", "wip"],
)
def test_subject_outside_the_convention_fails(repo: Repo, subject: str) -> None:
    sha = repo.commit(subject, {"tests/test_feature.py": TEST_ALWAYS_TRUE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} subject does not follow the commit convention: {subject!r}"
    ) in result.stdout


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("kind", ["feat", "fix", "refactor", "chore", "docs", "build", "ci"])
def test_tests_added_outside_a_test_commit_fail(repo: Repo, kind: str) -> None:
    # Owner decision 2026-10-07: only test(...) commits add or change tests.
    sha = repo.commit(f"{kind}(FR-01): sneak a test", {"tests/test_feature.py": TEST_ALWAYS_TRUE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} {kind}(FR-01): adds or changes tests/test_feature.py::test_new "
        "outside a test(...) commit"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_feat_that_loosens_the_red_test_fails(repo: Repo) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    sha = repo.commit(
        "feat(FR-01): the answer",
        {"tests/test_feature.py": TEST_ANSWER.replace("assert answer() == 42", "assert True")},
    )
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} feat(FR-01): adds or changes tests/test_feature.py::test_answer "
        "outside a test(...) commit"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_tests_removed_outside_a_test_commit_fail(repo: Repo) -> None:
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    sha = repo.commit("feat(FR-01): drop the red test", {"tests/test_feature.py": None})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} feat(FR-01): removes tests/test_feature.py::test_answer "
        "outside a test(...) commit"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_implementation_on_a_parallel_branch_does_not_count(repo: Repo) -> None:
    # "Later" means a descendant of the test commit, not a commit listed after it.
    repo.git("switch", "-q", "-c", "side")
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    repo.git("switch", "-q", "main")
    repo.commit("test(FR-01): the answer", {"tests/test_feature.py": TEST_ANSWER})
    repo.git("merge", "-q", "--no-edit", "side")
    result = red_first(repo)
    assert result.returncode == 1
    assert "no later feat, fix, build or ci commit for FR-01" in result.stdout


@pytest.mark.req("TOOLING")
def test_phase_commit_that_touches_more_than_acceptance_tests_needs_a_test(repo: Repo) -> None:
    sha = repo.commit("test(P1): helpers", {"tests/conftest.py": "VALUE = 1\n"})
    result = red_first(repo)
    assert result.returncode == 1
    assert f"{repo.short(sha)} test(P1): adds or changes no test" in result.stdout


# --- review findings: what counts as a valid red --------------------------------------------------


@pytest.mark.req("TOOLING")
def test_typo_in_the_test_body_is_not_a_valid_red(repo: Repo) -> None:
    typo = "from feature import answer\n\n\ndef test_answer() -> None:\n    assert answr() == 42\n"
    sha = repo.commit("test(FR-01): typo", {"tests/test_feature.py": typo})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_answer fails with NameError "
        "(a typo or a missing import is not a valid red)"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_runtime_import_of_a_missing_module_is_not_a_valid_red(repo: Repo) -> None:
    lazy = "def test_answer() -> None:\n    from missing_module import answer\n\n    assert answer() == 42\n"
    sha = repo.commit("test(FR-01): lazy import", {"tests/test_feature.py": lazy})
    repo.commit("feat(FR-01): the module", {"missing_module.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_answer fails with "
        "ModuleNotFoundError (a typo or a missing import is not a valid red)"
    ) in result.stdout


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "fixture",
    [
        "",  # the fixture does not exist
        "import pytest\n\n\n@pytest.fixture\ndef target() -> int:\n    raise RuntimeError('broken')\n\n\n",
    ],
    ids=["missing fixture", "fixture raises"],
)
def test_broken_fixture_is_not_a_valid_red(repo: Repo, fixture: str) -> None:
    test = fixture + "def test_answer(target: int) -> None:\n    assert True\n"
    sha = repo.commit("test(FR-01): broken fixture", {"tests/test_feature.py": test})
    repo.commit("feat(FR-01): nothing", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} test(FR-01): tests/test_feature.py::test_answer errors outside the "
        "test body (a broken fixture is not a valid red)"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_test_that_never_finishes_is_reported(repo: Repo) -> None:
    endless = "import time\n\n\ndef test_answer() -> None:\n    time.sleep(3600)\n"
    sha = repo.commit("test(FR-01): endless", {"tests/test_feature.py": endless})
    repo.commit("feat(FR-01): nothing", {"feature.py": FEATURE_DONE})
    result = red_first(repo, "--timeout", "5")
    assert result.returncode == 1
    assert f"{repo.short(sha)} test(FR-01): the tests did not finish within 5 s" in result.stdout
    assert repo.git("worktree", "list").count("\n") == 1


@pytest.mark.req("TOOLING")
def test_bench_tests_are_listed_not_run(repo: Repo) -> None:
    # Owner decision 2026-10-07: bench tests cannot run in CI; their red evidence comes from the bench.
    bench = (
        "import pytest\n\n\n@pytest.mark.bench\ndef test_on_hardware() -> None:\n    assert True\n"
    )
    sha = repo.commit("test(FR-01): on the bench", {"tests/test_feature.py": bench})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    result = red_first(repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"not checked (bench) {repo.short(sha)}: tests/test_feature.py::test_on_hardware" in (
        result.stdout
    )


@pytest.mark.req("TOOLING")
def test_bench_test_still_needs_its_implementation(repo: Repo) -> None:
    bench = "import pytest\n\npytestmark = pytest.mark.bench\n\n\ndef test_on_hardware() -> None:\n    assert True\n"
    repo.commit("test(FR-01): on the bench", {"tests/test_feature.py": bench})
    result = red_first(repo)
    assert result.returncode == 1
    assert "no later feat, fix, build or ci commit for FR-01" in result.stdout


@pytest.mark.req("TOOLING")
def test_worktrees_are_removed_after_findings(repo: Repo) -> None:
    repo.commit("test(FR-01): cases", {"tests/test_feature.py": CASES_42})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    repo.commit(
        "test(FR-02): a row that passes",
        {"tests/test_feature.py": CASES_42.replace("[42]", "[42, 101]")},
    )
    repo.commit("test(FR-03): vacuous", {"tests/test_other.py": TEST_ALWAYS_TRUE})
    assert red_first(repo).returncode == 1
    assert repo.git("worktree", "list").count("\n") == 1


# --- review findings: which tests a commit changes ------------------------------------------------


@pytest.mark.req("TOOLING")
def test_changed_row_with_an_explicit_id_must_fail(repo: Repo) -> None:
    rows = (
        "import pytest\n\nfrom feature import answer\n\n\n"
        "@pytest.mark.parametrize('value', [pytest.param(42, id='row')])\n"
        "def test_cases(value: int) -> None:\n"
        "    assert answer() == value or value == 0\n"
    )
    repo.commit("test(FR-01): cases", {"tests/test_feature.py": rows})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    sha = repo.commit(
        "test(FR-02): the row now accepts anything",
        {"tests/test_feature.py": rows.replace("param(42,", "param(0,")},
    )
    repo.commit("feat(FR-02): nothing", {"README.md": "0\n"})
    result = red_first(repo)
    assert result.returncode == 1
    assert f"{repo.short(sha)} test(FR-02): tests/test_feature.py::test_cases[row] passes" in (
        result.stdout
    )


@pytest.mark.req("TOOLING")
def test_row_inserted_before_generated_ids_is_the_one_checked(repo: Repo) -> None:
    rows = (
        "import pytest\n\nfrom feature import answer\n\n\n"
        "@pytest.mark.parametrize('case', [{'x': 42}])\n"
        "def test_cases(case: dict[str, int]) -> None:\n"
        "    assert answer() == case['x'] or case['x'] == 0\n"
    )
    repo.commit("test(FR-01): cases", {"tests/test_feature.py": rows})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    sha = repo.commit(
        "test(FR-02): a vacuous row in front",
        {"tests/test_feature.py": rows.replace("[{'x': 42}]", "[{'x': 0}, {'x': 42}]")},
    )
    repo.commit("feat(FR-02): nothing", {"README.md": "0\n"})
    result = red_first(repo)
    assert result.returncode == 1
    assert f"{repo.short(sha)} test(FR-02): tests/test_feature.py::test_cases[case0] passes" in (
        result.stdout
    )
    assert "test_cases[case1]" not in result.stdout


@pytest.mark.req("TOOLING")
def test_rows_added_to_a_module_level_case_table_must_fail(repo: Repo) -> None:
    table = (
        "import pytest\n\nfrom feature import answer\n\nCASES = [42]\n\n\n"
        "@pytest.mark.parametrize('value', CASES)\n"
        "def test_cases(value: int) -> None:\n"
        "    assert answer() == value or value > 100\n"
    )
    repo.commit("test(FR-01): cases", {"tests/test_feature.py": table})
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    sha = repo.commit(
        "test(FR-02): one more row",
        {"tests/test_feature.py": table.replace("CASES = [42]", "CASES = [42, 101]")},
    )
    repo.commit("feat(FR-02): nothing", {"README.md": "101\n"})
    result = red_first(repo)
    assert result.returncode == 1
    assert f"{repo.short(sha)} test(FR-02): tests/test_feature.py::test_cases[101] passes" in (
        result.stdout
    )
    assert "test_cases[42]" not in result.stdout


@pytest.mark.req("TOOLING")
def test_changed_conftest_fixture_marks_the_tests_using_it(repo: Repo) -> None:
    conftest = "import pytest\n\n\n@pytest.fixture\ndef expected() -> int:\n    return 42\n"
    uses = "from feature import answer\n\n\ndef test_a(expected: int) -> None:\n    assert answer() == expected\n"
    repo.commit(
        "test(FR-01): the answer",
        {"tests/conftest.py": conftest, "tests/test_a.py": uses},
    )
    repo.commit("feat(FR-01): the answer", {"feature.py": FEATURE_DONE})
    sha = repo.commit(
        "test(FR-02): any answer and a double",
        {
            "tests/conftest.py": conftest.replace(
                "return 42", "from feature import answer\n\n    return answer()"
            ),
            "tests/test_b.py": "def test_b() -> None:\n    assert False\n",
        },
    )
    repo.commit("feat(FR-02): nothing", {"README.md": "b\n"})
    result = red_first(repo)
    assert result.returncode == 1
    assert f"{repo.short(sha)} test(FR-02): tests/test_a.py::test_a passes" in result.stdout


@pytest.mark.req("TOOLING")
def test_async_methods_of_test_classes_are_seen(repo: Repo) -> None:
    # Seen through the rule on tests outside test(...) commits: running an async test needs a plugin.
    in_class = "class TestAnswer:\n    async def test_value(self) -> None:\n        assert True\n"
    sha = repo.commit("feat(FR-01): sneak an async test", {"tests/test_feature.py": in_class})
    result = red_first(repo)
    assert result.returncode == 1
    assert (
        f"{repo.short(sha)} feat(FR-01): adds or changes tests/test_feature.py::TestAnswer::test_value "
        "outside a test(...) commit"
    ) in result.stdout


# --- Rust tests -----------------------------------------------------------------------------------

CARGO_TOML = '[package]\nname = "sample"\nversion = "0.1.0"\nedition = "2021"\npublish = false\n'
LIB_STUB = "pub fn answer() -> u32 {\n    todo!()\n}\n"
LIB_DONE = "pub fn answer() -> u32 {\n    42\n}\n"
RUST_TEST = "#[test]\nfn answer_is_42() {\n    assert_eq!(sample::answer(), 42);\n}\n"


@pytest.fixture
def rust_repo(tmp_path: Path, tmp_path_factory: pytest.TempPathFactory) -> Repo:
    repo = Repo(tmp_path / "repo")
    repo.commit(
        "chore: crate",
        {
            "Cargo.toml": CARGO_TOML,
            "src/lib.rs": LIB_STUB,
            "rust-toolchain.toml": (REPO / "rust-toolchain.toml").read_text(),
            ".gitignore": "/target\n",
        },
    )
    repo.base = repo.head()
    return repo


@pytest.mark.req("TOOLING")
def test_red_rust_test_then_feat_passes(rust_repo: Repo) -> None:
    rust_repo.commit("test(FR-01): the answer", {"tests/answer.rs": RUST_TEST})
    rust_repo.commit("feat(FR-01): the answer", {"src/lib.rs": LIB_DONE})
    result = red_first(rust_repo)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_rust_test_passing_before_its_implementation_fails(rust_repo: Repo) -> None:
    rust_repo.commit("feat(FR-00): early", {"src/lib.rs": LIB_DONE})
    sha = rust_repo.commit("test(FR-01): the answer", {"tests/answer.rs": RUST_TEST})
    rust_repo.commit("fix(FR-01): nothing", {"README.md": "x\n"})
    result = red_first(rust_repo)
    assert result.returncode == 1
    assert (
        f"{rust_repo.short(sha)} test(FR-01): tests/answer.rs::answer_is_42 passes" in result.stdout
    )


@pytest.mark.req("TOOLING")
def test_rust_test_that_does_not_compile_is_not_a_valid_red(rust_repo: Repo) -> None:
    missing = "#[test]\nfn answer_is_42() {\n    assert_eq!(sample::missing(), 42);\n}\n"
    sha = rust_repo.commit("test(FR-01): the answer", {"tests/answer.rs": missing})
    rust_repo.commit(
        "feat(FR-01): the answer",
        {"src/lib.rs": LIB_DONE + "pub fn missing() -> u32 {\n    42\n}\n"},
    )
    result = red_first(rust_repo)
    assert result.returncode == 1
    assert (
        f"{rust_repo.short(sha)} test(FR-01): the Rust tests do not compile "
        "(commit a stub that returns todo!() with the tests)"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_rust_tests_with_the_same_name_in_two_files_are_told_apart(rust_repo: Repo) -> None:
    red = "#[test]\nfn same_name() {\n    assert_eq!(sample::answer(), 42);\n}\n"
    vacuous = "#[test]\nfn same_name() {\n    assert!(true);\n}\n"
    sha = rust_repo.commit("test(FR-01): two files", {"tests/a.rs": red, "tests/b.rs": vacuous})
    rust_repo.commit("feat(FR-01): the answer", {"src/lib.rs": LIB_DONE})
    result = red_first(rust_repo)
    assert result.returncode == 1
    assert f"{rust_repo.short(sha)} test(FR-01): tests/b.rs::same_name passes" in result.stdout
    assert "tests/a.rs::same_name" not in result.stdout


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    "attribute",
    ["#[test]", "#[tokio::test]", '#[tokio::test(flavor = "multi_thread")]', "#[rstest]"],
)
def test_rust_test_attributes_are_recognised(rust_repo: Repo, attribute: str) -> None:
    # Seen through the rule on tests outside test(...) commits, so nothing needs to compile.
    test = f"{attribute}\nasync fn answer_is_42() {{\n    assert_eq!(sample::answer(), 42);\n}}\n"
    sha = rust_repo.commit("feat(FR-01): sneak a test", {"tests/answer.rs": test})
    result = red_first(rust_repo)
    assert result.returncode == 1
    assert (
        f"{rust_repo.short(sha)} feat(FR-01): adds or changes tests/answer.rs::answer_is_42 "
        "outside a test(...) commit"
    ) in result.stdout


@pytest.mark.req("TOOLING")
def test_rust_test_attribute_in_a_comment_or_string_is_ignored(rust_repo: Repo) -> None:
    text = (
        "// #[test] in a comment\n"
        'const NOTE: &str = "#[test]";\n'
        "pub fn helper() -> char {\n    '}'\n}\n"
    )
    rust_repo.commit("chore(FR-01): a helper", {"src/notes.rs": text})
    result = red_first(rust_repo)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_rust_bench_targets_are_listed_not_run(rust_repo: Repo) -> None:
    rust_repo.commit(
        "chore: bench feature",
        {
            "Cargo.toml": CARGO_TOML
            + '\n[features]\nbench = []\n\n[[test]]\nname = "hw"\npath = "tests/hw.rs"\n'
            'required-features = ["bench"]\n'
        },
    )
    rust_repo.base = rust_repo.head()
    hardware = "#[test]\nfn on_hardware() {\n    assert!(true);\n}\n"
    sha = rust_repo.commit("test(FR-01): on the bench", {"tests/hw.rs": hardware})
    rust_repo.commit("feat(FR-01): the answer", {"src/lib.rs": LIB_DONE})
    result = red_first(rust_repo)
    assert result.returncode == 0, result.stdout + result.stderr
    assert f"not checked (bench) {rust_repo.short(sha)}: tests/hw.rs::on_hardware" in result.stdout


# --- wiring ---------------------------------------------------------------------------------------


@pytest.mark.req("TOOLING")
def test_just_recipe_runs_red_first_against_main() -> None:
    recipe = run(["just", "--show", "red-first"], cwd=REPO)
    assert recipe.returncode == 0, recipe.stderr
    assert "python3 tools/ci/red_first.py --base origin/main" in recipe.stdout
