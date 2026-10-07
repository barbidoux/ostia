"""A locked acceptance directory cannot change without its manifest (WP-0.9, spec §18).

The kit's lock tool (`tools/lock/ostia_lock.py`, owner-managed) is run for real in a throwaway git
repository built at test time: it locks a directory there, then `verify` must fail when a locked file is
changed, added or removed, and pass again once the file is restored. `just check` (verify-locks) and the
rails workflow run the same `verify`. No LOCK.sha256 fixture is ever committed.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

LOCK_TOOL = REPO / "tools" / "lock" / "ostia_lock.py"
LOCKED_TEST = '''"""Seeded acceptance test."""


def test_answer() -> None:
    assert 6 * 7 == 42
'''


def git(root: Path, *args: str) -> None:
    identity = ["-c", "user.name=Ostia Tests", "-c", "user.email=tests@ostia.invalid"]
    result = run(["git", *identity, *args], cwd=root)
    assert result.returncode == 0, result.stderr


def lock_tool(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    # The tool refuses a CLAUDE_PROJECT_DIR or OSTIA_REPO_ROOT that is not the repository it runs in.
    env = {
        k: v for k, v in os.environ.items() if k not in ("CLAUDE_PROJECT_DIR", "OSTIA_REPO_ROOT")
    }
    return run([sys.executable, str(LOCK_TOOL), *args], cwd=root, env=env)


@pytest.fixture
def locked(tmp_path: Path) -> Path:
    """A git repository whose tests/acceptance/p9 is locked; returns the directory."""
    root = tmp_path / "repo"
    directory = root / "tests" / "acceptance" / "p9"
    directory.mkdir(parents=True)
    (directory / "test_answer.py").write_text(LOCKED_TEST)
    (directory / "README.md").write_text("# p9\n")
    git(root, "init", "-q", "-b", "main")
    git(root, "add", ".")
    git(root, "commit", "-q", "-m", "test(P9): seeded acceptance tests")
    return directory


def lock(directory: Path) -> None:
    result = lock_tool(directory.parents[2], "lock", "p9")
    assert result.returncode == 0, result.stdout + result.stderr
    assert (directory / "LOCK.sha256").is_file()


def verify(directory: Path) -> subprocess.CompletedProcess[str]:
    return lock_tool(directory.parents[2], "verify")


@pytest.mark.req("TOOLING")
def test_freshly_locked_directory_verifies(locked: Path) -> None:
    lock(locked)
    result = verify(locked)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_changing_a_locked_test_fails_verify(locked: Path) -> None:
    lock(locked)
    (locked / "test_answer.py").write_text(LOCKED_TEST.replace("6 * 7 == 42", "True"))
    result = verify(locked)
    assert result.returncode == 1
    assert "LOCK VIOLATION  p9: locked file changed: test_answer.py" in result.stdout


@pytest.mark.req("TOOLING")
def test_adding_a_file_to_a_locked_directory_fails_verify(locked: Path) -> None:
    lock(locked)
    (locked / "helpers.py").write_text("ANSWER = 42\n")
    result = verify(locked)
    assert result.returncode == 1
    assert "LOCK VIOLATION  p9: file added after lock: helpers.py" in result.stdout


@pytest.mark.req("TOOLING")
def test_removing_a_locked_file_fails_verify(locked: Path) -> None:
    lock(locked)
    (locked / "test_answer.py").unlink()
    result = verify(locked)
    assert result.returncode == 1
    assert "LOCK VIOLATION  p9: locked file removed: test_answer.py" in result.stdout


@pytest.mark.req("TOOLING")
def test_restoring_the_locked_file_verifies_again(locked: Path) -> None:
    lock(locked)
    test = locked / "test_answer.py"
    test.write_text(LOCKED_TEST.replace("6 * 7 == 42", "True"))
    assert verify(locked).returncode != 0
    test.write_text(LOCKED_TEST)
    result = verify(locked)
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.req("TOOLING")
def test_ci_runs_the_lock_verification() -> None:
    # `just check` (the ci job) and the owner's rails workflow both run `verify`.
    check = run(["just", "--show", "check"], cwd=REPO)
    assert check.returncode == 0, check.stderr
    header = [line for line in check.stdout.splitlines() if line.startswith("check:")]
    assert len(header) == 1 and "verify-locks" in header[0].split()
    verify_recipe = run(["just", "--show", "verify-locks"], cwd=REPO)
    assert verify_recipe.returncode == 0, verify_recipe.stderr
    assert "tools/lock/ostia_lock.py verify" in verify_recipe.stdout
    rails = (REPO / ".github" / "workflows" / "rails.yml").read_text()
    assert "python tools/lock/ostia_lock.py verify" in rails


@pytest.mark.req("TOOLING")
def test_no_lock_manifest_is_committed_outside_tests_acceptance() -> None:
    tracked = run(["git", "ls-files", "*LOCK.sha256"], cwd=REPO)
    assert tracked.returncode == 0, tracked.stderr
    stray = [p for p in tracked.stdout.split() if not p.startswith("tests/acceptance/")]
    assert stray == []
