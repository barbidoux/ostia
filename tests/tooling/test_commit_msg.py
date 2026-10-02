"""The commit-msg hook enforces the commit message discipline of AGENTS.md."""

import sys
from pathlib import Path

import pytest

from tooling_support import REPO, run

HOOK = str(REPO / "tools" / "ci" / "commit_msg.py")

ACCEPTED = [
    "test(FR-06): too deep archives are unscannable",
    "feat(NFR-09): forbid unsafe code in the workspace",
    "contract(CTR-03, FR-06): engine identity in every response",
    "fix(WP-1.2): reject a policy with an unknown key",
    "refactor: rename the frame reader",
    "chore: rails kit",
    "docs: dev setup",
    "build: pin the toolchain",
    "ci: run just check",
    "perf: avoid a copy",
    "feat: x\n\nBody line.\n\nCo-Authored-By: Someone <someone@example.org>\n",
]

REJECTED = [
    "Add stuff",
    "feat: ",
    "feat:missing space",
    "feature(FR-06): wrong type",
    "Feat: capitalised type",
    "feat(FR_06): underscore in scope",
    "feat(FR-06) missing colon",
    "feat(): empty scope",
    "feat:   ",
    "feat( ): blank scope",
    "feat(, FR-06): scope starting with a separator",
    "",
    "# only a comment\n",
]


def check(tmp_path: Path, message: str) -> tuple[int, str]:
    path = tmp_path / "COMMIT_EDITMSG"
    path.write_text(message)
    result = run([sys.executable, HOOK, str(path)], cwd=REPO)
    return result.returncode, result.stderr


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("message", ACCEPTED)
def test_conventional_message_is_accepted(tmp_path: Path, message: str) -> None:
    code, stderr = check(tmp_path, message)
    assert code == 0, stderr


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("message", REJECTED)
def test_other_message_is_rejected(tmp_path: Path, message: str) -> None:
    code, stderr = check(tmp_path, message)
    assert code == 1
    assert "invalid commit message" in stderr


@pytest.mark.req("TOOLING")
def test_git_comment_lines_after_the_subject_are_ignored(tmp_path: Path) -> None:
    message = "docs: readme\n# Please enter the commit message for your changes.\n"
    code, stderr = check(tmp_path, message)
    assert code == 0, stderr


@pytest.mark.req("TOOLING")
def test_missing_message_file_is_rejected(tmp_path: Path) -> None:
    result = run([sys.executable, HOOK, str(tmp_path / "absent")], cwd=REPO)
    assert result.returncode == 1
    assert "invalid commit message" in result.stderr
