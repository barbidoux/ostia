"""The `just` recipes that CI runs really invoke the gates the other tooling tests prove.

Recipes are read with `just --show <recipe>`, the exact text just would execute.
"""

import shutil

import pytest

from tooling_support import REPO, run

CLIPPY = "cargo clippy --workspace --all-targets --locked -- -D warnings"
NO_SKIPS = "python3 tools/ci/junit_no_skips.py target/nextest/ci/junit.xml target/junit/pytest.xml"
GATES = ["check", "fmt-check", "lint", "types", "test", "test-rust", "test-py"]


def recipe(name: str) -> list[str]:
    just = shutil.which("just")
    assert just, "just is not on PATH"
    result = run([just, "--show", name], cwd=REPO)
    assert result.returncode == 0, result.stderr
    return [line.strip() for line in result.stdout.splitlines()]


@pytest.mark.req("TOOLING")
def test_check_runs_every_gate() -> None:
    lines = recipe("check")
    assert "check: fmt-check lint types test verify-locks rails-verify kit-test" in lines


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("fmt-check", ["cargo fmt --all --check", "uv run ruff format --check"]),
        ("lint", [CLIPPY, "uv run ruff check"]),
        ("types", ["uv run mypy"]),
        ("test", ["test: test-rust test-py"]),
        ("test-py", ["rm -f target/junit/pytest.xml"]),
        ("test-rust", ["rm -f target/nextest/ci/junit.xml target/nextest/list.json"]),
    ],
)
def test_gate_recipe_lines(name: str, expected: list[str]) -> None:
    lines = recipe(name)
    for line in expected:
        assert line in lines, f"{name}: missing {line!r}"


@pytest.mark.req("TOOLING")
def test_fast_suite_fails_on_skipped_or_ignored_tests() -> None:
    lines = recipe("test")
    assert NO_SKIPS in lines
    rust = recipe("test-rust")
    assert "cargo nextest run --workspace --locked --profile ci --no-tests=pass {{ args }}" in rust
    assert (
        "cargo nextest list --workspace --locked --message-format json > target/nextest/list.json"
        in rust
    )
    assert "python3 tools/ci/nextest_no_ignored.py target/nextest/list.json" in rust


@pytest.mark.req("TOOLING")
def test_python_suite_excludes_bench_and_writes_junit() -> None:
    lines = recipe("test-py")
    expected = (
        'uv run python tools/ci/run_pytest.py {{ py_test_dirs }} -- -m "not bench" '
        "--junitxml=target/junit/pytest.xml {{ args }}"
    )
    assert expected in lines


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize("name", GATES)
def test_gate_recipes_never_swallow_failures(name: str) -> None:
    text = "\n".join(recipe(name))
    for lever in ("|| true", "|| :", "set +e", "--no-verify"):
        assert lever not in text, f"{name} contains {lever!r}"
