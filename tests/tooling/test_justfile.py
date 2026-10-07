"""The `just` recipes that CI runs really invoke the gates the other tooling tests prove.

Recipes are read with `just --show <recipe>`, the exact text just would execute.
"""

import shutil

import pytest

from tooling_support import REPO, run

CLIPPY = "cargo clippy --workspace --all-targets --locked -- -D warnings"
# fuzz/ is its own workspace (nightly for fuzzing); it is still formatted and linted with the stable gates.
FUZZ_CLIPPY = (
    "cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --features fuzzing_selftest "
    "--locked -- -D warnings"
)
NO_SKIPS = "python3 tools/ci/junit_no_skips.py target/nextest/ci/junit.xml target/junit/pytest.xml"
GATES = [
    "check",
    "fmt-check",
    "lint",
    "types",
    "test",
    "test-rust",
    "test-py",
    "trace",
    "test-fuzz",
    "audit",
    "sbom",
]


def recipe(name: str) -> list[str]:
    just = shutil.which("just")
    assert just, "just is not on PATH"
    result = run([just, "--show", name], cwd=REPO)
    assert result.returncode == 0, result.stderr
    return [line.strip() for line in result.stdout.splitlines()]


@pytest.mark.req("TOOLING")
def test_check_runs_every_gate() -> None:
    lines = recipe("check")
    expected = (
        "check: fmt-check lint types test registry-check trace audit verify-locks rails-verify "
        "kit-test"
    )
    assert expected in lines


@pytest.mark.req("TOOLING")
def test_trace_recipe_runs_the_matrix() -> None:
    lines = recipe("trace")
    assert "trace *args:" in lines
    assert "uv run python tools/traceability/matrix.py {{ args }}" in lines


@pytest.mark.req("TOOLING")
def test_registry_recipes_generate_and_check_requirements_yaml() -> None:
    assert "uv run python tools/traceability/registry.py generate" in recipe("registry")
    assert "uv run python tools/traceability/registry.py check" in recipe("registry-check")


@pytest.mark.req("TOOLING")
@pytest.mark.parametrize(
    ("name", "expected"),
    [
        (
            "fmt-check",
            [
                "cargo fmt --all --check",
                "cargo fmt --manifest-path fuzz/Cargo.toml --check",
                "uv run ruff format --check",
            ],
        ),
        ("lint", [CLIPPY, FUZZ_CLIPPY, "uv run ruff check"]),
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
@pytest.mark.parametrize(
    ("name", "fingerprint", "suite"),
    [
        ("test-rust", "target/nextest/ci/sources.sha256", "cargo nextest run "),
        ("test-py", "target/junit/sources.sha256", "uv run python tools/ci/run_pytest.py "),
    ],
)
def test_each_suite_fingerprints_its_sources_before_running(
    name: str, fingerprint: str, suite: str
) -> None:
    lines = recipe(name)
    write = f"uv run python tools/traceability/matrix.py --write-fingerprint {fingerprint}"
    assert write in lines
    runs = [i for i, line in enumerate(lines) if line.startswith(suite)]
    assert runs, f"{name}: no line starts with {suite!r}"
    assert lines.index(write) < runs[0]


@pytest.mark.req("TOOLING")
def test_fuzz_suite_writes_junit_and_fails_on_skips() -> None:
    lines = recipe("test-fuzz")
    run = "uv run python tools/ci/run_pytest.py tests/fuzz -- --junitxml=target/junit/fuzz.xml {{ args }}"
    no_skips = "python3 tools/ci/junit_no_skips.py target/junit/fuzz.xml"
    assert "rm -f target/junit/fuzz.xml" in lines
    assert run in lines
    assert no_skips in lines
    assert lines.index(run) < lines.index(no_skips)


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
