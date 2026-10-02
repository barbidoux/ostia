# Ostia task runner. The rails recipes live in tools/kit/rails.just (owner-managed);
# WP-0.1 adds the project recipes below. Keep the import line.
set shell := ["bash", "-euo", "pipefail", "-c"]

import 'tools/kit/rails.just'

# Python test directories of the fast suite (acceptance runs only through test-acceptance and gate)
py_test_dirs := "tests/tooling"

default:
    @just --list

# Everything that must be green before a work package is done (trace from WP-0.4, audit from WP-0.8)
check: fmt-check lint types test verify-locks rails-verify kit-test

# Format Rust and Python sources in place
fmt:
    cargo fmt --all
    uv run ruff format

# Formatting is clean (no change)
fmt-check:
    cargo fmt --all --check
    uv run ruff format --check

# Lints: clippy with warnings denied, ruff
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings
    uv run ruff check

# Types: mypy --strict (configured in pyproject.toml)
types:
    uv run mypy

# Fast suite (no bench tests); fails if any test was skipped
test: test-rust test-py
    python3 tools/ci/junit_no_skips.py target/nextest/ci/junit.xml target/junit/pytest.xml

# Rust tests with nextest (JUnit in target/nextest/ci/junit.xml); an empty suite passes
test-rust *args:
    cargo nextest run --workspace --locked --profile ci --no-tests=pass {{args}}

# Python tests, bench excluded (JUnit in target/junit/pytest.xml); an empty suite passes
test-py *args:
    mkdir -p target/junit
    uv run python tools/ci/run_pytest.py {{py_test_dirs}} -- -m "not bench" --junitxml=target/junit/pytest.xml {{args}}

# Informational run of an acceptance directory (hardened, same isolation as the gate)
test-acceptance dir *args:
    just acceptance-dry-run {{dir}} {{args}}

# Everything, bench tests included: Debian bench only (P4, P5)
test-bench:
    cargo nextest run --workspace --locked --profile ci --all-features --no-tests=pass
    uv run python tools/ci/run_pytest.py {{py_test_dirs}} --

# Coverage reports for Rust (cargo-llvm-cov) and Python (pytest-cov); thresholds come with the owner
coverage:
    cargo llvm-cov nextest --workspace --locked --no-tests=pass --html
    uv run python tools/ci/run_pytest.py {{py_test_dirs}} -- -m "not bench" --cov=tools --cov-report=term --cov-report=html:target/coverage/python

# Traceability matrix: not built yet (WP-0.4); fails rather than pretending
trace:
    @echo "trace: not implemented until WP-0.4" >&2
    @exit 1

# Supply-chain audit: not built yet (WP-0.8); fails rather than pretending
audit:
    @echo "audit: not implemented until WP-0.8" >&2
    @exit 1
