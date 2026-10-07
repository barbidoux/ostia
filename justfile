# Ostia task runner. The rails recipes live in tools/kit/rails.just (owner-managed);
# WP-0.1 adds the project recipes below. Keep the import line.
set shell := ["bash", "-euo", "pipefail", "-c"]

import 'tools/kit/rails.just'

# Python test directories of the fast suite (acceptance runs only through test-acceptance and gate)
py_test_dirs := "tests/tooling workers-py/common/tests"

default:
    @just --list

# Everything that must be green before a work package is done
check: fmt-check lint types test registry-check trace audit verify-locks rails-verify kit-test

# Regenerate the committed Python code of proto/ostia/engine/v1/engine.proto (Rust regenerates at build)
proto:
    uv run python tools/contracts/gen_python.py

# Rewrite the golden vectors in proto/testdata (written once: changing one is a contract change)
vectors:
    uv run python tools/contracts/gen_vectors.py

# Regenerate requirements.yaml from docs/spec.md and docs/plan.md
registry:
    uv run python tools/traceability/registry.py generate

# requirements.yaml is valid and up to date with the specification and the plan
registry-check:
    uv run python tools/traceability/registry.py check

# Format Rust and Python sources in place
fmt:
    cargo fmt --all
    uv run ruff format

# Formatting is clean (no change)
fmt-check:
    cargo fmt --all --check
    cargo fmt --manifest-path fuzz/Cargo.toml --check
    uv run ruff format --check

# Lints: clippy with warnings denied, ruff
lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --features fuzzing_selftest --locked -- -D warnings
    uv run ruff check

# Types: mypy --strict (configured in pyproject.toml)
types:
    uv run mypy

# Fast suite (no bench tests); fails if any test was skipped
test: test-rust test-py
    python3 tools/ci/junit_no_skips.py target/nextest/ci/junit.xml target/junit/pytest.xml

# Rust tests with nextest (JUnit in target/nextest/ci/junit.xml); an empty suite passes.
# nextest leaves #[ignore] tests out of its JUnit report, so the test list is checked too.
test-rust *args:
    rm -f target/nextest/ci/junit.xml target/nextest/list.json
    uv run python tools/traceability/matrix.py --write-fingerprint target/nextest/ci/sources.sha256
    cargo nextest run --workspace --locked --profile ci --no-tests=pass {{args}}
    mkdir -p target/nextest
    cargo nextest list --workspace --locked --message-format json > target/nextest/list.json
    python3 tools/ci/nextest_no_ignored.py target/nextest/list.json

# Python tests, bench excluded (JUnit in target/junit/pytest.xml); an empty suite passes
test-py *args:
    mkdir -p target/junit
    rm -f target/junit/pytest.xml
    uv run python tools/traceability/matrix.py --write-fingerprint target/junit/sources.sha256
    uv run python tools/ci/run_pytest.py {{py_test_dirs}} -- -m "not bench" --junitxml=target/junit/pytest.xml {{args}}

# Fuzz suite (pinned nightly + cargo-fuzz, NFR-06): the frame decoder target runs FUZZ_SECONDS (default 60),
# a planted crash must be caught, regression inputs must not crash (JUnit in target/junit/fuzz.xml)
test-fuzz *args:
    mkdir -p target/junit
    rm -f target/junit/fuzz.xml
    uv run python tools/ci/run_pytest.py tests/fuzz -- --junitxml=target/junit/fuzz.xml {{args}}
    python3 tools/ci/junit_no_skips.py target/junit/fuzz.xml

# Long local fuzzing of the frame decoder, growing fuzz/corpus/frame_decoder (git-ignored): `just fuzz 3600`
fuzz seconds="1800":
    mkdir -p fuzz/corpus/frame_decoder
    cargo "+$(sed -n 's/^NIGHTLY_TOOLCHAIN=//p' tools/dev/versions.env)" fuzz run frame_decoder fuzz/corpus/frame_decoder proto/testdata -- -max_total_time={{seconds}} -timeout=5

# Red-first check of this branch's commits (spec §18): each test(<ID>) commit fails at its commit, then a
# feat, fix, build or ci commit implements the id (CI runs it on every pull request)
red-first:
    python3 tools/ci/red_first.py --base origin/main

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
    uv run python tools/ci/run_pytest.py {{py_test_dirs}} -- -m "not bench" --cov=tools/ci --cov-report=term --cov-report=html:target/coverage/python

# Traceability matrix from the reports of `just test` (target/traceability.{json,md});
# `just trace --gate P1` also fails on a MUST of that phase without a passing test
trace *args:
    uv run python tools/traceability/matrix.py {{ args }}

# Supply-chain gates (UPD-07, NFR-11): cargo-deny (licences, sources, advisories, bans) and cargo-audit on
# both workspaces; Python pins and hashes, pip-audit on the hash-pinned export of uv.lock, Python licences
# against the deny.toml allowlist; CycloneDX SBOMs. Fetches the RustSec database and queries PyPI (Q-27).
audit:
    cargo deny --workspace --locked --config deny.toml check
    cargo deny --manifest-path fuzz/Cargo.toml --locked --config deny.toml check
    cargo audit --deny warnings
    cargo audit --deny warnings --file fuzz/Cargo.lock
    uv lock --locked
    mkdir -p target/supply
    uv export --quiet --frozen --all-groups --all-extras --no-emit-project --format requirements-txt --output-file target/supply/requirements.txt
    python3 tools/supply/check_pins.py --pyproject pyproject.toml --requirements target/supply/requirements.txt --lock uv.lock
    uv run pip-audit --strict --require-hashes --disable-pip --requirement target/supply/requirements.txt
    uv run cyclonedx-py environment --pyproject pyproject.toml --output-file target/supply/python-environment.cdx.json .venv
    uv run python tools/supply/python_licences.py --sbom target/supply/python-environment.cdx.json
    just sbom

# CycloneDX SBOMs of the shipped Rust crates and of the Python runtime dependencies (target/sbom)
sbom:
    uv run python tools/supply/sbom.py --out target/sbom
