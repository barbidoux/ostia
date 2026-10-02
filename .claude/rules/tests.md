---
paths:
  - "tests/**"
  - "**/tests/**"
  - "**/test_*.py"
  - "**/*_test.py"
  - "**/*.test.ts"
  - "**/*.spec.ts"
  - "**/conftest.py"
  - "fuzz/**"
---

# Rules for tests

## Every test
- Tagged with the requirement it proves: `#[req("FR-06")]` (Rust, from the traceability crate),
  `@pytest.mark.req("FR-06")` (Python), `req("FR-06")` in the TypeScript test title. Several ids allowed.
  Tests with no requirement (helpers, fixture self-tests, tooling) carry `req("TOOLING")`, a reserved id
  that WP-0.3/WP-0.4 add to the registry and to the attribute's validation.
- Named after the behaviour: `too_deep_archive_is_unscannable`, not `test_extract_3`.
- Expected values are literal, taken from the spec or from the fixture definition written in the
  test. Never derive the expected value by calling the code under test.
- Deterministic: fake clock (`tests/fakes`), fixed seeds for `proptest`/`hypothesis`, no sleep-based
  timing, no dependence on test order, temp dirs per test.
- No network. No real malware. EICAR is built at runtime from its two halves, never stored in a file.
- Hardware tests (USB gadgets, real drives, raw devices) are marked, never skipped:
  in Python the `bench` marker; in Rust a separate test target with `required-features = ["bench"]`
  in its `Cargo.toml` `[[test]]` section. CI runs `-m "not bench"` and builds without the feature;
  `just test-bench` on the Debian bench runs everything. A bench test that lacks its hardware fails
  with a clear message; it never skips itself. Do not put `-m "not bench"` in `addopts`.
  Marking a test `bench` needs the owner's approval (the guard asks): only real hardware justifies it.
- A non-bench run with any skipped test fails CI (WP-0.1 wires the check).
- Property tests for invariants (worst-of, tree depth, framing round-trip); table tests for the
  verdict policy (one row per rule and per precedence pair).

## Red first
- Run the new tests before writing code and paste the relevant failure lines in your notes and in the
  merge request. Acceptable reasons: assertion failure, `not implemented`, missing symbol behind a stub.
  Not acceptable: syntax error, import error at collection, broken fixture, wrong path.
- In Rust, create the minimal stub (signature returning `todo!()` or an error variant) so tests compile
  and fail at run time, in the `test(...)` commit.

## Acceptance tests (`tests/acceptance/<dir>/`)
- Written only in a phase's lock WP (`/phase-lock`). Locked by the owner; then never touched again.
- Python pytest only, including UI journeys (pytest-playwright), so the lock tool can count and gate them.
- They run in an isolated pytest (gate, `collect`, `dry-run`): `-c /dev/null` (no ini file, no addopts),
  `--confcutdir` at the phase directory (no parent `conftest.py`), entry-point plugins disabled,
  `PYTHONPATH` = repository root and `tests/acceptance`. So: import helpers explicitly
  (`from common import run_ostia`), keep any `conftest.py` inside the phase directory, and list the pytest
  plugins the phase needs (module names, e.g. `pytest_playwright.pytest_playwright`) in its `GATE_PLUGINS` file.
- Black-box only. Allowed surfaces: the `ostia` binary (path from `OSTIA_BIN`, else `target/debug/ostia`),
  `ostia-enrich`, the local API over its socket, the UI through Playwright, JSON schemas in `schemas/`,
  public generator APIs in `tests/fixtures/`, fakes in `tests/fakes/`, helpers in `tests/acceptance/common/`.
  Never import from `crates/`, `workers-py/` or `ui/src/`.
- Collection must succeed before anything is implemented: import code that does not exist yet lazily,
  inside the test or fixture body, so pytest fails the test at run time with a clear reason.
  `python3 tools/lock/ostia_lock.py collect <dir>` must list every test at lock time (the lock refuses
  a directory with collection errors).
- Expected values never come from unlocked code: a test declares the content it plants (bytes, names,
  attributes) and computes expected hashes from those bytes itself; generator manifests, fakes and
  schemas are inputs, not oracles. A broken generator must make the test fail, never pass.
- Each phase directory has a `README.md`: requirement → tests table, and for each test the reason it
  fails today and the WP expected to turn it green.
- Every MUST requirement whose phase is the phase being locked has at least one acceptance test, or a
  line in the README explaining why it is verified elsewhere (unit, fuzz, bench, review) and where.
- One behaviour per test; assert on report fields, exit codes, files written, events emitted —
  never on log wording or timing unless the requirement is about them.
- Use the `common` helpers (`run_ostia`, `load_report`, `build_image`, ...). If a helper is missing,
  add it to `tests/acceptance/common/` during a lock WP while `common` is not yet locked; once locked,
  new helpers go into the next phase's own directory.

## Never
- No `skip`, `skipif`, `xfail`, `#[ignore]`, `.only`, `.skip`, deselection, `collect_ignore`, or
  conditional early `return` that makes a test pass vacuously. The guard hook blocks most of them;
  the rule covers all of them.
- No mocking of the unit under test. Mock only across process or I/O boundaries, with the fakes.
- No assertions weakened to make a test pass (`>=` instead of `==`, `in` instead of equality,
  wider tolerance, removed assertion). If a test is wrong, stop and tell the owner.
