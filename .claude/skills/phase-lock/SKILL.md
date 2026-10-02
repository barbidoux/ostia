---
name: phase-lock
description: Write the acceptance tests of the next Ostia phase (the "Lock" work package that closes each phase, e.g. WP-1.12 writes P2's tests). Produces black-box, failing, traced tests and a README, then stops for the owner to review and lock. Never creates LOCK files.
argument-hint: P<n> (the phase whose acceptance tests are written)
disable-model-invocation: true
---

# Write the acceptance tests of $ARGUMENTS

These tests are the rails of the whole phase: once locked they never change. Quality matters more
than speed. Read `.claude/rules/tests.md` first. The coverage list for $ARGUMENTS is in the brief of the
**previous** phase, in its lock package section (for P2: `prompts/P1.md`, section "WP-1.12 Lock").
Read `prompts/$ARGUMENTS.md` too (the phase's own plan), and list the requirements of the target phase with
`python3 tools/kit/req.py phase $ARGUMENTS` (it also names requirements no package cites: cover them here).

## 1. Branch and scope
- Branch `wp/<lock WP id>-lock-<phase lowercase>` (for example `wp/1.12-lock-p2`) from `main`.
- Directory `tests/acceptance/<phase lowercase>/` (for example `p2`). It must not contain `LOCK.sha256`.
- Inputs: spec §20 row for the phase ("Tests written first (examples)" and "Exit criterion"),
  every requirement whose phase is $ARGUMENTS (`req.py phase $ARGUMENTS`), the "Tests written first"
  column of every package of the phase, the phase brief in `prompts/`.

## 2. Coverage table first
Write `tests/acceptance/<dir>/README.md` before any test:
| Requirement | Level | Acceptance test(s) | Verified elsewhere (unit/fuzz/bench/review) | Turns green in WP |
Every MUST requirement of the phase appears. A requirement verified elsewhere says exactly where and why
(for example "NFR-06: fuzz target in CI, not observable black-box").
Add the exit criterion of the phase as its own row ("EXIT").
Show this table to the owner and wait for a go before writing tests if anything is uncertain.

## 3. Contracts needed by the tests
If the tests need a public surface that does not exist yet (CLI subcommand or flag, report field,
API endpoint, schema), add or extend the contract first, in its own commit `contract(<REQ>): ...`:
`docs/contracts/cli.md`, `schemas/*.json`, `proto/`, `openapi.yaml`. Stubs that exit with code 3
"not implemented" are acceptable so that tests fail for the right reason. Contract changes are part of
what the owner reviews before locking.

## 4. Write the tests
- Black-box only, through the surfaces allowed in `.claude/rules/tests.md`. No imports of internals.
- One behaviour per test, literal expected values, requirement tags, deterministic, no network,
  no real malware, bench marker for hardware tests.
- Imports of code that does not exist yet are lazy (inside the test body or fixture), so that
  `python3 tools/lock/ostia_lock.py collect <dir>` succeeds.
- Include the negative and limit cases the requirement implies: refusal, UNSCANNABLE on failure,
  nothing transferred, nothing logged that must not be.
- Shared helpers go in `tests/acceptance/common/` only while `common` is unlocked; otherwise in the
  phase directory.

## 5. Prove they fail for the right reason
1. `python3 tools/lock/ostia_lock.py collect <dir>` lists every test (no collection error) in the same
   isolated pytest the gate uses. Put needed pytest plugins in `<dir>/GATE_PLUGINS`.
2. `python3 tools/lock/ostia_lock.py dry-run <dir> -- -m "not bench"` : every test fails. Record, per test,
   the failure reason in the README ("ostia scan: not implemented (exit 3)", "fixture generator WP-1.3
   not implemented", ...). A test that passes now is wrong: fix it.
3. Ask the `test-auditor` subagent to audit the directory against the README and the requirements.
   Fix its findings.

## 6. Hand over to the owner, then stop
- Commit: `test(P<n>): acceptance tests for <phase name>` (plus contract commits before it).
- Tick nothing in the gate. Write `.wp-notes/<WP>.pr.md` with the coverage table, the failing output
  summary, the contracts added, and the questions.
- Tell the owner the tests are ready for review and that locking is his act, on the lock branch:
  `just lock <dir>` → commit `chore(lock): lock <dir>` → `git tag -s lock-<dir>` and push the tag →
  then merge (rebase or merge commit, never squash). `GUIDE-FR.md` §6 has the exact steps.
- Never run the lock command, never create or edit `LOCK.sha256`, never tag.
