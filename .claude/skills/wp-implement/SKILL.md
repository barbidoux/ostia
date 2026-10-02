---
name: wp-implement
description: Implement the current Ostia work package with strict red-green-refactor and the test()/feat() commit discipline. Use after /wp-start, on a wp/ branch, one requirement at a time.
argument-hint: "[REQ-ID to focus on, optional]"
---

# Implement the current work package (test first)

Context: read `.wp-notes/<WP>.md` (WP id from the branch name `wp/<x.y>-...`) and `git log --oneline -15`.
If the notes file is missing, run `/wp-start` first.
Focus requested: "$ARGUMENTS" (if empty: all requirements of the package, one at a time, in the order of the test plan).

## Loop, per requirement (or per coherent group of tests)

### Red
1. Write the tests from the plan for this requirement, tagged with the requirement id.
   Expected values literal; failure paths covered; no skip/xfail/ignore; deterministic.
2. If the code under test does not exist, add the smallest stub so the tests compile/collect
   (Rust: function returning `todo!()` or an `Err(NotImplemented)`; Python: `raise NotImplementedError`).
3. Run only these tests. Confirm each one fails, and fails for the expected reason. Copy the key
   failure lines into the notes under the test. If a test passes already, it is not testing the new
   behaviour: fix the test (it is yours, not locked) before going on.
4. Commit only tests and stubs: `test(<REQ>): <behaviour checked>`.

### Green
5. Write the minimum code that makes these tests pass. No speculative features, no code for later packages.
6. Run the new tests, then the whole fast suite (`just test`). Everything green.
   If a previously passing test breaks, fix the code, not the test.
7. Commit: `feat(<REQ>): <what was built>`.

### Refactor
8. Improve names, structure and duplication with the suite green after each step.
   Commit `refactor: <what>` if anything changed.
9. Update the Status section of the notes.

## Rules inside the loop
- Three honest attempts without getting a test green: stop and describe the problem to the owner
  (what you tried, observed output, hypotheses). Do not loosen the test.
- A locked acceptance test that seems wrong: stop and report with evidence; never touch it.
- New dependency, `unsafe`, privilege, network or licence question: stop and ask before adding it.
- Need a decision not covered by the spec or an ADR: write an ADR draft in `docs/adr/` (status
  "proposed") and ask the owner; continue only on parts that do not depend on it.
- Keep commits small and focused; never mix test and implementation in one commit.

When every planned test is green and the notes are up to date, continue with `/wp-finish`.
