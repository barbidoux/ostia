---
name: wp-finish
description: Finish the current Ostia work package. Runs every check, gets an independent review from the reviewer and test-auditor subagents, fixes findings, ticks the status and prepares the merge request. Use when all planned tests of the package are green.
---

# Finish the current work package

WP id: from the branch name `wp/<x.y>-...`. Notes: `.wp-notes/WP-<x.y>.md`.

## 1. Checks (all must pass; report honestly what ran)
1. `just check` (format, lint, types, all non-bench tests, coverage thresholds, traceability, licences, audit).
2. `python3 tools/lock/ostia_lock.py verify` and `python3 tools/lock/ostia_lock.py rails-verify`.
3. `git diff main...HEAD --stat`: only files the package needs. Revert unrelated changes.
   If the diff touches a test lever (pytest settings, `conftest.py`, `Cargo.toml` `[[test]]`/features,
   `.cargo/`, CI workflows, coverage or lint configuration, `schemas/`), justify each change in the
   merge request: reviewers treat unexplained ones as high-severity findings.
4. Every requirement cited by the package has at least one test tagged with it (`just trace`, or
   `rg -n '<REQ-ID>' crates workers-py tests ui` before WP-0.4 exists).
5. Commit history shows, for each requirement, a `test(...)` commit before its `feat(...)` commit.
6. If the package touches P4/P5 hardware paths: ask the owner to run `just test-bench` on the bench
   and paste the result; do not claim it passed otherwise.

## 2. Independent review
Launch both subagents in parallel, giving each the WP id, the requirement ids and the base branch `main`:
- `reviewer`: correctness, scope, invariants, security, contracts.
- `test-auditor`: test quality, red-first evidence, traceability, weakening.
Fix every finding of severity high or medium (test first if it is a behaviour change), or explain
in the merge request why it does not apply. Re-run step 1 after fixes.

## 3. Status and documentation
- Tick the package in `docs/phase-status.md`: `- [x] WP-x.y <scope> — <branch>`.
- Add a line to `CHANGELOG.md` under "Unreleased" (from WP-0.1 on).
- ADRs: any decision taken is recorded (status "proposed" until the owner accepts it).
- Answered questions: move them to the "Answered" part of `docs/questions.md` with the answer.
- Commit: `docs(WP-x.y): status, changelog`.

## 4. Merge request
Write the description to `.wp-notes/WP-<x.y>.pr.md` using `.github/pull_request_template.md`:
title `[WP-x.y] <scope>`; requirements covered; tests added with their first failing output;
contracts changed; dependencies added (name, version, licence, reason); decisions/ADRs;
review findings and how they were handled; what is left open.
Then ask the owner whether to push the branch and open the merge request (`git push -u origin <branch>`,
`gh pr create --title ... --body-file ...`). Never merge.

## 5. Report
Tell the owner in a few lines: what was built, checks run and their result, anything open,
and the next package that becomes ready (from `docs/phase-status.md` and the "After" column).
