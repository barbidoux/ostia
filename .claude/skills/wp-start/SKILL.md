---
name: wp-start
description: Start an Ostia work package (WP-x.y). Checks prerequisites, creates the wp branch, gathers the cited requirements, writes the test plan and the open questions. Use before writing any code for a work package.
argument-hint: WP-x.y
disable-model-invocation: false
---

# Start work package $ARGUMENTS

Follow these steps in order. Stop at the first failed check and report it; do not work around it.

## 1. Preconditions
1. `git status --porcelain` is empty. If not, show what is pending and ask the owner what to do.
2. You are on `main` and it is up to date with the remote if one exists (`git fetch` then compare;
   ask before pulling if it would merge anything).
3. `python3 tools/lock/ostia_lock.py verify` and `python3 tools/lock/ostia_lock.py rails-verify` pass.
4. `python3 tools/kit/req.py $ARGUMENTS` prints the package. Note its phase `P<n>`.
5. `docs/phase-status.md`: `Current phase` is `P<n>` (or the owner said otherwise in this session),
   every package in the "After" column is ticked, and the previous phase's gate is ticked.
   If the package is a lock package (scope starts with "Lock:"), stop: tell the owner it is ready and
   ask him to run `/phase-lock P<n+1>` (only the owner can trigger it).
6. If the size is L, stop: propose a split into S/M packages to the owner.

## 2. Branch
Create `wp/<x.y>-<slug>` where slug is 2–4 lowercase words from the scope, for example
`git switch -c wp/1.8-extraction-zip-tar`.

## 3. Understand
1. Read `prompts/P<n>.md`: the phase brief and the section for this package (guidance, pitfalls, stop points).
2. Read the full text of each cited requirement (printed by `req.py`) and every ADR, contract and
   schema the package touches. Read existing code only where the package plugs in.
3. If the package cites `Spec §N`, read that section of `docs/spec.md` only.
4. Check whether locked acceptance tests of the current phase exercise this package
   (`rg -n "<REQ-ID>" tests/acceptance/`). Those tests must go green as a result of the phase, and
   your package must not make any of them harder to satisfy.

## 4. Plan (write `.wp-notes/$ARGUMENTS.md`, git-ignored)
```
# $ARGUMENTS — <scope>
Branch: wp/...
Requirements: <ids with one-line summary each>
Acceptance tests touched: <paths::names or "none">
## Test plan (written first)
- [ ] <test name> — <req id> — <what it proves> — <expected first failure>
## Design notes
<modules, types, contracts touched; why; alternatives rejected>
## Dependencies to add
<crate/package, version, licence, reason — or "none">
## Questions for the owner
<numbered, each with options and your recommendation — or "none">
## Status
<updated as you go: tests red / green / refactor / check / review>
```
The test plan covers every item of "Tests written first" plus the edge cases the requirement implies
(limits, malformed input, failure paths that must yield UNSCANNABLE or a refusal).

## 5. Report and wait if needed
Show the owner a short summary: scope, requirements, the test list, dependencies, questions.
- If there are blocking questions or new dependencies/licences/privileges: stop and wait for answers.
  Append the questions to `docs/questions.md` as well.
- Otherwise continue with `/wp-implement`.
