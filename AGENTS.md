# Ostia — rules for coding agents

Ostia is an open-source media kiosk ("station blanche"): it scans removable media with several
engines (LightGBM EMBER2024, ClamAV, YARA-X, heuristics, third-party antivirus plug-ins),
defends against BadUSB devices, analyses areas outside files, and transfers only what passes.
Rust core, Python analysis workers, Apache-2.0. These rules bind every coding agent.

## Sources of truth, in order
1. Locked acceptance tests: `tests/acceptance/<dir>/` holding a `LOCK.sha256`.
2. Contracts: `proto/`, `schemas/`, `docs/contracts/`, OpenAPI files.
3. `docs/spec.md` (requirements: FR, NFR, ENG, USB, DEEP, ENR, SEC, CTR, LOG, UI, UPD).
4. `docs/plan.md` (101 work packages, WP-0.1 to WP-9.9) and `docs/adr/`.
If two of them disagree, stop and ask. Never resolve a conflict by guessing or by editing a source.
This file and `CLAUDE.md` come from the owner's rails kit and supersede plan §15 (and the "agent
instructions file" item of WP-0.9). A phase's lock WP writes the next phase's acceptance directory
while it is still unlocked; that is the only time an agent writes under `tests/acceptance/`.

## Roles
- **Owner** (Matthias Vaytet) decides. Owner-only acts: locking or re-locking acceptance tests,
  tagging, merging, ticking a phase gate, changing the spec or the plan, approving a licence,
  an `unsafe` crate, a new dependency, or anything touching real hardware destructively.
- **Agent** implements one work package (WP) at a time, test first, and stops at every owner act.

## Before writing anything
- Be on branch `wp/<id>-<slug>` (for example `wp/1.8-extraction-part1`), created from up-to-date `main`.
- Run `python3 tools/kit/req.py WP-x.y`: it prints the WP row and the full text of each cited
  requirement. Read every cited ADR and contract too. Do not read the whole spec as a brief.
- Check that every package in the "After" column is merged (`docs/phase-status.md`).
- If a requirement is ambiguous, missing, contradictory or untestable: stop, write the question
  in `docs/questions.md` (WP, requirement, options, your recommendation) and ask the owner.

## Test first, always
1. Write the tests listed for the WP ("Tests written first" is a minimum). Tag each test with the
   requirement it proves: `#[req("FR-06")]` in Rust, `@pytest.mark.req("FR-06")` in Python,
   `req("FR-06")` in the test title for TypeScript.
2. Run them. Show they fail, and that they fail for the expected reason (assertion or
   "not implemented"), not because of a typo, an import error or a broken fixture.
3. Commit: `test(FR-06): <what the tests check>`.
4. Write the minimum code that makes them pass. Commit: `feat(FR-06): <what was built>`.
5. Refactor only with the whole suite green. Commit: `refactor: <what>`.
Expected values in tests are literal and come from the spec or the fixture definition, never
computed by the code under test. A test that passes before the code exists is a wrong test.

## Never
- Never edit, delete, skip, ignore, xfail, focus, deselect or weaken a test to make it pass.
  Hardware-only tests carry the `bench` marker; they are never skipped.
- Never touch a locked acceptance directory, a `LOCK.sha256`, or the rails files:
  `CLAUDE.md`, `AGENTS.md`, `.claude/`, `prompts/`, `tools/lock/`, `tools/kit/`, `docs/spec.md`,
  `docs/plan.md`, `docs/unsafe-allowlist.md`, `.github/CODEOWNERS`, `.github/workflows/rails.yml`.
- Never lower a coverage, mutation or lint threshold, or add a suppression (`# noqa`,
  `# type: ignore`, `#[allow]`, `# pragma: no cover`) without the owner's explicit approval.
- Never add real malware, secrets, API keys, private keys or live network calls to code, tests or
  fixtures. Malicious behaviour is simulated: EICAR generated at test time, harmless macros,
  markers, recorded API responses, fake engines and fake providers.
- Never contact VirusTotal, MalwareBazaar or any malware repository from the shell or from tests.
- Never parse file content or device data in the orchestrator; parsing happens in sandboxed workers.
- Never add `unsafe` outside the crates listed in `docs/unsafe-allowlist.md`.
- Never add a dependency without naming it, its version, its licence and why, in the merge request.
  Licences outside `deny.toml` are refused; GPL code only ever runs as a separate process.
- Never write to a real block device; tests use generated images, loop devices and USB gadgets.
- Never change tests or test, lint, coverage or CI configuration through the shell (`sed -i`, `>`,
  scripts): use the Edit and Write tools, so every change can be inspected.
- Never force-push, rewrite history, bypass hooks (`--no-verify`), tag, merge or publish.

## Scope
- One WP per branch and per merge request, titled `[WP-x.y] <scope>`.
- Change only what the WP needs. An unrelated problem goes in `docs/questions.md`, not in the diff.
- An L-sized WP, or one that grows beyond its row, is split with the owner before continuing.

## Stop and ask the owner when
- a locked acceptance test seems wrong, impossible, or contradicts the spec;
- the WP needs a dependency, licence, `unsafe` block, privileged operation or network access
  not already approved;
- a decision has more than one reasonable answer and no ADR covers it (propose an ADR draft);
- three honest attempts at making a test pass have failed;
- you would have to change a contract (`proto/`, `schemas/`, OpenAPI) in a breaking way;
- hardware, a model file, a corpus or a credential you do not have is required.
Write what you tried, what you observed and the options. Then wait.

## Before saying "done"
- `just check` passes: format, lint, types, tests, coverage, traceability, licences, audit.
- `python3 tools/lock/ostia_lock.py verify` and `rails-verify` pass.
- The merge request lists: requirements covered, tests added (with their first failing output),
  decisions taken (ADR if any), dependencies added with licences, anything left open.
- The WP is ticked in `docs/phase-status.md` in the same merge request.
