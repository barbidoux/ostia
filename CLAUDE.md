# CLAUDE.md — Ostia

@AGENTS.md

The rules above are binding. This file adds how to work on Ostia with Claude Code.
Language: everything in the repository is in English (code, comments, commits, docs).
Talk to the owner in French, informally ("tu"), when he writes in French.

## Where things are
| Path | What |
|---|---|
| `docs/spec.md` | Requirements. Never read it whole: use `python3 tools/kit/req.py <WP-x.y or REQ-ID>` |
| `docs/plan.md` | Work packages per phase, gate checklist (§14) |
| `docs/phase-status.md` | Current phase, WP checkboxes, gate state |
| `docs/questions.md` | Open questions for the owner (append, never delete) |
| `docs/adr/` | Architecture decision records (MADR format), ADR-01 to ADR-13 then new ones |
| `docs/contracts/` | CLI contract, exit codes, report format notes |
| `prompts/P<n>.md` | Phase brief: order, technical guidance, pitfalls, stop points. Read it when a phase starts and before each WP |
| `proto/`, `schemas/` | Protobuf contracts (`ostia.engine.v1`), JSON schemas (report, manifests, bundles) |
| `crates/` | Rust workspace (core-domain, orchestrator, sandbox, media, usb-sentinel, engine-host, enrich, journal, updater, api, workers, ostia-cli) |
| `workers-py/` | Python workers (ember, office, pdf, pe, common) managed with `uv` |
| `tests/acceptance/<dir>/` | Phase acceptance tests, black-box, locked by the owner |
| `tests/fixtures/`, `tests/fakes/` | Generators (images, files, gadgets) and fakes (engine, clock, collector, provider) |
| `tools/kit/`, `tools/lock/` | Rails tooling (read-only for you) |

The target layout is in `docs/spec.md` §19. Create directories only when a WP needs them.

## Commands
- `python3 tools/kit/req.py WP-1.8` · `req.py FR-06` · `req.py phase P1` · `req.py rules`
- `python3 tools/lock/ostia_lock.py status | verify | rails-verify | collect p2 | dry-run p1 | gate p1`
  (`collect` and `dry-run` use the same isolated pytest as the gate: no ini file, no parent conftest,
  no auto-loaded plugins — see `.claude/rules/tests.md`)
- `just kit-test` — self-test of the rails (hooks, lock tool, req tool)
- From WP-0.1 on: `just check` (everything), `just test`, `just test-rust`, `just test-py`,
  `just test-acceptance p1`, `just lint`, `just fmt`, `just trace`, `just audit`.
  `just test-bench` (P4, P5) runs hardware tests on the Debian bench only.
- Owner only: `just lock <dir>`, `just relock <dir> "<reason>"`, `just rails-update`, tags, merges.

## Workflow (skills in `.claude/skills/`)
1. `/wp-start WP-x.y` — checks prerequisites, creates the branch, gathers requirements, writes the test plan, lists questions.
2. `/wp-implement` — red → green → refactor per requirement, with the commit discipline.
3. `/wp-finish` — `just check`, independent review by the `reviewer` and `test-auditor` subagents, merge request text, status tick.
4. `/phase-lock P<n+1>` (the owner triggers it) — the lock WP of each phase: writes the next phase's
   acceptance tests, then stops for the owner. When `/wp-start` meets a lock WP, it stops and asks for it.
5. `/phase-gate P<n>` (the owner triggers it) — evidence for every gate item; the owner ticks the gate.
Keep working notes in `.wp-notes/WP-x.y.md` (git-ignored): plan, test list, status, open points.
After a compaction or a new session, re-read that file and `git log --oneline -15` before acting.

## Architecture invariants (any change needs an ADR and the owner)
- The orchestrator (Rust, unprivileged) never interprets file content or device data. Typing,
  extraction, carving, mapping and every engine run in throwaway sandboxed workers.
- Workers talk length-prefixed Protobuf (4-byte big-endian length, size cap) on stdin/stdout;
  the analysed object is passed read-only as file descriptor 3. No network in sandboxes
  (loopback only for clamd/ICAP engines declared as such).
- Each object is read once from the medium, hashed (SHA-256, SHA-1) and copied into the
  encrypted workspace; the scanned copy is the one transferred.
- Only the small mount and raw-read helper is privileged; it validates every parameter.
- Verdicts come only from the signed, declarative policy (R1–R7, E1, D1, D2). No verdict
  logic hard-coded elsewhere. The worst-of ordering of verdicts is fixed in WP-1.1 with the
  owner (the spec does not rank MALICIOUS against UNSCANNABLE; both block the medium).
- Any failure, timeout or limit yields UNSCANNABLE, never CLEAN. Fail closed everywhere.
- Logs carry metadata, hashes and offsets, never file content. Enrichment is off by default and
  can only harden a verdict, never soften it.
- The kiosk downloads nothing at runtime: models, signatures and rules arrive in signed bundles.

## Acceptance tests are black-box
They drive the product only through its public surfaces: the `ostia` CLI (JSON report validated
against `schemas/report.schema.json`), later `ostia-enrich`, the local HTTP API and the UI
(Playwright). They never import crate or worker internals. Details: `.claude/rules/tests.md`.

## Environment
- P0–P3 and P6–P8: WSL2 Debian or the dev container. P4–P5: the dedicated Debian bench.
- `sudo` is only for the scripts in `tools/dev/` that the owner allowed in sudoers (loop devices,
  read-only mounts, gadgets). Everything else runs unprivileged.
- Network: package registries only. Models and datasets are fetched by the owner with pinned hashes.

## Working well here
- Small steps, frequent commits on the WP branch, suite green after every step.
- Prefer the standard library and the crates already in use; justify any new one.
- Use subagents (Explore) for wide searches so the main context stays on the WP.
- Say plainly when something is not done, not tested or not understood. Never claim a check ran
  if it did not.
