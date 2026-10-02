# ADR-14: Acceptance tests drive the product only through its public surfaces

- Status: proposed (from the owner's rails: CLAUDE.md, .claude/rules/tests.md; awaiting the owner's acceptance)
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner), to accept
- Source: spec §18; CLAUDE.md "Acceptance tests are black-box"; `.claude/rules/tests.md`;
  `.claude/rules/contracts.md`; prompts/P0.md (WP-0.10, WP-0.12)

## Context and problem statement

Each phase's acceptance tests are written first, locked by the owner (hash manifest, CODEOWNERS, tag)
and never changed afterwards without a traced decision (spec §18). They must stay valid while the
implementation is written, refactored and split into crates and workers that do not exist yet when the
tests are locked. If they imported internal modules, every refactoring would break a locked test or
tempt someone to change it.

## Decision drivers

- Locked tests must survive any internal refactoring.
- The tests must prove behaviour a user or an integrator can observe.
- Collection must succeed before anything is implemented, so the lock can count the tests.
- Expected values must never come from unlocked code.

## Considered options

1. Black-box tests through public surfaces only: the `ostia` CLI with its JSON report validated against
   `schemas/report.schema.json`, later `ostia-enrich`, the local HTTP API and the UI through Playwright.
2. Tests importing crate or worker internals.

## Decision outcome

Chosen option 1: **acceptance tests use only the public surfaces** — the `ostia` binary (path from
`OSTIA_BIN`, else `target/debug/ostia`), the JSON report and its schema, `ostia-enrich`, the local API,
the UI through Playwright, the public fixture generators in `tests/fixtures/`, the fakes in
`tests/fakes/` and the helpers in `tests/acceptance/common/`. They never import from `crates/`,
`workers-py/` or `ui/src/`. They run in an isolated pytest (no ini file, conftest lookup cut at the phase
directory, no auto-loaded plugins), and code that does not exist yet is imported lazily inside tests.

## Consequences

- Good: locked tests are independent of the internal structure; the CLI, the report schema and the API
  become explicit contracts.
- Bad: the report schema is the contract of the acceptance tests; adding an optional field is fine,
  changing or removing one is a breaking change that needs the owner (`.claude/rules/contracts.md`).
- Bad: internal behaviour that is not observable through a public surface is proved by unit, fuzz or
  bench tests instead, listed in each phase's acceptance README.
- Follow-ups: WP-0.12 lands the CLI skeleton (`crates/ostia-cli`), `docs/contracts/cli.md`
  (subcommands, flags, exit codes) and `schemas/report.schema.json` v1 for the owner's review before the
  P1 tests are locked. Whether development-only flags exist only behind a `dev` cargo feature is part
  of the CLI shape proposed in WP-0.12.

## Links

- Requirements: spec §18 (test strategy).
- Related: ADR-03 (worker contract), ADR-09 (policy observable through the report).
