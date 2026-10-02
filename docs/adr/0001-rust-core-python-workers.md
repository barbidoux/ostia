# ADR-01: Rust core, Python engines as workers

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21 (ADR table), §1 "Locked choices", §7, §8

## Context and problem statement

Ostia reads hostile removable media. Whatever orchestrates a scan must never be the component that
crashes, leaks memory or gets exploited when a file or a file system is malformed (threat M1, spec §4;
SEC-05: the orchestrator parses no file content). At the same time the analysis ecosystem Ostia relies
on is Python-only: `thrember`, `pefile` and LightGBM for EMBER2024 (spec §8), the Office, PDF and PE
heuristics. Which language for which part?

## Decision drivers

- Memory safety of the long-lived, privileged-adjacent components (NFR-09: no `unsafe` outside listed
  modules; NFR-06: decoders fuzzed continuously).
- Access to the mature Python malware-analysis libraries and models (spec §8).
- A worker crash must cost one object, never the session (NFR-05).
- Coverage targets per side: ≥ 90 % Rust core, ≥ 85 % Python workers (NFR-14, G8).

## Considered options

1. Rust core (orchestrator, media, sandbox, engine host, journal, API, updater) with analysis engines
   as Python or Rust worker processes.
2. All Python.

## Decision outcome

Chosen option 1: **a Rust core drives throwaway workers; engines that need the Python ecosystem run as
Python workers.** Orchestrator and workers talk only through the framed Protobuf contract (ADR-03,
CTR-01); the analysed object is handed over as a read-only descriptor.

## Consequences

- Good: the components that live for the whole session are memory-safe and fuzzable; a parser bug in a
  Python library is contained in one sandboxed worker (ADR-04).
- Good: EMBER2024 and the heuristics are used as published, without re-implementation.
- Bad: two toolchains, two test stacks, two dependency audits (cargo-deny/cargo-audit and pip-audit).
- Bad: Python dependencies are less stable; `thrember` needed `signify` pinned to 0.7.1 (spec §21 risk
  table). Mitigation: exact pins with hashes and reference vectors.
- Bad: Python feature extraction may be slow for the 10-minute budget (NFR-01). Mitigation: process
  pool, cascade, size caps, measured from phase 2.
- Follow-ups: WP-0.1 (workspace, `unsafe` forbidden), WP-1.6 (worker host), WP-2.3 (Python worker
  framework). Some C/Python tools may later be replaced by Rust parsers (e.g. The Sleuth Kit, ADR-13).

## Links

- Requirements: NFR-01, NFR-02, NFR-05, NFR-06, NFR-09, NFR-14, SEC-05, CTR-01.
- Related: ADR-03, ADR-04, ADR-13.
