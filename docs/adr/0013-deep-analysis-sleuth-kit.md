# ADR-13: Deep media analysis with The Sleuth Kit in the sandbox, as a separate time-budgeted mode

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §11

## Context and problem statement

Payloads can hide outside files: boot code, gaps between partitions, unallocated space, slack and
deleted entries (threat M2). Hidden areas are never copied, but their content matters for the verdict on
the medium (D2, HIDDEN_PAYLOAD). Reading a whole device takes minutes for a large drive, while the
standard scan must fit the 10-minute budget (NFR-01).

## Decision drivers

- Mature tooling for partition tables, file systems and unallocated space.
- Hostile structures parsed only inside the sandbox (SEC-01, ADR-04).
- Time budget with an estimate shown to the user and an administrator limit (NFR-18, DEEP-07).
- Findings and offsets only, never content (DEEP-09, LOG-09).

## Considered options

1. The Sleuth Kit (`mmls`, `fls`, `blkls`) in the sandbox; boot code and gaps always checked; unallocated
   space, slack and deleted entries only in a separate, time-budgeted deep mode.
2. Always read the full device.
3. Rust parsers (possible later replacement).

## Decision outcome

Chosen option 1: **boot code and gaps are always checked; a separate deep mode, under a time budget,
analyses unallocated space, slack and deleted entries with The Sleuth Kit inside the sandbox.** The raw
read goes through the same privileged helper, which passes only the descriptor (DEEP-01).

## Consequences

- Good: mature toolset; the standard scan keeps its budget.
- Bad: The Sleuth Kit parses hostile structures in C; it runs only in the sandbox, and Rust parsers may
  replace it later.
- Bad: deep mode can be slow on large media (spec §21 risk table). Mitigation: time budget, estimate,
  policy by device size; the regulated profile enables it up to an administrator-set size.
- Follow-ups: phase 5, WP-5.2 to WP-5.7, on the Debian bench. Open questions: deep mode by default for
  small media and size threshold; HIDDEN_PAYLOAD alert only or block (spec §21).

## Links

- Requirements: FR-24, DEEP-01 to DEEP-09, NFR-01, NFR-18, SEC-01, LOG-09.
- Related: ADR-04, ADR-05, ADR-09 (D2).
