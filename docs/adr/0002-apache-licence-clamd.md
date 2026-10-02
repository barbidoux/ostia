# ADR-02: Apache-2.0 licence; ClamAV called through `clamd`

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §1 "Locked choices", §8, §17

## Context and problem statement

Ostia is published under Apache-2.0 (spec §1). ClamAV is one of its engines, and libclamav is GPL.
Linking it would make the combined work GPL. The same question arises for every GPL component
(usbsas, ADR-05).

## Decision drivers

- Keep a permissive licence so integrators and engine vendors can build on Ostia.
- Use ClamAV without a licence conflict.
- Licences checked automatically (NFR-11, UPD-07: `cargo-deny`).

## Considered options

1. Apache-2.0; ClamAV runs as its own `clamd` process, reached over a local socket.
2. Link libclamav (makes the project GPL).
3. Reach ClamAV through ICAP (c-icap), the generic third-party route of ADR-11.

## Decision outcome

Chosen option 1: **Ostia is Apache-2.0 and talks to `clamd` over a local socket, never linking the
library** (spec §17). `clamd` runs as a daemon engine with a loopback-only network namespace (ENG-03).
GPL code only ever runs as a separate process.
Option 3 is not needed for the built-in engine: the spec specifies the `clamd` socket for it (spec §8,
§17); ICAP stays the route for third-party engines (ADR-11).

## Consequences

- Good: permissive licence kept; ClamAV signatures keep their own signature check on top of TUF (ADR-07).
- Bad: one more long-running daemon with its own memory profile: 3 to 4 GiB recommended, peak during a
  concurrent reload (spec §21 risk table). Mitigation: concurrent reload disabled on offline kiosks.
- Bad: the socket protocol is a boundary to validate and fuzz like any other input.
- Follow-ups: WP-0.1 (LICENSE), WP-0.8 (`deny.toml` licence allowlist; GPL refused in linked code),
  WP-3.5 (ClamAV through `clamd`, concurrent reload off). YARA rule-set licences are listed and checked
  in CI (spec §17).

## Links

- Requirements: NFR-11, UPD-07, ENG-03, ENG-08, FR-08, SEC-13.
- Related: ADR-05 (usbsas, GPLv3, same reasoning), ADR-11 (ICAP).
