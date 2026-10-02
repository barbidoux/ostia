# ADR-07: Offline updates with TUF, verified by `tough`

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §17

## Context and problem statement

The kiosk downloads nothing at runtime: software, models, signatures, rules, the verdict policy and
third-party engines arrive in signed bundles, often carried by hand to isolated sites (FR-18). An
attacker who controls a bundle or replays an old one must not be able to install arbitrary software,
roll a component back or freeze it on a vulnerable version (threat M5).

## Decision drivers

- Authenticity and anti-rollback per component (UPD-01, UPD-02).
- Offline root keys with M-of-N signing (UPD-03); atomic apply (UPD-04).
- One vendor's key cannot sign another vendor's engine (ENG-06: per-engine delegated role).

## Considered options

1. The Update Framework (TUF), verified on the kiosk by the `tough` Rust library.
2. A simple signature over each archive.

## Decision outcome

Chosen option 1: **bundles are TUF repositories verified by `tough`.** TUF protects against rollback,
version freeze, mix-and-match metadata and arbitrary installation (spec §17); each third-party engine
gets its own delegated role.

## Consequences

- Good: well-studied threat model; per-component anti-rollback; delegation fits engine packs (ADR-11).
- Bad: on isolated sites metadata travels by hand, so metadata expiry must match the real offline
  update cadence, or the kiosk would reject legitimate bundles (spec §17).
- Bad: key ceremonies (M-of-N, offline root) are an operational cost.
- Follow-ups: ClamAV databases keep their own signature check (ADR-02). WP-9.1 (`tuftool`, delegated
  roles, ceremony), WP-9.2 (`tough` verification, atomic apply), WP-9.3 (boot integrity).

## Links

- Requirements: FR-18, UPD-01 to UPD-05, ENG-06.
- Related: ADR-02, ADR-09 (the policy ships in the bundle), ADR-11.
