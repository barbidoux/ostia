# ADR-16: Worst-of ordering of verdicts — MALICIOUS above UNSCANNABLE

- Status: accepted (2026-10-08, the owner's answer to the WP-1.1 stop point, Q-42)
- Date: 2026-10-08
- Deciders: Matthias Vaytet (owner)
- Source: spec §8 ("Medium verdict", "In compliant mode ..."), FR-09, FR-10; ADR-09; prompts/P1.md WP-1.1;
  `docs/contracts/report.md` ("Medium verdict")

## Context and problem statement

The medium verdict is the worst object verdict (spec §8), and a container's state depends on its entries. CLEAN
is the best and SUSPICIOUS is worse than CLEAN; MALICIOUS and UNSCANNABLE both block the whole medium in
compliant mode, but the specification does not say which of the two is "worse". The report shows one medium
verdict, so a medium holding both needs one answer, and the domain model needs a total order for its property
tests (commutative, associative, idempotent, monotonic, order-independent).

## Decision drivers

- Blocking is decided by the policy and the mode, not by the rank: both verdicts block in compliant mode
  whatever the order (FR-10), and `blocking_objects` lists both kinds.
- The single verdict shown should carry the strongest signal for the operator and the administrator alert.
- Enrichment can only harden (E1 upgrades any verdict to MALICIOUS, ENR-05): MALICIOUS must be reachable from
  UNSCANNABLE as an upgrade.
- The P1 acceptance tests never combine both in one medium, so either order satisfies them.

## Considered options

1. `CLEAN < SUSPICIOUS < UNSCANNABLE < MALICIOUS`: a medium holding a detected threat and an unanalysable file
   shows MALICIOUS.
2. `CLEAN < SUSPICIOUS < MALICIOUS < UNSCANNABLE`: the medium shows UNSCANNABLE ("not everything could be
   analysed") even when a threat was found.
3. No total order: a medium verdict holding both values.

## Decision outcome

Chosen option 1. A confirmed detection is the stronger and more actionable signal; the unanalysable objects
stay visible in `blocking_objects` and in their own verdicts, and both block in compliant mode. E1's upgrade to
MALICIOUS is then an upgrade from every other verdict, which matches "harden only". Option 2 would hide a
detection behind a weaker message; option 3 breaks the single verdict of the report contract.

## Consequences

- Good: one total order, property-tested in `crates/core-domain`; the report's single medium verdict is defined.
- Good: an alert on MALICIOUS is never masked by an unrelated unscannable file.
- Bad: a medium with both shows MALICIOUS; an operator must read `blocking_objects` to see what could not be
  analysed (the UI of P7 lists both).
- Follow-ups: WP-1.2 (medium rule in the policy uses this order), WP-1.10 (report), P8 (E1).

## Links

- Requirements: FR-09, FR-10, ENR-05.
- Related: ADR-09, `docs/contracts/report.md`.
