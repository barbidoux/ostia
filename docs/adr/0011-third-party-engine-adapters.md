# ADR-11: Third-party engines through native, CLI and ICAP adapters with a conformance kit

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §9, §3

## Context and problem statement

Commercial kiosks ship several antivirus engines. Ostia must be able to add third-party engines,
including commercial ones it cannot ship (ENG-08), without changing its core (FR-23, NFR-13). The ANSSI
profile itself asks that the choice of engines be left to the customer (spec §3).

## Decision drivers

- No core change to add an engine: a manifest and an adapter only (NFR-13).
- No extra privilege for third-party engines (SEC-13); same sandbox and limits as other workers.
- Proof that an engine behaves before it is enabled (ENG-04).
- Wide vendor support.

## Considered options

1. Three generic adapters (native Protobuf worker, command-line wrapper, ICAP client) described by a
   published manifest schema, plus a conformance kit.
2. Per-vendor integration code in the core.

## Decision outcome

Chosen option 1: **engines integrate through native (ADR-03), CLI or ICAP (RFC 3507) adapters, each
described by a manifest (CTR-06), and are enabled only after passing the conformance kit**
(`ostia engine certify <manifest>`, the same suite as CI, writing a signed report). Trust levels (alone,
K-of-N, advisory) feed the verdict policy (ENG-05, ADR-09).

## Consequences

- Good: the core stays vendor-neutral; ICAP reaches many products (ClamAV through c-icap, and several
  commercial engines listed in spec §9).
- Bad: commercial licensing and Linux availability limit which engines exist (spec §21 risk table).
  Mitigation: engine packs in a separate repository, the ICAP route.
- Bad: ICAP and CLI outputs are less structured than the native contract; adapters must map them strictly
  and fail closed.
- Follow-ups: WP-3.1 to WP-3.4 and WP-3.11; per-engine delegated update roles (ENG-06, ADR-07, WP-9.1);
  open question: which commercial engines first (spec §21).

## Links

- Requirements: FR-23, NFR-13, ENG-01 to ENG-08, CTR-06, SEC-13.
- Related: ADR-02, ADR-03, ADR-07, ADR-09.
