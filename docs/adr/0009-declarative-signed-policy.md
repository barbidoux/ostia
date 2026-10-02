# ADR-09: Declarative, signed verdict policy

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §8; prompts/P0.md (WP-0.12) and prompts/P1.md (policy signature format)

## Context and problem statement

Each object gets a verdict from the results of several engines, and the medium gets a verdict from its
objects (FR-09, FR-10). How those results combine decides what reaches the protected network. The logic
must be auditable, explainable for each verdict (NFR-12) and reproducible: same versions, same verdict
(NFR-07).

## Decision drivers

- Auditability and publication of the rules.
- Table-driven tests: one row per rule and per precedence pair; mutation score ≥ 70 % (NFR-14).
- Changeable by a signed update, without recompiling (ADR-07).
- Enrichment can only harden a verdict (ENR-05, rule E1).

## Considered options

1. A signed, versioned declarative policy file; rules apply in order and the first match decides.
2. Verdict logic hard-coded in the orchestrator.
3. A learned fusion meta-model (spec §8).

## Decision outcome

Chosen option 1: **verdicts come only from the signed declarative policy** (object rules R1–R7, E1;
medium rules D1, D2). No verdict logic is hard-coded elsewhere. The learned fusion is planned after
1.0; the rule-based policy stays the auditable reference meanwhile.

## Consequences

- Good: auditable, table-testable, explainable; deployments tune it through signed bundles.
- Bad: a policy loader and validator to harden; an unsigned or altered policy must be refused (fail closed).
- Bad: the worst-of ordering between MALICIOUS and UNSCANNABLE is not ranked by the spec; it is fixed
  with the owner in WP-1.1 (both block the medium).
- Follow-ups: WP-1.1 (verdict ordering), WP-1.2 (policy engine, table tests, signature check: Ed25519
  detached signature over the exact policy bytes), WP-3.12 (mutation testing). Enrichment settings live
  in the signed policy (ENR-13).

## Links

- Requirements: FR-09, FR-10, NFR-07, NFR-12, NFR-14, ENR-05, ENR-13, ENG-05.
- Related: ADR-07, ADR-12.
