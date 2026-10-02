# ADR-06: OCSF logs

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §15

## Context and problem statement

Every session, verdict, device event and administrative action must be logged in a tamper-evident
journal and forwarded to a central platform or SIEM (FR-19, LOG-01 to LOG-09; threats M6, M7). Ostia
needs an event format for that.

## Decision drivers

- Interoperability with existing SIEMs without per-customer mapping.
- An open, vendor-neutral schema that already covers file scans, device events and admin actions.
- Logs carry metadata, hashes and offsets, never file content (LOG-09).

## Considered options

1. OCSF (Open Cybersecurity Schema Framework).
2. A custom format.
3. Elastic Common Schema (ECS).

## Decision outcome

Chosen option 1: **events follow OCSF**, a vendor-neutral schema backed by many security vendors that
already covers the events Ostia needs (spec §15). The class mapping is in spec §15; identity and
application classes are fixed in phase 6. Syslog output (LOG-10, MAY, after 1.0) would complement it,
not replace it.

## Consequences

- Good: no format to invent and maintain; easier SIEM integration; a published schema to validate against.
- Bad: OCSF evolves; Ostia pins one schema version and validates every emitted event against it.
- Follow-ups: WP-6.1 (events validated against the pinned OCSF version) to WP-6.6; the fake collector
  is the executable specification of the future central platform (spec §15).

## Links

- Requirements: FR-19, LOG-01 to LOG-10.
- Related: ADR-12 (enrichment events are logged).
