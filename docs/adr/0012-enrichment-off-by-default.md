# ADR-12: Online enrichment off by default, user-chosen within a configured upload mode, harden-only

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §12, §2 (deployment profiles)

## Context and problem statement

Online services such as VirusTotal can confirm or raise a verdict, but sending a hash, and even more a
file, to an outside service can leak confidential data, breaks the offline posture of isolated sites,
and is restricted by service terms (the free API forbids business use, ENR-09). Ostia serves both
regulated organisations and the community (threat M8).

## Decision drivers

- Confidentiality and offline posture by default (the regulated profile is the proposed default,
  spec §2; still an open question in spec §21).
- Enrichment can only make a verdict stricter, never softer (ENR-05: never turns UNSCANNABLE or
  SUSPICIOUS into CLEAN).
- Configuration enforced through the signed policy, changed only by a super-administrator (ENR-13).
- Never blocks a session (NFR-19).

## Considered options

1. Off by default; when enabled, an upload mode (`disabled`, `admin_approval`, `user_choice`) bounds
   what the user may send; hash preselected, full file only by explicit choice; harden-only.
2. Automatic upload of unscannable files.

## Decision outcome

Chosen option 1: **enrichment is off by default; when a super-administrator enables it through the signed policy, the signed policy
sets the upload mode and the deny list, the user chooses hash or full file within those bounds, and
results can only harden a verdict** (rule E1). Connectivity modes: offline export/import (default for
air-gapped sites), central relay, direct (discouraged). VirusTotal Private Scanning is preferred when
licensed (ENR-03).

## Consequences

- Good: safe default for regulated deployments; community deployments can opt in.
- Bad: offline export/import adds latency; results may arrive after the session (they never block it).
- Bad: free-tier quotas (4/min, 500/day) limit what direct mode can do.
- Follow-ups: phase 8, WP-8.1 to WP-8.8; open question: default N for E1 (3 proposed, spec §21).

## Links

- Requirements: FR-25, ENR-01 to ENR-13, NFR-08, NFR-19, SEC-14, UI-09, CTR-07.
- Related: ADR-09 (E1 lives in the policy), ADR-06.
