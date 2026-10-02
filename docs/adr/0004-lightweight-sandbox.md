# ADR-04: bubblewrap or nsjail sandbox with cgroups v2

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §13

## Context and problem statement

"No byte from the medium is interpreted by a privileged process or by the orchestrator" (spec §13).
Every parser, extractor and engine therefore runs in an isolated, throwaway environment (threats M1,
M4). The isolation must work on the Debian target and on the WSL2 development machines (NFR-15).

## Decision drivers

- User, mount and network namespaces, allowlist seccomp, read-only root (SEC-01); private tmpfs
  (SEC-03); a fresh sandbox per medium (SEC-02).
- Resource limits with cgroups v2; any breach yields UNSCANNABLE (SEC-04, NFR-04, NFR-05).
- Runs on WSL2 for phases 0–3 and 6–8.
- Simplicity for 1.0.

## Considered options

1. A lightweight isolator (bubblewrap or nsjail) plus cgroups v2.
2. A micro-VM per medium from 1.0.

## Decision outcome

Chosen option 1: **version 1.0 isolates workers with bubblewrap or nsjail and cgroups v2.** The choice
between the two isolators is made in WP-2.1 with tests. Micro-VM isolation is reassessed after 1.0 for
the most demanding deployments (spec §13, "After 1.0" row of §20).

## Consequences

- Good: simple, WSL-compatible, testable in CI.
- Bad: the kernel is shared with the host; a kernel exploit from a worker is not contained the way a
  micro-VM would contain it. Mitigation: minimal seccomp allowlist, no network, unprivileged user,
  per-medium sandbox.
- Follow-ups: WP-2.1 (namespaces, seccomp, read-only root, tmpfs, sandbox escape tests), WP-2.2
  (cgroups v2 limits). Micro-VM evaluation after 1.0.

## Links

- Requirements: SEC-01, SEC-02, SEC-03, SEC-04, SEC-13, NFR-04, NFR-05, NFR-15, ENG-03.
- Related: ADR-01, ADR-03, ADR-05, ADR-13.
