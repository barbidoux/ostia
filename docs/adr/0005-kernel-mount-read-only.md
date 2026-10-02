# ADR-05: Read-only kernel mount in a dedicated namespace for 1.0

- Status: accepted (to be revisited by the usbsas evaluation, WP-0.11)
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §3, §13

## Context and problem statement

Ostia has to read the files of untrusted media. The file-system driver that mounts them is attack
surface: a malformed file system can target the kernel's driver (threat M1). The open-source kiosk
usbsas (CEA) already provides a user-space USB and file-system stack written in Rust, "stronger than a
kernel mount" (spec §3), but it is GPLv3 and cannot be merged into an Apache-2.0 core (ADR-02).

## Decision drivers

- Read-only access with `ro,noexec,nosuid,nodev` (FR-02) to FAT12/16/32, exFAT, NTFS, ext2/3/4, refusing
  others (FR-03).
- No root except a minimal mount and raw-read helper that validates every parameter (NFR-10, SEC-08).
- Licence compatibility (Apache-2.0).
- Effort and maturity for 1.0.

## Considered options

1. Kernel mount, read-only, in a dedicated namespace, through the minimal privileged helper.
2. Reuse usbsas as a separate process (GPLv3, after licence review).
3. Write Ostia's own user-space USB and file-system stack now.

## Decision outcome

Chosen option 1 for 1.0, **unless the phase 0 evaluation of usbsas (WP-0.11) concludes otherwise.**
Option 3 is rejected: usbsas already does this in Rust. Option 2 stays open: as GPLv3 it can only ever
run as a separate process.

## Consequences

- Good: mature drivers for every required file system; simple helper; works for development with loop
  devices.
- Bad: the kernel driver parses hostile structures. Mitigation: read-only mount, dedicated namespace,
  kernel modules of unsupported file systems disabled (SEC-08).
- Bad: on WSL2 the kernel may lack exFAT and NTFS modules; FUSE (`ntfs-3g`, `exfat-fuse`) or the Debian
  bench covers that (WP-0.2).
- Follow-ups: WP-0.11 (time-boxed usbsas spike: licence, process interface, file systems, performance on
  the reference images; no code copied) updates this ADR with a recommendation and evidence, status
  "proposed", for the owner to decide. WP-1.4 (development mount layer), WP-4.5 (production helper).

## Links

- Requirements: FR-02, FR-03, NFR-10, SEC-08, SEC-12, DEEP-01.
- Related: ADR-02, ADR-04, ADR-13. Open question: usbsas reuse (spec §21, docs/questions.md Q-1).
