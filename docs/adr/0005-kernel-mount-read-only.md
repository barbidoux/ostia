# ADR-05: Read-only kernel mount in a dedicated namespace for 1.0

- Status: accepted for 1.0. The usbsas evaluation (WP-0.11, below) recommends keeping it; the owner
  accepted that recommendation on 2026-10-07 (docs/questions.md Q-35, option b).
- Date: 2026-10-02 (evaluation added 2026-10-07)
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
  "proposed"; the owner accepted it on 2026-10-07 (Q-35, option b). WP-1.4 (development mount layer),
  WP-4.5 (production helper).

## usbsas evaluation (WP-0.11)

### What was evaluated

| Item | Value |
|---|---|
| Version | usbsas v0.3.3, commit `5b9ef006ed4794d23fe532ad1d1c4e1f5932464b` (2026-01-29), github.com/cea-sec/usbsas |
| Method | A shallow clone outside the repository; nothing was copied into Ostia. The code and docs were read; the code was built with the `mock` feature and run on generated images. Time box: 2 sessions. |
| Machine | WSL2, kernel 6.6.87.2, 12 threads, rustc 1.99.0 |

### Findings

| Topic | Finding | Evidence (usbsas tree) |
|---|---|---|
| Licence | All crates are GPLv3-or-later. The vendored ntfs-3g (NTFS writing only) is GPLv2+, and the vendored FatFs (FAT/exFAT) is BSD-1. libusb is built in statically and libseccomp is linked; both are LGPL-2.1. | `LICENSE`, `*/Cargo.toml`, `usbsas-fsrw/{ff,ntfs3g}` |
| Licence, grey area | Ostia would drive usbsas through its protobuf protocol. The `.proto` files are GPL, and code generated from them for an Apache-2.0 client may be a derived work. The way out is a small GPL adapter process, or a written clarification from CEA. | `usbsas-proto/proto/*.proto3` |
| Process interface | `usbsas-usbsas` is the entry point, reached through inherited pipes or one Unix-socket connection (`-s`). The internal processes (`dev2scsi`, `scsi2files`, `files2tar`…) are restarted for every transfer. Messages are framed with a u64 little-endian length that has no cap. The protocol carries no version and is still 0.x. The selected files come out as a plaintext tar. | `doc/architecture.md`; `usbsas-comm/src/lib.rs:114-135` |
| Media access | It reads USB mass-storage devices only, through libusb (`/dev/bus/usb`), and never takes a block-device path. It blacklists `usb_storage` and `uas`, which conflicts with a kernel mount on the same host. The `mock` feature reads an image file instead, but then seccomp is not applied in `dev2scsi`. | `usbsas-dev2scsi/src/lib.rs:96-137`; `assets/usbsas.conf` |
| File systems | It reads FAT12/16/32 and exFAT (FatFs), NTFS (`ntfs` crate), ext4 (ext4-rs from git) and ISO9660 (a personal fork from git), with MBR, GPT, or no partition table. **ext2 and ext3 are refused.** Ostia requires both (FR-03), and refuses ISO9660. | `usbsas-dev2scsi/src/lib.rs:310-324` |
| Sandbox and privileges | Each process gets its own seccomp policy that kills it on a forbidden call. Landlock is applied only when the kernel supports it. It uses no namespaces and needs no root: a `usbsas` user with a udev rule. | `usbsas-sandbox/src/*` |
| Analysis | It sends the tar to an HTTP analyzer that answers CLEAN or DIRTY per file; files left unknown are not copied. A file that cannot be read is marked as an error and the transfer goes on, which is not fail-closed. | `doc/usage.md`; `usbsas-usbsas/src/states.rs` |
| Areas outside files | Only a full-device dump (`ImgDisk`, a separate session, so a second read of the medium). Slack, unallocated space and deleted entries are not exposed. | `usbsas-proto/proto/usbsas.proto3` |
| Hashes | SHA-256 is computed during the tar copy. There is no SHA-1. | `usbsas-usbsas/src/states.rs` |
| Maturity | One unit test, and one integration test of 5 scenarios on a single 25 MiB image. No fuzzing. Some branches still end in `unimplemented!()`. CI runs fmt, cargo audit, clippy and the tests. Debian packages and a live ISO are published. | `.github/workflows/`, `tests/` |
| Build | 785 crates in `Cargo.lock`. It needs pkgconf, clang, cmake, protobuf, libseccomp, libusb, libudev and libkrb5 (plus libfuse3 for the tools). The release build of the needed binaries took 1 min 40 s here. | `doc/build.md` |

### Measurements

The corpus was generated with seed 20261007: 1,040 files, 230.1 MiB in total (1,000 files of 16–128 KiB in
70 directories, plus 40 files of 2–6 MiB). It was copied onto four 512 MiB images with no partition table,
made with `tools/dev/mkimage.sh` and filled through the `rw-image` mode of the helper.

Each run read every file once and hashed it with SHA-256, the way Ostia reads a medium. Times are wall-clock
seconds over 3 runs. In every run, all 1,040 hashes matched the corpus.

| File system | Kernel, read-only mount (`loopmount.sh ro`) | usbsas (`mock` + `usbsas-fuse-mount`) | Ratio |
|---|---|---|---|
| FAT32 | 0.77, 0.77, 0.78 (kernel driver) | 7.98, 8.62, 8.22 | about 10 to 11× |
| exFAT | 1.18, 1.05, 1.13 (FUSE driver on WSL2) | 3.48, 3.62, 2.87 | about 3× |
| NTFS | 1.10, 1.43, 1.81 (ntfs-3g, FUSE) | 2.37, 2.36, 2.68 | about 1.5 to 2× |
| ext4 | 1.40, 1.05, 1.04 (kernel driver) | 2.81, 2.91, 2.43 | about 2.5× |

Limits of these numbers:
- The image file sits in the page cache on both sides.
- The usbsas path includes FUSE, but not the USB and SCSI transport, and not seccomp (mock mode).
- They do not test resistance to malformed file systems.
- `usbsas-imager` (a raw stream of the device) could not be measured: in mock mode, `dev2scsi` stops at the first exchange ("failed to fill whole buffer"). Its throughput on a real device is left to the bench (P4).

Even at the worst ratio (FAT32, about 8 s for 230 MiB), the media layer would not decide the 10-minute
budget of NFR-01. The functional gaps decide the choice.

### Recommendation (accepted by the owner, 2026-10-07)

**Keep option 1, the read-only kernel mount, for 1.0. Do not reuse usbsas as the media layer.**
- The main blockers are its model:
  - access to files only, with areas outside files reachable only through a second full read;
  - per-file errors where Ostia fails closed;
  - CLEAN/DIRTY per file, where Ostia has its own verdict policy;
  - no SHA-1, and a plaintext tar outside the encrypted workspace.
- Coverage is short: ext2 and ext3 are refused.
- The protocol is unversioned and has no length cap, and the `.proto` files raise a licence grey area.
- It is immature for a security component: one integration test, and no fuzzing of its parsers.

**Candidate for later, a new ADR if the owner wants it (P4 or P5):** a hybrid that reuses only the
user-space USB reader (`usbsas-imager`, or `dev2scsi`) as a separate GPL process.
- It would stream the raw device to Ostia, which would hash and encrypt it as it arrives.
- Ostia's own sandboxed file-system workers and The Sleuth Kit would then work on that single image.
- The kernel's USB-storage and file-system drivers would never touch the device, the medium would be read
  once, and ext2/3 would stay covered.
- It costs a full-device copy (time and space), and needs:
  - the licence review of the protocol;
  - a bench measurement on real devices;
  - an upstream fix for the mock-mode failure seen above.
- To consider alongside it: contributing upstream (fuzzing, a length cap, ext2/3) where the licences
  allow.

## Links

- Requirements: FR-02, FR-03, NFR-10, SEC-08, SEC-12, DEEP-01.
- Related: ADR-02, ADR-04, ADR-13. Open question: usbsas reuse (spec §21, docs/questions.md Q-1).
