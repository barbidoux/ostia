# ADR-17: Development mount layer — ntfs-3g for NTFS, the ext4 driver for ext2/3/4, detection by the helper

- Status: proposed (2026-10-08; the owner chose the helper change in Q-46 and the exFAT worker in Q-45)
- Date: 2026-10-08
- Deciders: Matthias Vaytet (owner)
- Source: FR-03, FR-04, DEEP-05, SEC-05; prompts/P1.md WP-1.4, WP-1.5; `docs/questions.md` Q-44, Q-45, Q-46;
  `tools/dev/loopmount.sh`

## Context and problem statement

P1 scans disk images through a development mount layer (`crates/media`, `MediaAccess` trait, WP-1.4) that
calls the root-run helper `tools/dev/loopmount.sh`. The report needs the file system in its own vocabulary
(`fat12` … `ext4`), an unsupported file system must be told from a mount failure (exit 4 against exit 5), and
WP-1.5 must list NTFS alternate data streams and ext extended attributes (FR-04, DEEP-05). On the WSL2
development kernel, and possibly elsewhere:
- the kernel `ntfs3` driver does not show alternate data streams; ntfs-3g shows them as `user.<stream>`
  extended attributes (`streams_interface=xattr`, its default);
- the kernel ext2 driver may be built without xattr support and then hides `user.*` attributes the image holds;
  the ext4 driver reads ext2, ext3 and ext4 with them;
- no exFAT driver exposes the hidden and read-only attributes (exfat-fuse has no interface for them, the kernel
  exfat attribute ioctls are newer than 6.6).
The orchestrator must not read the image to find its file system (SEC-05).

## Decision drivers

- One behaviour on every machine: the same image gives the same inventory on WSL2, in CI and on the bench.
- Detection stays outside the orchestrator: the helper's blkid probes, the layer reads only the helper's answer.
- Fail closed: a missing driver is a failure, never a mount that silently hides streams or attributes.

## Considered options

1. The helper chooses the drivers and reports the variant and an unsupported file system (exit 4).
2. The layer runs blkid itself, unprivileged, on the image file; the helper only changes drivers.
3. Keep the kernel drivers and read streams and attributes with offline tools in workers.

## Decision outcome

Option 1. `tools/dev/loopmount.sh`:
- prints the file system as `fat12`, `fat16`, `fat32` (blkid VERSION), `exfat`, `ntfs`, `ext2`, `ext3`, `ext4`
  on its last line, with the mount point;
- exits 4, mounting nothing, for no file system, one outside FR-03, a partition table (refused in P1, cli.md)
  or ambivalent signatures; exits 5 when the driver refuses a recognised file system (damaged); exits 1 for
  its own failures (blkid failing included);
- mounts NTFS with ntfs-3g only (`streams_interface=xattr`; a machine without it cannot mount NTFS), ext2/3/4
  with the ext4 driver, FAT with the kernel vfat driver (`utf8,tz=UTC`, Q-44), exFAT with the kernel driver
  when present, else exfat-fuse.
The layer maps exit 4 to the refusal `unsupported_file_system` (exit 4 of `ostia scan`), exit 5 to a mount
failure and anything else to a helper failure (both exit 5).
exFAT hidden and read-only attributes are read from the image by a sandboxed worker in WP-1.5 (Q-45), never by
the orchestrator.

## Consequences

- Good: the report's file system and the refusal come from one place; streams and ext attributes are visible
  on every supported kernel; the P4 privileged helper (WP-4.5) inherits a precise contract (variant, exit 4).
- Bad: NTFS depends on ntfs-3g (GPL, run as a separate process by root, development only); the production
  helper must make its own driver choice, recorded in its own ADR.
- ntfs-3g is installed by `tools/dev/packages.txt` everywhere the helper runs, and `setup-debian.sh --check`
  reports it missing otherwise.
- Known P1 limit: the layer waits for the helper without a deadline (a driver hanging on a crafted image hangs
  the scan); a killed `sudo` cannot stop the root helper it started, so the deadline belongs to the privileged
  helper of WP-4.5, which owns the mount namespace.

## Links

- Q-44 (FAT names and times), Q-45 (exFAT attributes, ext2 xattrs), Q-46 (helper contract)
- `crates/media` (WP-1.4), WP-1.5 (inventory), WP-4.5 (privileged helper)
