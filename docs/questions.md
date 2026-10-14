# Questions for the owner

Append new questions at the end of "Open". Never delete: move answered ones to "Answered" with the answer
and the date. Format:

```
### Q-<n> · WP-x.y · <REQ-ID> · <short title>
Context: ...
Options: (a) ... (b) ...
Recommendation: ...
Blocking: yes/no
```

## Open

### Q-1 · spec §21 · open questions inherited from the specification
The specification lists open questions (name trademark search, default business formats, EMBER false-positive
ceiling, reference medium, E1 default N, deep mode default and size threshold, HIDDEN_PAYLOAD default, first
commercial engine packs, FS15 network airlock, kiosk user authentication, usbsas reuse, regulated profile as
default). usbsas reuse: answered in Q-35 (2026-10-07). Each phase brief says when an answer is needed.
Blocking: no (each becomes blocking in the phase that needs it)

### Q-10 · WP-0.3 · NFR-07, NFR-19 · requirements with no phase
Context: NFR rows have no Phase column; their phase comes from the work packages that cite them. NFR-07 (same
versions give the same verdict) and NFR-19 (enrichment never blocks a session) are cited by no work package, so
the registry gives them no phase (`phase_source: none`) and no phase gate will require them.
Options: (a) leave them without a phase and cover them in the lock tests of P1 (NFR-07) and P8 (NFR-19)
(b) the owner adds them to work packages in the plan.
Recommendation: (b) at the next plan revision; (a) until then.
Blocking: no.

### Q-17 · WP-0.4 · — · acceptance tests in the traceability matrix
Context: `just trace` reads the nextest report and the pytest report of `just test`. The acceptance tests run in
the isolated gate pytest (`ostia_lock.py gate`, report `target/gate-<dir>.xml`), which loads no plugin, so their
report carries no `req` property and the matrix does not see them. They are the main proof of a phase's MUSTs.
Also, `.claude/skills/phase-gate/SKILL.md` runs `just trace` without `--gate P<n>`, so only rule 1 of Q-14 applies
there.
Options: (a) WP-0.12 (first acceptance directory) teaches the matrix to read `target/gate-*.xml` and map each
testcase to the `@pytest.mark.req` ids of its function (parsed with `ast` from the locked test files, which never
change after the lock); the owner adds `--gate P<n>` to the phase-gate skill (b) the owner allows the req plugin
in the isolated gate run.
Recommendation: (a): the gate run stays isolated, and the mapping is tested on a real gate report.
Blocking: no (blocking for the P1 gate).

### Q-30 · WP-0.8 · UPD-07 · unhashed pytest in rails.yml
Context: `.github/workflows/rails.yml` (rails kit, owner-managed) runs
`python -m pip install --disable-pip-version-check pytest==8.*`: neither pinned exactly nor hash-checked,
which UPD-07 asks of every Python dependency. Agents may not edit the file;
`tests/tooling/test_supply_chain.py::test_python_installs_verify_hashes` leaves it out by name.
Options: (a) the owner pins it with a hash (`pip install --require-hashes -r` a two-line requirements file
in the kit, or `uv tool run --from pytest==8.x.y`) at the next rails update (b) accept it: it only runs the
kit's own self-tests on an isolated runner.
Recommendation: (a), together with pinning `actions/setup-python` (see the Dependabot PR).
Blocking: no.

Also for the owner (WP-0.8): add `deny.toml` (and, if wanted, `tools/supply/python-licences.toml`) to the
rails manifest and the guard, as prompts/P0.md plans ("after this package deny.toml is owner-gated").

### Q-34 · WP-0.9 · — · red-first limits left open
Context: `tools/ci/red_first.py` (WP-0.9) traces changed Python helpers, fixtures (conftest included) and
constants to the tests that use them. It does not trace these:
- Rust helpers and constants;
- tests with the same name in two `mod` blocks of one file;
- `proptest!` blocks;
- Python helper modules that are not conftest (`tests/fakes`, `tooling_support.py`);
- imports a test module changes.
It also does not require that a `feat(<ID>)` commit follows a `test(<ID>)` commit of the same pull request
(spec §18 rule 1 for code changes): Dependabot and tooling commits have none.
Options: (a) leave them, documented in the tool, and revisit when a phase needs them (b) close them now.
Recommendation: (a). Every one of them needs a deliberate weakening to slip through, and the review still
reads each diff.
Blocking: no.

### Q-52 · WP-4.5 (from WP-1.5) · FR-04, SEC-10 · reading ext content owned by other users
Context: the inventory runs unprivileged on the read-only mount. FAT, exFAT and NTFS are mounted with the
orchestrator's uid; ext keeps the on-disk owners and modes, so a real medium from a Linux machine (root's
`lost+found` 0700, other users' files 0600) has content the inventory cannot read. It is recorded as unlisted or
unreadable and the medium is UNSCANNABLE (fail closed). Generated images avoid it (Q-51).
Options: (a) the privileged helper mounts ext through an idmapped read-only mount mapping the on-disk owners to
the orchestrator (b) unreadable objects are read through the raw-read helper (c) keep refusing such media.
Recommendation: decide with the privileged helper in WP-4.5; (a) if the target kernel supports idmapped mounts
for every FR-03 file system there.
Blocking: no (P4).

### Q-53 · WP-1.10, WP-1.11 (from WP-1.5) · FR-14, NFR-05 · bounding and stopping the inventory
Context: `take_inventory` is synchronous, with no deadline, no byte limit and no way to cancel it. A few-MiB
ext4 or NTFS image can hold a sparse file of terabytes: the single read copies zeros until the workspace disk is
full, and a hung FUSE read blocks for ever. The locked `test_scan_time.py` counts mount and inventory in the
FR-14 budget.
Options: (a) WP-1.10/1.11 give the inventory a cancel token and a deadline, checked per chunk and per entry,
and a byte limit (per object and per medium, from the policy's limits) whose breach makes the object
UNSCANNABLE with the limit named (b) run the inventory in a killable process.
Recommendation: (a), designed with the pipeline in WP-1.10 and the scan time in WP-1.11.
Blocking: no.

## Answered

### Q-68 · WP-1.9 · FR-06 · the cab crate replaced by our own cabinet reader (after Q-63)
Context: the owner approved `cab` 0.6.0 in Q-63. During implementation: its decoders are private and its file
reader decodes a folder from its start again for every file (a cabinet of many files decodes for a quadratic
time). The branch reads the cabinet container itself, MSZIP through `flate2` and LZX through `lzxd` 0.2.7 (MIT
OR Apache-2.0, a transitive crate of `cab`, now direct). More of our own code parses hostile input.
Options: (a) keep our reader and `lzxd` (b) go back to the `cab` crate.
Recommendation: (a).
Answer (owner, 2026-10-14): (a).

### Q-67 · WP-1.9 · FR-06 · decoder dictionary cap (7z, rar)
Context: a 7z of about 200 bytes can declare an LZMA2 dictionary of about 4 GiB, which the decoder allocates and
zero-fills before decoding (rust.md: a size cap before allocation); `rars` is capped at 1 GiB today. 7-Zip's
presets use at most 64 MiB, WinRAR's default 32 MiB.
Options: (a) one cap of 256 MiB for both; a larger dictionary is an unsupported method (b) 1 GiB (c) 64 MiB.
Recommendation: (a). The P2 sandbox memory limit must stay above it.
Answer (owner, 2026-10-14): (a).

### Q-66 · WP-1.9 · FR-06 · rar service headers
Context: `rars` extracts files only. RAR service headers carry data too: `STM` (an NTFS alternate stream that
WinRAR restores), `CMT` (the archive comment), `QO` (quick-open copy of the headers), `RR` (recovery record),
and others. An `STM` payload would be CLEAN unscanned.
Options: (a) refuse an archive holding a service with data other than `QO`, `RR` and `CMT`; the comment is
extracted as an entry `[comment]` (b) refuse any service with data other than `QO` and `RR` (a commented rar is
UNSCANNABLE) (c) refuse `STM` and unknown services, ignore comments.
Recommendation: (a).
Answer (owner, 2026-10-14): (a).

### Q-65 · WP-1.9 · FR-06 · iso content outside the tree the worker reads
Context: the WP-1.9 reviews found that the iso reader walks only the Joliet tree (or the primary one), and
ignores UDF descriptors after the terminator, El Torito boot records and bytes past the volume size. A crafted
image can show a harmless file in Joliet and another in its primary/Rock Ridge tree (what Linux mounts) or in
its UDF tree (what Windows mounts): it would be CLEAN unscanned. ADR-18 says these are "not read".
Options: (a) fail closed: walk the primary tree and every Joliet tree and require the same files (extent and
size), else malformed; a UDF descriptor (BEA01, NSR02, NSR03) or a boot record is an unsupported method; bytes
past the volume size are malformed. Bootable and UDF-bridge images (most install images) are UNSCANNABLE until a
later WP reads them (b) as (a), but each El Torito boot image is extracted as an entry instead of refused (its
declared size is often only the loader's) (c) keep one tree and record the gap.
Recommendation: (a).
Answer (owner, 2026-10-14): (a).

### Q-64 · WP-1.9 · FR-06 · ratio when entries share a compressed stream
Context: Q-60 fixed the ratio literally, per entry and per container. In a 7z folder, a cab folder or a solid
rar, entries share one compressed stream: one entry has no compressed size of its own.
Options: (a) the per-entry ratio becomes the ratio of the shared stream: bytes decoded from it so far over its
packed size, checked per chunk; the container ratio is unchanged (b) spread the packed size over entries in
proportion to their declared sizes (c) check only the container ratio for these formats.
Recommendation: (a): it holds while streaming and a compressed bomb in a shared stream is still caught at the
first chunk past the ratio. Recorded in ADR-18.
Answer (owner, 2026-10-14): (a).

### Q-63 · WP-1.9 · FR-06 · crates for 7z, cab and msi; iso and msi read by our code
Context: prompts/P1.md prefers pure-Rust crates. Proposed, all in `ostia-workers` only: `sevenz-rust2` 0.23.0
(Apache-2.0; default features off: LZMA, LZMA2, BCJ, delta and copy; no AES, bzip2, PPMd, zstd, so such entries
are malformed), `cab` 0.6.0 (MIT; stored, MSZIP, LZX; Quantum is malformed), `cfb` 0.15.0 (MIT; the compound
file under an msi). New transitive crates: lzma-rust2 0.21 (Apache-2.0), lzxd 0.2 (MIT OR Apache-2.0),
byteorder 1.5 (Unlicense OR MIT), time 0.3 (MIT OR Apache-2.0), uuid 1 (Apache-2.0 OR MIT), web-time 1 (MIT OR
Apache-2.0). Not proposed: `cdfs` (ISO 9660) pulls `fuser`, `clap` and `libc` as normal dependencies; `msi`
only adds table parsing on top of `cfb`. So iso (ISO 9660 with Joliet names) is read by our own code, and an msi
yields every stream of its compound file (tables, embedded cabinets) under its decoded MSI stream name; an
embedded cabinet is then extracted as a cab one level deeper. Test archives are built by hand-written
standard-library builders in `tests/fixtures/archives.py` (7z with LZMA2 through `lzma`, RAR5 stored, cab
MSZIP, ISO 9660, msi as a compound file with the MSI class id): no new Python dependency (py7zr and pycdlib are
LGPL and py7zr brings eight more packages, several compiled).
Options: (a) these three crates, iso and msi streams by our code (b) also `cdfs` for iso (c) also `msi`.
Recommendation: (a).
Answer (owner, 2026-10-14): (a).
Implementation note (WP-1.9): the `cab` crate is not used after all. Its file reader decodes a folder from its
start again for every file (quadratic on a cabinet of many files) and its decoders are private, so the
cabinet container is read by our code, MSZIP through `flate2` (already in use) and LZX through `lzxd` 0.2.7,
one of the transitive crates listed above, now a direct dependency. `byteorder` and `time` are then not needed.

### Q-62 · WP-1.9 · FR-06 · rar extraction
Context: prompts/P1.md: `unrar` is non-free. The locked p1 tests `test_archive_format_is_extracted[rar]` and
`test_archive_format_tree_is_clean[rar]` need a rar's entries extracted and CLEAN, so "listing only" (every rar
UNSCANNABLE) cannot make them pass. A new pure-Rust crate exists: `rars` 0.10.2 (Apache-2.0, crates.io
2026-10-13; first releases 2026-08; one maintainer; about 110,000 lines; `#![forbid(unsafe_code)]`; reads RAR 1.3
to RAR 7, solid and multi-volume; with default features off it adds only `aho-corasick`, already in the lock).
Options: (a) `rars` =0.10.2, default features off (no writer, no encryption: an encrypted rar is malformed), in
`ostia-workers` only (b) libarchive (BSD-2-Clause, C) through `compress-tools` (MIT OR Apache-2.0): FFI, a C
parser of hostile input inside the worker, `libarchive-dev` on every build host (c) our own reader for RAR5
stored entries only: any compressed rar is malformed, so nearly every real rar is UNSCANNABLE.
Recommendation: (a): pure Rust with no unsafe code, permissive licence, fail-closed through our limits and the P2
sandbox; its youth is the risk, so it is fuzzed by our extraction target and pinned exactly.
Answer (owner, 2026-10-14): (a).

### Q-61 · WP-1.8 · FR-06 · Windows forms of entry paths and device names
Context: the extraction worker refused only `/`-absolute paths, `..` components split on `/`, and NUL. Windows
extractors also honour `..\..\evil.exe`, `\x`, `C:\x`, `C:x` and `\\host\share\x` once a container is transferred,
and the P1 brief lists "devices" among the names to sanitise (`CON`, `aux.txt`, `COM1`). report.md defines only
`/` as a separator.
Options: (a) `\` also separates components for the `..` and absolute checks, a drive letter or a UNC prefix is
absolute, and a component named after a Windows device (CON, PRN, AUX, NUL, COM1-9, LPT1-9, CONIN$, CONOUT$, any
extension, any case) is refused (b) the Windows forms only (c) `/` only, as written.
Recommendation: (a), one sentence in report.md.
Answer (owner, 2026-10-14): (a).

### Q-60 · WP-1.8 · FR-06 · compression ratio on small entries
Context: policy.md checks the ratio per entry and per container while streaming. A small sparse file breaches it:
10 KiB of zeros deflate to about 30 bytes (340:1, over the default 200). ClamAV-style scanners only judge the
ratio past a size.
Options: (a) literal: any entry or container over `max_ratio` breaches, whatever its size (b) the ratio is judged
only once an entry or container has produced more than 1 MiB.
Recommendation: (a): it is the contract as written, and the owner can raise `max_ratio`. (b) would be a contract
change in policy.md.
Answer (owner, 2026-10-14): (a).

### Q-59 · WP-1.8, WP-1.10 · FR-06 · where the recursion over an archive tree lives
Context: WP-1.8's "tests written first" need recursion: nested archives fully listed, too deep, and limits
counted over the whole tree. That means triage, extraction again for each child container, the tree's
cumulative budget, and the depth check. WP-1.10 builds the pipeline that calls it.
Options: (a) WP-1.8 adds the tree driver: a module of a new `crates/orchestrator` that runs triage and
extraction over one medium file's tree, with the budget, returning the objects and each container's failure.
WP-1.10 calls it. (b) WP-1.8 stops at one container with a budget given by its caller; recursion and depth wait
for WP-1.10.
Recommendation: (a): the limit tests then prove the real recursion, and WP-1.10 stays at its size.
Answer (owner, 2026-10-14): (a).

### Q-58 · WP-1.8 · FR-06 · archive crates
Context: prompts/P1.md prefers pure-Rust crates. Proposed, all in `ostia-workers` only (the SEC-05 test already
forbids them elsewhere): `zip` 9.0.3 (MIT; default features off, `deflate-flate2` only: no AES, bzip2, lzma,
zstd), `flate2` 1.1.10 (MIT OR Apache-2.0; `rust_backend`, miniz_oxide), `tar` 0.4.46 (MIT OR Apache-2.0; default
features off, no xattr). New transitive crates: miniz_oxide 0.9.1, adler2 2.0.1, simd-adler32 0.3.10,
crc32fast 1.5.2, typed-path 0.12.3, indexmap 2.14.2, filetime 0.2.29 (MIT, Apache-2.0 or Zlib options).
Options: (a) these three crates (b) a hand-written zip and tar reader on top of `flate2` only.
Recommendation: (a). A zip entry using another method (bzip2, lzma, zstd, AES) is reported as malformed: it
cannot be extracted, so it is UNSCANNABLE.
Answer (owner, 2026-10-14): (a).

### Q-57 · WP-1.8 · FR-06, SEC-05, CTR-04 · how the extraction worker hands back extracted objects
Context: `ostia.engine.v1` has one request and one response, and the object never travels in a message; nothing
can return an archive's entries. In P2 the worker has no network, a read-only root and no view of the workspace.
Options: (a) stream over standard output: per entry a header frame (path, kind, size, time), then its bytes in
chunks, then one final response; the host counts bytes and entries itself and copies each entry into the
workspace as it arrives (b) an output file on descriptor 4 that the host creates in the workspace, the response
listing offsets (a 100,000-entry list does not fit one 16 MiB frame) (c) an output directory the worker fills,
read back by the host. Each needs additive contract fields (minor 2): a budget on `AnalyzeRequest`, a limit name
on `AnalyzeResponse`, and for (a) an `ExtractFrame` message. Details in ADR-18 (proposed).
Recommendation: (a): nothing writable is shared with the sandbox, and the totals hold even against a lying worker.
Answer (owner, 2026-10-14): (a).

### Q-56 · WP-1.7 · FR-05 · trailing dots and spaces in names; dot names and double extensions
Context: Windows drops trailing dots and spaces from a name when it opens it: `invoice.pdf.exe.` and
`invoice.pdf.exe ` run as `invoice.pdf.exe`. report.md's name flags do not mention them, so today
`invoice.pdf.exe.` has an empty last extension: neither an extension mismatch nor a double extension. Also,
report.md says a dot name's first dot is not an extension for `extension_mismatch` but is silent for
`double_extension`; the code reads `.a.b.exe` as stem `.a` with two extensions (a double extension).
Options: (a) both flags first strip trailing dots and spaces from the name, as Windows does, and treat a dot name's
first dot as part of the stem for both flags; an empty last part after that means no extension (b) keep the
literal reading, an empty last part being an extension that matches nothing.
Recommendation: (a), and a sentence added to report.md for both points.
Answer (owner, 2026-10-12): (a).

### Q-55 · WP-1.7 · FR-05 · an object that matches two type rules (polyglot)
Context: report.md's "Types" table does not say which rule wins when several match. A crafted file can: a tar
whose first member is named `MZ…` or `%PDF-…` (the name is at offset 0, `ustar` at 257), an ISO 9660 image whose
free 32 KiB system area starts with `PK\x03\x04` or `MZ` (`CD001` at 32769), a zip with `ustar` at 257. Whatever
type wins, the other view is never extracted or scanned as such (WP-1.8/1.9 pick the extractor by type).
Legitimate files rarely match two of these rules: every rule is at offset 0, 257 or 32769, where real formats
put their own headers.
Options: (a) the table's order is the priority, first match wins (documented in report.md) (b) a container type
(zip, gzip, tar, 7z, rar, cab, iso9660, msi) wins over an opaque one (pe, elf, pdf, png) (c) fail closed: an
object matching two rules "could not be typed" (policy.md R1, UNSCANNABLE); the triage worker answers status
ERROR with a finding naming the matched types, so no contract field changes.
Recommendation: (c): one hidden view would be enough to carry a payload past the scan, and the cost on
legitimate media is close to nothing.
Answer (owner, 2026-10-12): (c).

### Q-54 · WP-1.7 · FR-05, CTR-01 · how the triage worker returns the detected type
Context: the triage worker (WP-1.7) reads the object on descriptor 3 and must hand back its type (`detected_type`,
report.md "Types"). Workers speak `ostia.engine.v1` through the worker host (CTR-01), and `AnalyzeResponse` has no
field for a type: it carries engine identity, status, hint, score and findings. The spec defines no other worker
message. WP-1.8 (extracted children) and WP-1.13 (exFAT attribute listing) will need messages of their own.
Options: (a) one additive field `string detected_type = 9` on `AnalyzeResponse` ("type identified from the
content; set by the triage worker, empty for engines"), appended to `compat.json` with contract minor 1; the
Python stubs are regenerated (b) a new internal package `ostia.worker.v1` for triage, extraction and listings:
cleaner, but it generalizes the codegen, the compatibility check, the Python generator and the golden vectors,
better done once in WP-1.8 where extraction needs real messages (c) no contract change: the triage worker answers
status OK, hint NONE and one finding `{id: "type", evidence: "<type>"}`, which the orchestrator reads.
Recommendation: (a): typed, small, and compatible within v1 (CTR-04). Decided independently of this: the
extension flags (`extension_mismatch`, `double_extension`) depend only on the name and the detected type, so they
are pure functions of the domain (no content read), and type identification is a small magic table written to
report.md's rules (no dependency: `infer` recognises other things and misses `e_lfanew`, ISO 9660 and the MSI
root CLSID).
Answer (owner, 2026-10-12): (a).

### Q-51 · WP-1.5 · FR-04, SEC-10 · ext content the unprivileged orchestrator cannot read
Context: the inventory runs unprivileged on the read-only mount (FAT, exFAT and NTFS are mounted with the
orchestrator's uid; ext keeps the on-disk owners and modes). mke2fs always creates `lost+found` owned by root,
mode 0700, so on every ext medium, generated images included, the inventory cannot list it and records it as
unlisted, which must make the medium UNSCANNABLE (fail closed) and turns the locked ext cases of
`test_file_systems.py` red when not run as root (CI runs as root, so it would not notice). Real media from
Linux machines also hold files owned by other users with modes like 0600.
Options: (a) P1: the generator stages a `lost+found` owned by the invoking user (`mkfs.ext4 -d` then keeps it),
so generated images are fully readable; the inventory keeps refusing what it cannot read (unlisted or
unreadable, UNSCANNABLE); the real-media case is decided in P4 with the privileged helper (idmapped read-only
mount mapping the on-disk owners to the orchestrator, or reads through the raw-read helper) (b) the inventory
skips an unreadable `lost+found` at the root of an ext file system (an empty directory e2fsck owns) and keeps
refusing anything else (c) decide the P4 mechanism now and build it in WP-1.5.
Recommendation: (a): no silent skip, test images that match what P1 can read, and the privilege question
settled where the privileged helper is built. I add a line for it to the P4 open points.
Answer (owner, 2026-10-12): (a). Open for P4: how the kiosk reads ext content owned by other users (idmapped
read-only mount or the raw-read helper), to be settled with the privileged helper.

### Q-50 · WP-1.5 · FR-04, SEC-10 · dependencies of the inventory
Context: the inventory lists extended attributes and NTFS streams (ntfs-3g `user.*` names) on the descriptor it
opened, and hashes each object with SHA-256 and SHA-1. The standard library has no extended-attribute calls;
`sha2 =0.11.0` is already used (policy loader) but SHA-1 is not.
Options: (a) `rustix =1.1.5` (feature `fs`; `flistxattr`, `fgetxattr` on the opened descriptor, safe API;
Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT; already in Cargo.lock through tempfile) and `sha1 =0.11.0`
(MIT OR Apache-2.0, RustCrypto, same `digest` 0.11 as sha2) (b) the `xattr` crate (MIT OR Apache-2.0, built on
rustix) instead of rustix directly.
Recommendation: (a): no new crate for the attributes beyond what the lock already holds.
Answer (owner, 2026-10-12): (a).

### Q-49 · WP-1.5 · FR-04 · split out the exFAT attribute worker
Context: Q-45 put the exFAT hidden and read-only attributes in WP-1.5, read from the image by a sandboxed worker.
That worker is a parser of exFAT directory entry sets (boot sector, cluster chains, NoFatChain, file and stream
entries) with its own fuzz target, and it needs a new message in the worker contract to return a listing
(`ostia.engine.v1` answers carry findings, not inventories). With the inventory, single read, streams,
attributes and workspace copy, WP-1.5 (size M) would become L.
Options: (a) split: WP-1.5 does the inventory over the mount, the single hashed read into the workspace,
streams, extended attributes and the FAT, NTFS and dot-name attributes; a new package (WP-1.5b, after WP-1.5 and
WP-1.6, before WP-1.10) adds the exFAT attribute worker and its contract message (b) keep everything in WP-1.5.
Recommendation: (a). The exFAT hidden and read-only acceptance cases stay red until WP-1.5b; they need WP-1.10
anyway.
Answer (owner, 2026-10-12): (a); the owner added the package to the plan as WP-1.13 (the plan tools accept numeric
ids only), before WP-1.10.

### Q-48 · WP-1.5 · FR-04 · FAT hidden, system and archive attributes
Context: the locked `test_file_systems.py::test_hidden_files_are_marked_hidden` expects the FAT hidden attribute
(fat12/16/32) and report.md lists `system` and `archive` too. The vfat driver exposes them only through the
`FAT_IOCTL_GET_ATTRIBUTES` ioctl (read-only shows in the mode bits, the others nowhere). Every `ioctl` call is
`unsafe` in Rust, even through nix or rustix, and no crate is on `docs/unsafe-allowlist.md`. NTFS attributes come
from ntfs-3g's `system.ntfs_attrib_be` extended attribute (no `unsafe`); exFAT ones need the image worker (Q-45).
Options: (a) a tiny crate `ostia-fat-attributes` with one `unsafe` call (`FAT_IOCTL_GET_ATTRIBUTES` on a
descriptor the inventory opened), listed on the unsafe allowlist by the owner; the kernel already parsed the
directory for the mount, nothing is parsed in Ostia (b) the exFAT image worker of Q-45 also reads FAT12/16/32
directory entries from the image (long names, cluster chains) and returns the attributes per path: no `unsafe`,
but a second parser and a path-matching problem between image names and mounted names.
Recommendation: (a): one reviewed line instead of a parser, and the same data the mount already uses.
Answer (owner, 2026-10-12): (a); the owner listed `ostia-fat-attributes` (`crates/fat-attributes`) on the unsafe
allowlist.

### Q-47 · WP-1.6 · CTR-01, NFR-05 · dependencies of the worker host
Context: the worker host (`crates/sandbox`, prompts/P1.md WP-1.6) must give the worker the object as file
descriptor 3, read-only, and kill the worker's whole process group on a timeout. The Rust standard library
does neither: placing an open file on fd 3 in the child needs `dup2` between fork and exec
(`CommandExt::pre_exec`, which is `unsafe`), and `killpg` is a libc call. `unsafe` is forbidden outside
`docs/unsafe-allowlist.md`, which lists no crate. P2's bubblewrap sandbox will also need to pass descriptors
(`bwrap --seccomp FD`).
Options: (a) two dependencies, no `unsafe` in Ostia: `command-fds =0.3.3` (Apache-2.0, Google; maps open
files to child descriptor numbers) and `nix =0.31.3` (MIT; safe `killpg` and `waitid`, already required by
command-fds). Transitive crates: `bitflags`, `cfg-if`, `libc` (already in Cargo.lock), `cfg_aliases` (MIT,
build only) (b) list `ostia-sandbox` in the unsafe allowlist and call `libc` (`dup2` in `pre_exec`, `killpg`)
(c) no dependency and no `unsafe`: spawn through `/bin/sh -c 'exec 3<"$1"; …'` (the child opens the object by
path) and kill the group with the `kill` command.
Recommendation: (a): no `unsafe` in Ostia, small and maintained crates under allowed licences, and the same
descriptor passing serves P2's sandbox; (c) leaves a shell in every worker launch.
Answer (owner, 2026-10-08): (a), command-fds 0.3.3 and nix 0.31.3.

### Q-46 · WP-1.4 · FR-03, SEC-05 · what the development mount helper tells the mount layer
Context: WP-1.4's mount layer (`crates/media`, behind a `MediaAccess` trait) must report the file system in the
report's vocabulary (`fat12` … `ext4`) and tell an unsupported file system (exit 4) from a mount failure
(exit 5), without parsing the image itself (SEC-05: detection is blkid run by the helper). Today
`tools/dev/loopmount.sh` prints blkid's TYPE (`vfat` for all FAT variants) and exits 1 for both cases. It also
mounts ext2/ext3 with drivers that may hide extended attributes and NTFS with the kernel ntfs3 driver, which
does not expose alternate data streams (Q-45; prompts/P1.md WP-1.5).
Options: (a) one helper change, re-installed once: print the variant (FAT version from blkid), exit 4 for an
unsupported or unrecognised file system, mount ext2/ext3 with the ext4 driver and NTFS with ntfs-3g in both
modes; ADR-17 (proposed) records the drivers (b) the mount layer runs blkid itself, unprivileged, on the image
file, and the helper only changes drivers.
Recommendation: (a): all detection stays in one place, outside the orchestrator.
Answer (owner, 2026-10-08): (a), ADR-17.

### Q-45 · WP-1.4, WP-1.5 · FR-04 · exFAT attributes and ext2 extended attributes are invisible on a mount
Context: found while writing the WP-1.3 generator on the WSL2 kernel 6.6. (1) No exFAT driver there exposes the
hidden and read-only attributes: exfat-fuse has no attribute interface and the kernel's exfat attribute ioctls
are newer than 6.6; the generator sets them in the directory entry set itself. The locked
`test_file_systems.py::test_hidden_files_are_marked_hidden` and `test_read_only_attribute_is_reported` expect
them for exFAT. (2) The kernel ext2 driver there is built without xattr support: an ext2 image holding
`user.*` attributes shows none through `loopmount.sh ro`; the ext4 driver reads ext2 and ext3 with them.
Options: (a) WP-1.5 reads exFAT attributes from the image in a sandboxed worker (the orchestrator never parses
it, SEC-05) and WP-1.4 mounts ext2 and ext3 with the ext4 driver (b) decide in WP-1.4/1.5 with an ADR.
Recommendation: (a), confirmed in the ADR WP-1.5 writes for the NTFS driver (prompts/P1.md).
Answer (owner, 2026-10-08): (a): WP-1.5 reads exFAT attributes from the image in a sandboxed worker;
WP-1.4 mounts ext2 and ext3 with the ext4 driver (Q-46).

### Q-44 · WP-1.3 · FR-03, FR-04 · FAT names and times through the development mount helper
Context: `tools/dev/loopmount.sh` mounted vfat with the kernel defaults: `iocharset=ascii` (Debian and Ubuntu
kernels; utf8 off) and times in `sys_tz`. Through it, any FAT name outside ASCII (accents, the bidi override
U+202E of a trapped name) was refused with EINVAL, both when the generator plants it (`rw-image`) and when
WP-1.4 reads a medium (`ro`); FAT times followed the kernel's time zone instead of UTC (report.md reads FAT
times as UTC). exFAT, NTFS and ext take UTF-8 names already.
Options: (a) add `utf8,tz=UTC` to the vfat options of both modes in `loopmount.sh`; the owner re-installs the
root-owned copy (b) add `mtools` and plant FAT without mounting (c) refuse non-ASCII FAT names until WP-1.4.
Answer (owner, 2026-10-08): (a); the owner re-installs with `sudo tools/dev/setup-debian.sh --install`.

### Q-43 · WP-1.2 · FR-09, ADR-09 · dependencies of the policy loader
Context: the loader verifies an Ed25519 signature over the exact policy bytes, parses strict JSON, and reports
the policy's SHA-256 (`docs/contracts/policy.md`, `cli.md`).
Answer (owner, 2026-10-08): ed25519-dalek =3.0.0 (BSD-3-Clause, `verify_strict`); serde =1.0.229 with derive
and serde_json =1.0.151 (MIT OR Apache-2.0); sha2 declared directly at the version ed25519-dalek resolves
(MIT OR Apache-2.0). The verdict policy lives in `crates/core-domain` (spec §19).

### Q-42 · WP-1.1 · FR-09, FR-10 · worst-of ordering of MALICIOUS and UNSCANNABLE
Context: the spec says both block the medium but does not rank them; the medium verdict is the worst object
verdict (ADR-16).
Options: (a) CLEAN < SUSPICIOUS < UNSCANNABLE < MALICIOUS (b) CLEAN < SUSPICIOUS < MALICIOUS < UNSCANNABLE.
Answer (owner, 2026-10-08): (a), recorded in ADR-16 (accepted).

### Q-41 · P0 gate · NFR-14 · which code the coverage thresholds apply to
Context: at the P0 gate the Rust workspace total was 84.7 % against 90 %: the `ostia-cli` stub had no test and
the `ostia-traceability` crate (the `#[req]` attribute, a dev-dependency never shipped) is at 78.5 %, its
uncovered lines being compile-error paths that run inside rustc during `tests/tooling/test_req_attribute.py`,
where cargo-llvm-cov cannot see them. `just coverage` measured `tools/ci`, run as subprocesses (always 0 %).
Answer (owner, 2026-10-08, "solve all the remaining issues", applied by the agent): NFR-14 applies to the shipped
code: the crates of `crates/` except `ostia-traceability`, and the hand-written code of `workers-py/` (protoc
output excluded). `ostia-cli` gained usage tests (100 %); `just coverage` prints the Rust summary and measures
`ostia_common`. Thresholds are enforced from WP-3.12 (NFR-14).

### Q-40 · WP-0.12 · — · the `dev` feature in lint and unit tests
Context: `just lint` and `just test-rust` build without `ostia-cli/dev`, so code behind `cfg(feature = "dev")`
(the `--dev-engine` path of WP-1.10) is neither linted nor unit-tested; the release guard keys on
`debug_assertions` only.
Options: (a) WP-1.10 adds `--features ostia-cli/dev` to the clippy and nextest runs (a lint configuration
change, owner approval), and the release pipeline (P9) checks that the binary has no `--dev-` flag (b) leave.
Recommendation: (a).
Blocking: no.
Answer (owner, 2026-10-08, the recommendation): (a). WP-1.10 adds `--features ostia-cli/dev` to the clippy and
nextest runs (lint configuration change approved here); P9 checks that release binaries have no `--dev-` flag.

### Q-39 · WP-0.12 · CTR-04 · the v1 JSON schemas are not locked
Context: the locked P1 tests validate every report against `schemas/report.schema.json`, which is in no
`LOCK.sha256` and not in the rails manifest. Loosening it later (dropping a required field, widening an enum)
would make the locked tests check less while still passing.
Options: (a) the owner adds `schemas/report.schema.json` and `schemas/policy.schema.json` to the rails manifest
(`just rails-update`, guard) (b) a tooling compatibility test like `proto/ostia/engine/v1/compat.json`: required
fields stay required, enums only grow, closed objects stay closed (c) leave it to review.
Recommendation: (a) at the lock, then (b) in a later tooling package.
Blocking: no.
Answer (owner, 2026-10-08, the recommendation): (a) at the lock: the owner adds `schemas/report.schema.json` and
`schemas/policy.schema.json` to the rails manifest and the guard (owner-managed files), then (b) in a later tooling
package.
Status (P0 gate, 2026-10-08): not applied yet; `RAILS_FILES` and `PROTECTED_EXACT` do not list the schemas.

### Q-38 · WP-0.12 · NFR-17, FR-09 · where the EMBER thresholds come from
Context: spec §8 says the EMBER high and low thresholds ship with the model in its signed bundle; the P1 policy
contract (ADR-09 follow-up) needs thresholds for a scorer now, so `policy.md` gives each scorer `thresholds`
and says that, when a model bundle also carries thresholds (P2), the stricter of each pair applies.
Options: (a) as written: the policy's thresholds, hardened by the bundle's (b) the bundle's thresholds replace
the policy's in P2 (the P1 tests still pass: they run without a bundle) (c) thresholds only in the policy.
Recommendation: (a): neither source can soften the other.
Blocking: no for the lock (P1 tests run without a bundle); decide before WP-2.x.
Answer (owner, 2026-10-08, the recommendation): (a). The policy's thresholds apply; a model bundle's can only
harden them (the stricter of each pair). WP-2.x implements it.

### Q-37 · WP-0.12 · FR-03..FR-14 · decisions in the P1 contracts to confirm before the lock
Context: the P1 tests freeze the contracts of `docs/contracts/` (cli, report, policy). The agent decided these
points under the owner's delegation, several after the lock review (reviewer and test-auditor):
- symbolic links, reparse points and special files are listed, never followed or read, and UNSCANNABLE (R1):
  a medium holding one is blocked in compliant mode;
- a scan runs with exactly the policy's engines and at least one (exit 2 otherwise): no default role;
- R1 also covers a scorer answering OK without a score, an encrypted archive entry, sizes that do not match the
  declared ones, and an entry path that is absolute or has a `..` component;
- a heuristic engine's MALICIOUS hint is a risky heuristic (R6), never a detection; reputation is an engine role
  (known bad: R2, known good: R3); the scorer's hint is ignored;
- `--on-expiry block` blocks the medium in compliant mode (part of it may never have been listed);
- selective and scan-only modes are locked now (FR-21 is P7);
- names that are not UTF-8 are written with `\xNN` escapes; XATTR objects go to engines as ALT_STREAM;
- zip-based documents (docx, xlsx, odt, jar, apk, epub...) count as consistent with `zip`;
- `policy verify` prints exactly two keys; exit codes 0/2/3/4/5 as in cli.md.
Options: (a) confirm (b) change some of them before `just lock p1` (the tests follow the contracts).
Recommendation: (a). Each choice fails closed; the first one is the strictest reading of "no transfer when an
analysis fails" and could be relaxed later only by a relock.
Blocking: yes, for the lock.
Answer (owner, 2026-10-08, "answer the questions": the recommendation): (a), every decision confirmed as
written in docs/contracts/.

### Q-36 · WP-0.12 · FR-09, FR-10, SEC-10, FR-06 · contracts the P1 lock freezes
Context: the P1 tests write signed policies, observe transfers, check signatures and build archives, before the
packages that build them exist.
Answer (owner, 2026-10-07):
- policy format: a JSON contract `ostia.policy.v1` now (`docs/contracts/policy.md`, `schemas/policy.schema.json`),
  fixed rule order R1–R7, parameters as data; WP-1.2 implements it;
- transfers: a regular `ostia scan --output <dir>` flag and a `transferable` field per object;
- signature files: 64 raw bytes, trusted key 32 raw bytes;
- archives: one extraction test per format (7z, rar, cab, iso, msi) through a fixture builder written in WP-1.9;
  zip, tar, gzip and the limits with the standard library. The rar test expects extraction, not listing.

### Q-35 · WP-0.11 · FR-02, FR-03, SEC-08 · usbsas as the media layer (ADR-05)
Context: the WP-0.11 spike evaluated usbsas v0.3.3 (ADR-05, section "usbsas evaluation"). Every file read
back correctly through usbsas on the FAT32, exFAT, NTFS and ext4 images, 1.5 to 11 times slower than a
kernel mount. Its model does not fit Ostia:
- access to files only, with areas outside files reachable only through a second full read;
- per-file errors instead of fail-closed;
- CLEAN/DIRTY per file;
- no SHA-1, and a plaintext tar;
- ext2 and ext3 refused;
- an unversioned protocol with no length cap, and GPL `.proto` files;
- one integration test, and no fuzzing.
Options: (a) keep the kernel mount for 1.0 and do not reuse usbsas (b) keep the kernel mount for 1.0, and
open an ADR later (P4/P5) for a hybrid that uses only the usbsas user-space USB reader, streaming the raw
device into Ostia's own workers and The Sleuth Kit (c) reuse usbsas as the media layer now.
Recommendation: (b): (a) for 1.0, with the hybrid kept as a measured candidate on the bench.
Blocking: no for P1 (the kernel mount is already the accepted decision).
This also answers the usbsas item of Q-1 (spec §21).
Answer (owner, 2026-10-07): (b). The kernel mount stays for 1.0 (ADR-05); the hybrid that reuses only the
usbsas user-space USB reader is a candidate for a later ADR (P4/P5), after a bench measurement.

### Q-33 · WP-0.9 · — · bench tests in the red-first check
Context: bench tests (the `bench` marker, Rust targets that require the `bench` feature) cannot run in the
red-first CI job: there they look red only because the hardware is missing, or nextest cannot find them.
Options: (a) not run, listed as "not checked (bench)"; the red evidence is the `just test-bench` output in
the MR, and the implementation commit is still required (b) a `Pins:` line required for each.
Recommendation: (a).
Blocking: yes (WP-0.9 design).
Answer (2026-10-07): (a).

### Q-32 · WP-0.9 · — · tests outside test(...) commits
Context: the reviews of WP-0.9 showed that checking only `test(...)` commits lets a vacuous test through
in a `feat(...)` commit, or under a malformed subject, and that CI did not check commit subjects.
Options: (a) every pull-request subject follows the commit convention, and only `test(...)` commits add,
change or remove tests (a test refactor goes in a `test(...)` commit with `Pins:`) (b) the same, but
`refactor` commits may change existing tests (c) the subject format only.
Recommendation: (a).
Blocking: yes (WP-0.9 design).
Answer (2026-10-07): (a).

### Q-31 · WP-0.9 · — · red-first rules
Context: `tools/ci/red_first.py` checks each `test(<ID>)` commit of a pull request.
Answer (2026-10-07), the owner's rules:
- the implementation commit is `feat`, `fix`, `build` or `ci`, carries the same id, and descends from the
  test commit;
- a test that passes at its commit, because it pins behaviour that is already correct, is listed on a
  `Pins: <test ids>` line of the commit message (a pin may name one parametrized case); the tool prints
  every pinned test;
- the check runs in CI on every pull request, for Rust and Python (job `red-first`).

### Q-29 · WP-0.8 · UPD-07, NFR-11 · licences allowed for the Python dependencies only
Context: the review of WP-0.8 noted that MIT-0 (cffi, via cryptography), 0BSD (chardet, via cyclonedx-bom)
and PSF-2.0 (typing_extensions, defusedxml) had been added to the shared allowlist of `deny.toml`, which
would have allowed them for Rust crates too; approving a licence is an owner act.
Options: (a) Python only: `deny.toml` keeps the brief's list plus MPL-2.0; the three licences go in
`[allow] python-only` of `tools/supply/python-licences.toml` (b) everywhere (c) refuse.
Recommendation: (a).
Blocking: yes (licence).
Answer (2026-10-07): (a).

### Q-28 · WP-0.8 · NFR-11 · licence check of the Python dependencies
Context: the WP-0.8 scope names cargo-deny for licences (Rust only); NFR-11 asks for licence-checked dependencies.
Options: (a) a stdlib script checks the licences in the CycloneDX SBOM of the Python environment against the
`deny.toml` allowlist, with an explicit alias table for non-SPDX metadata; it fails on a missing or unknown licence
(b) Rust only for now.
Recommendation: (a).
Blocking: yes (scope).
Answer (2026-10-07): (a), in WP-0.8.

### Q-27 · WP-0.8 · NFR-11 · network access of `just audit`
Context: cargo-audit and cargo-deny fetch the RustSec advisory database (github.com/rustsec/advisory-db);
pip-audit queries the PyPI vulnerability service. A new advisory then fails CI, even on an unrelated change.
Options: (a) `just check` runs `just audit`, so any advisory blocks (fail closed); an advisory that does not apply
is ignored one by one in `deny.toml`, with the owner's approval (b) licences and pins in `check`, advisories in a
separate non-blocking job.
Recommendation: (a). Tests stay offline (licences, sources, pins, SBOM).
Blocking: yes (network).
Answer (2026-10-07): (a).

### Q-26 · WP-0.8 · UPD-07 · MPL-2.0 in the licence allowlist
Context: MPL-2.0 is a file-level copyleft. No Rust dependency uses it today; the Python dev tools hypothesis,
pathspec (via mypy), certifi and fqdn (via pip-audit) do.
Options: (a) allow it everywhere, unmodified (b) Python dev tools only (c) refuse it.
Recommendation: (a): unmodified MPL-2.0 code can be distributed in an Apache-2.0 product.
Blocking: yes (licence).
Answer (2026-10-07): (a).

### Q-25 · WP-0.8 · UPD-07, NFR-11 · supply-chain tools
Context: WP-0.8 needs cargo-deny 0.20.2 (MIT OR Apache-2.0), cargo-audit 0.22.2 (Apache-2.0 OR MIT) and
cargo-cyclonedx 0.5.9 (Apache-2.0), installed with `cargo install --locked` and pinned in `tools/dev/versions.env`,
and pip-audit 2.10.1 (Apache-2.0) and cyclonedx-bom 7.5.0 (Apache-2.0) in a new uv dependency group `audit`,
hash-locked in `uv.lock`. Their dependencies are MIT, BSD, Apache-2.0, ISC, PSF-2.0, 0BSD and MPL-2.0 (certifi,
fqdn). None of them is shipped.
Options: (a) approve all (b) Rust tools only.
Recommendation: (a).
Blocking: yes (new tools).
Answer (2026-10-07): (a).

### Q-24 · WP-0.6 · NFR-06 · CI time budget for fuzzing
Context: the repository is public (free Actions minutes) but the owner prefers to limit CI use.
Options: (a) 60 s per push and pull request, 30 min every night on a cached corpus (b) 30 min weekly
(c) no scheduled run.
Recommendation: (a), as prompts/P0.md asks.
Blocking: yes (CI configuration).
Answer (2026-10-05): (a).

### Q-23 · WP-0.6 · NFR-06 · fuzzing tools and the NCSA licence
Context: cargo-fuzz needs a nightly toolchain; the fuzz crate depends on libfuzzer-sys, whose bundled libFuzzer
is under NCSA (a permissive BSD-like licence) in addition to MIT OR Apache-2.0.
Options: (a) cargo-fuzz 0.13.2 (MIT OR Apache-2.0), libfuzzer-sys 0.4.13 ((MIT OR Apache-2.0) AND NCSA) in the
fuzz crate only (never shipped), nightly-2026-10-04 pinned for fuzzing only (b) another fuzzer.
Recommendation: (a); WP-0.8's deny.toml allows NCSA for the fuzz crate only.
Blocking: yes (new dependencies, licence).
Answer (2026-10-05): (a).

### Q-22 · WP-0.5 · CTR-02 · validating hint and finding severity
Context: the decoders checked status strictly but accepted any hint (-1, 99) and any severity (up to 2^32-1),
although the contract says severity is 0 to 4 and the hint feeds the verdict policy.
Options: (a) decoders refuse a hint outside the enum (HINT_UNSPECIFIED allowed: an engine reporting ERROR or
only a score need not set it) and a severity above 4 (`invalid_response`) (b) leave it to the policy (WP-1.x).
Recommendation: (a): fail closed at the boundary, as for status.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-21 · WP-0.5 · — · clippy on prost's generated code
Context: prost's generated helpers (`as_str_name`, `from_str_name`) trip clippy pedantic `must_use_candidate`
and `doc_markdown` (15 findings, none from our `.proto`).
Options: (a) `#[allow(clippy::must_use_candidate, clippy::doc_markdown)]` on the generated module only
(b) rewrite the generated file in build.rs.
Recommendation: (a), as Q-19 for Python.
Blocking: yes (lint suppression).
Answer (2026-10-05): (a).

### Q-20 · WP-0.5 · — · mypy-strict stubs for the generated Python code
Context: protoc's own `.pyi` fails `mypy --strict` (bare `Mapping` twice).
Options: (a) mypy-protobuf 5.1.0 (Apache-2.0, dev) as protoc plugin: strict-clean stubs (b) a mypy override
disabling `type-arg` for the generated module.
Recommendation: (a).
Blocking: yes (new dependency or type-check exception).
Answer (2026-10-05): (a).

### Q-18 · WP-0.5 · CTR-01..04 · dependencies for the Protobuf contracts
Context: WP-0.5 needs Protobuf code generation and runtimes in Rust and Python, offline (no protoc installed).
Options: (a) Rust: prost 0.14.4, prost-build 0.14.4 (Apache-2.0), protox 0.9.1 (MIT OR Apache-2.0, pure-Rust
protobuf compiler, build-time), thiserror 2.0.21 (MIT OR Apache-2.0), proptest 1.11.0 (MIT OR Apache-2.0, dev);
Python: protobuf 7.36.2 (BSD-3-Clause, runtime), grpcio-tools 1.84.0 (Apache-2.0, dev, bundles protoc),
types-protobuf 7.35.1.20260906 (Apache-2.0, dev) (b) install protoc/buf on every machine.
Recommendation: (a).
Blocking: yes (new dependencies).
Answer (2026-10-05): (a), all approved.

### Q-19 · WP-0.5 · — · generated Python code and ruff
Context: protoc's `engine_pb2.py`/`.pyi` (committed) fail ruff (7 findings, formatting).
Options: (a) exclude the generated files from ruff; mypy checks them through the `.pyi`; a test keeps them in sync
with the `.proto` (b) run ruff --fix and format on the generated files (c) build classes at runtime (untyped).
Recommendation: (a).
Blocking: yes (lint configuration).
Answer (2026-10-05): (a).

### Q-4 · WP-0.1 · NFR-09, NFR-15 · requirement tags of the tooling tests
Context: P0.md says the seeded-bad-sample tests are NFR-09/NFR-15 tests "check the wording". NFR-09 is about
`unsafe`, NFR-15 about Debian/WSL portability.
Options: (a) seeded `unsafe` and clippy tests → NFR-09; CI-on-Debian and toolchain pin → NFR-15;
rustfmt, ruff, mypy, commit-msg, JUnit-skip and acceptance-plan tests → TOOLING (b) tag all lint tests NFR-09/NFR-15.
Recommendation: (a), it keeps the matrix honest.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-5 · WP-0.1 · NFR-15 · CI image before WP-0.2
Context: NFR-15 is verified by "CI on a Debian image"; WP-0.2 builds the pinned CI image. The dev machine is
Ubuntu 24.04 on WSL2, not Debian.
Options: (a) `ci.yml` runs in a `debian:13` container now, replaced by the WP-0.2 image (b) `ubuntu-latest` until WP-0.2.
Recommendation: (a).
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a); WP-0.2 keeps debian:13 and adds the dev container built from the same package and version lists.

### Q-6 · WP-0.1 · — · NOTICE copyright line and Rust edition
Context: `NOTICE` needs a copyright holder; the brief allows edition 2021 or the current one.
Options: NOTICE "Copyright 2026 Matthias Vaytet and the Ostia contributors"; edition 2024 (resolver 3), toolchain 1.99.0.
Recommendation: as stated.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): as stated.

### Q-7 · WP-0.1 · NFR-09 · how an allowlisted crate uses unsafe
Context: the workspace sets `unsafe_code = "forbid"`. Under `forbid`, a local `#![allow(unsafe_code)]` is a
compile error (E0453, proven by a tooling test), so a crate listed in `docs/unsafe-allowlist.md` cannot simply
override it. The tooling test requires `lints.workspace = true` for every crate not in the allowlist.
Options: (a) a listed crate declares its own full `[lints]` table (copy of the workspace one with
`unsafe_code = "deny"`) and allows unsafe per block with a justification comment; a future test checks that
the copy matches the workspace table apart from that line (b) the workspace uses `deny` instead of `forbid`.
Recommendation: (a); it keeps `forbid` for every other crate.
Blocking: no (first needed by the sandbox or media crates, P2/P4).
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-8 · WP-0.1 · — · linting locked acceptance directories
Context: ruff and mypy also check `tests/acceptance/`. Once a directory is locked, a later ruff or mypy upgrade
could flag it and break `just check`, and only the owner can change it (relock).
Options: (a) keep linting it and pin tool upgrades so that they are checked before locking (b) exclude locked
acceptance directories from ruff and mypy (a test-lever change, owner approval).
Recommendation: (a) for now; revisit at the first tool upgrade after `lock-p1`.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a); revisit at the first tool upgrade after `lock-p1`.

### Q-11 · WP-0.2 · NFR-15 · privileged path for image mounts in development
Context: P0.md prefers FUSE without root, sudo as fallback. ntfs-3g needs setuid root to mount as a user and
loop devices need root, so an unprivileged path would only cover some file systems.
Options: (a) one privileged path: `loopmount.sh` runs as root (CI container root; locally `sudo -n` on a
root-owned copy `/usr/local/sbin/ostia-loopmount` installed by `setup-debian.sh --install`); kernel driver when
the kernel offers the type, else the FUSE driver run as root on the read-only loop device (b) unprivileged FUSE
where possible plus sudo for the rest.
Recommendation: (a). The sudoers line names only the root-owned copy: a sudoers rule on a script in the
user-writable repository would amount to giving root to anyone who can edit it.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a). On this WSL kernel exFAT and NTFS have no kernel module, so they are mounted with exfat-fuse and
ntfs-3g; the kernel-driver path for them is exercised in CI and on the Debian bench (P4).

### Q-12 · WP-0.2 · NFR-15 · loop mounts in CI
Context: the `ci` job runs in a `debian:13` container, which cannot attach loop devices or mount without
privileges, so the image smoke tests would fail there.
Options: (a) run the `ci` container with `--privileged` (b) run the image tests in a separate job on the
runner host.
Recommendation: (a): one job, same container, same `just check`.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-13 · WP-0.2 · NFR-15 · publishing the CI image
Context: P0.md asks for a dev container identical to the CI image. Publishing an image to a registry is an
outward-facing act and needs credentials.
Options: (a) one Dockerfile in `.devcontainer/` built locally; CI keeps installing from the same single sources
(`tools/dev/packages.txt`, `tools/dev/versions.env`) on `debian:13`, and a test checks the parity (b) publish the
image to GHCR and use it in CI.
Recommendation: (a) for now; (b) when CI time matters.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-15 · WP-0.2 · NFR-15 · where the development helper mounts images
Context: P0.md says the dev mount helper mounts under `target/mnt/<name>`. The review showed that a mount point
inside a directory the caller controls lets the caller redirect a root mount with a symlink (for example
`target/mnt -> /`, name `root`), which turns the sudoers rule into root for the developer account.
Options: (a) mount points under the root-owned `/run/ostia-loopmount/<uid>/<name>`, umount by name; the helper
opens the image once and works only through that descriptor (b) keep `target/mnt/<name>` and validate the path
through an opened directory descriptor.
Recommendation: (a): simpler, no race to get right; fixture generators read the mount point the helper prints.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-16 · WP-0.4 · — · how the matrix knows which Rust test proves which requirement
Context: the first matrix read `#[req]` from the Rust sources and matched function names against the nextest
report. The review showed false coverage: a failing tagged test covered by a passing test with the same name in
another module, a commented-out tag still counted, tags the scanner could not attach skipped silently.
Options: (a) the attribute makes the test print one `ostia-req: <ids>` line; nextest keeps the stdout of passing
tests in its JUnit report (`store-success-output = true`), so the report alone says which test ran, passed and
proves what; `#[req]` must sit above `#[test]` (otherwise a compile error); the sources are only scanned to check
ids (b) compute full module paths from the sources (files, inline `mod` blocks) and match exactly.
Recommendation: (a): one source of truth, symmetric with the pytest property; (b) needs a Rust parser to be exact.
Blocking: no.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-14 · WP-0.4 · — · traceability CI rules
Context: P0.md asks the owner to confirm the rules before WP-0.4 is coded: (1) always, unknown ids fail and a
requirement cited by a ticked work package without a passing test fails; (2) `just trace --gate P<n>` fails on
any MUST of phase P<n> without a passing test, `--gate all` on any MUST of the spec.
Options: (a) as proposed (b) gate every MUST of the active phase on every CI run.
Recommendation: (a): CI stays green during a phase, the gate bites at `/phase-gate`.
Blocking: yes for WP-0.4.
Answer (2026-10-05, decided by the agent under the owner's delegation "prends les décisions"): (a).

### Q-9 · WP-0.3 · — · PyYAML for requirements.yaml
Context: the registry is `requirements.yaml`; generating it, validating the committed file against its JSON
schema and reading it in WP-0.4 needs a YAML library. The standard library has none.
Options: (a) PyYAML 6.0.3 (MIT), `safe_load`/`safe_dump` only, plus types-PyYAML 6.0.12.20260906 (Apache-2.0)
for mypy (b) no dependency: write the registry as JSON (`requirements.json`), diverging from the name in P0.md.
Recommendation: (a).
Blocking: yes (new dependency).
Answer (2026-10-02): (a) PyYAML and types-PyYAML approved.


### Q-2 · WP-0.1 · — · CODEOWNERS handle
Context: `.github/CODEOWNERS` is a rails file (agents cannot edit it); it still holds `@OWNER`. The owner
gave `@Barbidou`, but the git remote is `github.com/barbidoux/ostia`.
Options: (a) `@barbidoux` (matches the remote) (b) `@Barbidou` as given.
Recommendation: (a) if that is the GitHub account; the owner edits the file and runs `just rails-update`.
Blocking: no for WP-0.1 code; yes before the first push with branch protection.
Answer (2026-10-02): `@barbidoux` (https://github.com/barbidoux). The owner edits the file and runs `just rails-update`.

### Q-3 · WP-0.1 · — · Python dev dependencies and the MPL-2.0 licence of hypothesis
Context: P0.md lists the dev dependencies pytest 9.1.1 (MIT), hypothesis 6.168.3 (MPL-2.0), ruff 0.16.10 (MIT),
mypy 2.4.0 (MIT), jsonschema 4.26.0 (MIT), pytest-cov 7.1.0 (MIT), cryptography 50.0.2 (Apache-2.0 OR BSD-3-Clause),
plus dev tools pre-commit 4.6.2 (MIT, via uvx), cargo-nextest 0.9.146 and cargo-llvm-cov 0.9.1 (Apache-2.0/MIT).
hypothesis is MPL-2.0 (file-level copyleft), test-only, never shipped.
Options: (a) approve all, hypothesis as a test-only dependency (b) approve all but hypothesis.
Recommendation: (a).
Blocking: yes (new dependencies).
Answer (2026-10-02): (a) approved, hypothesis as a test-only dependency.
