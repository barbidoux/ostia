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

## Answered

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
