# P1 · Pipeline — acceptance tests

Written in WP-0.12 (`/phase-lock P1`), locked by the owner (`lock-p1`, with `lock-common` for
`tests/acceptance/common/`). Black-box: the tests drive the `ostia` binary built with the development flags,
validate every report against `schemas/report.schema.json`, and build their inputs with the public generators
of `tests/fixtures/` and the fake engine of `tests/fakes/`. Contracts: `docs/contracts/cli.md`,
`docs/contracts/report.md`, `docs/contracts/policy.md`.

Run them (debug build with the dev flags, then the isolated gate pytest):

```
cargo build --workspace --locked --features ostia-cli/dev
python3 tools/lock/ostia_lock.py dry-run p1 -- -m "not bench"
```

They need the development mount helper (`tools/dev/loopmount.sh` behind its sudoers rule, or the privileged CI
container), `mkfs.minix` (util-linux) and the disk-image tools of `tools/dev/packages.txt`. No test needs USB
hardware: none carries the `bench` marker.

Notes for the packages that turn them green:
- WP-1.3 and WP-1.4: FAT and exFAT store local times without a zone; the generator writes them as UTC
  (`TZ=UTC` for mtools) and the mount layer reads them as UTC (`tz=UTC`), so `modified` round-trips.
- WP-1.3 implements `build_image(fs, files)` exactly as documented in `common/images.py` (keys `path`,
  `content`, `hidden`, `read_only`, `modified`, `streams`, `xattrs`, `symlink`); WP-1.9 implements
  `build_archive(fmt, entries)` as documented in `common/archives.py`.
- The owner decided at the lock (2026-10-07) that 7z, rar, cab, iso and msi are each extracted, through a
  fixture builder written in WP-1.9; how rar is read (and how its fixtures are built without the non-free `rar`
  tool) stays a WP-1.9 decision, but listing only would not satisfy these tests.

## Coverage

Every MUST requirement of P1 (`python3 tools/kit/req.py phase P1`) and the exit criterion.

| Requirement | Level | Acceptance tests | Verified elsewhere | Turns green in |
|---|---|---|---|---|
| FR-03 file systems, clean refusal | MUST | `test_file_systems`: each of fat12, fat16, fat32, exfat, ntfs, ext2, ext3, ext4 scanned; no file system and MINIX refused (exit 4, message, report); damaged ext4 never transferred | — | WP-1.3, WP-1.4, WP-1.10 |
| FR-04 inventory: hidden files, streams, metadata | MUST | `test_file_systems`: inventory, sizes, hashes, modification time, hidden (attribute and dot name), read-only attribute, `kind`, symbolic links listed and never followed; `test_streams`: stream and attribute listed | `system` and `archive` attributes: WP-1.5 unit tests | WP-1.3, WP-1.5, WP-1.10 |
| FR-05 type from content, mismatch is a risk | MUST | `test_triage` (type, mismatch, double extension, R6 verdict, disguised archive, flags disabled by policy); `test_policy_rules` (name flags under R1, R2, R3, R4) | — | WP-1.7, WP-1.10 |
| FR-06 recursive extraction under limits | MUST | `test_extraction`: nesting within limits, tar, gzip, 7z, rar, cab, iso, msi, containers travel and entries do not, too deep, too dense (zip, gzip), too large, too many entries, at the limits (count, size, ratio), limits over the whole tree (count, size), path length, malformed (truncated, corrupt, lying sizes, encrypted entry, entry leaving its container); `test_policy_rules`: a known-good archive still meets the limits | Entry-name sanitising details: WP-1.8 unit tests | WP-1.8, WP-1.9 |
| FR-08 every object to every applicable engine | MUST (P2–P3) | `test_file_systems::test_every_object_is_analysed_by_the_engine`, `test_extraction::test_extracted_objects_are_analysed_by_every_engine`, `test_streams::*_is_scanned`, `test_policy_rules::test_engine_results_carry_each_engine_identity`; `test_usage`: no scan without its engines | Real engine applicability by type: P2, P3 | WP-1.10 |
| FR-09 per-object verdict with score, engines, explanation | MUST | `test_policy_rules` (every rule R1–R7, every precedence pair observable with fake engines, contributing engines, score, explanation naming rule and engines, engine identity, policy version and hash, parameters and R6 flags from the policy, scorer without a score); `test_policy_signature` (signed policy only, 16 refusals); `test_usage` (engines must match the policy) | Exhaustive rule tables: WP-1.2 unit tests, scored by mutation testing in P3 (NFR-14) | WP-1.2, WP-1.10 |
| FR-10 compliant mode blocks the medium, notifies | MUST | `test_medium_verdict` (default compliant, clean, suspicious, malicious, unscannable, archive entry, selective, scan-only); limit, stream, symbolic link, expiry and malformed tests check blocking too | Notification of the user and administrators: P6 (log events, LOG-*) and P7 (UI, UI-*), no notification surface in P1. Device rejection (D1): P4 | WP-1.10 |
| FR-14 maximum scan time, expiry action | MUST | `test_scan_time` (default 600 s and `block`, expiry with `block`, with `abort`, `abort` in selective mode); `test_usage` (invalid budget or action) | Fake-clock unit tests: WP-1.11 | WP-1.11 |
| NFR-05 a crashed worker yields UNSCANNABLE | MUST | `test_robustness` (exit code, SIGSEGV, SIGKILL, SIGABRT, garbage, hang past the policy's engine timeout; engine keeps serving; scan completes in time); `test_extraction::test_malformed_archive_*`; `test_file_systems::test_damaged_file_system_*` | Worker host fault injection: WP-1.6 unit tests; sandbox limits: P2 | WP-1.6, WP-1.10 |
| DEEP-05 streams and attributes listed, scanned, never copied | MUST | `test_streams` (NTFS stream and ext4 `user.*` attribute: listed, scanned, never transferable, not copied, a malicious stream blocks) | — | WP-1.3, WP-1.5, WP-1.10 |
| SEC-05 orchestrator parses no content | MUST | — | Not observable black-box: WP-1.7 structural test (`cargo metadata`: the orchestrator crate depends on no type-detection or archive crate) and review of every P1 package | WP-1.7 |
| SEC-10 read once, scanned copy transferred | MUST | `test_file_systems` (hashes equal the planted bytes; the engine received the hashed bytes; `--output` receives those bytes; symbolic links never read); `test_streams` (stream not copied) | Single read and TOCTOU (source changed after the read): WP-1.5 unit tests, not observable black-box | WP-1.5, WP-1.10 |
| CTR-01 framed Protobuf on stdin/stdout | MUST (P0) | Indirect only: every test drives the fake engine, which speaks the framed contract through `workers-py/common` (so a framing bug shared by Rust and Python would not show here) | WP-0.5 contract tests and the golden vectors shared by both languages; WP-1.6 worker host tests | — (P0) |
| EXIT end-to-end scan of each image type without USB hardware | — | `test_file_systems` for the eight file systems (scan, inventory, hashes, transfer of a clean medium) | — | WP-1.10 |

Not ranked here on purpose: MALICIOUS against UNSCANNABLE in the medium verdict (WP-1.1 stop point). No test
combines both in one medium.

## Tests and why they fail today

416 tests. The dry-run (`ostia_lock.py dry-run p1 -- -m "not bench"`) on the lock branch: 0 passed, 61 failed,
355 errors (fixture setup). The first failure of each test:

| Module | Tests | Fails today because | Green after |
|---|---|---|---|
| `test_file_systems.py` | 76 | 72: disk-image generator `tests/fixtures/images.py` is not implemented (WP-1.3); 4 (unsupported file systems): `ostia: not implemented: scan` (exit 3, expected 4) | WP-1.3, WP-1.4, WP-1.5, WP-1.10 |
| `test_streams.py` | 8 | Disk-image generator not implemented (WP-1.3) | WP-1.3, WP-1.5, WP-1.10 |
| `test_triage.py` | 30 | Disk-image generator not implemented (WP-1.3) | WP-1.7, WP-1.8, WP-1.10 |
| `test_extraction.py` | 41 | 15 (7z, rar, cab, iso, msi): archive builder `tests/fixtures/archives.py` is not implemented (WP-1.9); 26: disk-image generator not implemented | WP-1.8, WP-1.9, WP-1.10 |
| `test_policy_rules.py` | 186 | Disk-image generator not implemented (WP-1.3) | WP-1.2, WP-1.10 |
| `test_policy_signature.py` | 34 | 17: `ostia: not implemented: policy verify`; 17: `ostia: not implemented: scan` (exit 3) | WP-1.2 (verify), WP-1.10 (scan) |
| `test_medium_verdict.py` | 9 | Disk-image generator not implemented (WP-1.3) | WP-1.10 |
| `test_scan_time.py` | 8 | Disk-image generator not implemented (WP-1.3) | WP-1.11 |
| `test_robustness.py` | 15 | Disk-image generator not implemented (WP-1.3) | WP-1.6, WP-1.10 |
| `test_usage.py` | 9 | `ostia: not implemented: scan` (exit 3, expected 2) | WP-1.10 |

With a throwaway stand-in for the two generators (outside the repository, returning placeholder files), every
test reaches the binary and fails with `ostia: not implemented: scan` or `ostia: not implemented: policy
verify`, except the damaged-image test, whose 4 KiB placeholder is smaller than the range it damages. No test
passes before the product exists.

## Contracts these tests rely on

- `docs/contracts/cli.md`: `ostia scan` flags, exit codes 0/2/3/4/5, `--output`, `--dev-engine`, the engine
  checks against the policy, and the `OSTIA_DEV_PYTHON` / `OSTIA_DEV_FAKE_ENGINE` variables set by
  `common.run_ostia`.
- `docs/contracts/report.md` and `schemas/report.schema.json`: every field read here, and the cross-field rules
  of the schema (validated on every report).
- `docs/contracts/policy.md` and `schemas/policy.schema.json`: the documents built by `common.policy_document`.
- `tests/acceptance/common/images.py` and `archives.py`: the signatures WP-1.3 and WP-1.9 implement.
