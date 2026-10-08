# Changelog

All notable changes to this project are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Repository skeleton (WP-0.1): Cargo workspace forbidding `unsafe` code, `uv` project, `justfile`,
  pinned Rust toolchain, pre-commit hooks, CI on Debian, Apache-2.0 licence, security policy.
  `just test` fails on any skipped pytest test or ignored Rust test; CI gates the locked acceptance
  directories of closed phases and reports the current phase's as "N/M green".
- Architecture decision records (WP-0.10): ADR-01 to ADR-13 from the specification, ADR-14 (black-box
  acceptance tests, proposed) and an index in `docs/adr/`.
- Requirements registry (WP-0.3): `requirements.yaml` generated from the specification and the plan
  (`just registry`), validated against `schemas/requirements.schema.json`; `just check` fails when it is
  out of date or when the plan cites an unknown requirement.
- Development environment (WP-0.2): `tools/dev/setup-debian.sh` (`--check` reports tools, pinned versions,
  loop devices and exFAT/NTFS support; `--install` for the owner), disk-image scripts `mkimage.sh` and
  `loopmount.sh` (root helper behind a sudoers rule on a root-owned copy), a Debian 13 dev container and CI
  built from the same package and version lists; disk-image smoke tests for FAT32, exFAT, NTFS and ext4.
- Traceability tool (WP-0.4): `#[req("ID")]` attribute (crate `ostia-traceability`), pytest `req` marker
  checked against the registry at collection, and `just trace`: a matrix (`target/traceability.{json,md}`)
  built from the test reports; it fails on unknown ids and on requirements of ticked work packages without a
  passing test, and `--gate P<n>|all` on MUSTs without one. `just check` runs it.
- Engine contract and framing (WP-0.5): `proto/ostia/engine/v1/engine.proto` with a frozen v1 shape
  (`compat.json`), offline code generation (ADR-15), framing libraries in Rust (`ostia-contracts`) and Python
  (`ostia_common.framing`): 4-byte big-endian length, 16 MiB cap checked before allocation, contract major
  check, engine identity required in every response; golden vectors shared by both languages.
- Fuzzing (WP-0.6): cargo-fuzz target for the frame decoder and message validation (`fuzz/`), with a harness
  self-test that must catch a planted crash; `just test-fuzz` runs in CI on every push and pull request
  (60 s) and every night (30 min, growing corpus); regression inputs in `fuzz/regressions/` replay in
  `just test`.
- Test doubles (WP-0.7): a fake engine speaking the real framing (answers, delays, crashes, garbage by
  sha256, object id or type, from a JSON config), the `Clock` trait with a fake clock and a file-driven clock
  for dev builds, and loopback-only fake collector and fake provider skeletons (`tests/fakes/`).
- Supply-chain gates (WP-0.8): `just audit`, part of `just check`, runs these checks:
  - cargo-deny on both Rust workspaces (`deny.toml`: licence allowlist, crates.io only, advisories);
  - cargo-audit;
  - exact pins and sha256 hashes for every Python dependency, from PyPI only;
  - pip-audit on the hash-pinned export of `uv.lock`;
  - a licence check of the Python dependencies.

  `just sbom` writes CycloneDX SBOMs of the shipped crates and of the Python runtime to `target/sbom`.
- Test locking and red first (WP-0.9):
  - A tooling test proves that a locked acceptance directory cannot change without its manifest.
  - `tools/ci/red_first.py`, run by the `red-first` CI job on every pull request and by `just red-first`:
    - each `test(<ID>)` commit's tests fail at that commit, for a valid reason;
    - a later `feat`, `fix`, `build` or `ci` commit implements each id;
    - only `test(...)` commits touch tests;
    - every subject follows the commit convention.
  - `docs/contracts/repository-settings.md` lists the GitHub settings the owner applies.
- usbsas evaluation (WP-0.11), recorded in ADR-05:
  - covers licence, process interface, file systems, sandbox and maturity;
  - measures reading through usbsas against a kernel mount on FAT32, exFAT, NTFS and ext4 images;
  - recommends keeping the kernel mount for 1.0, with a later hybrid as a candidate (accepted; Q-35).
- P1 acceptance tests (WP-0.12), to be locked by the owner:
  - contracts: the `ostia` command line (`docs/contracts/cli.md`, stub binary from `crates/ostia-cli`), the scan
    report (`docs/contracts/report.md`, `schemas/report.schema.json`) and the signed verdict policy
    (`docs/contracts/policy.md`, `schemas/policy.schema.json`);
  - `tests/acceptance/p1` (416 black-box tests) and the shared helpers of `tests/acceptance/common`;
  - CI builds the acceptance binary with the `ostia-cli/dev` feature, which release builds refuse.
- Domain model (WP-1.1, `crates/core-domain`): verdicts with the worst-of order CLEAN < SUSPICIOUS <
  UNSCANNABLE < MALICIOUS (ADR-16); object verdicts that pair each rule with the verdict of spec §8 and carry
  score, contributing engines, explanation and limit; the object tree (files of the medium as roots, streams on
  their host file, links never read, depth within the policy's limit); session, medium, device placeholder and
  engine results.
- Verdict policy engine (WP-1.2, `core-domain::policy`): the signed policy `ostia.policy.v1` is verified
  with Ed25519 over its exact bytes before anything is parsed, then parsed strictly (unknown keys, duplicates,
  null and non-integer numbers refused); rules R1 to R7 in the order of spec §8, with contributing engines,
  score and an explanation; inconsistent or failed engine results give UNSCANNABLE; the medium verdict and
  the transferable objects for the compliant, selective and scan-only modes, with hooks for D1 and D2.
  `ostia policy verify` is built (exit 0 with the policy's version and SHA-256, 4 when refused).
- Disk-image fixture generator (WP-1.3, `tests/fixtures/images.py`): `build_image(fs, files)` builds bare
  FAT12/16/32, exFAT, NTFS and ext2/3/4 images under `target/fixtures/` with planted names (trapped names
  included), bytes, times, hidden and read-only attributes, NTFS alternate data streams, ext `user.*`
  attributes and symbolic links, checks them with fsck, caches them by request with a manifest, and refuses
  any request a file system cannot hold exactly. The development mount helper mounts FAT with `utf8` names
  and UTC times (Q-44).
