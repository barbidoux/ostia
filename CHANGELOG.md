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
