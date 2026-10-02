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
