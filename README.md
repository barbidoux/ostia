# Ostia

Ostia is an open-source media kiosk ("station blanche"). It scans removable media with several
engines (LightGBM EMBER2024, ClamAV, YARA-X, heuristics, third-party antivirus plug-ins), defends
against BadUSB devices, analyses areas outside files, and transfers only what passes.
Rust core, Python analysis workers.

**Status:** pre-alpha. Nothing is usable yet; see [`docs/phase-status.md`](docs/phase-status.md).

- Requirements: [`docs/spec.md`](docs/spec.md)
- Plan: [`docs/plan.md`](docs/plan.md)
- Security reports: [`SECURITY.md`](SECURITY.md)

## Licence

Apache License 2.0, see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
