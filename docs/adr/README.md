# Architecture decision records

Decisions follow the [MADR](https://adr.github.io/madr/) format: one file per decision,
`NNNN-<slug>.md`, never renumbered. A superseded record keeps its file and points to its successor.
ADR-01 to ADR-13 come from spec §21; they were decided by the owner in the specification.

| ADR | Decision | Status |
|---|---|---|
| [ADR-01](0001-rust-core-python-workers.md) | Rust core, Python engines as workers | accepted |
| [ADR-02](0002-apache-licence-clamd.md) | Apache-2.0; ClamAV through `clamd` | accepted |
| [ADR-03](0003-framed-protobuf-stdio.md) | Length-prefixed Protobuf on workers' stdin/stdout | accepted |
| [ADR-04](0004-lightweight-sandbox.md) | bubblewrap or nsjail sandbox with cgroups v2 | accepted |
| [ADR-05](0005-kernel-mount-read-only.md) | Read-only kernel mount for 1.0, unless the usbsas evaluation concludes otherwise | accepted; usbsas evaluated in WP-0.11, kernel mount kept for 1.0 (Q-35) |
| [ADR-06](0006-ocsf-logs.md) | OCSF logs | accepted |
| [ADR-07](0007-tuf-updates-tough.md) | Offline updates with TUF, verified by `tough` | accepted |
| [ADR-08](0008-web-ui-cage-chromium.md) | Web UI in Chromium kiosk mode under `cage` | accepted |
| [ADR-09](0009-declarative-signed-policy.md) | Declarative, signed verdict policy | accepted |
| [ADR-10](0010-project-name-ostia.md) | Project name "Ostia" (working name) | accepted (trademark search pending) |
| [ADR-11](0011-third-party-engine-adapters.md) | Third-party engines through native, CLI and ICAP adapters, conformance kit | accepted |
| [ADR-12](0012-enrichment-off-by-default.md) | Enrichment off by default, user choice within a configured upload mode, harden-only | accepted |
| [ADR-13](0013-deep-analysis-sleuth-kit.md) | Deep analysis with The Sleuth Kit in the sandbox, time-budgeted mode | accepted |
| [ADR-14](0014-black-box-acceptance-tests.md) | Acceptance tests drive the product only through its public surfaces | proposed |
| [ADR-15](0015-offline-protobuf-codegen.md) | Offline Protobuf code generation with protox/prost (Rust) and grpcio-tools (Python) | accepted |

## Template for a new record

```markdown
# ADR-NN: <decision in a few words>

- Status: proposed | accepted | superseded by ADR-MM
- Date: YYYY-MM-DD
- Deciders: <owner>
- Source: <spec sections, work package>

## Context and problem statement
## Decision drivers
## Considered options
## Decision outcome
## Consequences
## Links
```

An agent writes new records with status "proposed"; only the owner accepts them.
