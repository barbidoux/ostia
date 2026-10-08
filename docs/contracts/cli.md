# `ostia` command line — contract v1

Status: proposed in WP-0.12 (P1 lock), reviewed by the owner with the P1 acceptance tests. Once `lock-p1` is
tagged, the locked tests depend on everything below: changes are additive (new flags, new report fields), and
a breaking change needs a new major version and a relock decided by the owner (CTR-04).

The binary is built by the `ostia-cli` crate. Until a subcommand is built it exits with code 3 and prints
`ostia: not implemented: <subcommand>` on standard error.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The command completed. For `scan`: the medium was analysed and the verdict is in the report, whatever it is (a blocked medium still exits 0). |
| 2 | Usage error, checked before anything is analysed: unknown subcommand or flag, missing required flag, invalid flag value, missing or unreadable input file (`--image`, `--policy`, `--policy-sig`, `--trust`, `--dev-engine`), `--report` in a directory that does not exist, non-empty `--output` directory, no analysis engine, an engine id outside the policy's id pattern, two engines with the same id, an engine of the session missing from the policy or a policy engine missing from the session. Nothing is written. |
| 3 | Not implemented (contract stub). |
| 4 | Input refused: no file system or one outside FR-03 (a partition table is refused in P1), or a policy whose signature does not verify with the trusted key, or whose content is invalid. The report says why (`refusal`); nothing is analysed or transferred. |
| 5 | Internal error after the input was accepted (mount, inventory, workspace, report), a damaged file system included: fail closed. Nothing is transferred (`--output` is left empty); the report, when it can be written, carries an UNSCANNABLE, blocked medium verdict. A panic exits 5 too. |

Any exit code other than 0, 2, 3 and 4 means that nothing the run produced may be trusted.

A damaged file system (valid signature, broken metadata) gives exit 4 if it is not recognised, exit 5 if it cannot
be mounted or listed, or exit 0 with every unreadable object UNSCANNABLE; in every case the medium is blocked and
nothing is transferred.

On codes 2, 4 and 5 a one-line reason goes to standard error, prefixed with `ostia: `. Refusals read
`ostia: input refused: <refusal code>: <detail>` (refusal codes: [report.md](report.md#refusal)). For
`unsupported_file_system` the detail contains the words `unsupported file system`. A missing required flag names
the flag (`--policy-sig`).

## `ostia scan`

Analyses a disk image end to end and writes the JSON report.

```
ostia scan --image <path> --report <out.json>
           --policy <policy.json> --policy-sig <policy.sig> --trust <key.pub>
           [--output <dir>]
           [--mode compliant|selective|scan-only]
           [--max-scan-time <seconds>] [--on-expiry block|abort]
           [--dev-engine <fake-engine-config.json>]...        (dev builds only)
```

| Flag | Required | Meaning |
|---|---|---|
| `--image` | yes | Disk image file holding one file system, no partition table (partitioned media: P4, P5). Opened read-only; mounted read-only through the development mount layer (P1) or the privileged helper (P4). |
| `--report` | yes | Where the report is written ([report.md](report.md), `schemas/report.schema.json`). Written on exit codes 0 and 4, and on 5 when possible. |
| `--policy` | yes | The verdict policy ([policy.md](policy.md), `schemas/policy.schema.json`). |
| `--policy-sig` | yes | Ed25519 detached signature over the exact bytes of the policy file: 64 raw bytes. Without the flag the scan does not start (exit 2): an unsigned policy is never used. |
| `--trust` | yes | The trusted Ed25519 public key: 32 raw bytes. |
| `--output` | no | Transfer target for development and investigation (see [below](#output)). The P4 output medium replaces it in the kiosk. |
| `--mode` | no | `compliant` (default, FR-10), `selective` (non-compliant, flagged in the report), `scan-only` (nothing is ever transferable). See [report.md](report.md#transferable). |
| `--max-scan-time` | no | Scan budget in whole seconds, from 1; default 600 (10 minutes, FR-14). Counted from the start of the analysis (after the policy check), inventory included. |
| `--on-expiry` | no | Action when the budget expires: `block` (default) stops the analysis, every object without a final verdict becomes UNSCANNABLE (rule R1, limit `scan_time`), and the medium is blocked in compliant and scan-only modes (part of it may never have been listed); `abort` stops the session: `timing.aborted` is true, nothing is transferable in any mode, the medium is blocked. |
| `--dev-engine` | no, repeatable | Dev builds only. Runs the fake engine of `tests/fakes/fake_engine.py` with this config as one analysis engine. |

At least one analysis engine runs in every scan, and the session's engines are exactly the policy's `engines`
(exit 2 otherwise): a missing engine can never weaken a verdict silently, and an engine without a role in the
signed policy never contributes.

Order of checks: flags and input files (exit 2), then the policy signature and content (exit 4), then the
session's engines against the verified policy (exit 2), all before the image is opened; then the file system
(exit 4), then the analysis (exit 0, or 5 on an internal error).

### Output

After the scan, the scanned copy of every object whose `transferable` is true is written to `<dir>/<path>`,
directories created as needed. The copy goes to a staging area first and is moved into place only when every
copy succeeded; on any failure `--output` is left empty and the exit code is 5.
- Nothing else is written there: no report, no alternate data stream, no extended attribute, no extracted object
  (extracted objects travel inside their container), no symbolic link, no special file.
- No write ever leaves `<dir>` or follows a symbolic link. An object whose path has an absolute, empty, `.` or `..`
  component is not transferable.
- `--output` is created if absent; if it exists it must be an empty directory (exit 2 otherwise, checked before
  anything else).

### Development flags (`dev` feature)

Flags starting with `--dev-` exist only in builds with the `ostia-cli/dev` cargo feature. The feature is refused
in release builds (compile error), so a kiosk binary never has them. The acceptance tests run a debug build with
the feature: `cargo build --workspace --locked --features ostia-cli/dev`; `OSTIA_BIN` overrides the binary path
(default `target/debug/ostia`).

`--dev-engine <config>` declares one engine:
- the engine identity (id, version, content version) is read from the config's `engine` object and is
  authoritative: its id selects the role in the policy;
- every dev engine is applied to every object: medium files, extracted objects, alternate data streams and
  extended attributes, archives included (FR-08);
- each engine runs once per object (no retry: a failed run gives a synthesised result, and the next object
  gets a fresh worker);
- each analysis spawns `$OSTIA_DEV_PYTHON $OSTIA_DEV_FAKE_ENGINE --config <config>` (defaults `python3` and
  `tests/fakes/fake_engine.py` relative to the working directory) through the worker host: object on fd 3
  read-only, one framed request on stdin, one framed response on stdout (CTR-01).

### Synthesised engine results

The worker host synthesises a result, with the declared identity, when the engine:
- crashes, is killed by a signal, writes garbage or answers with another `engine_id`: status `ERROR`;
- gives no answer within the policy's `engine_timeout_seconds` (the worker is killed): status `TIMEOUT`.

A synthesised result has hint `NONE`, score null, no findings and `duration_ms` equal to the time spent.

## `ostia policy verify`

```
ostia policy verify --policy <policy.json> --policy-sig <policy.sig> --trust <key.pub>
```

Checks the signature over the exact bytes, then the content against `schemas/policy.schema.json` and the loader
rules of [policy.md](policy.md). Exit 0 with exactly one JSON object on stdout holding exactly two keys:
`{"version": "<policy version>", "sha256": "<hex SHA-256 of the policy file>"}`. Exit 4 with
`ostia: input refused: <refusal code>: <detail>` on stderr and nothing on stdout when the policy is refused.
Missing flag or unreadable file: exit 2.

## `ostia version`

Exit 0 with one JSON object on stdout: `{"ostia": "<semver>", "report": "<report schema version>",
"policy": "ostia.policy.v1", "engine_contract": <major>}`.
