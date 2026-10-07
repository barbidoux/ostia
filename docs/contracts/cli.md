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
| 2 | Usage error: unknown subcommand or flag, missing required flag, invalid flag value, non-empty `--output` directory, duplicate engine id. Nothing is read, nothing is written. |
| 3 | Not implemented (contract stub). |
| 4 | Input refused: unsupported or absent file system, or a policy that is unsigned by the trusted key, altered or invalid. The report says why (`refusal`); nothing is analysed or transferred. |
| 5 | Internal error. Fail closed: nothing is transferred; the report, when it could be written, carries an UNSCANNABLE, blocked medium verdict. |

On codes 2, 4 and 5 a one-line reason goes to standard error, prefixed with `ostia: `. Refusals read
`ostia: input refused: <refusal code>: <detail>` (refusal codes: [report.md](report.md#refusal)). For
`unsupported_file_system` the detail contains the words `unsupported file system`.

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
| `--image` | yes | Disk image file holding one file system (no partition table in P1). Opened read-only; mounted read-only through the development mount layer (P1) or the privileged helper (P4). |
| `--report` | yes | Where the report is written ([report.md](report.md), `schemas/report.schema.json`). Written on exit codes 0 and 4. |
| `--policy` | yes | The verdict policy ([policy.md](policy.md), `schemas/policy.schema.json`). |
| `--policy-sig` | yes | Ed25519 detached signature over the exact bytes of the policy file: 64 raw bytes. Without it the scan does not start (exit 2): an unsigned policy is never used. |
| `--trust` | yes | The trusted Ed25519 public key: 32 raw bytes. |
| `--output` | no | Transfer target for development and investigation: after the scan, the scanned copy of every object whose `transferable` is true is written to `<dir>/<path>` (directories created as needed). Nothing else is written there: no report, no alternate data stream, no extended attribute, no extracted object (extracted objects travel inside their container). Created if absent; if it exists it must be an empty directory (exit 2 otherwise, checked before anything else). The P4 output medium replaces it in the kiosk. |
| `--mode` | no | `compliant` (default, FR-10), `selective` (non-compliant, flagged in the report), `scan-only` (nothing is ever transferable). See [report.md](report.md#transferable). |
| `--max-scan-time` | no | Scan budget in whole seconds, from 1; default 600 (10 minutes, FR-14). Counted from the start of the analysis (after the policy check). |
| `--on-expiry` | no | Action when the budget expires: `block` (default) stops the analysis, every object without a final verdict becomes UNSCANNABLE (rule R1, limit `scan_time`) and the medium verdict follows the mode; `abort` stops the session: `timing.aborted` is true, nothing is transferable in any mode, the medium is blocked. |
| `--dev-engine` | no, repeatable | Dev builds only. Runs the fake engine of `tests/fakes/fake_engine.py` with this config as one analysis engine. |

Order of checks: usage (exit 2), then the policy signature and content (exit 4, before the image is opened),
then the file system (exit 4), then the analysis (exit 0).

### Development flags (`dev` feature)

Flags starting with `--dev-` exist only in builds with the `ostia-cli/dev` cargo feature. The feature is refused
in release builds (compile error), so a kiosk binary never has them. The acceptance tests run a debug build with
the feature: `cargo build --workspace --locked --features ostia-cli/dev`; `OSTIA_BIN` overrides the binary path
(default `target/debug/ostia`).

`--dev-engine <config>` declares one engine:
- the engine identity (id, version, content version) is read from the config's `engine` object; two engines with
  the same id are a usage error;
- every dev engine is applied to every object: medium files, extracted objects, alternate data streams and
  extended attributes, archives included (FR-08);
- each analysis spawns `$OSTIA_DEV_PYTHON $OSTIA_DEV_FAKE_ENGINE --config <config>` (defaults `python3` and
  `tests/fakes/fake_engine.py` relative to the working directory) through the worker host: object on fd 3
  read-only, one framed request on stdin, one framed response on stdout (CTR-01);
- a crash, a kill by a signal, garbage on stdout or no answer within the policy's `engine_timeout_seconds` gives a
  synthesised engine result with that identity and status `ERROR` (crash, signal, garbage) or `TIMEOUT`.

## `ostia policy verify`

```
ostia policy verify --policy <policy.json> --policy-sig <policy.sig> --trust <key.pub>
```

Checks the signature over the exact bytes, then the content against `schemas/policy.schema.json` and the loader
rules of [policy.md](policy.md). Exit 0 with one JSON object on stdout: `{"version": "<policy version>",
"sha256": "<hex SHA-256 of the policy file>"}`. Exit 4 with `ostia: input refused: <refusal code>: <detail>` on
stderr and nothing on stdout when the policy is refused. Missing flag: exit 2.

## `ostia version`

Exit 0 with one JSON object on stdout: `{"ostia": "<semver>", "report": "<report schema version>",
"policy": "ostia.policy.v1", "engine_contract": <major>}`.
