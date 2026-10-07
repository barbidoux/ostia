# Verdict policy — contract v1 (`ostia.policy.v1`)

Status: proposed in WP-0.12 (P1 lock); implemented in WP-1.2. Schema: `schemas/policy.schema.json`.
Decision record: ADR-09 (verdicts come only from the signed, declarative policy). The P1 acceptance tests write
policies in this format, so a later format is a new `schema` value that the loader accepts next to v1 (CTR-04).

## File and signature

- A UTF-8 JSON document. Every object refuses unknown keys; every key of the schema is required (no hidden
  default: what decides a verdict is written in the file).
- Signed with Ed25519 over the **exact file bytes** (no canonicalisation): the signature file holds the 64 raw
  signature bytes, the trusted key file the 32 raw public key bytes.
- The loader verifies the signature **before** parsing. Refusals: `policy_signature_invalid` (signature or key
  malformed, or no match), then `policy_invalid` (not JSON, schema mismatch, `thresholds.low >= thresholds.high`).
- The report records the policy `version` and the SHA-256 of the file bytes.

## Engines and roles

`engines` maps an engine id to its role. An engine that answers but is not listed counts as a `detector` with
`trusted_alone: false`.

| Role | What its result means |
|---|---|
| `detector` | Hint MALICIOUS is a detection. `trusted_alone: true`: one detection is enough (R2). Hint SUSPICIOUS is a risky heuristic (R6). |
| `scorer` | Its `score` is compared with `thresholds` (`low < high`, both in (0, 1]); its hint is ignored. The EMBER engine of P2 is a scorer (thresholds may then come from its signed model bundle). |
| `reputation` | Hint MALICIOUS: known-bad hash (R2). Hint CLEAN: exact known-good hash (R3). |
| `heuristic` | Hint SUSPICIOUS or MALICIOUS: risky heuristic (R6). |

Any engine's finding with `severity >= rules.R2.critical_severity` is a critical finding (R2), whatever its role.

## Object rules

The order is fixed by the spec (§8); the first rule that matches decides. Parameters come from the file.

| Rule | Matches when | Verdict | `contributing_engines` |
|---|---|---|---|
| R1 | Any engine result has status `ERROR` or `TIMEOUT`; or a limit was reached on the object (`limits`, scan time); or the object could not be read, typed or extracted (malformed archive); or `detected_type` is in `rules.R1.risky_types` and no engine answered `OK` | UNSCANNABLE | The engines with `ERROR` or `TIMEOUT` |
| R2 | A reputation engine says MALICIOUS; or a `trusted_alone` detector says MALICIOUS; or at least `rules.R2.k` other detectors say MALICIOUS; or a critical finding | MALICIOUS | The engines that matched |
| R3 | A reputation engine says CLEAN | CLEAN | The reputation engine |
| R4 | A scorer's score `>= thresholds.high` | MALICIOUS | The scorer |
| R5 | A scorer's score `>= thresholds.low` | SUSPICIOUS | The scorer |
| R6 | One of the enabled flags of `rules.R6`: `double_extension` and `extension_mismatch` (from triage, [report.md](report.md#objects)); `single_detection` (1 to `k - 1` detectors that are not `trusted_alone` say MALICIOUS); `suspicious_hint` (a detector says SUSPICIOUS, or a heuristic engine says SUSPICIOUS or MALICIOUS) | SUSPICIOUS | The engines that matched (empty for name flags) |
| R7 | None of the above | CLEAN | — |

E1 (enrichment, P8) and the medium rules D1, D2 (P4, P5) are added to this format in their phases.

## Limits

| Key | Meaning (any breach: the object is UNSCANNABLE through R1, `limit` names it) |
|---|---|
| `max_depth` | No object deeper than this exists: a container whose entries would be deeper is UNSCANNABLE (`depth`). Files of the medium have depth 0. |
| `max_ratio` | Uncompressed / compressed size, per entry and for a whole container, checked while streaming (`ratio`). |
| `max_total_bytes` | Bytes extracted from the tree of one file of the medium, all levels (`total_size`). |
| `max_entries` | Entries extracted from the tree of one file of the medium, all levels (`entry_count`). |
| `max_path_length` | Bytes of an entry path inside its container (`path_length`). |
| `engine_timeout_seconds` | One engine run on one object; beyond it the worker is killed and the result is `TIMEOUT`. |

The limit is reported on the container being extracted when it is reached.

## Example

```json
{
  "schema": "ostia.policy.v1",
  "version": "2026.10.0",
  "engines": {
    "clamav": {"role": "detector", "trusted_alone": true},
    "ember": {"role": "scorer", "thresholds": {"low": 0.6, "high": 0.9}},
    "hash-reputation": {"role": "reputation"},
    "pdf-heuristics": {"role": "heuristic"}
  },
  "rules": {
    "R1": {"risky_types": ["pe", "elf"]},
    "R2": {"k": 2, "critical_severity": 4},
    "R6": {"double_extension": true, "extension_mismatch": true, "single_detection": true, "suspicious_hint": true}
  },
  "limits": {
    "max_depth": 8,
    "max_ratio": 200,
    "max_total_bytes": 4294967296,
    "max_entries": 100000,
    "max_path_length": 4096,
    "engine_timeout_seconds": 60
  }
}
```
