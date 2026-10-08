# Verdict policy — contract v1 (`ostia.policy.v1`)

Status: proposed in WP-0.12 (P1 lock); implemented in WP-1.2. Schema: `schemas/policy.schema.json`.
Decision record: ADR-09 (verdicts come only from the signed, declarative policy). The P1 acceptance tests write
policies in this format, so the loader keeps accepting every valid v1 document (CTR-04). Keys added later to v1
(E1 and the enrichment settings in P8, D1 and D2 in P4 and P5) are optional, and their absence means the spec
default (enrichment off, so E1 inactive; D2 alert only); a change that a v1 document cannot express is a new
`schema` value.

## File and signature

- A UTF-8 JSON document of at most 1 MiB. Every object refuses unknown keys; every key of v1.0 is required (no
  hidden default: what decides a verdict is written in the file). A duplicate key anywhere, a `null` anywhere (no key
  accepts it: an explicit null is not an absent key), or an integer written with a fraction or an exponent
  (`2.0`), is `policy_invalid`. A file larger than 1 MiB is `policy_signature_invalid`: its exact bytes are
  never read in full, so its signature cannot be verified.
- Signed with Ed25519 over the **exact file bytes** (no canonicalisation): the signature file holds the 64 raw
  signature bytes, the trusted key file the 32 raw public key bytes; any other size is
  `policy_signature_invalid` (files are read with a cap, never whole when larger).
- The loader verifies the signature **before** parsing. Refusals: `policy_signature_invalid` (signature or key
  malformed, or no match), then `policy_invalid` (not JSON, schema mismatch, `thresholds.low >= thresholds.high`).
- The report records the policy `version` and the SHA-256 of the file bytes.

## Engines and roles

`engines` maps an engine id to its role. The engines of a session are exactly the policy's engines: an engine
missing from the policy, or a policy engine missing from the session, stops the scan before the medium is opened
(exit 2, [cli.md](cli.md)). Engine ids follow the pattern of the schema everywhere, command line included.

| Role | What its result means |
|---|---|
| `detector` | Hint MALICIOUS is a detection. `trusted_alone: true`: one detection is enough (R2). Hint SUSPICIOUS is a risky heuristic (R6). |
| `scorer` | Its `score`, in a result with status `OK`, is compared with `thresholds` (`low < high`, both in (0, 1]); its hint is ignored. An answer with status `OK` and no score is a failure (R1). The EMBER engine of P2 is a scorer: when its signed model bundle carries thresholds too, the stricter of each pair applies (the lower `high`, the lower `low`), so the bundle can only harden the policy (owner decision Q-38 in `docs/questions.md`). |
| `reputation` | Hint MALICIOUS: known-bad hash (R2). Hint CLEAN: exact known-good hash (R3). |
| `heuristic` | Hint SUSPICIOUS or MALICIOUS: risky heuristic (R6). |

Any engine's finding with `severity >= rules.R2.critical_severity` is a critical finding (R2), whatever its role.

## Object rules

The order is fixed by the spec (§8); the first rule that matches decides. Parameters come from the file.

| Rule | Matches when | Verdict | `contributing_engines` |
|---|---|---|---|
| R1 | Any engine result has status `ERROR`, `TIMEOUT` or an unknown value, or is inconsistent (a scorer answering `OK` without a score in [0, 1]; `UNSUPPORTED` with a hint, a score or findings; an engine without an id, without a role in the policy, or with several results for the object); or the object is a `symlink` or `special` ([report.md](report.md#objects)); or a limit was reached on the object (`limits`, scan time); or the object could not be read, typed or extracted (malformed archive, an encrypted entry, sizes that do not match the declared ones, an entry path that is absolute or has a `..` component); or `detected_type` is in `rules.R1.risky_types` and no engine answered `OK` | UNSCANNABLE | The engines with a failed or inconsistent result (an engine without an id is not named) |
| R2 | A reputation engine says MALICIOUS; or a `trusted_alone` detector says MALICIOUS; or at least `rules.R2.k` other detectors say MALICIOUS; or a critical finding | MALICIOUS | The engines that matched |
| R3 | A reputation engine says CLEAN | CLEAN | The reputation engine |
| R4 | A scorer's score `>= thresholds.high` | MALICIOUS | The scorer |
| R5 | A scorer's score `>= thresholds.low` | SUSPICIOUS | The scorer |
| R6 | One of the enabled flags of `rules.R6`: `double_extension` and `extension_mismatch` (from triage, [report.md](report.md#objects)); `single_detection` (1 to `k - 1` detectors that are not `trusted_alone` say MALICIOUS); `suspicious_hint` (a detector says SUSPICIOUS, or a heuristic engine says SUSPICIOUS or MALICIOUS) | SUSPICIOUS | The engines that matched (empty for name flags) |
| R7 | None of the above | CLEAN | — |

E1 (enrichment, P8) and the medium rules D1, D2 (P4, P5) are added in their phases as optional keys (see the top
of this document).

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
