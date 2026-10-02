# Acceptance tests

One directory per phase (`p1` … `p9`) plus `common/` (shared black-box helpers). Each is written in the
lock work package of the previous phase, reviewed by the owner, then locked (`LOCK.sha256` + tag `lock-<dir>`).
Rules: `.claude/rules/tests.md`. Status: `python3 tools/lock/ostia_lock.py status`.
