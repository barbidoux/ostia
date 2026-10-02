# Rails recipes (owner-managed, imported by the root justfile). CI calls the tools directly as well.

# Self-test of the guard hooks, the lock tool and the requirement lookup
kit-test:
    if [ -f pyproject.toml ] && command -v uv >/dev/null; then uv run python -m unittest tools/kit/test_kit.py; else python3 -m unittest tools/kit/test_kit.py; fi

# Show a work package or a requirement: just req WP-1.8 | just req FR-06 | just req phase P1
req +args:
    python3 tools/kit/req.py {{args}}

# Every locked acceptance directory matches its manifest (and its owner tag when present)
verify-locks:
    python3 tools/lock/ostia_lock.py verify

# The rails files match tools/lock/RAILS.sha256
rails-verify:
    python3 tools/lock/ostia_lock.py rails-verify

lock-status:
    python3 tools/lock/ostia_lock.py status

# Run a locked acceptance directory as a gate: all pass, none skipped, same count as at lock time
gate dir *args:
    python3 tools/lock/ostia_lock.py gate {{dir}} {{args}}

# OWNER ONLY: lock an acceptance directory (agents are blocked from running this)
lock dir:
    python3 tools/lock/ostia_lock.py lock {{dir}}

# OWNER ONLY: re-lock after an explicit, traced decision
relock dir reason:
    python3 tools/lock/ostia_lock.py relock {{dir}} --reason "{{reason}}"

# OWNER ONLY: record the rails files after an owner change to them
rails-update:
    python3 tools/lock/ostia_lock.py rails-update

# Hardened collect-only / informational run of an acceptance directory (same isolation as the gate)
acceptance-collect dir:
    python3 tools/lock/ostia_lock.py collect {{dir}}

acceptance-dry-run dir *args:
    python3 tools/lock/ostia_lock.py dry-run {{dir}} {{args}}
