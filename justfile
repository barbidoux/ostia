# Ostia task runner. The rails recipes live in tools/kit/rails.just (owner-managed);
# WP-0.1 adds the project recipes below. Keep the import line.
set shell := ["bash", "-euo", "pipefail", "-c"]

import 'tools/kit/rails.just'

default:
    @just --list

# Everything that must be green before a work package is done (extended in WP-0.1)
check: verify-locks rails-verify kit-test
    @echo "check: rails only so far; WP-0.1 adds fmt, lint, types, tests, coverage, trace, audit"
