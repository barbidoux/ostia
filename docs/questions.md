# Questions for the owner

Append new questions at the end of "Open". Never delete: move answered ones to "Answered" with the answer
and the date. Format:

```
### Q-<n> · WP-x.y · <REQ-ID> · <short title>
Context: ...
Options: (a) ... (b) ...
Recommendation: ...
Blocking: yes/no
```

## Open

### Q-1 · spec §21 · open questions inherited from the specification
The specification lists open questions (name trademark search, default business formats, EMBER false-positive
ceiling, reference medium, E1 default N, deep mode default and size threshold, HIDDEN_PAYLOAD default, first
commercial engine packs, FS15 network airlock, kiosk user authentication, usbsas reuse, regulated profile as
default). Each phase brief says when an answer is needed.
Blocking: no (each becomes blocking in the phase that needs it)

### Q-4 · WP-0.1 · NFR-09, NFR-15 · requirement tags of the tooling tests
Context: P0.md says the seeded-bad-sample tests are NFR-09/NFR-15 tests "check the wording". NFR-09 is about
`unsafe`, NFR-15 about Debian/WSL portability.
Options: (a) seeded `unsafe` and clippy tests → NFR-09; CI-on-Debian and toolchain pin → NFR-15;
rustfmt, ruff, mypy, commit-msg, JUnit-skip and acceptance-plan tests → TOOLING (b) tag all lint tests NFR-09/NFR-15.
Recommendation: (a), it keeps the matrix honest.
Blocking: no.

### Q-5 · WP-0.1 · NFR-15 · CI image before WP-0.2
Context: NFR-15 is verified by "CI on a Debian image"; WP-0.2 builds the pinned CI image. The dev machine is
Ubuntu 24.04 on WSL2, not Debian.
Options: (a) `ci.yml` runs in a `debian:13` container now, replaced by the WP-0.2 image (b) `ubuntu-latest` until WP-0.2.
Recommendation: (a).
Blocking: no.

### Q-6 · WP-0.1 · — · NOTICE copyright line and Rust edition
Context: `NOTICE` needs a copyright holder; the brief allows edition 2021 or the current one.
Options: NOTICE "Copyright 2026 Matthias Vaytet and the Ostia contributors"; edition 2024 (resolver 3), toolchain 1.99.0.
Recommendation: as stated.
Blocking: no.

### Q-7 · WP-0.1 · NFR-09 · how an allowlisted crate uses unsafe
Context: the workspace sets `unsafe_code = "forbid"`. Under `forbid`, a local `#![allow(unsafe_code)]` is a
compile error (E0453, proven by a tooling test), so a crate listed in `docs/unsafe-allowlist.md` cannot simply
override it. The tooling test requires `lints.workspace = true` for every crate not in the allowlist.
Options: (a) a listed crate declares its own full `[lints]` table (copy of the workspace one with
`unsafe_code = "deny"`) and allows unsafe per block with a justification comment; a future test checks that
the copy matches the workspace table apart from that line (b) the workspace uses `deny` instead of `forbid`.
Recommendation: (a); it keeps `forbid` for every other crate.
Blocking: no (first needed by the sandbox or media crates, P2/P4).

### Q-8 · WP-0.1 · — · linting locked acceptance directories
Context: ruff and mypy also check `tests/acceptance/`. Once a directory is locked, a later ruff or mypy upgrade
could flag it and break `just check`, and only the owner can change it (relock).
Options: (a) keep linting it and pin tool upgrades so that they are checked before locking (b) exclude locked
acceptance directories from ruff and mypy (a test-lever change, owner approval).
Recommendation: (a) for now; revisit at the first tool upgrade after `lock-p1`.
Blocking: no.

### Q-10 · WP-0.3 · NFR-07, NFR-19 · requirements with no phase
Context: NFR rows have no Phase column; their phase comes from the work packages that cite them. NFR-07 (same
versions give the same verdict) and NFR-19 (enrichment never blocks a session) are cited by no work package, so
the registry gives them no phase (`phase_source: none`) and no phase gate will require them.
Options: (a) leave them without a phase and cover them in the lock tests of P1 (NFR-07) and P8 (NFR-19)
(b) the owner adds them to work packages in the plan.
Recommendation: (b) at the next plan revision; (a) until then.
Blocking: no.

## Answered

### Q-9 · WP-0.3 · — · PyYAML for requirements.yaml
Context: the registry is `requirements.yaml`; generating it, validating the committed file against its JSON
schema and reading it in WP-0.4 needs a YAML library. The standard library has none.
Options: (a) PyYAML 6.0.3 (MIT), `safe_load`/`safe_dump` only, plus types-PyYAML 6.0.12.20260906 (Apache-2.0)
for mypy (b) no dependency: write the registry as JSON (`requirements.json`), diverging from the name in P0.md.
Recommendation: (a).
Blocking: yes (new dependency).
Answer (2026-10-02): (a) PyYAML and types-PyYAML approved.


### Q-2 · WP-0.1 · — · CODEOWNERS handle
Context: `.github/CODEOWNERS` is a rails file (agents cannot edit it); it still holds `@OWNER`. The owner
gave `@Barbidou`, but the git remote is `github.com/barbidoux/ostia`.
Options: (a) `@barbidoux` (matches the remote) (b) `@Barbidou` as given.
Recommendation: (a) if that is the GitHub account; the owner edits the file and runs `just rails-update`.
Blocking: no for WP-0.1 code; yes before the first push with branch protection.
Answer (2026-10-02): `@barbidoux` (https://github.com/barbidoux). The owner edits the file and runs `just rails-update`.

### Q-3 · WP-0.1 · — · Python dev dependencies and the MPL-2.0 licence of hypothesis
Context: P0.md lists the dev dependencies pytest 9.1.1 (MIT), hypothesis 6.168.3 (MPL-2.0), ruff 0.16.10 (MIT),
mypy 2.4.0 (MIT), jsonschema 4.26.0 (MIT), pytest-cov 7.1.0 (MIT), cryptography 50.0.2 (Apache-2.0 OR BSD-3-Clause),
plus dev tools pre-commit 4.6.2 (MIT, via uvx), cargo-nextest 0.9.146 and cargo-llvm-cov 0.9.1 (Apache-2.0/MIT).
hypothesis is MPL-2.0 (file-level copyleft), test-only, never shipped.
Options: (a) approve all, hypothesis as a test-only dependency (b) approve all but hypothesis.
Recommendation: (a).
Blocking: yes (new dependencies).
Answer (2026-10-02): (a) approved, hypothesis as a test-only dependency.
