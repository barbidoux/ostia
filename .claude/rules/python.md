---
paths:
  - "**/*.py"
  - "**/pyproject.toml"
  - "uv.lock"
  - "workers-py/**"
---

# Rules for Python code

- Python 3.12, managed with `uv`. Dependencies are locked in `uv.lock`; the worker images install from
  hash-pinned requirements exported from it (`uv export --format requirements-txt --hashes`).
  `pip-audit` must pass.
- Typing: `mypy --strict` on `workers-py/` and `tools/` (kit tools excepted). `ruff` for lint and format.
- Workers are thin: read framed Protobuf from stdin, read the object from fd 3 (`os.fdopen(3, "rb")`),
  write one framed response to stdout, exit. All framing goes through `workers-py/common`
  (golden vectors shared with Rust, WP-0.5). Never print anything else to stdout; diagnostics go to stderr.
- Any exception, timeout or resource limit turns into a structured `ERROR`/`TIMEOUT` response or a
  non-zero exit; never a guessed verdict. A worker never returns CLEAN because something failed.
- No network access, no writes outside the private tmpfs, no subprocess unless the worker's manifest
  declares it. Workers run under seccomp: avoid libraries that spawn threads or helpers unexpectedly
  and document the syscalls a worker needs.
- EMBER: `thrember` and `pefile` pinned exactly (with `signify==0.7.1` as the known-good pin, see the
  risk table in the spec); feature dimension asserted to be 2,568; model files loaded only from the
  signed bundle, checked by hash, never downloaded at runtime.
- Tests with `pytest` and `hypothesis`; every test carries `@pytest.mark.req("ID")`; the `req`, `bench`
  and `slow` markers are registered in `pyproject.toml` with `--strict-markers`.
- No `print` debugging left behind, no `assert` for runtime validation (use explicit checks and errors).
