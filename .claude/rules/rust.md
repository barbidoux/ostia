---
paths:
  - "**/*.rs"
  - "**/Cargo.toml"
  - "Cargo.lock"
  - "rust-toolchain.toml"
  - "deny.toml"
---

# Rules for Rust code

- Toolchain pinned in `rust-toolchain.toml` (stable). Nightly only for `cargo fuzz`, invoked as
  `cargo +nightly fuzz`, never as the default toolchain.
- Workspace lints in the root `Cargo.toml` (`[workspace.lints]`): `unsafe_code = "forbid"` by default;
  crates in `docs/unsafe-allowlist.md` override it locally with a comment explaining every block.
  `clippy::all`, `clippy::pedantic` as warn, and CI runs `clippy -D warnings`.
- No `unwrap()`, `expect()`, `panic!`, indexing that can panic, or `as` casts that truncate in
  non-test code that handles external input (frames, files, devices, manifests, policies, HTTP).
  Return typed errors (`thiserror` in libraries, `anyhow` only in binaries and tools).
- Every decoder and parser of external input has: a size cap checked before allocation, a fuzz
  target under `fuzz/`, and tests for truncated, oversized and wrong-version input.
- Async: `tokio` in the orchestrator, API and journal only. Workers are simple synchronous processes.
  Bounded channels everywhere; no unbounded queues.
- Subprocesses go through the `sandbox` crate; never `std::process::Command` on content-handling code
  outside it. Pass the object as fd 3, close every other descriptor.
- Time comes from an injected clock trait (`Clock`), never `SystemTime::now()` directly in logic.
- Secrets (`zeroize`), keys and tokens never appear in `Debug`, `Display`, logs or errors.
- Logging with `tracing`; structured fields; no file content, no full paths at info level on
  user data (paths are pseudonymised in events, see LOG-09).
- Dependencies: prefer crates already in `Cargo.lock`; any new one is declared in the merge request
  with version, licence and reason; `cargo deny check` must pass. GPL crates are never linked.
- Traceability: tests use the `#[req("ID")]` attribute from the `traceability` crate (built in WP-0.4)
  together with `#[test]` / `#[tokio::test]` / `proptest!`.
- Formatting `cargo fmt`; docs on every public item of library crates (`#![warn(missing_docs)]`).
