# ADR-03: Length-prefixed Protobuf on the workers' standard input and output

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §14, §18 rule 4

## Context and problem statement

The orchestrator and the engines are built and tested independently, in two languages (ADR-01).
Workers run in sandboxes with no network interface (SEC-01, ADR-04). They need a typed, versioned
contract that does not require a network stack, and whose decoder can be hardened against a hostile
or broken peer.

## Decision drivers

- No network stack inside the sandbox (SEC-01: loopback only for declared daemon engines).
- A typed contract written before the code, with contract tests first (spec §14, §18 rule 4).
- Robust decoding: malformed, oversized or incompatible messages rejected without panicking (CTR-02),
  decoders fuzzed (NFR-06).
- Versioning with explicit compatibility rules (CTR-04).

## Considered options

1. Length-prefixed Protobuf messages on stdin/stdout; the object as a read-only fd 3.
2. gRPC over sockets.

## Decision outcome

Chosen option 1: **each worker reads and writes versioned Protobuf messages (`ostia.engine.v1`), each
preceded by a 4-byte big-endian length, on its standard input and output** (CTR-01). The analysed
object is passed read-only as file descriptor 3 (SEC-03). A size cap is checked before allocation;
length 0, lengths over the cap, truncated frames and trailing bytes are rejected.

## Consequences

- Good: no sockets in the sandbox; the contract stays typed and language-neutral.
- Good: the framing is small enough to fuzz completely (WP-0.6).
- Bad: no built-in RPC features (streaming, deadlines); timeouts and cancellation are the worker host's
  job (WP-1.6).
- Bad: third-party engines that cannot speak the contract need the CLI or ICAP adapters (ADR-11).
- Follow-ups: WP-0.5 (proto v1, framing in Rust and Python, golden vectors shared by both, CTR-03 engine
  identity in every response); the codegen path is chosen and recorded in WP-0.5 (ADR-15); WP-0.6 (fuzz
  target); WP-1.6 (worker host); WP-2.3 (Python framework). Breaking changes need a new major package
  and compatibility tests (CTR-04).

## Links

- Requirements: CTR-01, CTR-02, CTR-03, CTR-04, NFR-06, SEC-01, SEC-03.
- Related: ADR-01, ADR-04, ADR-11.
