# Ostia — Development Plan

Companion to the Ostia Software Specification v0.2 · 2026-10-02 · Matthias Vaytet

## 1. How to use this plan

The plan breaks the ten phases of the [specification](spec.md) into 101 work packages. Each package is one branch and one merge request, small enough for a person or a coding agent to finish in a few focused sessions, and starts with the tests that prove it done.

**Reading a work package row.**

| Column              | Meaning                                                                       |
|---------------------|-------------------------------------------------------------------------------|
| WP                  | Identifier `WP-<phase>.<n>`, used in the branch name and merge request title  |
| Scope               | What gets built                                                               |
| Requirements        | Specification identifiers the package satisfies; its tests carry these ids    |
| Tests written first | The failing tests that open the package; the list is a minimum, not a ceiling |
| Size                | S, M or L (see section 2); an L package is split before it starts             |
| After               | Packages that must be merged first                                            |

**Order.** Packages are listed in a workable order inside each phase. Within a phase, packages whose “After” column is satisfied can run in parallel. A phase is closed only by its gate (section 14), never by its last package.

**Two kinds of package do not follow the test-first rule:** spikes (time-boxed investigations that end in a decision record, marked “spike”) and “lock” packages, which write the next phase's acceptance tests. Every other package does.

## 2. Assumptions and per-package workflow

The plan assumes one developer working with a coding agent, phases run in order, and no calendar dates until the first two phases have been measured.

**Assumptions.**

- One developer plus a coding agent; the dependency map (section 3) shows what can run in parallel if contributors join.

- Development on WSL2 (Debian) for P0–P3 and P6–P8; a dedicated Debian machine from P4, for USB gadget emulation, real drives and raw device reads.

- CI on GitHub Actions; nothing in the plan depends on it, so another CI system works the same way.

- Sizes: **S** about one focused session, **M** two to three sessions, **L** too big, split before starting.

- Durations are estimated only after P0 and P1, from the measured pace per size (section 16).

**Workflow for every package.**

1.  Open the issue for the package; read the requirements it cites in the specification.

2.  Create the branch `wp/<id>-<slug>`.

3.  Write the tests listed in “Tests written first”, tagged with their requirement ids. Run them and confirm they fail for the expected reason.

4.  Commit `test(<REQ>): …`. CI must show these tests failing.

5.  Write the minimum code to pass. Commit `feat(<REQ>): …`.

6.  Refactor with the whole suite green. Commit `refactor: …` if needed.

7.  Run `just check`: format, lint, types, tests, coverage, traceability, dependency audit.

8.  Open the merge request titled `[WP-x.y] <scope>`; review against the definition of done (spec section 18); merge.

**What a coding agent receives.** The package row, the cited requirements copied from the specification, the instructions file (section 15) and the relevant contracts. Never the whole specification as a free-form brief: a narrow, testable scope is what keeps it on the rails.

## 3. Dependency map

With one developer, phases run in order P0 to P9. The map shows what each phase really needs, so work can run in parallel if contributors join.

```text
P0 ─► P1 ─┬─► P2 ─┬─► P3 ─► P8 ─┐
          │       └─► P4 ─► P5 ─┼─► P9
          └─► P6 ─► P7 ─────► P8┘
P4 and P5 need the dedicated Debian machine.
```

P6 (logging) needs only P1's domain events, so it is the first candidate for a second contributor. P4 and P5 need the dedicated Debian machine; ordering it during P2 avoids a wait. P9 starts only when every other phase has passed its gate.

## 4. P0 · Foundations

P0 builds the rails: repository, contracts, traceability and test locking. Exit gate: CI green, P1 acceptance tests written, reviewed and locked.

| WP      | Scope                                                                                                                                                    | Requirements     | Tests written first                                                                                                                | Size | After    |
|---------|----------------------------------------------------------------------------------------------------------------------------------------------------------|------------------|------------------------------------------------------------------------------------------------------------------------------------|------|----------|
| WP-0.1  | Repository skeleton: Cargo workspace, `uv` project, `justfile`, `rust-toolchain.toml`, pre-commit hooks, Apache-2.0 licence, `SECURITY.md`, `CODEOWNERS` | NFR-09, NFR-15   | `just check` passes on empty suites; lint gates fail on a seeded bad sample (format, clippy, ruff, mypy)                           | S    | —        |
| WP-0.2  | Dev environment: Debian WSL setup script, dev container identical to the CI image; checks for loop devices, NTFS and exFAT support                       | NFR-15           | Environment script asserts tool versions; a disk-image smoke test creates, mounts read-only and unmounts each file-system type     | S    | 0.1      |
| WP-0.3  | Requirements registry: `requirements.yaml` (id, level, phase, ANSSI) generated from the specification                                                    | —                | Schema validation; unique ids; every id cited by the plan exists                                                                   | S    | 0.1      |
| WP-0.4  | Traceability tool: `#[req]` attribute and pytest marker, matrix generator, CI rule “a MUST of the active phase without a passing test fails”             | All (tooling)    | On a fixture repository: missing test fails; failing test fails; unknown id fails; complete repository passes                      | M    | 0.3      |
| WP-0.5  | Protobuf contracts v1 and framing libraries in Rust and Python: length prefix, size cap, version check                                                   | CTR-01 to CTR-04 | Round-trip; oversized, truncated and wrong-version messages rejected without panic; Rust and Python agree on shared golden vectors | M    | 0.1      |
| WP-0.6  | Fuzz target for the frame decoder, wired into CI (short run per merge, long nightly)                                                                     | NFR-06           | Fuzz target builds and runs for a fixed time in CI; a seeded crash input is caught                                                 | S    | 0.5      |
| WP-0.7  | Test doubles: fake engine (configurable hint, score, delay, crash), fake clock, fake collector and fake provider skeletons                               | —                | Behaviour tests of each double                                                                                                     | S    | 0.5      |
| WP-0.8  | Supply-chain gates: `cargo-deny` (licences, sources, advisories), `cargo-audit`, `pip-audit` with hash-pinned requirements, CycloneDX SBOM               | UPD-07, NFR-11   | CI fails on a seeded disallowed licence and on an unpinned Python dependency                                                       | S    | 0.1      |
| WP-0.9  | Test locking: hash manifest per `tests/acceptance/pN/`, CI check, `CODEOWNERS` rule; agent instructions file (section 15)                                | Spec §18         | Changing a locked test without updating its manifest fails CI                                                                      | S    | 0.4      |
| WP-0.10 | Decision records ADR-01 to ADR-13 in `docs/adr/`                                                                                                         | —                | Reviewed, not tested                                                                                                               | S    | —        |
| WP-0.11 | Spike: usbsas evaluation as media layer (licence review, process interface, performance on reference images); outcome recorded in ADR-05                 | ADR-05           | Spike, time-boxed                                                                                                                  | M    | 0.2      |
| WP-0.12 | Lock: write P1 acceptance tests, review, lock                                                                                                            | P1 scope         | They exist, fail, and are locked                                                                                                   | M    | 0.4, 0.9 |

## 5. P1 · Pipeline

P1 scans a disk image end to end with a fake engine: inventory, single hashed read, triage, extraction, verdict, report. Exit gate: full scan of every disk-image type with no USB hardware.

| WP      | Scope                                                                                                                                                           | Requirements           | Tests written first                                                                                                   | Size | After         |
|---------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------|-----------------------------------------------------------------------------------------------------------------------|------|---------------|
| WP-1.1  | Domain model: Session, Medium, ObjectNode, verdicts, worst-of ordering                                                                                          | FR-09                  | Property tests: worst-of is monotonic and order-independent; object tree invariants (parent, depth)                   | S    | P0            |
| WP-1.2  | Verdict policy engine: declarative policy format, loader with signature check, rules R1–R7, hooks for D1 and D2                                                 | FR-09, FR-10, ADR-09   | Table-driven tests, one row per rule and per precedence case (R3 never beats R2); unsigned or altered policy rejected | M    | 1.1           |
| WP-1.3  | Disk-image fixture generator: FAT, exFAT, NTFS, ext4 with planted files, hidden files, alternate data streams, trapped names and a manifest of expected content | —                      | Generator self-tests: every image mounts and matches its manifest                                                     | M    | P0            |
| WP-1.4  | Development mount layer: loop device, read-only, file-system detection, clean refusal of unsupported systems                                                    | FR-03                  | Each supported image mounts read-only; an unsupported file system returns a clear refusal                             | S    | 1.3           |
| WP-1.5  | Inventory with hidden files and alternate streams, metadata, single read with SHA-256 and SHA-1, copy into the workspace                                        | FR-04, SEC-10, DEEP-05 | Counts and hashes match the fixture manifest; changing the source after the read leaves the analysed copy unchanged   | M    | 1.4           |
| WP-1.6  | Worker host v0: spawn a worker, pass the object as descriptor 3, framed exchange, timeout and crash handling                                                    | CTR-01, NFR-05         | Echo worker round-trip; a sleeping worker yields TIMEOUT; a crashing worker yields ERROR and the host survives        | M    | 1.1           |
| WP-1.7  | Triage worker (Rust): type from content, extension mismatch flag                                                                                                | FR-05, SEC-05          | Typed sample corpus identified; renamed files flagged; the orchestrator holds no file-type parsing code               | S    | 1.6           |
| WP-1.8  | Extraction worker, part 1: zip, tar, gz; limits on depth, ratio, total size, count; children returned as objects                                                | FR-06                  | Nested archive within limits fully listed; too deep, too dense, too large and too many each give UNSCANNABLE          | M    | 1.6           |
| WP-1.9  | Extraction worker, part 2: 7z, rar, cab, iso, msi                                                                                                               | FR-06                  | Same limit tests per format; malformed archives give UNSCANNABLE, never a crash                                       | M    | 1.8           |
| WP-1.10 | Orchestrator pipeline: session lifecycle, bounded queues, dispatch to the fake engine, medium verdict, JSON report                                              | FR-08, FR-09, FR-10    | End-to-end on each image with scripted fake-engine outcomes; one MALICIOUS object blocks the medium in compliant mode | M    | 1.2, 1.5, 1.7 |
| WP-1.11 | Maximum scan time and configurable expiry action                                                                                                                | FR-14                  | With a fake clock, expiry triggers each configured action; the report records it                                      | S    | 1.10          |
| WP-1.12 | Lock: write P2 acceptance tests, review, lock                                                                                                                   | P2 scope               | They exist, fail, and are locked                                                                                      | M    | 1.10          |

## 6. P2 · EMBER engine

P2 hardens the sandbox and ships the first real engine, calibrated and explained. Exit gate: latency and memory budgets met, thresholds shipped in a signed model bundle.

| WP      | Scope                                                                                                                               | Requirements           | Tests written first                                                                                                                     | Size | After    |
|---------|-------------------------------------------------------------------------------------------------------------------------------------|------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|------|----------|
| WP-2.1  | Sandbox: user, mount and network namespaces, allowlist seccomp, read-only root, private tmpfs, one sandbox per medium               | SEC-01, SEC-02, SEC-03 | A worker trying to open a socket, write outside its tmpfs or read the workspace fails; a second medium never sees the first one's files | M    | P1       |
| WP-2.2  | Resource limits with cgroups v2: memory, CPU, process count, write size, duration                                                   | SEC-04, NFR-04         | A memory hog, fork bomb and disk filler are each killed and give UNSCANNABLE; the orchestrator keeps running                            | M    | 2.1      |
| WP-2.3  | Python worker framework: framing, descriptor input, structured errors, shared test harness                                          | CTR-01, CTR-02         | Python worker passes the golden vectors of WP-0.5 and rejects malformed frames                                                          | S    | P0       |
| WP-2.4  | Model bundle: model files, thresholds, hashes, metadata, signature; build-time fetch script that pins `thrember` models by hash     | NFR-17                 | Tampered or unsigned bundle rejected; wrong feature dimension (not 2,568) rejected                                                      | S    | 2.3      |
| WP-2.5  | EMBER worker: feature extraction with pinned `thrember` and `pefile`, routing to per-format models, inference                       | FR-08                  | Frozen reference predictions on known vectors; truncated or corrupted PE gives UNSCANNABLE; PDF, ELF and APK routed to their models     | M    | 2.4, 2.1 |
| WP-2.6  | Explanation: per-feature contributions from LightGBM, top factors, readable label table                                             | NFR-12                 | Contributions sum to the raw score within tolerance; every top factor has a label                                                       | S    | 2.5      |
| WP-2.7  | Calibration tool: run the clean corpus, choose high and low thresholds for a target false-positive rate, write them into the bundle | NFR-17                 | On synthetic score distributions the tool picks the expected thresholds; reruns are reproducible                                        | M    | 2.5      |
| WP-2.8  | Performance: inference benchmark, feature-extraction profile, process-pool sizing                                                   | NFR-02                 | Benchmark fails above 10 ms per inference on the reference machine                                                                      | S    | 2.5      |
| WP-2.9  | Policy integration: rules R4 and R5 with the real model; verdict log carries model hash and thresholds                              | NFR-17, FR-09          | End to end: clean system binaries give CLEAN; a test bundle with lowered thresholds forces SUSPICIOUS and MALICIOUS paths               | S    | 2.6, 2.7 |
| WP-2.10 | Lock: write P3 acceptance tests, review, lock                                                                                       | P3 scope               | They exist, fail, and are locked                                                                                                        | M    | 2.9      |

## 7. P3 · Engines

P3 adds the built-in heuristic engines and the plug-in SDK that lets anyone add an antivirus. Exit gate: mutation score ≥ 70 % on the verdict policy, and the conformance kit certifies every built-in engine.

| WP      | Scope                                                                                                     | Requirements           | Tests written first                                                                                                        | Size | After       |
|---------|-----------------------------------------------------------------------------------------------------------|------------------------|----------------------------------------------------------------------------------------------------------------------------|------|-------------|
| WP-3.1  | Engine manifest: schema, loader, signature check                                                          | CTR-06, ENG-01         | Each invalid manifest rejected with a precise reason; unsigned manifest rejected                                           | S    | P2          |
| WP-3.2  | Engine host: native adapter, trust levels (alone, K-of-N, advisory), per-engine unwanted-software mapping | ENG-05, NFR-13         | Fake engines with each trust level drive R2 and R6 as specified; adding a fake engine needs no core change                 | M    | 3.1         |
| WP-3.3  | CLI adapter: command template, exit-code mapping, output parsing, sandbox profile                         | ENG-02, ENG-03         | A fake command-line scanner script: EICAR detected, clean file clean, garbage output gives ERROR, hang gives TIMEOUT       | M    | 3.2         |
| WP-3.4  | ICAP adapter (RFC 3507 client): OPTIONS, RESPMOD, preview, 204; loopback-only network namespace           | ENG-02, ENG-03         | Against a fake ICAP server: infected, clean, error and timeout replies; then against c-icap with ClamAV in CI              | M    | 3.2         |
| WP-3.5  | ClamAV through `clamd` over a local socket; concurrent reload off; manifest                               | FR-08, ENG-01          | EICAR gives MALICIOUS through R2; `clamd` down gives UNSCANNABLE for every object                                          | S    | 3.2         |
| WP-3.6  | YARA-X worker: rule bundle compilation, severity convention, licence list per rule set                    | FR-08                  | A marker rule fires; a critical rule triggers R2; a rule set without a declared licence fails the build                    | M    | 3.2         |
| WP-3.7  | Reputation worker: NSRL bloom filter, MalwareBazaar hash lists                                            | FR-08                  | Known-bad hash gives MALICIOUS; known-good hash beats an EMBER detection (R3) but never a ClamAV one                       | S    | 3.2         |
| WP-3.8  | Office heuristics worker (oletools)                                                                       | FR-08                  | Generated document with a harmless auto-run macro gives SUSPICIOUS; DDE field detected; plain document clean               | M    | 3.2         |
| WP-3.9  | PDF heuristics worker                                                                                     | FR-08                  | Generated PDF with harmless JavaScript or an OpenAction gives SUSPICIOUS; plain PDF clean                                  | S    | 3.2         |
| WP-3.10 | PE heuristics worker: Authenticode check, entropy, abnormal sections                                      | FR-08                  | Signed and unsigned clean binaries distinguished; a UPX-packed clean binary raises a packer finding                        | M    | 3.2         |
| WP-3.11 | Conformance kit `ostia engine certify` and engine health reporting                                        | ENG-04, ENG-07, ENG-08 | Kit passes a well-behaved fake engine and fails one fake engine per broken criterion; health shows version and content age | M    | 3.3, 3.4    |
| WP-3.12 | Cascade tuning and mutation testing of the policy                                                         | NFR-14                 | Mutation score below 70 % fails CI                                                                                         | S    | 3.5 to 3.10 |
| WP-3.13 | Lock: write P4 acceptance tests, review, lock                                                             | P4 scope               | They exist, fail, and are locked                                                                                           | M    | 3.12        |

## 8. P4 · USB and media

P4 moves from disk images to real devices on the dedicated Debian machine: USB defence, privileged helper, verified transfer. Exit gate: full journey with a real drive, and every emulated malicious device blocked or flagged.

| WP      | Scope                                                                                                                                                                                     | Requirements                  | Tests written first                                                                                                                        | Size | After      |
|---------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------|------|------------|
| WP-4.1  | Device test bench: Debian machine, kernel with `dummy_hcd` and configfs gadgets; gadget fixtures for plain storage, HID plus storage, class liar, delayed re-enumeration, network adapter | —                             | Each gadget fixture enumerates as designed                                                                                                 | M    | P2         |
| WP-4.2  | USB sentinel: udev events, USBGuard policy generation for external and internal ports, descriptor fingerprint                                                                             | USB-01, USB-02, USB-05, FR-01 | Plain storage allowed; HID plus storage blocked; internal device allowed only by exact hash and port; fingerprint logged                   | M    | 4.1        |
| WP-4.3  | Driver allowlist on external ports                                                                                                                                                        | USB-03, SEC-07                | The class-liar gadget gets no driver and is reported                                                                                       | M    | 4.2        |
| WP-4.4  | Session-long device monitoring and anomaly heuristics                                                                                                                                     | USB-04, USB-06                | Re-enumeration mid-scan aborts the session and discards results; a multi-configuration device raises a finding                             | M    | 4.2        |
| WP-4.5  | Privileged mount and raw-read helper: minimal binary, strict parameter validation, dedicated namespace, file-system module blocklist                                                      | SEC-08, FR-02, NFR-10         | Mount is `ro,noexec,nosuid,nodev`; path and option injection refused; unsupported file-system modules cannot load; parameter parser fuzzed | M    | 4.2        |
| WP-4.6  | Encrypted ephemeral workspace and cryptographic erasure                                                                                                                                   | SEC-11, FR-20                 | After session end the key is gone and the volume cannot be read; a crash mid-session still leaves it unreadable                            | M    | 4.5        |
| WP-4.7  | Output medium: controlled-medium marker, formatting, copy of the scanned copies, SHA-256 verification                                                                                     | FR-13, SEC-09, USB-08         | The input device is refused as output; an unknown output device is refused; a bit flipped during copy is detected                          | M    | 4.5        |
| WP-4.8  | Signed transfer manifest                                                                                                                                                                  | FR-22, CTR-05                 | Manifest verifies with the kiosk key; any edit breaks the signature; canonical JSON stable across runs                                     | S    | 4.7        |
| WP-4.9  | Service accounts and systemd units                                                                                                                                                        | SEC-06, SEC-12, NFR-10        | Only the helper runs privileged; the workspace is non-executable; each service runs under its own account                                  | S    | 4.5        |
| WP-4.10 | End-to-end on real drives (scripted, plus a short manual protocol)                                                                                                                        | FR-01, FR-13                  | Scripted journey with FAT, exFAT and NTFS drives passes on the bench                                                                       | S    | 4.6 to 4.9 |
| WP-4.11 | Lock: write P5 acceptance tests, review, lock                                                                                                                                             | P5 scope                      | They exist, fail, and are locked                                                                                                           | S    | 4.10       |

## 9. P5 · Deep scan

P5 reads the raw device to find payloads hidden outside files. Exit gate: every planted marker found on every image type, within the time estimate, with no content in logs.

| WP     | Scope                                                                                                                                                   | Requirements              | Tests written first                                                                                                       | Size | After |
|--------|---------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------|---------------------------------------------------------------------------------------------------------------------------|------|-------|
| WP-5.1 | Deep-scan fixtures: images with markers in MBR and VBR boot code, partition gaps, unallocated blocks, slack, deleted entries, an extra hidden partition | —                         | Fixture self-tests: every marker sits at its declared offset                                                              | M    | P4    |
| WP-5.2 | Raw read path: helper hands a read-only block-device descriptor to a sandboxed deep-scan worker                                                         | DEEP-01                   | The worker cannot write to the device or open another one; no other worker receives the descriptor                        | S    | 5.1   |
| WP-5.3 | Device mapper with The Sleuth Kit in the sandbox: partitions, file-system extents, gaps, allocated and unallocated totals                               | DEEP-02                   | Maps of every fixture match their expected layout; a malformed partition table gives a finding, not a crash               | M    | 5.2   |
| WP-5.4 | Boot code and gap scanning with YARA-X and signature carving; carved objects re-enter the cascade with their origin                                     | DEEP-03, FR-24            | Markers in boot code and gaps found; a carved PE goes through EMBER and the AV engines and is reported with origin CARVED | M    | 5.3   |
| WP-5.5 | Deep mode: unallocated blocks, slack and deleted entries; mode selection by policy, size or request                                                     | DEEP-04, DEEP-07          | Markers in each area found in deep mode and absent from standard-mode results                                             | M    | 5.4   |
| WP-5.6 | Time estimate and budget from measured read throughput                                                                                                  | NFR-18                    | On large images the estimate stays within a set tolerance; the budget stops the scan cleanly and reports coverage         | S    | 5.5   |
| WP-5.7 | Entropy map, HIDDEN_PAYLOAD finding and rule D2, privacy rules                                                                                          | DEEP-06, DEEP-08, DEEP-09 | A high-entropy region is reported; D2 alerts by default and blocks when configured; logs hold offsets and hashes only     | S    | 5.5   |
| WP-5.8 | Lock: write P6 acceptance tests, review, lock                                                                                                           | P6 scope                  | They exist, fail, and are locked                                                                                          | S    | 5.7   |

## 10. P6 · Logging

P6 makes every event provable and forwardable. Exit gate: tampering detected, full replay to the fake collector with no loss. P6 only needs P1's domain events, so it can start early if someone else takes it.

| WP     | Scope                                                                                   | Requirements           | Tests written first                                                                                                         | Size | After    |
|--------|-----------------------------------------------------------------------------------------|------------------------|-----------------------------------------------------------------------------------------------------------------------------|------|----------|
| WP-6.1 | OCSF event model and mapping of every kiosk event to its class                          | LOG-01                 | Each emitted event validates against the pinned OCSF schema version                                                         | S    | P1       |
| WP-6.2 | Append-only, hash-chained store with signed checkpoints, and a verification tool        | LOG-02, LOG-03         | Edited, deleted, reordered or inserted entries are each detected; a clean log verifies                                      | M    | 6.1      |
| WP-6.3 | Separate event and transfer logs, rotation, capacity notification, unprivileged service | LOG-01, LOG-04, LOG-05 | Rotation at capacity keeps the chain valid across files; the kiosk keeps scanning; the service holds no privilege           | S    | 6.2      |
| WP-6.4 | Fake collector implementing the platform contract (`events:batch`, `heartbeat`)         | LOG-06                 | Contract tests for the collector itself: ack semantics, duplicate handling, authentication                                  | S    | 6.1      |
| WP-6.5 | Forwarder: persistent queue, mutual TLS, at-least-once delivery, de-duplication         | LOG-06, LOG-07         | Collector cut then restored: no loss, no reordering; duplicates ignored; wrong certificate refused                          | M    | 6.3, 6.4 |
| WP-6.6 | Signed manual export and path pseudonymisation                                          | LOG-08, LOG-09         | Export verifies offline; pseudonymised paths are stable per kiosk and reveal no original path; no file content in any event | S    | 6.3      |
| WP-6.7 | Lock: write P7 acceptance tests, review, lock                                           | P7 scope               | They exist, fail, and are locked                                                                                            | S    | 6.6      |

## 11. P7 · Kiosk UI

P7 gives the kiosk its screens and its administration. Exit gate: user and administrator journeys green in Playwright.

| WP      | Scope                                                                                                       | Requirements               | Tests written first                                                                                                                  | Size | After |
|---------|-------------------------------------------------------------------------------------------------------------|----------------------------|--------------------------------------------------------------------------------------------------------------------------------------|------|-------|
| WP-7.1  | OpenAPI contract for the local API                                                                          | UI-01, UI-02               | Contract tests generated from the schema fail against an empty server                                                                | S    | P6    |
| WP-7.2  | Local API: Unix socket or loopback, per-boot token, progress stream                                         | UI-01, UI-02               | Requests without a valid token refused; no listener on any external interface; progress events arrive in order                       | M    | 7.1   |
| WP-7.3  | Administrator authentication: Argon2id, lockout, administrator and super-administrator roles                | FR-17, UI-07               | Wrong passwords lock the account after the set count; an administrator cannot manage administrator accounts; super-administrator can | M    | 7.2   |
| WP-7.4  | Kiosk shell: `cage` and Chromium lockdown, strict content security policy                                   | UI-03, UI-04               | Keyboard shortcuts cannot leave the page; navigation to another origin blocked; inline scripts refused                               | M    | 7.2   |
| WP-7.5  | User journey, part 1: home, device check with USB explanations, scan progress, results tree                 | USB-07, FR-16              | Playwright: rejected device explained; results filter by verdict; explanations shown per object                                      | M    | 7.4   |
| WP-7.6  | User journey, part 2: selection, quarantine, transfer, report, safe file-name rendering                     | FR-11, FR-12, FR-16, UI-05 | Only CLEAN files selectable in compliant mode; trapped names (control characters, right-to-left override) shown escaped and flagged  | M    | 7.5   |
| WP-7.7  | Password-protected archives opened in an isolated environment                                               | FR-07                      | Without the password nothing transfers; with it, contents are scanned like any archive                                               | M    | 7.6   |
| WP-7.8  | Administrator screens: policy and profiles, engines and certifications, update import, logs, scan-only mode | FR-21, ENG-07              | Policy change requires the right role and is logged; scan-only mode never writes to any medium                                       | M    | 7.3   |
| WP-7.9  | English and French, touch use, readability                                                                  | UI-08, NFR-16              | Every string has both translations; journeys pass at kiosk resolution with touch input                                               | S    | 7.6   |
| WP-7.10 | Lock: write P8 acceptance tests, review, lock                                                               | P8 scope                   | They exist, fail, and are locked                                                                                                     | S    | 7.8   |

## 12. P8 · Enrichment

P8 adds optional online analysis without weakening the offline posture. Exit gate: no upload possible outside the configured mode, and every ENR requirement green. Tests never call the real VirusTotal API: they run against recorded responses.

| WP     | Scope                                                                                                                                         | Requirements                   | Tests written first                                                                                                                                        | Size | After    |
|--------|-----------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|------|----------|
| WP-8.1 | Provider interface and fake provider (found, not found, quota exceeded, timeout, server error)                                                | ENR-01                         | Contract tests run against the fake provider, then reused for every real provider                                                                          | S    | P7       |
| WP-8.2 | Policy settings and deployment profiles: `enrichment.enabled`, `enrichment.upload`, `enrichment.deny_types`, regulated and community profiles | ENR-04, ENR-13                 | Each upload mode allows exactly what it should; the deny list holds in every mode; no profile means regulated defaults; changes need a super-administrator | M    | 8.1      |
| WP-8.3 | VirusTotal provider: v3 hash lookup, standard upload, Private Scanning endpoints                                                              | ENR-01, ENR-03, ENR-10         | Recorded responses parsed into findings; Private Scanning used when licensed; ZIP password passed only with Private Scanning                               | M    | 8.1      |
| WP-8.4 | Quota-aware scheduler, priority order, asynchronous results, rule E1, post-transfer alert                                                     | ENR-05, ENR-06, ENR-07         | Rate limits respected under load; UNSCANNABLE served first; “not found” never downgrades; a late detection on a transferred file raises the alert          | M    | 8.3      |
| WP-8.5 | Enrichment dialog: hash or full file per file, sharing warning, administrator approval when required                                          | ENR-02, ENR-03, UI-09          | Hash preselected; no upload button in `disabled` mode; approval required in `admin_approval` mode; warning shown before any upload                         | M    | 8.2, 8.4 |
| WP-8.6 | Offline bundles and the analyst tool `ostia-enrich`                                                                                           | ENR-12                         | Bundle signatures checked both ways; a tampered result bundle refused on import                                                                            | M    | 8.3      |
| WP-8.7 | Relay client against the fake platform; direct mode with an egress allowlist                                                                  | ENR-01, NFR-08                 | Relay mode never holds the key on the kiosk; direct mode can reach only the provider API, and only in a profile that allows it                             | S    | 8.4      |
| WP-8.8 | Key storage and enrichment logging                                                                                                            | ENR-08, ENR-09, ENR-11, SEC-14 | Key encrypted at rest and absent from every log; each request logged with what was sent, by whom and approved by whom                                      | S    | 8.5      |
| WP-8.9 | Lock: write P9 acceptance tests, review, lock                                                                                                 | P9 scope                       | They exist, fail, and are locked                                                                                                                           | S    | 8.8      |

## 13. P9 · Release 1.0

P9 makes Ostia updatable, hardened, measured and documented. Exit gate: every MUST requirement green in the traceability matrix, reference medium scanned in under 10 minutes, 1.0 released.

| WP     | Scope                                                                                                               | Requirements                  | Tests written first                                                                                        | Size | After      |
|--------|---------------------------------------------------------------------------------------------------------------------|-------------------------------|------------------------------------------------------------------------------------------------------------|------|------------|
| WP-9.1 | TUF repository tooling (`tuftool`): top-level roles, one delegated role per engine, documented M-of-N root ceremony | UPD-03, ENG-06                | A bundle signed by one engine's key cannot carry another engine's content; root rotation test              | M    | P8         |
| WP-9.2 | Updater: verify with `tough`, atomic apply, anti-rollback per component, return to previous state on failure        | UPD-01, UPD-02, UPD-04, FR-18 | Older bundle refused; altered bundle refused; an update failing midway leaves the previous version running | M    | 9.1        |
| WP-9.3 | Integrity check of binaries, policies and configuration at boot                                                     | UPD-05                        | A modified binary or policy stops the kiosk in a safe state and logs why                                   | S    | 9.2        |
| WP-9.4 | Release pipeline: signed artefacts, SBOM, hashes, reproducible-build check                                          | UPD-06, UPD-08                | Release job fails without an SBOM; two builds of the same commit compared                                  | M    | 9.2        |
| WP-9.5 | Hardening checklist automated where possible (ANSSI-BP-028 subset) and integrator guide                             | Spec §13                      | Checklist script fails on a deliberately weakened test image                                               | M    | 9.3        |
| WP-9.6 | Performance bench on the reference medium and tuning                                                                | NFR-01, NFR-03                | Bench fails above 10 minutes in standard mode or 60 s to ready                                             | M    | 9.2        |
| WP-9.7 | Evaluation bench (isolated, opt-in, outside CI) and public benchmark report per engine and fused                    | Spec §3                       | Spike-like: report produced from a pinned corpus; reproducible from its manifest                           | M    | 9.6        |
| WP-9.8 | Documentation: user, administrator, integrator, deployment profiles, engine-pack authoring                          | —                             | Reviewed, not tested; every configuration key documented (checked by script)                               | M    | 9.5        |
| WP-9.9 | Release 1.0: final traceability review, tag, publish                                                                | All MUST                      | Traceability matrix shows 100 % of MUST requirements green                                                 | S    | 9.1 to 9.8 |

**After 1.0.** Content disarm (FR-15), capa, learned fusion, syslog output (LOG-10), the central platform, the workstation agent and micro-VM isolation each get their own plan once 1.0 is out.

## 14. Phase gate checklist

A phase closes only when every item below is ticked, by the project owner, in the phase's gate issue. A failed item reopens a work package; it never waives the gate.

- Every acceptance test of the phase passes, unchanged since it was locked (hash manifest verified).

- Traceability matrix: every MUST requirement of the phase has at least one passing test.

- Coverage at or above the thresholds of NFR-14 on the code touched by the phase.

- No static-analysis warning, no dependency advisory, no licence outside the allowlist.

- Fuzz targets of the phase ran their nightly campaign with no open crash.

- Performance budgets of the phase met on the reference machine.

- Decision records written for every choice made during the phase.

- Specification updated if the phase changed a requirement (version bumped, affected work packages re-planned).

- Next phase's acceptance tests written, reviewed and locked (the phase's lock package).

- Short retrospective written: measured pace per size, surprises, plan adjustments.

## 15. Instructions file for coding agents

This file sits at the repository root as `AGENTS.md`, with a `CLAUDE.md` pointing to it. It is created in WP-0.9 and changes only through a reviewed merge request.

``` markdown
# Ostia — rules for coding agents

## Before writing anything
- Read the work package (WP) row and every requirement it cites in docs/spec.
- If a requirement is ambiguous, stop and write the question in the merge request. Do not guess.

## Test first, always
1. Write the tests listed for the WP. Tag each one: #[req("FR-06")] or @pytest.mark.req("FR-06").
2. Run them. Show they fail, and that they fail for the expected reason.
3. Commit: test(FR-06): <what the tests check>
4. Write the minimum code to make them pass. Commit: feat(FR-06): <what was built>
5. Refactor only with the whole suite green.

## Never
- Never edit, skip, mark expected-to-fail or weaken an existing test to make it pass.
- Never touch tests/acceptance/** (locked acceptance tests).
- Never add real malware, secrets, API keys or network calls to code, tests or fixtures.
- Never parse file content in the orchestrator; parsing belongs in sandboxed workers.
- Never add `unsafe` outside crates listed in docs/unsafe-allowlist.md.
- Never add a dependency without naming it and its licence in the merge request.

## Scope
- One WP per branch: wp/<id>-<slug>. Merge request title: [WP-x.y] <scope>.
- Change only what the WP needs. Unrelated fixes go in their own WP.

## Before saying "done"
- `just check` passes: format, lint, types, tests, coverage, traceability, audit.
- The merge request lists: requirements covered, tests added, decisions taken, anything left open.
```

## 16. Tracking and re-planning

Each work package is an issue; progress is read from merged packages and gate issues, not from estimates. Durations appear only once P0 and P1 have given a measured pace.

**Tracking.**

- One issue per work package, titled `[WP-x.y] <scope>`, labelled with its phase, size and requirement ids.

- One gate issue per phase, holding the checklist of section 14.

- A project board with columns: ready (all “After” packages merged), in progress, in review, merged.

- The traceability matrix, published by CI on every merge, is the single view of requirement coverage.

**Estimating after P1.** Record the number of sessions each package took. The median per size (S, M) gives the pace; the remaining packages per size give a range for each phase, recomputed at every gate.

**Re-planning triggers.**

| Trigger                                                                  | Action                                                                                                                                 |
|--------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------|
| A package grows beyond M while in progress                               | Stop, split it into new packages, re-plan the phase                                                                                    |
| A gate fails twice                                                       | Retrospective before any new package; adjust scope or split the phase                                                                  |
| A requirement changes                                                    | Bump the specification version, update the registry (WP-0.3), re-plan affected packages; locked tests change only by explicit decision |
| A spike changes an architecture decision (for example usbsas in WP-0.11) | Update the ADR, then the packages it affects, before the next lock package                                                             |
| A dependency breaks (for example `thrember`, `signify`)                  | Pin, add a non-regression test, open a package to track the upgrade                                                                    |
