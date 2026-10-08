# Ostia — phase status

Updated by the agent in each work package's merge request (tick the WP).
`Current phase` and the gate boxes are changed by the owner only.

Current phase: P1 · Pipeline

Legend: `- [x] WP-x.y scope — branch` once merged. Gate: ticked by the owner after `/phase-gate` evidence.

## P0 · Foundations

- [x] WP-0.1 Repository skeleton: Cargo workspace, uv project, justfile, rust-toolchain.toml, pre-commit hooks, Apache-2... (after: —) — wp/0.1-repository-skeleton
- [x] WP-0.2 Dev environment: Debian WSL setup script, dev container identical to the CI image; checks for loop devices,... (after: 0.1) — wp/0.2-dev-environment
- [x] WP-0.3 Requirements registry: requirements.yaml (id, level, phase, ANSSI) generated from the specification (after: 0.1) — wp/0.3-requirements-registry
- [x] WP-0.4 Traceability tool: #[req] attribute and pytest marker, matrix generator, CI rule “a MUST of the active phas... (after: 0.3) — wp/0.4-traceability-tool
- [x] WP-0.5 Protobuf contracts v1 and framing libraries in Rust and Python: length prefix, size cap, version check (after: 0.1) — wp/0.5-protobuf-framing
- [x] WP-0.6 Fuzz target for the frame decoder, wired into CI (short run per merge, long nightly) (after: 0.5) — wp/0.6-fuzz-frame-decoder
- [x] WP-0.7 Test doubles: fake engine (configurable hint, score, delay, crash), fake clock, fake collector and fake pro... (after: 0.5) — wp/0.7-test-doubles
- [x] WP-0.8 Supply-chain gates: cargo-deny (licences, sources, advisories), cargo-audit, pip-audit with hash-pinned req... (after: 0.1) — wp/0.8-supply-chain-gates
- [x] WP-0.9 Test locking: hash manifest per tests/acceptance/pN/, CI check, CODEOWNERS rule; agent instructions file (s... (after: 0.4) — wp/0.9-test-locking
- [x] WP-0.10 Decision records ADR-01 to ADR-13 in docs/adr/ (after: —) — wp/0.10-decision-records
- [x] WP-0.11 Spike: usbsas evaluation as media layer (licence review, process interface, performance on reference images... (after: 0.2) — wp/0.11-usbsas-spike
- [x] WP-0.12 Lock: write P1 acceptance tests, review, lock (after: 0.4, 0.9) — wp/0.12-lock-p1

Gate P0 (owner): [x] evidence in `docs/gates/P0.md` reviewed; `tests/acceptance/p1` locked and tagged `lock-p1`; retrospective written

## P1 · Pipeline

- [x] WP-1.1 Domain model: Session, Medium, ObjectNode, verdicts, worst-of ordering (after: P0) — wp/1.1-domain-model
- [x] WP-1.2 Verdict policy engine: declarative policy format, loader with signature check, rules R1–R7, hooks for D1 an... (after: 1.1) — wp/1.2-verdict-policy
- [x] WP-1.3 Disk-image fixture generator: FAT, exFAT, NTFS, ext4 with planted files, hidden files, alternate data strea... (after: P0) — wp/1.3-disk-image-fixtures
- [x] WP-1.4 Development mount layer: loop device, read-only, file-system detection, clean refusal of unsupported systems (after: 1.3) — wp/1.4-dev-mount-layer
- [ ] WP-1.5 Inventory with hidden files and alternate streams, metadata, single read with SHA-256 and SHA-1, copy into... (after: 1.4)
- [ ] WP-1.6 Worker host v0: spawn a worker, pass the object as descriptor 3, framed exchange, timeout and crash handling (after: 1.1)
- [ ] WP-1.7 Triage worker (Rust): type from content, extension mismatch flag (after: 1.6)
- [ ] WP-1.8 Extraction worker, part 1: zip, tar, gz; limits on depth, ratio, total size, count; children returned as ob... (after: 1.6)
- [ ] WP-1.9 Extraction worker, part 2: 7z, rar, cab, iso, msi (after: 1.8)
- [ ] WP-1.10 Orchestrator pipeline: session lifecycle, bounded queues, dispatch to the fake engine, medium verdict, JSON... (after: 1.2, 1.5, 1.7)
- [ ] WP-1.11 Maximum scan time and configurable expiry action (after: 1.10)
- [ ] WP-1.12 Lock: write P2 acceptance tests, review, lock (after: 1.10)

Gate P1 (owner): [ ] evidence in `docs/gates/P1.md` reviewed; `tests/acceptance/p2` locked and tagged `lock-p2`; retrospective written

## P2 · EMBER engine

- [ ] WP-2.1 Sandbox: user, mount and network namespaces, allowlist seccomp, read-only root, private tmpfs, one sandbox... (after: P1)
- [ ] WP-2.2 Resource limits with cgroups v2: memory, CPU, process count, write size, duration (after: 2.1)
- [ ] WP-2.3 Python worker framework: framing, descriptor input, structured errors, shared test harness (after: P0)
- [ ] WP-2.4 Model bundle: model files, thresholds, hashes, metadata, signature; build-time fetch script that pins threm... (after: 2.3)
- [ ] WP-2.5 EMBER worker: feature extraction with pinned thrember and pefile, routing to per-format models, inference (after: 2.4, 2.1)
- [ ] WP-2.6 Explanation: per-feature contributions from LightGBM, top factors, readable label table (after: 2.5)
- [ ] WP-2.7 Calibration tool: run the clean corpus, choose high and low thresholds for a target false-positive rate, wr... (after: 2.5)
- [ ] WP-2.8 Performance: inference benchmark, feature-extraction profile, process-pool sizing (after: 2.5)
- [ ] WP-2.9 Policy integration: rules R4 and R5 with the real model; verdict log carries model hash and thresholds (after: 2.6, 2.7)
- [ ] WP-2.10 Lock: write P3 acceptance tests, review, lock (after: 2.9)

Gate P2 (owner): [ ] evidence in `docs/gates/P2.md` reviewed; `tests/acceptance/p3` locked and tagged `lock-p3`; retrospective written

## P3 · Engines

- [ ] WP-3.1 Engine manifest: schema, loader, signature check (after: P2)
- [ ] WP-3.2 Engine host: native adapter, trust levels (alone, K-of-N, advisory), per-engine unwanted-software mapping (after: 3.1)
- [ ] WP-3.3 CLI adapter: command template, exit-code mapping, output parsing, sandbox profile (after: 3.2)
- [ ] WP-3.4 ICAP adapter (RFC 3507 client): OPTIONS, RESPMOD, preview, 204; loopback-only network namespace (after: 3.2)
- [ ] WP-3.5 ClamAV through clamd over a local socket; concurrent reload off; manifest (after: 3.2)
- [ ] WP-3.6 YARA-X worker: rule bundle compilation, severity convention, licence list per rule set (after: 3.2)
- [ ] WP-3.7 Reputation worker: NSRL bloom filter, MalwareBazaar hash lists (after: 3.2)
- [ ] WP-3.8 Office heuristics worker (oletools) (after: 3.2)
- [ ] WP-3.9 PDF heuristics worker (after: 3.2)
- [ ] WP-3.10 PE heuristics worker: Authenticode check, entropy, abnormal sections (after: 3.2)
- [ ] WP-3.11 Conformance kit ostia engine certify and engine health reporting (after: 3.3, 3.4)
- [ ] WP-3.12 Cascade tuning and mutation testing of the policy (after: 3.5 to 3.10)
- [ ] WP-3.13 Lock: write P4 acceptance tests, review, lock (after: 3.12)

Gate P3 (owner): [ ] evidence in `docs/gates/P3.md` reviewed; `tests/acceptance/p4` locked and tagged `lock-p4`; retrospective written

## P4 · USB and media

- [ ] WP-4.1 Device test bench: Debian machine, kernel with dummy_hcd and configfs gadgets; gadget fixtures for plain st... (after: P2)
- [ ] WP-4.2 USB sentinel: udev events, USBGuard policy generation for external and internal ports, descriptor fingerprint (after: 4.1)
- [ ] WP-4.3 Driver allowlist on external ports (after: 4.2)
- [ ] WP-4.4 Session-long device monitoring and anomaly heuristics (after: 4.2)
- [ ] WP-4.5 Privileged mount and raw-read helper: minimal binary, strict parameter validation, dedicated namespace, fil... (after: 4.2)
- [ ] WP-4.6 Encrypted ephemeral workspace and cryptographic erasure (after: 4.5)
- [ ] WP-4.7 Output medium: controlled-medium marker, formatting, copy of the scanned copies, SHA-256 verification (after: 4.5)
- [ ] WP-4.8 Signed transfer manifest (after: 4.7)
- [ ] WP-4.9 Service accounts and systemd units (after: 4.5)
- [ ] WP-4.10 End-to-end on real drives (scripted, plus a short manual protocol) (after: 4.6 to 4.9)
- [ ] WP-4.11 Lock: write P5 acceptance tests, review, lock (after: 4.10)

Gate P4 (owner): [ ] evidence in `docs/gates/P4.md` reviewed; `tests/acceptance/p5` locked and tagged `lock-p5`; retrospective written

## P5 · Deep scan

- [ ] WP-5.1 Deep-scan fixtures: images with markers in MBR and VBR boot code, partition gaps, unallocated blocks, slack... (after: P4)
- [ ] WP-5.2 Raw read path: helper hands a read-only block-device descriptor to a sandboxed deep-scan worker (after: 5.1)
- [ ] WP-5.3 Device mapper with The Sleuth Kit in the sandbox: partitions, file-system extents, gaps, allocated and unal... (after: 5.2)
- [ ] WP-5.4 Boot code and gap scanning with YARA-X and signature carving; carved objects re-enter the cascade with thei... (after: 5.3)
- [ ] WP-5.5 Deep mode: unallocated blocks, slack and deleted entries; mode selection by policy, size or request (after: 5.4)
- [ ] WP-5.6 Time estimate and budget from measured read throughput (after: 5.5)
- [ ] WP-5.7 Entropy map, HIDDEN_PAYLOAD finding and rule D2, privacy rules (after: 5.5)
- [ ] WP-5.8 Lock: write P6 acceptance tests, review, lock (after: 5.7)

Gate P5 (owner): [ ] evidence in `docs/gates/P5.md` reviewed; `tests/acceptance/p6` locked and tagged `lock-p6`; retrospective written

## P6 · Logging

- [ ] WP-6.1 OCSF event model and mapping of every kiosk event to its class (after: P1)
- [ ] WP-6.2 Append-only, hash-chained store with signed checkpoints, and a verification tool (after: 6.1)
- [ ] WP-6.3 Separate event and transfer logs, rotation, capacity notification, unprivileged service (after: 6.2)
- [ ] WP-6.4 Fake collector implementing the platform contract (events:batch, heartbeat) (after: 6.1)
- [ ] WP-6.5 Forwarder: persistent queue, mutual TLS, at-least-once delivery, de-duplication (after: 6.3, 6.4)
- [ ] WP-6.6 Signed manual export and path pseudonymisation (after: 6.3)
- [ ] WP-6.7 Lock: write P7 acceptance tests, review, lock (after: 6.6)

Gate P6 (owner): [ ] evidence in `docs/gates/P6.md` reviewed; `tests/acceptance/p7` locked and tagged `lock-p7`; retrospective written

## P7 · Kiosk UI

- [ ] WP-7.1 OpenAPI contract for the local API (after: P6)
- [ ] WP-7.2 Local API: Unix socket or loopback, per-boot token, progress stream (after: 7.1)
- [ ] WP-7.3 Administrator authentication: Argon2id, lockout, administrator and super-administrator roles (after: 7.2)
- [ ] WP-7.4 Kiosk shell: cage and Chromium lockdown, strict content security policy (after: 7.2)
- [ ] WP-7.5 User journey, part 1: home, device check with USB explanations, scan progress, results tree (after: 7.4)
- [ ] WP-7.6 User journey, part 2: selection, quarantine, transfer, report, safe file-name rendering (after: 7.5)
- [ ] WP-7.7 Password-protected archives opened in an isolated environment (after: 7.6)
- [ ] WP-7.8 Administrator screens: policy and profiles, engines and certifications, update import, logs, scan-only mode (after: 7.3)
- [ ] WP-7.9 English and French, touch use, readability (after: 7.6)
- [ ] WP-7.10 Lock: write P8 acceptance tests, review, lock (after: 7.8)

Gate P7 (owner): [ ] evidence in `docs/gates/P7.md` reviewed; `tests/acceptance/p8` locked and tagged `lock-p8`; retrospective written

## P8 · Enrichment

- [ ] WP-8.1 Provider interface and fake provider (found, not found, quota exceeded, timeout, server error) (after: P7)
- [ ] WP-8.2 Policy settings and deployment profiles: enrichment.enabled, enrichment.upload, enrichment.deny_types, regu... (after: 8.1)
- [ ] WP-8.3 VirusTotal provider: v3 hash lookup, standard upload, Private Scanning endpoints (after: 8.1)
- [ ] WP-8.4 Quota-aware scheduler, priority order, asynchronous results, rule E1, post-transfer alert (after: 8.3)
- [ ] WP-8.5 Enrichment dialog: hash or full file per file, sharing warning, administrator approval when required (after: 8.2, 8.4)
- [ ] WP-8.6 Offline bundles and the analyst tool ostia-enrich (after: 8.3)
- [ ] WP-8.7 Relay client against the fake platform; direct mode with an egress allowlist (after: 8.4)
- [ ] WP-8.8 Key storage and enrichment logging (after: 8.5)
- [ ] WP-8.9 Lock: write P9 acceptance tests, review, lock (after: 8.8)

Gate P8 (owner): [ ] evidence in `docs/gates/P8.md` reviewed; `tests/acceptance/p9` locked and tagged `lock-p9`; retrospective written

## P9 · Release 1.0

- [ ] WP-9.1 TUF repository tooling (tuftool): top-level roles, one delegated role per engine, documented M-of-N root ce... (after: P8)
- [ ] WP-9.2 Updater: verify with tough, atomic apply, anti-rollback per component, return to previous state on failure (after: 9.1)
- [ ] WP-9.3 Integrity check of binaries, policies and configuration at boot (after: 9.2)
- [ ] WP-9.4 Release pipeline: signed artefacts, SBOM, hashes, reproducible-build check (after: 9.2)
- [ ] WP-9.5 Hardening checklist automated where possible (ANSSI-BP-028 subset) and integrator guide (after: 9.3)
- [ ] WP-9.6 Performance bench on the reference medium and tuning (after: 9.2)
- [ ] WP-9.7 Evaluation bench (isolated, opt-in, outside CI) and public benchmark report per engine and fused (after: 9.6)
- [ ] WP-9.8 Documentation: user, administrator, integrator, deployment profiles, engine-pack authoring (after: 9.5)
- [ ] WP-9.9 Release 1.0: final traceability review, tag, publish (after: 9.1 to 9.8)

Gate P9 (owner): [ ] evidence in `docs/gates/P9.md` reviewed; retrospective written
