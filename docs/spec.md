# Ostia — Software Specification

Open-source removable-media kiosk · v0.2 · Oct 2, 2026 · Matthias Vaytet

## 1. How to read this document

This document states what Ostia must do, how each behaviour is verified, and the order in which it is built. Every requirement has an identifier, and every identifier is bound to at least one test written before the code.

**Status.** Version 0.2, draft for review. This English version is the reference; it supersedes the French v0.1. Locked choices: Rust core, Python analysis workers, Apache-2.0 licence, web UI in kiosk mode, LightGBM EMBER2024 as the first ML engine. New in v0.2: project name, third-party antivirus plug-in SDK, USB device defence, deep media analysis, optional online enrichment (VirusTotal).

**Requirement levels.**

- **MUST**: required for 1.0. A MUST without a passing test blocks the phase exit.
- **SHOULD**: expected; a waiver needs an architecture decision record (section 21).
- **MAY**: optional, planned after 1.0.

**Identifiers.**

| Prefix | Area | Section |
| --- | --- | --- |
| FR | Functional requirements | 5 |
| NFR | Non-functional requirements | 6 |
| ENG | Third-party engine SDK | 9 |
| USB | USB device defence | 10 |
| DEEP | Deep media analysis | 11 |
| ENR | Online enrichment | 12 |
| SEC | Isolation and hardening | 13 |
| CTR | Contracts and data | 14 |
| LOG | Logging and forwarding | 15 |
| UI | Kiosk UI and local API | 16 |
| UPD | Updates and supply chain | 17 |

The “ANSSI” column refers to security functions FS1 to FS15 of ANSSI-PG-076, the French national cybersecurity agency's functional and security profile for import airlocks and media kiosks. It is the compliance baseline.

**Traceability.** Every test declares the requirement it covers: `#[req("FR-06")]` in Rust, `@pytest.mark.req("FR-06")` in Python. CI produces the requirement → tests → status matrix on every run.

**Reading order.** Sections 2–4: why and against what. Sections 5–17: what to build. Sections 18–20: how and in what order. Section 21: decisions, risks, open questions.

## 2. Context, name, goals and non-goals

Ostia is an offline kiosk that inspects a removable medium and transfers only files judged clean to a controlled output medium. It combines signature and heuristic engines, a static machine-learning model (EMBER2024), USB device defence and deep media analysis, a combination no open-source tool offers today.

**Name.** Ostia was the port of ancient Rome, where every cargo bound for the city was landed and checked; the word comes from the Latin *ostium*, the door. Ostia grants files the same passage, and its two syllables read the same in most languages. It is a working name until a trademark search is done (ADR-10). “Pratique” was dropped as too French; “Lazaret”, “Kordon”, “Cordon” and “Vigil” are already used by security projects.

**Why ML on a kiosk.** A kiosk is often disconnected, so its signature databases are structurally behind. A static model generalises without daily updates. This is where it adds the most.

**Measurable goals for 1.0.**

| ID | Goal | Success measure |
| --- | --- | --- |
| G1 | Functional compliance with ANSSI-PG-076 | Mandatory functions FS1, FS3, FS5–FS14 covered by passing tests (FS15 out of scope) |
| G2 | Scan time | Reference medium scanned in under 10 minutes on the recommended configuration (8 cores, 16 GB), standard mode |
| G3 | Controlled false positives | Rate measured on the reference clean corpus, under the ceiling set in phase 2 |
| G4 | Explainability | 100 % of non-clean verdicts list the engines, rules and factors behind them |
| G5 | Offline operation | Zero outbound connections at runtime, except the configured log collector and, if enabled, the enrichment relay |
| G6 | Device defence | 100 % of emulated malicious USB devices in the test harness blocked or flagged |
| G7 | Usable logs | OCSF events, hash-chained, signed, replayable to the central platform |
| G8 | Quality | 100 % of MUST requirements traced to a passing test; ≥ 90 % coverage on the Rust core |

The 10-minute figure follows the order of magnitude given by ANSSI-PG-076 for scanning a medium. The reference medium (volume, file count, types) is defined in phase 0.

**Non-goals for 1.0.**

- Workstation agent and EDR: only the transfer manifest they will rely on is specified (FR-22).
- Model retraining: Ostia consumes frozen, signed models.
- Dynamic sandbox detonation.
- Data export from the operational network, and classified networks (as in the ANSSI profile).
- Network import airlock (FS15): 1.0 is a two-media kiosk.
- Verifying USB controller firmware: not achievable in software in general (section 10).
- Enclosure hardware: physical requirements are listed for the integrator, not implemented.
- CSPN certification: a long-term aim, not guaranteed by 1.0.

**Users.** The three roles of the ANSSI profile: user (inserts a medium, selects files to transfer), administrator (configures, reads logs), super-administrator (also manages administrator accounts).

**Deployment profiles.** Ostia is open source for a broad community and must also pass the review of regulated organisations. Every setting that trades security for convenience is configurable, and two signed profiles ship with the kiosk:

| Setting | Regulated profile | Community profile |
| --- | --- | --- |
| Transfer mode | Compliant (FR-10) | Compliant, selective mode allowed |
| Enrichment | Off, or hash-only (`disabled`) | On, user choice (`user_choice`) |
| Upload deny list | Office documents | Empty |
| Enrichment connectivity | Offline export or central relay | Any, including direct |
| Deep analysis | On for media up to an administrator-set size | On request |

With no profile selected, the regulated defaults apply: secure by default, relaxed by explicit choice.

## 3. Landscape and positioning

Market leaders win on engine count, content disarm and certification; no open-source tool combines multi-engine scanning, offline static ML, device defence and standard logs. That is the gap Ostia targets.

| Product | Type | Published strengths | Limit for us |
| --- | --- | --- | --- |
| [OPSWAT MetaDefender Kiosk](https://www.opswat.com/products/metadefender/kiosk) | Commercial | Multiscanning with 30+ engines, content disarm on 200+ file types, AI detection | Proprietary, licensed engines |
| [Hogo S3Box / S3Pos](https://www.mysih.fr/hogo-obtient-la-certification-de-securite-de-premier-niveau-cspn-de-lanssi-pour-sa-station-blanche-s3pos-monobloc/) | Commercial (FR) | ANSSI CSPN certification; S3Agent checks on workstations that media went through the kiosk | Proprietary |
| [KUB Cleaner](https://www.globalsecuritymag.com/Schneider-Electric-choisit-la,20180515,78584.html) | Commercial (FR) | 2 to 5 antivirus engines, offline updates, workstation agent, management console | Proprietary |
| CIRCLean | Open source | USB-to-USB transfer with file conversion, on Raspberry Pi | No multi-engine detection |
| [Pandora (CIRCL)](https://github.com/pandora-analysis/pandora) | Open source (AGPL) | Modules for hashlookup, MalwareBazaar, OLE, msodde, YARA; self-hostable | Web analysis tool, not a kiosk; no ML |
| usbsas (CEA) | Open source (GPLv3), Rust | Reads untrusted USB drives without the kernel's USB storage and file-system drivers, each step in its own restricted process; kiosk web client; remote antivirus analysis | Closest prior art; GPLv3 cannot be merged into an Apache-2.0 core; no ML, no multi-engine policy |

**Closest prior art: [usbsas](https://github.com/cea-sec/usbsas).** It moves USB packet, SCSI and file-system parsing out of the kernel into separate seccomp-restricted processes, and is designed as a USB-to-USB transfer kiosk. Its media layer is stronger than a kernel mount. Ostia's added value lies elsewhere: ML detection, the multi-engine plug-in SDK, the verdict policy, device behaviour monitoring, deep analysis and standard logs. Reusing usbsas as Ostia's media layer, as a separate process, is evaluated in phase 0 (ADR-05).

**Differentiators to hold.**

1. Embedded EMBER2024 static ML, useful without connectivity.
2. Third-party antivirus engines pluggable through a public SDK and conformance kit.
3. Behavioural USB device defence and deep media analysis, reported to the user.
4. Per-verdict explanation, engine by engine.
5. Declarative, versioned, tested, published verdict policy.
6. Open OCSF logs that any SIEM can ingest.
7. Reproducible public benchmark: detection measured per engine, then fused.
8. Auditable code, a precondition for a future security evaluation.

**Accepted gaps.** Ostia will not ship 30 commercial engines. The answer is architectural: the plug-in SDK (section 9) lets a deployer add commercial engines under their own licence. The ANSSI profile itself asks that the choice of engines be left to the customer. Content disarm comes after 1.0, starting with office formats and PDF.

## 4. Threat model

We start from the ANSSI-PG-076 model and add the threats specific to an open-source detector and to the new features. Guiding principle: every byte and every descriptor coming from the medium is hostile, and the kiosk must survive any file and any device.

**Attackers (from the ANSSI profile).** A legitimate user inserting a compromised medium or making a mistake; an unauthorised person with physical access; an attacker who has compromised an administrator account, except the super-administrator.

**Assumptions (from the profile).** The attacker can reach every physical port and get a trapped device plugged in, but does not open the enclosure. They can buy an identical unit to hunt for flaws; for an open-source project they also have the code and the model weights. Administrators are competent, not hostile, and read the logs.

**Assets.** Software, signatures and models; accounts and secrets; configuration and verdict policy; event and transfer logs; analysed files, input medium and results; enrichment API keys; the downstream operational network.

| ID | Threat | Surface | Countermeasures |
| --- | --- | --- | --- |
| M1 | Kiosk compromise through a file exploiting a parser (PE, Office, PDF, archive, an antivirus engine) | Engines | Throwaway sandboxed workers; no parsing in the orchestrator (SEC-01 to SEC-06) |
| M1 | Malformed file system targeting the mount driver | Kernel, mount | Read-only, limited file systems, dedicated namespace (FR-02, FR-03, SEC-08) |
| M1 | Device presenting a keyboard, mouse or network interface (BadUSB) | USB stack | Exact mass-storage allowlist, driver allowlist (USB-01 to USB-03) |
| M1 | Device lying about its class, or re-enumerating mid-session | USB stack | Driver allowlist, session-long monitoring (USB-03, USB-04) |
| M2 | Analysis bypass: file changed between scan and copy, misleading extension, unpacked archive | Pipeline | Single hashed read, content-based typing, recursive extraction (FR-05, FR-06, SEC-10) |
| M2 | Payload hidden outside files: unallocated space, slack, boot code, alternate data streams | Medium layout | Deep media analysis (DEEP-01 to DEEP-09) |
| M2 | Evasion of the public ML model | EMBER engine | Engine ensemble, per-deployment weights, model hash logged (NFR-17) |
| M4 | Denial of service: archive bomb, huge file, millions of files, parser loop | Extraction, engines | Hard limits, timeouts, memory quotas, UNSCANNABLE verdict (FR-06, FR-14, SEC-04) |
| M5 | Corrupted or rolled-back update, including a third-party engine update | Update import | Signed TUF bundles, per-engine delegated roles, anti-rollback (UPD-01 to UPD-05, ENG-06) |
| M6, M7 | Deleted or altered logs | Local store, transport | Hash-chained, signed log; authenticated forwarding (LOG-01 to LOG-08) |
| M8 | Data leak through enrichment: a sensitive file uploaded to a third-party service | Enrichment | Hash preselected, uploads only within the configured mode, deny list (ENR-02 to ENR-04, ENR-13) |
| M1 | Trapped file name (control characters, right-to-left override, UI injection) | UI | Names never interpreted, escaped, invisible characters made visible (UI-05) |
| M3 | Administrator impersonation | Admin UI | Authentication, roles, no remote admin in 1.0 (FR-17, UI-06) |

M1 to M7 are the ANSSI profile's threats; M8 is added by the enrichment feature. The profile also stresses that a kiosk is not enough on its own: it belongs to a removable-media policy (ports disabled elsewhere, restricted use). That policy is outside the software scope, but the operations guide must restate it.

## 5. Functional requirements

Twenty-five requirements cover the full journey, from device insertion to the transfer manifest. The Phase column refers to the plan in section 20.

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| FR-01 | Detect media insertion and accept only mass-storage devices, under the USB defence rules of section 10 | MUST | FS14 | P4 |
| FR-02 | Mount the input medium read-only and non-executable (`ro,noexec,nosuid,nodev`) | MUST | FS14 | P4 |
| FR-03 | Support FAT12/16/32, exFAT, NTFS and ext2/3/4; reject any other file system cleanly with a clear message | MUST | FS1 | P1 |
| FR-04 | Inventory all content before analysis, including hidden files and NTFS alternate data streams, with metadata (path, size, dates, attributes) | MUST | FS3 | P1 |
| FR-05 | Identify each file's type from its content, not its extension; a type/extension mismatch is a risk indicator | MUST | FS3 | P1 |
| FR-06 | Extract archives recursively (zip, 7z, rar, tar, gz, cab, iso, msi) under limits on depth, compression ratio, total size and file count; any breach yields UNSCANNABLE | MUST | FS1 | P1 |
| FR-07 | For password-protected files, ask for the password and open the file in an isolated environment; without a password, no transfer | MUST | FS1 | P7 |
| FR-08 | Submit every file, including every extracted or carved object, to all engines applicable to its type | MUST | FS5 | P2–P3 |
| FR-09 | Produce a per-file verdict: CLEAN, SUSPICIOUS, MALICIOUS or UNSCANNABLE, with score, contributing engines and explanation | MUST | FS1 | P1 |
| FR-10 | In compliant mode (default), block every transfer as soon as a file is MALICIOUS or UNSCANNABLE, or the device is rejected, and notify the user and administrators | MUST | FS1 | P1 |
| FR-11 | Let the user select the files to transfer among CLEAN files; enforce a configurable allowlist of business file formats | MUST | FS3 | P7 |
| FR-12 | Let the user quarantine a file they consider risky | MUST | FS3 | P7 |
| FR-13 | Transfer to an output medium distinct from the input, formatted by the kiosk, by copying the scanned copy; verify every copied file by SHA-256 | MUST | FS1, FS13, FS14 | P4 |
| FR-14 | Enforce a configurable maximum scan time (10 minutes by default) and apply the administrator's chosen action when it expires | MUST | FS1, FS12 | P1 |
| FR-15 | Disarm (rebuild) selected formats: Office to PDF, rasterised PDF, re-encoded images; never binaries; fail if the format is unrecognised | MAY | FS2 | after 1.0 |
| FR-16 | Display a readable scan report and export it to the output medium | MUST | FS3 | P7 |
| FR-17 | Authenticate administrators and enforce the administrator and super-administrator roles | MUST | FS7 | P7 |
| FR-18 | Update engines, signatures, rules, models and software offline from signed bundles, with no rollback | MUST | FS5, FS8 | P9 |
| FR-19 | Log transfers and events, and forward them to a collector | MUST | FS4, FS9 | P6 |
| FR-20 | Reset the analysis environment between two media and wipe working data by cryptographic erasure | MUST | FS5, FS14 | P4 |
| FR-21 | Offer a “scan only” mode with no transfer or modification, which preserves evidence for investigation | SHOULD | — | P7 |
| FR-22 | Write a signed transfer manifest on the output medium, verifiable later by a workstation agent | SHOULD | FS13 | P4 |
| FR-23 | Let administrators add antivirus engines without modifying the core (section 9) | MUST | FS5 | P3 |
| FR-24 | Analyse areas of the medium outside files: boot code, partition gaps, unallocated space, slack (section 11) | MUST | FS1 | P5 |
| FR-25 | Offer an optional complementary online analysis of selected files, VirusTotal first (section 12) | SHOULD | — | P8 |

**Compliant and selective modes.** The ANSSI profile requires that no file be transferred when an analysis fails or a file is malicious. That is the default behaviour (FR-10). A selective mode, which would allow transferring only the clean files, can be enabled by a super-administrator. The UI and every log entry then flag it as non-compliant.

## 6. Non-functional requirements

Performance requirements are budgets checked automatically by CI, not intentions.

| ID | Area | Requirement | Level | Verification |
| --- | --- | --- | --- | --- |
| NFR-01 | Performance | Scan the reference medium in standard mode in under 10 minutes on the recommended configuration | MUST | Performance bench, phase 9 |
| NFR-02 | Performance | EMBER2024 inference under 10 ms per file, feature extraction excluded | MUST | `criterion` / `pytest-benchmark` |
| NFR-03 | Performance | Kiosk ready less than 60 s after service start, antivirus databases loaded | SHOULD | System test |
| NFR-04 | Resources | Every worker is capped in memory, CPU and process count (cgroups v2); a breach kills the worker without affecting the core | MUST | Integration test with a trap file |
| NFR-05 | Robustness | No file or device can stop the orchestrator; a crashed worker yields UNSCANNABLE and is restarted | MUST | Fault-injection tests |
| NFR-06 | Robustness | Core message decoders and parsers are fuzzed continuously | MUST | `cargo-fuzz` in CI |
| NFR-07 | Reproducibility | Same input and same engine, rule, model and policy versions give the same verdict | MUST | Non-regression tests on a frozen corpus |
| NFR-08 | Offline | No network connection at runtime except to the configured collector and, if enabled, the enrichment relay | MUST | System test with outbound firewall default-deny |
| NFR-09 | Code safety | No `unsafe` in the Rust core outside listed, justified modules | MUST | `#![forbid(unsafe_code)]` by default, review |
| NFR-10 | Least privilege | No service runs as root except a minimal mount and raw-read helper | MUST | systemd configuration test |
| NFR-11 | Dependencies | Pinned, audited, licence-checked dependencies; SBOM produced for every release | MUST | `cargo-deny`, `cargo-audit`, `pip-audit`, CycloneDX SBOM |
| NFR-12 | Explainability | Every non-CLEAN verdict lists engines, rules, scores and main model factors | MUST | Contract tests on the report |
| NFR-13 | Extensibility | Adding an engine requires no core change, only a manifest and an adapter (section 9) | MUST | Fake engine added in tests |
| NFR-14 | Quality | Coverage ≥ 90 % (Rust core), ≥ 85 % (Python workers); mutation score ≥ 70 % on the verdict policy | MUST | `cargo-llvm-cov`, `coverage.py`, `cargo-mutants`, `mutmut` |
| NFR-15 | Portability | Target Debian stable x86-64; development on WSL2 | MUST | CI on a Debian image |
| NFR-16 | Usability | English and French UI, touch-friendly, readable at 1 m | SHOULD | Playwright tests, review |
| NFR-17 | ML calibration | Model thresholds set for a target false-positive rate measured on the clean corpus; model version, hash and thresholds logged with every verdict | MUST | Calibration test, phase 2 |
| NFR-18 | Deep analysis | Deep mode shows an estimated time from measured read throughput and respects an administrator time budget | MUST | System test on large disk images |
| NFR-19 | Enrichment | Local verdicts never wait on enrichment; enrichment failures never block a session | MUST | Tests with an unreachable or throttled fake provider |

## 7. Architecture

An unprivileged Rust orchestrator drives throwaway workers. Only the mount and raw-read helper inside Media access is privileged, and no file content or device data is interpreted outside a sandbox.

```text
Input media ──► Media access (USB sentinel, ro mount, raw read; only privileged helper)
Admin media ──► Updater (TUF / tough, no rollback)
Kiosk UI (Chromium/cage) ◄──► Local API (Unix socket, token, SSE)
VirusTotal (relay or export) ◄┄┄► Enrichment (hash or full file, per policy)
          all of the above ◄──► ORCHESTRATOR (Rust, unprivileged):
                                inventory, hashing, cascade, verdict policy, transfer
                                     │  Protobuf over stdio; clamd and ICAP on loopback
                                     ▼
          ┌─ Throwaway sandboxes, one per medium ─────────────────────────────┐
          │ Rust workers   │ Python workers │ AV engines        │ Deep scan    │
          │ triage, unpack │ EMBER2024      │ ClamAV + plug-ins │ boot code,   │
          │ YARA-X, reput. │ format heurist.│ native/CLI/ICAP   │ gaps, slack  │
          └────────────────────────────────────────────────────────────────────┘
ORCHESTRATOR ──► Output media (signed manifest)
ORCHESTRATOR ──► Log (OCSF, hash-chained) ──► Forwarder (spool, mTLS) ┄┄► Central platform (later)
```

Solid arrows are 1.0 flows; dashed ones are optional (VirusTotal) or later (central platform). The side arrows run from the orchestrator to the output medium (left) and to the log (right).

| Component | Language | Account | Role |
| --- | --- | --- | --- |
| Media access (`media`, `usb-sentinel`) | Rust | `os-media` + minimal privileged helper | USB policy and monitoring, read-only mount, raw read for deep analysis, output formatting |
| Orchestrator (`orchestrator`) | Rust (tokio) | `os-orch` | Sessions, inventory, hashing, single copy, cascade, verdict policy, transfer |
| Sandbox (`sandbox`) | Rust | — | Worker launch, namespaces, seccomp, cgroups, timeouts |
| Rust workers | Rust | `os-worker` | Content-based type triage, archive extraction, YARA-X, reputation, deep scan |
| Python workers | Python | `os-worker` | EMBER2024, Office, PDF and PE heuristics |
| Engine host (`engine-host`) | Rust | `os-engine` | Manifest loading, CLI and ICAP adapters, conformance kit |
| clamd and third-party engines | Vendor code | per engine | Antivirus scanning, through local socket, CLI or ICAP |
| Enrichment (`enrich`) | Rust | `os-enrich` | Hash lookups, gated uploads, offline bundles, relay client |
| Log and forwarder (`journal`) | Rust | `os-journal` | OCSF events, hash chain, signatures, persistent queue, forwarding |
| Local API (`api`) | Rust (axum) | `os-api` | Endpoints for the UI, progress stream |
| Kiosk UI (`ui`) | TypeScript | `os-kiosk` | User and administrator screens |
| Updater (`updater`) | Rust (`tough`) | `os-update` | TUF bundle verification and application |

**Session flow.**

1. Media access applies the USB policy, fingerprints the device and keeps watching it; the medium is mounted read-only.
2. The orchestrator inventories files and alternate streams, reads each object once, hashes it and copies it into the encrypted workspace.
3. A triage worker identifies types; an extraction worker opens archives and returns their contents as new objects.
4. The orchestrator dispatches every object to applicable engines in parallel, with bounded queues to avoid overload.
5. The deep-scan worker maps the device and scans boot code and gaps, plus unallocated space and slack in deep mode; carved objects re-enter step 4.
6. The verdict policy combines results per object, then for the medium with device and hidden-payload findings.
7. The UI shows results; the user selects files and may request enrichment; Media access formats the output medium; the orchestrator copies the scanned copies, verifies hashes and writes the signed manifest.
8. Every step emits log events; the session ends with cryptographic erasure of the workspace. Late enrichment results are matched to the session afterwards.

## 8. Detection engines, cascade and verdict policy

LightGBM EMBER2024 ships first (phase 2). Built-in heuristic engines and the third-party plug-in SDK follow in phase 3, deep media analysis in phase 5, costly engines and content disarm after 1.0.

| Engine | Formats | Runs as | Output | Phase |
| --- | --- | --- | --- | --- |
| EMBER2024 (LightGBM) | PE (Win32, Win64, .NET), ELF, PDF, APK | Sandboxed Python worker | Score \[0,1\], main factors | P2 |
| Hash reputation | All | Rust worker | Known bad / known good / unknown | P3 |
| ClamAV | All | Separate `clamd` process, local socket | Signature name | P3 |
| Third-party antivirus | Declared per engine | Plug-in (native, CLI or ICAP adapter) | Detection name | P3 |
| YARA-X | All | Sandboxed Rust worker | Matching rules and severity | P3 |
| Office heuristics (oletools) | DOC, XLS, PPT, OOXML, RTF | Sandboxed Python worker | Macros, DDE, embedded objects | P3 |
| PDF heuristics | PDF | Sandboxed Python worker | JavaScript, automatic actions, embedded files | P3 |
| PE heuristics | PE | Sandboxed Python worker | Authenticode signature, entropy, abnormal sections | P3 |
| Deep media scanner | Raw device areas | Sandboxed worker | Hidden payloads, boot code anomalies | P5 |
| capa | PE, ELF | Python worker, cascade-triggered | Capabilities, MITRE ATT&CK techniques | after 1.0 |

**The EMBER2024 model.** The `thrember` package extracts 2,568-feature vectors with `pefile` and downloads the published models, one per format plus an all-formats model. Each booster weighs around 3.6 MB. On the EMBER2024 test set, the reference model detects about 94.5 % of malware at a 1 % false-positive rate, and drops sharply on the “challenge” set of evasive malware. Hence an engine ensemble rather than a single engine. Models are fetched once on the build machine, checked by hash and shipped in a signed bundle: the kiosk never downloads anything.

**Analysis cascade.**

1. Device checks (section 10), then inventory, SHA-256 and SHA-1 hashing, single copy into the workspace.
2. Content-based type identification, recursive archive extraction.
3. Hash reputation.
4. Fast engines in parallel: ClamAV, third-party antivirus, YARA-X, EMBER2024, format heuristics.
5. Device-level analysis: boot code and partition gaps always; unallocated space and slack in deep mode (section 11).
6. Costly engines only for ambiguous files (after 1.0).
7. Verdict policy, per file then for the medium.
8. Optional, asynchronous: online enrichment of selected files (section 12).

**File verdict policy.** A signed, versioned declarative file. Rules apply in order; the first one that matches decides.

| Rule | Condition | Verdict |
| --- | --- | --- |
| R1 | Failure, timeout, limit reached, unsupported format for a risky type | UNSCANNABLE |
| R2 | Known-bad hash, or a detection by an engine trusted alone, or K-of-N detections among the other engines, or a critical YARA rule | MALICIOUS |
| R3 | Exact known-good hash (NSRL list): overrides ML and heuristics, never R1 or R2 | CLEAN |
| R4 | EMBER score ≥ high threshold | MALICIOUS |
| R5 | EMBER score between low and high thresholds | SUSPICIOUS |
| R6 | Risky heuristic: auto-run macro, DDE, PDF JavaScript, double extension, type/extension mismatch, single non-trusted engine detection | SUSPICIOUS |
| R7 | None of the above | CLEAN |
| E1 | Asynchronous enrichment reports ≥ N engine detections (N configurable, default 3): upgrades any verdict to MALICIOUS, never downgrades | MALICIOUS |

**Medium verdict.** The worst file verdict, combined with device-level findings:

- **D1, device rejected** (non-storage interface, re-enumeration): session aborted, nothing transferred.
- **D2, hidden payload** (executable content found outside files): administrator alert; blocks transfers if the policy says so (default: alert only, since hidden areas are never copied).

In compliant mode, SUSPICIOUS blocks the file concerned; MALICIOUS and UNSCANNABLE block the whole medium.

**Thresholds.** EMBER high and low thresholds are chosen to reach a target false-positive rate measured on the reference clean corpus (NFR-17), never left at 0.5. They ship with the model in the same signed bundle.

**Explanation.** EMBER's main factors come from the per-feature contributions LightGBM can compute (SHAP-style values), mapped to readable labels (“high-entropy executable section”, “process-injection imports”).

**Evasion.** Public weights let an attacker optimise files against the model. Three answers: the engine ensemble, the option for each deployment to substitute its own private weights, and logging the hash of the model used for every verdict.

**Learned fusion.** A meta-model combining all engine outputs is planned after 1.0. It needs a clean labelled corpus; the rule-based policy stays auditable meanwhile.

## 9. Third-party antivirus engines: plug-in SDK

Adding an antivirus engine takes a signed manifest and one of three standard adapters, then a pass of the conformance kit. No core change is ever needed, which is how Ostia closes the engine-count gap with commercial kiosks.

**Three adapter types.**

- **Native**: a worker speaking the Protobuf engine contract (section 14). Best integration, used for built-in engines.
- **CLI**: a command template run inside the sandbox, with declared rules to map exit codes and parse the output into findings. Covers most Linux command-line scanners.
- **ICAP**: a client for the Internet Content Adaptation Protocol (RFC 3507). Many antivirus products expose an ICAP server; one client library lists compatibility with ClamAV (through c-icap), Sophos, Kaspersky, Trend Micro, ESET, McAfee and F-Secure.

**Example manifest.**

```toml
[engine]
id = "vendorx-av"
vendor = "Vendor X"
adapter = "cli"                  # native | cli | icap
file_types = ["*"]
trust = "alone"                  # alone | k_of_n | advisory

[cli]
command = ["/opt/vendorx/bin/scan", "--stdin-fd=3", "--json"]
clean_exit_codes = [0]
detect_exit_codes = [1]
finding_regex = '"threat":\s*"(?P<name>[^"]+)"'
version_command = ["/opt/vendorx/bin/scan", "--version"]

[sandbox]
network = "none"                 # "loopback" only for daemon-based engines
memory_mb = 1024
timeout_s = 60

[updates]
tuf_role = "engines/vendorx-av"   # delegated role, see section 17
apply_command = ["/opt/vendorx/bin/update", "--offline", "{bundle_dir}"]

[licence]
notice = "Commercial engine; licence held by the deployer."
```

| ID | Requirement | Level | Phase |
| --- | --- | --- | --- |
| ENG-01 | Every engine is declared by a signed manifest: identity, adapter, file types, trust level, sandbox profile, limits, verdict mapping, update hook, licence notice | MUST | P3 |
| ENG-02 | Native, CLI and ICAP adapters are provided and tested | MUST | P3 |
| ENG-03 | Each engine runs in its own sandbox; a daemon-based engine gets a dedicated loopback-only network namespace with no outside route | MUST | P3 |
| ENG-04 | An engine can be enabled only after passing the conformance kit: EICAR detected, clean corpus with no detection, correct timeout, crash and malformed-input handling, concurrent load, version reporting, offline update applied | MUST | P3 |
| ENG-05 | Per-engine trust: detection decisive alone, counted in a K-of-N vote, or advisory only; unwanted-software categories mapped per engine | MUST | P3 |
| ENG-06 | Each engine's content updates arrive through its own delegated TUF role, so one vendor's key cannot sign another's update | MUST | P9 |
| ENG-07 | Engine health shown in the UI and logs: version, content age, last self-test; the policy can refuse to scan when a required engine's content is older than a threshold | SHOULD | P3 |
| ENG-08 | The core ships no commercial engine; manifests for commercial engines live in a separate “engine packs” repository, and licence compliance is the deployer's responsibility | MUST | P3 |

**Conformance kit.** `ostia engine certify <manifest>` runs the ENG-04 suite and writes a signed certification report. The kit is itself built test-first, and is the same suite that guards the built-in engines in CI.

## 10. USB device defence (BadUSB)

Ostia can reliably detect and block what a malicious device *does*: present a keyboard, a network card, extra interfaces, or change identity mid-session. It cannot verify what a device *is*: USB controller firmware is out of reach of software scanners. The design defends on behaviour and says so plainly.

**What BadUSB is.** Researchers at SRLabs showed in 2014 that the firmware of common USB controllers can be reprogrammed, turning a thumb drive into a keyboard, a network adapter or a boot-time attacker. They noted that malware scanners cannot read that firmware, and that generic class allowlists can be bypassed.

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| USB-01 | External ports accept only devices whose interface set is exactly one mass-storage interface (USBGuard rule `allow with-interface equals { 08:*:* }`); everything else is blocked by default | MUST | FS14 | P4 |
| USB-02 | Internal devices (touchscreen and the like) are allowed only by exact identity, port and descriptor hash | MUST | FS14 | P4 |
| USB-03 | Driver allowlist: on external ports only the `usb-storage` and `uas` drivers may bind; HID, communications, networking, wireless, audio and video drivers cannot bind there, so a device lying about its class still gets no driver | MUST | FS14 | P4 |
| USB-04 | The input device is watched for the whole session: any re-enumeration, new interface or configuration change aborts the session, discards its results and raises a USB alert | MUST | FS14 | P4 |
| USB-05 | A descriptor fingerprint is logged for every device: VID/PID, serial, bcdDevice, strings, interface list, descriptor hash | MUST | FS9 | P4 |
| USB-06 | Anomaly heuristics raise USB findings: several configurations, vendor-specific interfaces, inconsistent strings, unusual storage subclass or protocol, reported capacity inconsistent with readable size | SHOULD | — | P4 |
| USB-07 | A blocked device is explained to the user (“this device tried to present itself as a keyboard”), never rejected silently | MUST | FS3 | P7 |
| USB-08 | Output media are of a controlled model and identified by a kiosk-written marker; an unknown output device is refused | MUST | FS13, FS14 | P4 |

**Why USB-03 matters.** Pulse Security showed that a device can declare the HID class while implementing mass storage: USBGuard accepted it on class alone and the kernel's storage driver took over. Class rules alone are not enough; restricting which drivers can bind on external ports closes that gap.

**Limits stated in the user documentation.**

- A storage-only device with malicious firmware that never changes interface is indistinguishable from a healthy one in software. Its risk to the kiosk is limited to the storage protocol and the file system, both of which are already handled as hostile.
- Electrical attacks (surge devices) need hardware protection on the controllers, an integrator requirement from the ANSSI profile.
- The organisational answer from the ANSSI profile remains: controlled output media of a known model, ideally with signed firmware.

**Testing without hardware.** Malicious devices are emulated with the Linux USB gadget framework (configfs) on a virtual host controller (`dummy_hcd`): HID plus storage composites, class liars, delayed re-enumeration. These tests run in CI on a kernel that provides those modules (section 19).

## 11. Deep media analysis

Ostia reads the raw device, not only the files, to find payloads hidden where a file-level scanner never looks. Boot code and partition gaps are checked on every medium; unallocated space, slack and deleted entries are checked in deep mode, under a time budget.

**Why it matters on a kiosk.** Only selected files are copied to the output medium, so a payload hidden outside files does not reach the operational network through Ostia. It still matters for three reasons: it is a strong sign of a targeted attack; the input medium may later be plugged in elsewhere; and some boot-time attacks live in boot code, not in files.

| Area | What can hide there | Checked |
| --- | --- | --- |
| Partition table and boot code (MBR, VBR, GPT) | Bootkit code | Always |
| Gaps before, between and after partitions | Raw payload, hidden volume | Always |
| NTFS alternate data streams, extended attributes | Payload attached to an innocent file | Always (in the inventory) |
| Unallocated file-system blocks | Payload written outside any file | Deep mode |
| File slack (between end of file and end of cluster) | Small payloads, staging data | Deep mode |
| Deleted entries not yet overwritten | Dropped tools, earlier stages | Deep mode |
| Additional logical units on the same device | Hidden second drive | Always (listed and scanned) |
| Controller firmware, controller-reserved flash | Firmware implants | Out of reach |

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| DEEP-01 | The raw device is opened read-only by the privileged helper; only the file descriptor is passed to a sandboxed deep-scan worker | MUST | FS14 | P5 |
| DEEP-02 | The worker maps the device: partition tables, file-system extents, gaps, allocated and unallocated bytes | MUST | FS1 | P5 |
| DEEP-03 | Boot code and gaps are scanned with YARA-X and signature carving (PE, ELF, scripts, archives); carved objects re-enter the normal cascade as virtual files marked “hidden origin” | MUST | FS1 | P5 |
| DEEP-04 | In deep mode, unallocated blocks, slack and deleted entries are scanned the same way | MUST | FS1 | P5 |
| DEEP-05 | Alternate data streams and extended attributes are listed in the standard inventory and scanned; they are never copied to the output medium | MUST | FS3 | P1 |
| DEEP-06 | An entropy map of unallocated areas is produced; large high-entropy regions are reported as possible encrypted containers | SHOULD | — | P5 |
| DEEP-07 | Two modes: standard (always on) and deep (by policy, by device size, or on administrator request), with an estimated time from measured read throughput | MUST | FS12 | P5 |
| DEEP-08 | Executable content found outside files raises the HIDDEN\_PAYLOAD medium finding (rule D2) | MUST | FS1 | P5 |
| DEEP-09 | Deep analysis reads deleted user data: only findings (offset, type, hash, rule) are stored and logged, never content; carved objects are wiped with the workspace | MUST | — | P5 |

**Implementation.** The Sleuth Kit is the reference toolset: `mmls` maps volumes and their unallocated ranges, `fls` lists names including deleted ones, and `blkls` extracts unallocated blocks or slack. It parses hostile structures in C, so it runs only inside the sandbox; Rust parsers may replace it later.

**Cost.** Deep mode reads the whole device: its duration is bounded by the device's read speed, often minutes for a large drive. That is why it is a separate mode with an estimate and a budget, rather than part of the 10-minute standard scan.

## 12. Online enrichment (VirusTotal)

Complementary online analysis is optional and can only make a verdict stricter. Whether a user may send only the hash or the whole file is a configuration choice: an organisation can lock the kiosk to hash lookups, while a community deployment can let users decide file by file, with the consequences shown before anything leaves the kiosk.

**Upload modes.** One setting, `enrichment.upload`, part of the signed policy, decides what users may send. The deny list `enrichment.deny_types` applies in every mode.

| `enrichment.upload` | Who decides what is sent | Typical deployment |
| --- | --- | --- |
| `disabled` | Nobody: hash lookups only | Regulated organisations; default of the regulated profile |
| `admin_approval` | The user asks for a full-file upload; an administrator approves or refuses | Organisations allowing uploads case by case |
| `user_choice` | The user picks hash or full file for each file, after a warning about sharing | Community and individual use; default of the community profile |

**Connectivity modes.** The kiosk stays offline by design, so enrichment never needs a direct internet route.

| Mode | How it works | When |
| --- | --- | --- |
| Offline export and import | The kiosk writes a signed request bundle (hashes, optionally approved files) to admin media; a companion tool, `ostia-enrich`, queries the provider from a connected analyst workstation; the signed results are imported back | Default for air-gapped sites |
| Central relay | The kiosk sends the request to the central platform over mutual TLS; the platform holds the API key and calls the provider | Once the central platform exists |
| Direct | The kiosk calls the provider through an egress allowlist limited to its API | Discouraged; only in an explicit “connected kiosk” profile |

| ID | Requirement | Level | Phase |
| --- | --- | --- | --- |
| ENR-01 | Enrichment providers are plug-ins behind one interface; VirusTotal API v3 is the first, others (internal threat intelligence, other services) can follow | MUST | P8 |
| ENR-02 | For each file, the user chooses between a hash lookup and a full-file upload, within what `enrichment.upload` allows; the hash lookup is always preselected | MUST | P8 |
| ENR-03 | Before any upload, the user sees the file, its size and type, the provider, and whether the file will be shared with the provider's community; VirusTotal Private Scanning is used when the deployment holds that licence, since its files are not shared with third parties | MUST | P8 |
| ENR-04 | The deny list `enrichment.deny_types` blocks uploads of listed types in every mode; it lists office documents in the regulated profile and is empty in the community profile | MUST | P8 |
| ENR-05 | Results only harden verdicts (rule E1): “not found” or zero detections never turns UNSCANNABLE or SUSPICIOUS into CLEAN | MUST | P8 |
| ENR-06 | Enrichment is asynchronous; results arriving after a transfer that flag a transferred file raise a post-transfer alert carrying the output medium's manifest identifier | MUST | P8 |
| ENR-07 | A quota-aware scheduler respects provider limits and prioritises UNSCANNABLE, then SUSPICIOUS files | MUST | P8 |
| ENR-08 | API keys are stored encrypted, never logged, never shown again after entry; in relay mode the key lives only on the central platform | MUST | P8 |
| ENR-09 | The project ships no key; documentation warns that the free public API terms forbid use in business workflows, so organisational deployments need a licence that permits it | MUST | P8 |
| ENR-10 | For password-protected ZIP files, Private Scanning can receive the password; otherwise only the hash is looked up | MAY | P8 |
| ENR-11 | Every request and result is logged: what was sent (hash or file), to which provider, chosen by whom, approved by whom, with what result | MUST | P8 |
| ENR-12 | Export and import bundles are signed by the kiosk and by the analyst tool respectively, and checked on import | MUST | P8 |
| ENR-13 | `enrichment.enabled`, `enrichment.upload` and `enrichment.deny_types` belong to the signed policy; changing them requires a super-administrator and is logged | MUST | P8 |

**What to expect for “unscannable” files.** A hash lookup only helps if the provider has seen the file before. Common files that local engines failed to parse benefit most; unique or encrypted files usually come back “unknown”, which by design changes nothing. Free-tier quotas observed on a standard account (4 lookups per minute, 500 per day, 15,500 per month) are enough for that targeted use, not for bulk lookups.

## 13. Isolation and hardening

No byte from the medium is interpreted by a privileged process or by the orchestrator. The orchestrator only reads, hashes and dispatches; all parsing happens in a throwaway worker.

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| SEC-01 | Every engine runs in a sandbox: dedicated user, mount and network namespaces, no network interface (loopback only for ENG-03 daemons), allowlist seccomp filter, read-only root | MUST | FS5, FS11 | P2 |
| SEC-02 | A fresh sandbox per medium, destroyed after the analysis | MUST | FS5 | P2 |
| SEC-03 | Workers receive files as read-only descriptors and write only to a private tmpfs | MUST | FS11 | P2 |
| SEC-04 | Per-worker limits on memory, CPU, process count, write size and duration; a breach kills the worker and yields UNSCANNABLE | MUST | FS1, FS12 | P2 |
| SEC-05 | The orchestrator parses no file content; type identification, extraction and carving happen in workers | MUST | FS11 | P1 |
| SEC-06 | Processes run under separate unprivileged accounts per function (orchestrator, workers, log, API, enrichment) | MUST | FS1, FS9, FS11 | P4 |
| SEC-07 | USB policy and driver allowlist as specified in section 10 | MUST | FS14 | P4 |
| SEC-08 | Mounting and raw reads go through a minimal privileged helper that validates its parameters and mounts in a dedicated namespace; kernel modules of unsupported file systems are disabled | MUST | FS14 | P4 |
| SEC-09 | The output medium is identified as controlled (kiosk-written marker) and can never be the input medium | MUST | FS14 | P4 |
| SEC-10 | Each file is read once from the medium; the scanned copy is the one transferred, closing the window between scan and copy | MUST | FS1 | P1 |
| SEC-11 | The workspace is an encrypted volume with an ephemeral per-session key, destroyed at session end | MUST | FS14 | P4 |
| SEC-12 | No file from the input medium can be executed by the kiosk | MUST | FS14 | P4 |
| SEC-13 | Third-party engines get no more privilege than built-in ones; their crashes and timeouts are handled like any worker | MUST | FS11 | P3 |
| SEC-14 | The enrichment component has no access to the workspace except files explicitly approved for upload | MUST | — | P8 |

**Sandbox.** Version 1.0 uses a lightweight isolator (bubblewrap or nsjail) with cgroups v2. Micro-VM isolation is considered after 1.0 for the most demanding deployments (ADR-04).

**Mounting.** Version 1.0 mounts through the kernel, read-only, in a dedicated namespace. A user-space media layer, as the open-source usbsas project already provides, would shrink the kernel surface further; its reuse is evaluated in phase 0 (ADR-05).

**Integrator requirements.** The ANSSI profile also asks for measures software cannot guarantee alone. They are listed in the integration guide and checked by a checklist in phase 9:

- Secure Boot, protected BIOS/UEFI access, no boot from removable media;
- full-disk encryption of the system disk;
- unused ports physically inaccessible, distinct input and output USB controllers, surge protection;
- physical tamper protection;
- OS hardening following the ANSSI GNU/Linux configuration guide (ANSSI-BP-028), which the profile cites.

## 14. Data model and contracts

Contracts are written in Protocol Buffers before any code, and their contract tests before any implementation. That lets the orchestrator and each engine be built independently.

| ID | Requirement | Level | Phase |
| --- | --- | --- | --- |
| CTR-01 | All orchestrator ↔ worker exchanges use versioned, length-prefixed Protobuf messages on the worker's standard input and output | MUST | P0 |
| CTR-02 | A decoder rejects any malformed, oversized or incompatible message without panicking | MUST | P0 |
| CTR-03 | Every engine result carries the engine id and version, and the version of its rules, signatures or model | MUST | P0 |
| CTR-04 | Schemas follow semantic versioning; a breaking change needs a new major version and compatibility tests | MUST | P0 |
| CTR-05 | The transfer manifest is a canonical JSON document signed with Ed25519: kiosk id, timestamp, files with SHA-256 and verdict, engine and policy versions | SHOULD | P4 |
| CTR-06 | The engine manifest (section 9) has a published schema, validated at load time | MUST | P3 |
| CTR-07 | Enrichment request and result bundles (section 12) have a published, signed schema | MUST | P8 |

**Engine contract (excerpt).**

```protobuf
syntax = "proto3";
package ostia.engine.v1;

enum Origin { ORIGIN_UNSPECIFIED = 0; FILE = 1; EXTRACTED = 2; ALT_STREAM = 3; CARVED = 4; BOOT_CODE = 5; }

message AnalyzeRequest {
  string session_id = 1;
  string object_id = 2;
  bytes sha256 = 3;
  string detected_type = 4;    // identified from content
  uint64 size = 5;
  Origin origin = 6;
  Limits limits = 7;           // memory, duration, write size
  // the object is passed as file descriptor 3, read-only
}

enum Status { STATUS_UNSPECIFIED = 0; OK = 1; ERROR = 2; TIMEOUT = 3; UNSUPPORTED = 4; }
enum Hint { HINT_UNSPECIFIED = 0; NONE = 1; CLEAN = 2; SUSPICIOUS = 3; MALICIOUS = 4; }

message Finding {
  string id = 1;               // YARA rule, AV signature, model feature
  string title = 2;
  uint32 severity = 3;         // 0 info to 4 critical
  string evidence = 4;
  repeated string attack_ids = 5;
}

message AnalyzeResponse {
  string engine_id = 1;
  string engine_version = 2;
  string content_version = 3;  // rules, signatures or model version
  Status status = 4;
  Hint hint = 5;
  optional double score = 6;   // [0,1] for scoring engines
  repeated Finding findings = 7;
  uint32 duration_ms = 8;
}
```

**Domain objects.**

| Object | Role | Key fields |
| --- | --- | --- |
| Session | One medium insertion, end to end | id, timestamps, mode (compliant, selective, scan only), scan depth, policy version |
| Device | USB device behind a medium | role, descriptor fingerprint, USB findings |
| Medium | Input or output medium | role, file system, layout map, size |
| ObjectNode | File, extracted, stream or carved object, as a tree | id, parent\_id, origin, depth, path or offset, type, size, SHA-256, SHA-1 |
| EngineResult | One engine's output for one object | full AnalyzeResponse |
| ObjectVerdict | Decision for one object | verdict, rule applied, score, explanation |
| MediumVerdict | Decision for the medium | verdict, blocking objects, device and hidden-payload findings |
| EnrichmentRecord | One online lookup or upload | provider, what was sent, approver, result, timestamps |
| Transfer | Copy to the output medium | files, verified hashes, manifest |

Session state lives in a local SQLite database, erased with the workspace except what goes to the log.

## 15. Logging and central forwarding

Ostia writes OCSF events to a hash-chained, signed local log, then forwards them store-and-forward to the central platform. The platform comes later, but its intake contract is fixed now and tested against a fake collector.

**Why OCSF.** It is an open, vendor-neutral schema backed by many security vendors. It already covers the events we need, which avoids inventing a format and eases SIEM integration.

| Kiosk event | OCSF class |
| --- | --- |
| Device inserted, rejected, removed; USB alert | Peripheral Activity \[1010\] |
| Medium scan start and end | Scan Activity \[6007\] |
| Object MALICIOUS, SUSPICIOUS or UNSCANNABLE; hidden payload; late enrichment detection | Detection Finding \[2004\] |
| Copy to output medium, quarantine | File System Activity \[1001\] |
| Administrator sign-in and actions, updates, policy changes, enrichment approvals | OCSF identity and application classes, fixed in phase 6 |

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| LOG-01 | Two separate logs: events (user, administrator and kiosk actions) and transfers (media, files, verdicts, outcome) | MUST | FS4, FS9 | P6 |
| LOG-02 | Append-only log; each entry holds the hash of the previous one; signed (Ed25519) checkpoints are issued periodically and at each rotation | MUST | FS4, FS9 | P6 |
| LOG-03 | Any alteration or deletion of an entry is detected by chain verification | MUST | FS9 | P6 |
| LOG-04 | Rotation when capacity is reached, with administrator notification; the kiosk stays operational | MUST | FS4, FS9, FS12 | P6 |
| LOG-05 | The logging service runs under an isolated unprivileged account | MUST | FS4, FS9 | P6 |
| LOG-06 | Forwarding over TLS 1.3 with mutual authentication by kiosk certificate; at-least-once delivery, de-duplicated by event id and sequence number | MUST | FS9, FS10 | P6 |
| LOG-07 | Persistent on-disk queue while the collector is unreachable; resumes without loss or reordering | MUST | FS9 | P6 |
| LOG-08 | Manual signed log export to admin media, for kiosks that are never connected | MUST | FS9 | P6 |
| LOG-09 | No file content in logs; paths can be pseudonymised by configuration | MUST | — | P6 |
| LOG-10 | Optional syslog (RFC 5424) output over TLS for existing SIEMs | MAY | FS9 | after 1.0 |

**Central platform contract (v1).**

- `POST /v1/kiosks/{kiosk_id}/events:batch`: a batch of numbered OCSF events, with the latest signed checkpoint.
- Response: highest accepted sequence number; the kiosk purges its queue up to it.
- `POST /v1/kiosks/{kiosk_id}/heartbeat`: state, engine and model versions, queue size.
- `POST /v1/kiosks/{kiosk_id}/enrichment:lookup`: relay mode for section 12; the platform holds the provider key.
- Identity: one client certificate per kiosk, issued at enrolment.

A fake collector implements this contract from phase 6. It drives the resume, replay, duplicate and tampering tests, and then serves as the executable specification of the future platform.

## 16. Kiosk UI and local API

The UI is a web application served locally by the core and shown by Chromium in kiosk mode, inside a single-application Wayland compositor such as `cage`. The same code base will later serve the central console.

**User journey.**

1. Home: “Insert your medium”, with engine status and signature dates.
2. Device check: result of the USB defence; a rejected device is explained.
3. Scan: per-file progress, estimated time, deep-mode progress when active, cancel option.
4. Results: tree view, filters by verdict, per-file explanation, medium-level findings.
5. Selection: choose CLEAN files to transfer, quarantine, request complementary online analysis when enabled.
6. Transfer: insert the output medium, formatting, copy, verification.
7. End: report, instruction to remove media, reset.

**Local administration.** Sign-in; configuration (policy, thresholds, limits, business formats, mode, scan depth, engines, enrichment); enrichment approvals; update import; log viewing and export; engine health and certification reports.

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| UI-01 | The local API listens only on a Unix socket or 127.0.0.1, with a session token regenerated at every boot | MUST | FS10 | P7 |
| UI-02 | Progress is pushed in real time (Server-Sent Events or WebSocket) | MUST | — | P7 |
| UI-03 | The kiosk browser cannot be exited, cannot open other pages or developer tools | MUST | FS14 | P7 |
| UI-04 | Strict content security policy: no external resource, no inline script | MUST | — | P7 |
| UI-05 | File names are always rendered as escaped text; control and bidirectional override characters are made visible and flagged | MUST | FS3 | P7 |
| UI-06 | No remote administration in 1.0; it will come with the central platform, over mutual TLS | MUST | FS10 | P7 |
| UI-07 | Administrator passwords stored with a slow key-derivation function (Argon2id); lockout after repeated failures | MUST | FS6, FS7 | P7 |
| UI-08 | English and French UI, touch-friendly | SHOULD | — | P7 |
| UI-09 | The enrichment dialog lets the user choose hash or full file within the configured mode, and shows file name, size, type, provider and whether the file will be shared; in \`admin\_approval\` mode an administrator must approve | MUST | — | P8 |

**Main API endpoints.** `GET /api/v1/status`; `GET /api/v1/sessions/{id}`; `GET /api/v1/sessions/{id}/objects?verdict=`; `GET /api/v1/sessions/{id}/events` (stream); `POST /api/v1/sessions/{id}/selection`; `POST /api/v1/sessions/{id}/quarantine`; `POST /api/v1/sessions/{id}/transfer`; `POST /api/v1/sessions/{id}/enrichment`; `POST /api/v1/admin/login`; `PUT /api/v1/admin/policy`; `POST /api/v1/admin/updates`; `POST /api/v1/admin/enrichment/{id}/approve`. The OpenAPI contract is written in phase 7 before the screens, and covered by contract tests.

## 17. Offline updates and supply chain

All updates arrive as a The Update Framework (TUF) repository copied to admin media and verified by the Rust `tough` library. TUF protects against rollback, version freeze, mix-and-match metadata and arbitrary software installation.

**Bundle content.** ClamAV databases, compiled YARA-X rules, EMBER models and thresholds, reputation lists, verdict policy, kiosk software packages, and the content of each enabled third-party engine under its own delegated role.

| ID | Requirement | Level | ANSSI | Phase |
| --- | --- | --- | --- | --- |
| UPD-01 | Every update is checked for authenticity and integrity before it is applied; an invalid bundle is rejected and logged | MUST | FS5, FS8 | P9 |
| UPD-02 | No version older than the installed one can be applied, for any component | MUST | FS8 | P9 |
| UPD-03 | Root keys are offline; signing the root requires several key holders (M-of-N threshold) | MUST | FS8 | P9 |
| UPD-04 | Applying an update is atomic: on failure, the kiosk returns to the previous state and stays usable | MUST | FS8 | P9 |
| UPD-05 | Installed binaries, policies and configuration are integrity-checked at boot | MUST | FS8 | P9 |
| UPD-06 | Every release ships with a CycloneDX SBOM and its hashes | MUST | — | P9 |
| UPD-07 | Python dependencies installed only with verified hashes; Rust dependencies checked by `cargo-deny` (licences, sources, advisories) | MUST | — | P0 |
| UPD-08 | Reproducible builds targeted for Rust binaries | SHOULD | — | P9 |

**Known TUF limit.** The framework normally assumes a reachable repository; on isolated sites the metadata travels by hand with the files. Metadata expiry must therefore match the real offline update cadence, or the kiosk would reject legitimate bundles.

**ClamAV stays GPL in its own process.** Ostia talks to `clamd` over a local socket and does not link the library, which keeps the project under Apache-2.0 (ADR-02). ClamAV databases keep their own signature check on top of TUF.

**YARA rule licences.** Several public rule sets carry specific licences. Every embedded set is listed with its licence, checked in CI.

## 18. Full TDD strategy

Every phase opens by writing its acceptance tests, all failing, reviewed and then locked. Development, by a person or a coding model, then means making them pass without ever changing them. These are the rails.

**Cycle rules.**

1. No production code without a prior failing test that references a requirement.
2. Red → green → refactor in small steps; every step leaves the whole suite green.
3. Two separate commits: `test(FR-06): …` then `feat(FR-06): …`. The first must fail in CI, the second makes it pass.
4. Contracts (Protobuf, OpenAPI, engine manifest, enrichment bundles) and their contract tests come before any implementation.
5. A phase requirement without a passing test blocks the phase exit.

**Locking a phase's tests.** When a phase opens, its acceptance tests are reviewed by the project owner, then locked: the `tests/acceptance/pN/` directory is protected by CODEOWNERS and its hash is checked in CI. Changing a locked test needs an explicit, traced decision.

**Rules for model-assisted development.** An instructions file at the repository root makes them explicit:

- write the test before the code and show that it fails for the right reason;
- never modify, skip or weaken a test to make it pass, and never touch locked tests;
- one requirement per branch or merge request, with its id in the title;
- run the full suite and static checks before declaring a task done;
- report an ambiguous requirement instead of interpreting it.

**Test pyramid.**

| Level | Rust tools | Python tools | What it checks |
| --- | --- | --- | --- |
| Unit | `cargo nextest`, `proptest` | `pytest`, `hypothesis` | Pure functions, verdict policy (tables), extraction limits |
| Contract | Tests on `.proto`, OpenAPI, manifests | Same on the worker side | Message compatibility, rejection of invalid messages |
| Integration | Real pipeline on disk images | Real workers in sandboxes | End to end without USB hardware |
| Device | USB gadget emulation (`dummy_hcd`, configfs) | — | Composite HID + storage, class liars, re-enumeration |
| System | Full kiosk, network off | — | Complete journey, logs, crash recovery |
| UI | — | Playwright | User and administrator journeys |
| Robustness | `cargo-fuzz` | `atheris` | Decoders, extraction, parsers, layout mapping |
| Mutation | `cargo-mutants` | `mutmut` | Test quality on the verdict policy |
| Performance | `criterion` | `pytest-benchmark` | NFR-01, NFR-02, NFR-18 budgets |

**Test corpus, with no live malware in the repository.**

- The EICAR test file for every antivirus chain, generated by the tests.
- Synthetic files generated by the tests: nested archives, small high-ratio archives, double extensions, Office documents with a harmless auto-run macro, PDFs with harmless JavaScript, trapped file names.
- Synthetic disk images (FAT, exFAT, NTFS, ext4) with planted markers in boot code, partition gaps, unallocated blocks, slack, deleted entries and alternate data streams, to test deep analysis.
- EMBER2024 feature vectors (no binaries) for the scoring path and thresholds.
- Real clean binaries for the false-positive rate.
- A fake enrichment provider replaying recorded responses, quota errors and timeouts.

Real malware is used only by a separate evaluation bench: encrypted, outside CI, on an isolated machine, opt-in only. It measures the detection rates published in the benchmark.

**EMBER model tests.** Loading and validation (2,568 dimensions, file hash); frozen reference predictions on known vectors; threshold calibration on the clean corpus; latency budget; behaviour on truncated or corrupted PE files.

**Continuous integration.** Blocking formatting and static analysis (`rustfmt`, `clippy -D warnings`, `ruff`, `mypy --strict`), tests, coverage, traceability matrix, dependency and licence audit, SBOM, short fuzzing on every merge and long fuzzing nightly, performance budgets, engine conformance kit on built-in engines.

**Definition of done.** Tests passing and traced, coverage held, no static-analysis warning, documentation and decision records updated if a choice was made, changelog entry written.

## 19. Development environment on WSL

Everything except USB device tests is developed and tested in WSL2 without a USB drive: media are replaced by disk images. Device tests and real-hardware checks run on a small dedicated Debian machine from phase 4.

**Base.**

- Windows 11, WSL2 with a Debian stable distribution, to stay close to the target.
- systemd enabled in WSL (`[boot] systemd=true` in `/etc/wsl.conf`), to test services as in production.
- Rust stable pinned by `rust-toolchain.toml`; Python 3.12 managed by `uv`; `buf` for Protobuf contracts; `just` as task runner; ClamAV (`clamd`); bubblewrap; The Sleuth Kit; Node.js for the UI and Playwright.
- A Debian development container identical to the CI image, for parity.

**USB on WSL.** WSL does not expose USB devices natively. Microsoft's documented method is `usbipd-win`: share the device (`usbipd bind`, as administrator), then attach it (`usbipd attach --wsl`); Windows loses access while it is attached. For a storage device, several reports say a WSL kernel rebuilt with USB Mass Storage support is also needed. The USB gadget modules used for BadUSB emulation (`dummy_hcd`, configfs gadgets) are equally unlikely in the stock WSL kernel. Hence the dedicated Debian machine for phases 4 and 5, rather than a custom WSL kernel.

**Disk images.** Tests create images with `mkfs.vfat`, `mkfs.exfat`, `mkfs.ntfs` and `mkfs.ext4`, plant markers at known offsets for deep analysis, attach them as loop devices and mount them like a real drive. NTFS and exFAT support in the WSL kernel is checked in phase 0; otherwise those tests run in the container or on the Debian machine.

**Repository layout.**

```text
ostia/
├── proto/                   # versioned Protobuf contracts
├── schemas/                 # engine manifest, enrichment bundles, manifest
├── crates/
│   ├── core-domain/         # domain model, verdict policy
│   ├── orchestrator/        # pipeline, cascade, sessions
│   ├── sandbox/             # worker launch and limits
│   ├── media/               # mount and raw-read helper, output formatting
│   ├── usb-sentinel/        # USB policy, monitoring, fingerprints
│   ├── engine-host/         # manifest loading, CLI and ICAP adapters
│   ├── enrich/              # enrichment scheduler and providers
│   ├── journal/             # chained log, OCSF, forwarding
│   ├── updater/             # TUF bundles
│   ├── api/                 # local API
│   └── workers/             # Rust workers: triage, extraction, YARA-X, reputation, deep scan
├── workers-py/
│   ├── ember/               # thrember + LightGBM
│   ├── office/  pdf/  pe/   # format heuristics
│   └── common/              # Protobuf framing, test harness
├── engines/                 # built-in engine manifests
├── tools/
│   ├── ostia-enrich/     # analyst-side offline enrichment tool
│   └── traceability/        # requirements → tests matrix
├── ui/                      # kiosk UI
├── tests/
│   ├── acceptance/p0..p9/   # locked acceptance tests per phase
│   ├── fixtures/            # file, disk image and USB gadget generators
│   └── fakes/               # fake engine, collector, provider, clock
└── docs/adr/                # architecture decision records
```

## 20. Phase plan

Ten phases lead to 1.0. Each opens with its acceptance tests written and locked, and closes when they all pass.

```text
P0 Foundations ─► P1 Pipeline ─► P2 EMBER ─► P3 Engines ─► P4 USB & media ─► P5 Deep scan
  ─► P6 Logging ─► P7 Kiosk UI ─► P8 Enrichment ─► P9 Release 1.0 ┄► after 1.0
Each phase opens with locked acceptance tests and closes on its exit gate.
```

The EMBER engine comes first, right after the pipeline: everything else is built around an engine already measured. USB defence and deep analysis come once real media are handled; enrichment comes last because it is optional. No durations are set here; they will be measured on the first two phases.

**Common entry rule.** The phase's acceptance tests are written, failing, reviewed by the project owner and locked. The previous phase has met its exit criterion.

| Phase | Deliverables | Tests written first (examples) | Exit criterion |
| --- | --- | --- | --- |
| P0 · Foundations | Repository, CI, traceability tool, Protobuf contracts v1, fake engine, collector, provider and clock, ADR-01 to 13, dev container; NTFS and exFAT check on WSL | Contracts (CTR-01 to CTR-04); CI fails when a requirement has no test; dependency audit (UPD-07) | CI green; P1 tests written, reviewed, locked |
| P1 · Pipeline | Inventory with alternate streams, single hashed copy, type triage, extraction under limits, verdict policy with a fake engine, maximum scan time, JSON report | FR-03 to FR-06, FR-09, FR-10, FR-14, SEC-05, SEC-10, DEEP-05: generated FAT, exFAT, NTFS, ext4 images; too-deep archive gives UNSCANNABLE; double extension gives SUSPICIOUS; rules R1 to R7 as tables | End-to-end scan of a disk image, without USB hardware |
| P2 · EMBER engine | Sandboxed Python worker with `thrember` + LightGBM, model validation, threshold calibration, factor explanation; generic sandbox (SEC-01 to SEC-04) | 2,568 dimensions; reference predictions; thresholds holding the target false-positive rate on the clean corpus; latency under 10 ms (NFR-02); corrupted PE gives UNSCANNABLE; worker killed on memory breach without affecting the core (NFR-04, NFR-05) | Budgets met; thresholds shipped in the model bundle |
| P3 · Engines | clamd, YARA-X, reputation (MalwareBazaar, NSRL), Office, PDF and PE heuristics, cascade; engine host with native, CLI and ICAP adapters; conformance kit | EICAR gives MALICIOUS (R2); NSRL hash beats ML (R3); auto-run macro gives SUSPICIOUS (R6); a fake CLI engine and a fake ICAP server pass the kit (ENG-01 to ENG-05, ENG-08) | Mutation score ≥ 70 % on the policy (NFR-14); kit certifies built-in engines |
| P4 · USB and media | USB sentinel, driver allowlist, mount helper, output formatting, verified transfer, signed manifest, ephemeral encrypted workspace | USB-01 to USB-06, USB-08, FR-01, FR-02, FR-13, FR-20, FR-22, SEC-06 to SEC-12: emulated HID + storage composite blocked; class liar gets no driver; re-enumeration aborts the session; same medium as input and output refused; hashes verified after copy | Full journey on the Debian machine with a real drive |
| P5 · Deep scan | Raw read through the helper, device mapping, boot code and gap scanning, deep mode for unallocated space, slack and deleted entries, carving, entropy map | DEEP-01 to DEEP-09: markers planted in boot code, gaps, unallocated blocks, slack and deleted entries all found; carved PE re-enters the cascade; no content in logs; time estimate within budget (NFR-18) | All planted markers found on every image type |
| P6 · Logging | Hash-chained, signed OCSF log, rotation, persistent queue, mutual-TLS forwarding, fake collector, signed export | LOG-01 to LOG-09: altered entry detected; collector cut then restored without loss; duplicate ignored | Tampering detected, full replay without loss |
| P7 · Kiosk UI | OpenAPI contract, local API, screens, authentication and roles, selection, quarantine, archive passwords, scan-only mode, USB and deep-scan screens | UI-01 to UI-08, USB-07, FR-07, FR-11, FR-12, FR-16, FR-17, FR-21: trapped file name shown escaped; invalid token refused; Playwright journeys | User and administrator journeys green |
| P8 · Enrichment | Provider interface, VirusTotal provider, quota scheduler, offline export and import with `ostia-enrich`, relay client against the fake platform, approval dialog | ENR-01 to ENR-12, UI-09, SEC-14: each upload mode enforced, deny list holds in every mode; “not found” never downgrades; late detection raises a post-transfer alert; throttling handled; key never logged | No upload outside the configured mode; all ENR tests green |
| P9 · Release 1.0 | TUF bundles with per-engine delegated roles, anti-rollback, boot-time integrity, SBOM, hardening checklist, performance bench | UPD-01 to UPD-06, ENG-06, FR-18, NFR-01: older bundle refused; altered bundle refused; failed update rolls back; reference medium under 10 minutes | All MUST requirements green; 1.0 released |
| After 1.0 | Content disarm (FR-15), capa, learned fusion, syslog (LOG-10), central platform, workstation agent, micro-VM isolation | — | — |

## 21. Decisions, risks and open questions

Thirteen decisions are taken; each becomes a `docs/adr/` file in phase 0 with its context and alternatives.

| ADR | Decision | Rejected alternative | Reason |
| --- | --- | --- | --- |
| ADR-01 | Rust core, Python engines as workers | All Python | Memory-safe core; the analysis ecosystem stays in Python |
| ADR-02 | Apache-2.0, ClamAV called through `clamd` | Linking libclamav (GPL) | Keep the permissive licence |
| ADR-03 | Length-prefixed Protobuf on workers' standard input and output | gRPC over sockets | No network stack in the sandbox, typed contract kept |
| ADR-04 | bubblewrap or nsjail sandbox + cgroups v2 | Micro-VM from 1.0 | Simpler, WSL-compatible; micro-VM reassessed after 1.0 |
| ADR-05 | Kernel mount, read-only, in a dedicated namespace, for 1.0 unless the phase 0 evaluation of usbsas concludes otherwise | Writing our own user-space USB and file-system stack now | usbsas already does this in Rust; as GPLv3 it can only run as a separate process, after licence review |
| ADR-06 | OCSF logs | Custom format, ECS | Open, vendor-neutral standard |
| ADR-07 | TUF updates verified by `tough` | Simple archive signature | Protection against rollback, freeze and mix-and-match |
| ADR-08 | Web UI in Chromium kiosk under `cage` | Native application | Reusable for the central console |
| ADR-09 | Declarative, signed verdict policy | Hard-coded logic | Auditable, table-testable, changeable without recompiling |
| ADR-10 | Project name “Ostia” (working name) | “Lazaret” | Too French, or already used by security projects (also “Kordon”, “Cordon”, “Vigil”); trademark search pending |
| ADR-11 | Third-party engines through native, CLI and ICAP adapters plus a conformance kit | Per-vendor code in the core | Core stays vendor-neutral; ICAP is widely supported |
| ADR-12 | Enrichment off by default; hash or full file chosen by the user within a configurable upload mode; harden-only | Automatic upload of unscannable files | Serves both regulated organisations and the community; confidentiality, offline posture and licence terms enforced through the signed policy |
| ADR-13 | Deep analysis with The Sleuth Kit inside the sandbox, as a separate time-budgeted mode | Always-on full-device read | Mature toolset; full reads do not fit the 10-minute budget |

| Risk | Effect | Mitigation |
| --- | --- | --- |
| Unstable `thrember` dependencies: one project had to pin `signify` to 0.7.1 after an API break | Feature extraction broken by an update | Pinned versions with hashes, non-regression tests on reference vectors |
| Model false positives on legitimate software | Users reject the kiosk | Calibration on the clean corpus, known-good hash list, SUSPICIOUS tier |
| Adversarial evasion of the public model | Missed malware | Engine ensemble, per-deployment private weights, content disarm after 1.0 |
| Python feature extraction too slow | 10-minute budget missed | Process pool, cascade, size caps, measured from phase 2 |
| ClamAV memory use (3 to 4 GiB recommended, peak during concurrent reload) | Out-of-memory kill | Concurrent reload disabled on offline kiosks |
| Sensitive file uploaded to an online service | Data leak | ENR-02 to ENR-04, approval dialog, Private Scanning preferred |
| Commercial engine licensing and Linux availability | Fewer engines than hoped | Engine packs maintained separately, ICAP route |
| USB gadget and storage support missing in WSL | Device tests blocked | Dedicated Debian machine for phases 4 and 5 |
| Deep mode too slow on large media | Users skip it | Time budget, estimate, policy by device size |
| ANSSI profile compliance confused with certification | Wrong user expectations | Documentation states: compliance targeted, certification not obtained |
| Overlap with usbsas, an existing open-source kiosk | Duplicated effort, weaker media layer | Phase 0 evaluation of reuse as a separate process; contribute upstream where licences allow |

**Open questions.**

- [ ] Confirm the name “Ostia” after a trademark search, or pick another.
- [ ] Default business file formats allowed.
- [ ] False-positive ceiling for EMBER calibration.
- [ ] Exact composition of the reference medium for the 10-minute budget.
- [ ] Default N for the enrichment rule E1 (3 proposed).
- [ ] Deep mode by default for small media, and size threshold.
- [ ] HIDDEN\_PAYLOAD: alert only (proposed) or block transfers by default.
- [ ] Which commercial engines to target first for engine packs.
- [ ] Should the network import airlock (FS15) join the post-1.0 roadmap?
- [ ] User authentication on the kiosk? The ANSSI profile does not require it.

* [ ] Reuse usbsas as Ostia's media layer (separate process, GPLv3 review) or build our own user-space stack later?
* [ ] Ship the regulated profile as the default, as proposed?

## 22. Sources

| Topic | Source |
| --- | --- |
| Compliance baseline: functions FS1–FS15, threats, assumptions | [ANSSI-PG-076, Sas et station blanche (réseaux non classifiés), v1.0, 2020](https://messervices.cyber.gouv.fr/documents-guides/anssi-profil_de_fonctionnalites_et_de_securite-sas_et_station_blanche_reseaux_non_classifies-v1.0.pdf) |
| Market leader | [OPSWAT MetaDefender Kiosk](https://www.opswat.com/products/metadefender/kiosk) |
| CSPN-certified kiosk and workstation agent | [Hogo S3Pos CSPN (MySIH)](https://www.mysih.fr/hogo-obtient-la-certification-de-securite-de-premier-niveau-cspn-de-lanssi-pour-sa-station-blanche-s3pos-monobloc/) |
| Multi-antivirus kiosk with agent and console | [KUB Cleaner at Schneider Electric (Global Security Mag)](https://www.globalsecuritymag.com/Schneider-Electric-choisit-la,20180515,78584.html) |
| CIRCLean and kiosk attack surface | [SASUSB, SSTIC 2022](https://www.sstic.org/media/SSTIC2022/SSTIC-actes/sasusb_presentation_dun_protocole_sanitaire_pour_l/SSTIC2022-Article-sasusb_presentation_dun_protocole_sanitaire_pour_lusb-desclaux_syoen.pdf) |
| Open-source file analysis | [Pandora (CIRCL)](https://github.com/pandora-analysis/pandora) |
| Name conflicts for “Lazaret” | [lazaretemail/lazaret](https://github.com/lazaretemail/lazaret), [lazaret on PyPI](https://pypi.org/project/lazaret/) |
| EMBER2024 model, `thrember`, v3 features | [EMBER2024 (GitHub)](https://github.com/FutureComputing4AI/EMBER2024) |
| Reference model performance | [EMBER dataset (Emergent Mind)](https://www.emergentmind.com/topics/ember-dataset) |
| EMBER2024 feature dimension | [DeepMalNet (GitHub)](https://github.com/laam-egg/DeepMalNet) |
| EMBER2024 booster size | [cycloevan/ember-model (Hugging Face)](https://huggingface.co/cycloevan/ember-model) |
| `thrember` dependencies | [EMBER2024 + capa integration (GitHub)](https://github.com/BenjiTrapp/transportable-detonation-chamber/pull/1) |
| ClamAV memory | [ClamAV RAM requirements](https://docs.clamav.net/manual/Installing/Docker.html?highlight=memory) |
| YARA-X | [yara-x (lib.rs)](https://lib.rs/crates/yara-x) |
| ICAP and antivirus vendor support | [toolarium ICAP client](https://github.com/toolarium/toolarium-icap-client), [SFTPGo ICAP scanning](https://docs.sftpgo.com/enterprise/tutorials/eventmanager-icap/) |
| BadUSB | [SRLabs: USB peripherals can turn against their users](https://srlabs.de/blog/usb-peripherals-turn), [LMG Security: Bad USB](https://www.lmgsecurity.com/bad-usb-very-bad-usb/) |
| USB allowlisting | [USBGuard rules language](https://github.com/USBGuard/usbguard/blob/main/doc/man/usbguard-rules.conf.5.adoc) |
| Class-only rules bypass | [Pulse Security: Bypassing USBGuard on Linux](https://pulsesecurity.co.nz/advisories/usbguard-bypass) |
| Unallocated space, slack, deleted entries | [The Sleuth Kit tool overview](https://github.com/sleuthkit/sleuthkit/wiki/TSK_Tool_Overview), [FS analysis (Sleuth Kit wiki)](https://wiki.sleuthkit.org/FS-Analysis/) |
| VirusTotal Private Scanning | [Private Scanning](https://docs.virustotal.com/docs/private-scanning), [Private file upload](https://docs.virustotal.com/reference/upload-file-private-scanning) |
| Sharing of uploaded files | [Cowrie: VirusTotal integration](https://docs.cowrie.org/en/latest/virustotal/README.html) |
| OCSF schema and event classes | [OCSF Schema](https://schema.ocsf.io/), [Understanding OCSF](https://github.com/ocsf/ocsf-docs/blob/main/overview/understanding-ocsf.md) |
| The Update Framework | [The Update Framework (Wikipedia)](https://en.wikipedia.org/wiki/The_Update_Framework), [tough (docs.rs)](https://docs.rs/crate/tough/latest), [TUF in isolated environments (EJBCA)](https://www.ejbca.org/resources/keymaster-tuf-love-securing-software-updates-with-the-update-framework/) |
| USB on WSL | [Connect USB devices (Microsoft Learn)](https://learn.microsoft.com/en-us/windows/wsl/connect-usb), [USB mass storage on WSL2](https://blog.tian.it/mount-access-physical-disks-and-usb-devices-into-wsl2/) |
| Closest open-source prior art | usbsas (CEA), github.com/cea-sec/usbsas |
| Name conflicts for Kordon, Cordon, Vigil | github.com/jqnfxa/kordon, kordon.app, github.com/marras0914/cordon, github.com/vigil-agency/vigil |

Free-tier VirusTotal quotas and terms (section 12) come from the account page of the project owner's standard API key, as observed on 2 October 2026.
