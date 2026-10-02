---
paths:
  - "crates/sandbox/**"
  - "crates/media/**"
  - "crates/usb-sentinel/**"
  - "crates/enrich/**"
  - "crates/journal/**"
  - "crates/updater/**"
  - "crates/api/**"
  - "crates/engine-host/**"
  - "packaging/**"
  - "deploy/**"
  - "**/*.service"
  - "**/seccomp*"
  - "tools/dev/**"
---

# Security rules for sensitive components

Ostia defends a network against hostile media. Code in these paths is the attack surface.

- Fail closed: on any doubt (parse error, timeout, missing signature, unknown field, version
  mismatch), refuse and report. Never fall back to a permissive default.
- Validate all input at the boundary with an explicit allowlist (paths, mount options, device
  names, policy keys, manifest fields, HTTP parameters). Reject unknown fields in signed documents.
- Privileged helper (`media`): smallest possible binary, no shell, no `PATH` lookup, absolute tool
  paths, fixed option sets (`ro,noexec,nosuid,nodev`), arguments validated by a parser that is fuzzed.
  It never receives a path chosen by content on the medium.
- Sandbox: user, mount, network, PID and IPC namespaces; allowlist seccomp; read-only root;
  private tmpfs; cgroups v2 limits on memory, CPU, PIDs and write size; one sandbox per medium,
  destroyed after the session. A sandbox escape test is a requirement test, not an optional one.
- Signatures: Ed25519 for policies, manifests, bundles and exports; verify before parsing the payload
  where the format allows it; canonical JSON (JCS, RFC 8785) for signed JSON.
- Secrets: VirusTotal keys, signing keys and admin credentials never in code, tests, logs, errors,
  reports or crash dumps. Tests generate throwaway keys at runtime in a temp dir.
- Enrichment: off by default; `enrichment.upload` is one of `disabled`, `admin_approval`, `user_choice`;
  `enrichment.deny_types` holds in every mode; the regulated profile is the default; a lookup or upload
  can only raise a verdict (E1), never lower it. Tests use recorded responses only.
- Logs: OCSF events with metadata, hashes and offsets; never file content, never key material;
  user paths pseudonymised (HMAC per kiosk) where LOG-09 says so.
- Real devices: code must never write to the input medium. Output formatting targets only a device
  carrying the controlled-medium marker and distinct from the input.
- Dev scripts under `tools/dev/` that need root do one thing, validate their arguments, refuse any
  `/dev/sd*` or `/dev/nvme*` target, and are listed by the owner in sudoers. Adding one is an owner decision.
