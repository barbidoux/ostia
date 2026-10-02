---
paths:
  - "proto/**"
  - "schemas/**"
  - "docs/contracts/**"
  - "**/openapi*.yaml"
  - "**/openapi*.json"
---

# Rules for contracts

- Contracts come before code, and their contract tests before any implementation (spec §18 rule 4).
- Protobuf: package `ostia.engine.v1`; `buf lint` and `buf breaking` against `main` in CI. Never reuse
  or renumber a field; removed fields become `reserved`. A breaking change means a new major package
  (`v2`) plus compatibility tests (CTR-04) and an owner decision.
- Framing: 4-byte big-endian unsigned length, then the message; reject length 0, lengths above the cap,
  truncated frames and trailing garbage. Rust and Python share golden vectors in `proto/testdata/`.
- JSON schemas: draft 2020-12, `additionalProperties: false` on every object, `$id` with a version,
  examples validated in tests. The report schema is the contract of the acceptance tests: adding an
  optional field is fine, changing or removing one is a breaking change that needs the owner.
- OpenAPI (P7): hand-written `openapi.yaml`, checked with schemathesis against the server.
- Every change to a contract file is listed under "Contracts changed" in the merge request.
