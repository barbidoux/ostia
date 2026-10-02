# ADR-08: Web UI shown by Chromium in kiosk mode under `cage`

- Status: accepted
- Date: 2026-10-02
- Deciders: Matthias Vaytet (owner)
- Source: spec §21, §1 "Locked choices", §16

## Context and problem statement

The kiosk needs a touch interface that the user cannot leave, that renders untrusted file names safely
(threat M1, trapped names), and whose code can later serve the central console.

## Decision drivers

- Reuse for the future central console (spec §16).
- Lockdown: the UI cannot be exited, cannot open other pages or developer tools (UI-03).
- Strict content security policy: no external resource, no inline script (UI-04).
- Local API only: Unix socket or 127.0.0.1 with a token regenerated at each boot (UI-01).

## Considered options

1. A web UI shown by Chromium in kiosk mode inside a single-application Wayland compositor such as `cage`.
2. A native application.

## Decision outcome

Chosen option 1: **a TypeScript web UI, served locally, shown by Chromium in kiosk mode under `cage`**,
talking only to the local API (with SSE or WebSocket for progress, UI-02). The UI framework is chosen
in WP-7.1.

## Consequences

- Good: one code base for the kiosk and the console; Playwright journeys as acceptance tests.
- Bad: a browser is a large component on the kiosk. Mitigation: kiosk account, compositor running a
  single application, strict CSP, no remote administration in 1.0 (UI-06).
- Follow-ups: OpenAPI contract written in phase 7 before the screens; WP-7.1, WP-7.2 (API), WP-7.4
  (cage and Chromium lockdown, CSP).

## Links

- Requirements: UI-01 to UI-09, NFR-16.
- Related: ADR-06 (UI events are logged).
