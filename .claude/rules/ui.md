---
paths:
  - "ui/**"
---

# Rules for the kiosk UI

- TypeScript strict, minimal framework (decided in an ADR at WP-7.1; Svelte proposed), `pnpm`
  with a lockfile, no CDN, no remote fonts or assets: the kiosk is offline.
- Strict Content-Security-Policy: no inline scripts or styles, no `eval`, `connect-src` limited to the
  local API. The UI talks only to the local API with the per-boot token.
- Every string displayed comes from the translation catalogues (English and French, UI-08); a test
  checks that both catalogues have the same keys.
- File names and any text from the medium are untrusted: render as text, never as HTML; escape
  control characters and bidirectional overrides visibly and flag them (UI-05).
- Accessible and touch-friendly: large targets, keyboard-free journeys, readable at kiosk resolution.
- Unit and component tests in TypeScript (Vitest), titles tagged `req("ID")`. Acceptance journeys are
  Python pytest-playwright tests under `tests/acceptance/` (one runner for every locked test).
- Selectors use `data-testid` attributes, never CSS structure or text that changes with translation.
