# Sable 3.1 — Functionality and UX audit

This pass focused on features that were present visually but incomplete, fragile, or unnecessarily difficult to use.

## Fixed or hardened

- Saved views: workspace compatibility checks, state sanitization, deletion confirmation, and safer storage failures.
- Architecture search: keyboard navigation, visible match counts, risk context, and filter examples.
- Resource access: inventory rows and relevant finding cards open the selected resource in the architecture/details drawer.
- Relationship evidence: dedicated evidence mode with source/target navigation.
- Blast radius / incident: resource picker when no resource is selected and clearer deterministic dependency wording.
- Path finder: source/target swap, direction option, confidence-filter context, hop/edge details, and clickable path nodes.
- Mini-map: click-and-drag panning.
- Baseline: empty guards, status, confirmation before clearing, added/changed/removed/unchanged summary, and clickable current resources.
- Coverage: compact summary plus expandable parser/authority diagnostics.
- Custom policy pack: schema/operator validation, file-size guard, expected-vs-actual evidence, clickable resources, and collapsed long result sets.
- PR architecture: changes-only filter, added/changed/removed summary, inspectable resource nodes, before/after configuration, and changed-attribute evidence.
- Exports: guard empty analysis and make architecture-report scope explicit.
- Browser preference storage: user-visible failure handling rather than uncaught storage exceptions for newly added controls.

## Validation performed

- JavaScript syntax checks for `app.js`, `features.js`, `server.mjs`, and `engine/analyzer.mjs`.
- Browser interaction harness for search, drawers, relationship evidence, blast radius, path finding, saved views, baseline comparison, custom policies, PR architecture inspection, and clickable finding/resource flows.
- Responsive overflow checks at 1366, 768, 390, and 320 CSS-pixel widths.

The dependency-based analyzer test suite still requires `npm install` so `js-yaml` and the HCL parser are available.
