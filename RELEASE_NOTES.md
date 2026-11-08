# S4BLE 3.5.0 — November 8, 2026

## Architecture and presentation

Refined category cards, resource nodes, spacing, light/dark palettes, dotted canvas, arrowheads, rounded routes, crossing halos, relationship count labels, and fullscreen controls. Corrected reverse-direction arrows, confidence aggregation, edge click targets, Fit view, zoom scaling, keyboard navigation, focus behavior, and cramped diagram viewports. Relationship evidence is expandable and paginated.

## Functional corrections

Fixed stale analysis/review races; blocked or malformed browser storage; ambiguous parsing errors; hidden oversized PR inventories; architecture search keyboard behavior; stale highlights; workspace note isolation; custom-policy false passes; and incomplete example workflows. Added Open example workspace, explicit source submission, persistent analysis status, clear local data, and saved-workspace refresh for upgraded engine results.

## Analysis and server corrections

Fixed destroy-plan resources, literal strings falsely treated as Terraform references, ambiguous normalized names, Kubernetes typed lists, NetworkPolicy selectors, file/text precedence, malformed/cyclic input, sensitive error content, and missing-asset responses. Added API size limits, bounded per-client throttling, response no-store, Vercel security headers, and current dependency fixes.

## Verification

See VALIDATION.txt for the final regression counts and browser checks. Live domain deployment, DNS, production load testing, and a comprehensive external security review were not performed. Historical notes are in docs/history/.
