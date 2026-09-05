# Sable UI Production Hardening

This build includes a full overlap and responsive-layout hardening pass.

## Architecture viewport
- Large diagrams remain inside a bounded preview viewport.
- Maximize provides the full inspection workspace.
- Category headers remain fixed at the top of the diagram viewport while vertical panning moves resources underneath.
- Category headers stay aligned during horizontal panning.
- Two-finger scrolling pans and trackpad pinch / Ctrl-or-Cmd wheel zooms around the pointer.
- Click-drag pans empty diagram space.
- Large categories wrap resources into internal columns instead of expanding page height.
- Resource nodes contain long names and types without leaking outside cards.
- The floating preview CTA was removed because it could cover diagram resources; the header maximize control is now the single expansion control.
- Clicking the architecture title no longer accidentally toggles maximize.

## Layout and overlap fixes
- Mobile navigation uses concise labels and no longer compresses or overlaps.
- Topbar actions reflow into a stable mobile grid.
- Architecture and explorer controls wrap cleanly across desktop, tablet, and mobile widths.
- Maximized mobile architecture prioritizes diagram space with compact controls.
- Findings and inventory panels no longer stretch each other to equal height.
- Large resource inventories use a local scrolling table with a sticky header.
- Long workspace names, resource names, types, findings, relationship metadata, and recommendations wrap safely.
- Search and filter controls become full-width when panels stack on small screens.
- Relationship rows reflow on mobile without clipping.

## Content clarity
- Zero-risk resources display “No findings” instead of overclaiming that a resource is “Clean.”
- Empty findings state now distinguishes an analyzed workspace with no findings from a workspace that has not been analyzed.

## Validation
The final UI was exercised with headless browser layout checks at 1366×768, 768×800, 390×844, and 320×700, including minimized/maximized architecture views and reviewer/importer routes. A synthetic dense 54-resource multi-category topology with long resource names was also checked for node overlap and page-level horizontal overflow.


## Logo alignment refinement
- Vertically centered the radar-cloud logo against the complete two-line Sable wordmark.
- Applied only a small visual offset to the logo mark; no other site layout or behavior was changed.
