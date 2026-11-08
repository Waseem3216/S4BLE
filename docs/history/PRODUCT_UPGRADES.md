# Sable 3.1 — Product upgrades

Sable 3.1 focuses on deterministic infrastructure analysis, explainable architecture relationships, and production-oriented interaction design.

## Core capabilities

- Relationship Evidence / “Why is this connected?”
- Resource Details Drawer with Overview, Relationships, Configuration, Findings, and Evidence
- Architecture search with `type:`, `category:`, `risk:`, `provider:`, `name:`, `changed:true`
- Architecture lenses: Architecture, Network, Security, Reliability, Observability, Changes
- Confirmed/inferred relationship filters
- Blast-radius traversal and Incident dependency view
- Relationship path finder
- Architecture mini-map
- Browser-saved architecture views
- Analysis coverage and parser diagnostics
- Imported-workspace baseline comparison
- PR current/proposed/overlay architecture impact view
- Custom JSON policy packs
- Ownership/team/service/environment/repository metadata extraction from tags/labels
- Control-context references for findings (not certification claims)
- Resource notes
- Self-contained HTML architecture report export
- GitHub Actions template to generate an Sable-ready Terraform plan JSON artifact

## 3.1 interaction upgrades

- safer saved-view loading across workspace revisions
- empty-state guards for baseline, export, review, import, and snapshot actions
- clickable resource inventory rows and finding cards
- keyboard-navigable architecture search
- resource picker for dependency-impact tools
- richer path results with per-edge confidence/evidence labels
- draggable mini-map navigation
- compact coverage summary with expandable diagnostics
- validated policy schema, expected/actual evidence, and show-more behavior
- clickable baseline comparison resources
- PR change-only mode, change summary, and before/after resource inspection
- safe browser-storage error handling for user preferences and notes

## Storage behavior

The analysis service does not retain workspaces between requests. Optional browser preferences such as saved views, baselines, policy packs, notes, theme, zoom, and filters are stored in the browser. Imported source files are sent to the local analysis service for the current request and are not persisted by the included server.
