# Release readiness — 3.5.0

The packaged application has functional local analysis, architecture exploration, PR review, exports, examples, filtering, local review progress, and deployment configuration. No external service credentials are required for these features.

Implemented safeguards include strict script CSP, escaped UI content, safe CSV export, bounded parsing/request sizes/resource counts, safe parser errors, API no-store responses, dependency updates, rate limiting, timeout/error recovery, and browser storage fallbacks.

The release was verified with automated regressions and local browser flows. This is not a certification that all bugs or security issues are absent. Before making www.s4ble.com live, the operator must deploy and run the live checks in VERCEL_DEPLOY.md, verify HTTPS/DNS, configure hosting quotas/monitoring, and assess capacity under expected usage. Cloud authentication, team accounts, durable cloud storage, billing, and live-cloud scanning are not included features.

Rate limiting is 60 analysis/review calls per client per minute per server process, with bounded client tracking. Distributed abuse controls belong at the hosting edge. Never log request bodies containing customer infrastructure. Keep dependencies patched and run `npm audit --omit=dev` during release maintenance.
