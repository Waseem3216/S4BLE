# Deploy to www.s4ble.com

This project retains its Express/Vercel architecture. Vercel serves `public/**` through its CDN; `server.mjs` default-exports the Express application for API requests. `vercel.json` maps the five application pages and applies static security headers.

1. Put the extracted `s4ble` contents in your repository root, including package-lock.json, server.mjs, engine/, public/, and vercel.json.
2. Import that repository into your Vercel account. Select Express (or automatic detection), the repository root, and a supported Node.js LTS runtime. Use `npm ci` for installation. Leave build/output settings at their Express defaults; this app has no frontend build step.
3. Create a preview deployment and verify the checks below.
4. In the project's Domains settings, add **www.s4ble.com**. Apply the exact DNS records Vercel displays at your DNS provider; do not guess record targets. If you also own/configure s4ble.com, redirect it to the chosen www domain. Wait for domain verification and HTTPS, then promote the tested deployment.
5. Configure hosting-level request quotas, error monitoring without request bodies, and deployment rollback. The application rate limiter is per process and cannot provide a global quota across scaled instances.

Official references: [Express deployment](https://vercel.com/docs/frameworks/backend/express), [custom domains](https://vercel.com/docs/domains/working-with-domains/add-a-domain), [function limits](https://vercel.com/docs/functions/limitations).

## Live verification

- `/` opens `/infrastructure-posture`.
- `/api/health` returns version 3.5.0 and configured limits.
- Directly refresh each of `/terraform-pr-reviewer`, `/import-infrastructure`, `/resource-explorer`, and `/cloud-guide`.
- Import a sample, inspect arrows/evidence, run a review, and download a report.
- Check light/dark themes and a mobile viewport.
- Verify missing assets return 404 and API analysis responses use Cache-Control: no-store.

Vercel has a platform payload limit. This app uses a 4 MB request/response budget there, including serialized input, baseline, and analysis evidence. Large imports should be split or run on a Node host with the documented larger budget. Deploying to another Node provider uses `npm ci --omit=dev` and `npm start`, with HTTPS terminated at a trusted reverse proxy.

For a custom reverse proxy, set TRUSTED_PROXIES to only the IP addresses/subnets you operate. Forwarded headers are otherwise ignored. Never set blanket trust for untrusted clients.
