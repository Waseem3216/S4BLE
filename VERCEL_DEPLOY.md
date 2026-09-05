# Sable — Vercel deployment

## Important root-route fix

This package includes `vercel.json` with a root rewrite from `/` to `/index.html`.
It also includes an Express `/` fallback that redirects to `/index.html` on Vercel.
This prevents the `Cannot GET /` response from the Express function.

## Vercel project settings

- Framework Preset: Express (or let Vercel auto-detect)
- Root Directory: repository root (`./`)
- Build Command: leave default / blank
- Output Directory: leave blank
- Install Command: `npm install` (default is fine)

## Verify after deployment

Open these URLs:

- `/` — should display the Sable application
- `/index.html` — should display the same application
- `/styles.css` — should return CSS
- `/app.js` — should return JavaScript
- `/api/health` — should return JSON with version 3.2.2

If `/index.html` works but `/` does not, verify `vercel.json` is at the repository root and redeploy without build cache.

---

# Sable — Vercel deployment

## Correct project structure

- `public/` contains the browser frontend (`index.html`, CSS, JavaScript, images, favicon, loader animation).
- `server.mjs` is the Express backend entry point.
- `engine/` contains the infrastructure analyzer.

Vercel serves `public/**` from its CDN and routes `/api/*` to the Express app.

## Deploy

1. Push this folder to a GitHub repository.
2. In Vercel, choose **Add New → Project** and import that repository.
3. Leave **Root Directory** as the repository root.
4. Leave **Build Command** and **Output Directory** at their defaults / blank.
5. Deploy.

## Verify after deployment

Open these URLs:

- `/` — should show the fully styled Sable UI.
- `/styles.css` — should display CSS text, not a 404 or HTML page.
- `/app.js` — should display JavaScript text.
- `/assets/sable-brand-logo-source.png` — should display the Sable logo.
- `/api/health` — should return JSON with `ok: true`.

If an old broken deployment remains cached, redeploy this commit and use the new deployment URL or promote the new deployment to Production.
