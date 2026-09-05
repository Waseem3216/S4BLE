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
