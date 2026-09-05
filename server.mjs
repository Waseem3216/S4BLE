import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeRequest, reviewRequest } from './engine/analyzer.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, 'public');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const isVercel = Boolean(process.env.VERCEL);

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'],
      styleSrc: ["'self'"],
      scriptSrc: ["'self'"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));

app.use(express.json({ limit: '8mb' }));

// Vercel sends `/` to the Express function. The browser-facing HTML lives in
// public/index.html, which Vercel serves from its CDN as `/index.html`.
// Redirecting here is a safe fallback if the edge rewrite is ever bypassed.
app.get('/', (_req, res) => {
  if (isVercel) return res.redirect(302, '/index.html');
  return res.sendFile(path.join(publicDir, 'index.html'));
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'Sable analysis engine', version: '3.2.2' });
});

app.post('/api/analyze', async (req, res) => {
  try {
    const result = await analyzeRequest(req.body || {});
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error?.message || 'Analysis failed.' });
  }
});

app.post('/api/review', async (req, res) => {
  try {
    const result = await reviewRequest(req.body || {});
    res.json(result);
  } catch (error) {
    console.error(error);
    res.status(400).json({ error: error?.message || 'Review failed.' });
  }
});

app.use('/api', (_req, res) => {
  res.status(404).json({ error: 'API route not found.' });
});

// Vercel serves public/** directly from its CDN. This middleware is retained
// only so `npm start` and `npm run dev` behave the same way locally.
if (!isVercel) {
  app.use(express.static(publicDir, {
    etag: true,
    maxAge: 0,
    dotfiles: 'deny',
    index: 'index.html'
  }));

  app.get(/.*/, (req, res, next) => {
    if (!req.accepts('html')) return next();
    return res.sendFile(path.join(publicDir, 'index.html'));
  });
}

app.use((error, _req, res, _next) => {
  console.error(error);
  res.status(error?.status || 500).json({
    error: error?.message || 'Internal server error.'
  });
});

// Exporting the app lets Vercel detect this as an Express application.
export default app;

// Vercel owns the server lifecycle. Only open a local listener outside Vercel.
if (!isVercel) {
  const server = app.listen(PORT, HOST, () => {
    console.log(`Sable running on http://${HOST}:${PORT}`);
  });

  const shutdown = signal => {
    console.log(`${signal} received; shutting down Sable.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
