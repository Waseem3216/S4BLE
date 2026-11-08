import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { analyzeRequest, reviewRequest } from './engine/analyzer.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, 'public');

const app = express();
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const isVercel = Boolean(process.env.VERCEL);
const requestLimitBytes = isVercel ? 4_000_000 : 8 * 1024 * 1024;

app.disable('x-powered-by');
// Set this only to the IP addresses/subnets of your own reverse proxies.
// The default never trusts a caller-supplied X-Forwarded-For header.
if (process.env.TRUSTED_PROXIES) app.set('trust proxy', process.env.TRUSTED_PROXIES.split(',').map(value => value.trim()).filter(Boolean));
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

// Analysis responses contain user infrastructure and must never be cached.
app.use('/api', (_req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
// This is a bounded per-process burst guard. Production deployments should
// also apply distributed quotas at their hosting edge.
const analysisClients = new Map();
const RATE_WINDOW_MS = 60_000;
const RATE_LIMIT = 60;
let nextClientCleanup = 0;
app.use(['/api/analyze', '/api/review'], (req, res, next) => {
  if (req.method !== 'POST') return next();
  const now = Date.now();
  if (now >= nextClientCleanup) {
    for (const [key, value] of analysisClients) if (value.resetAt <= now) analysisClients.delete(key);
    nextClientCleanup = now + RATE_WINDOW_MS;
  }
  // Vercel overwrites this header at its edge; use it only in that runtime and
  // only when it is one IP, never a caller-controlled forwarding chain.
  const vercelIp = isVercel ? req.get('x-forwarded-for') : '';
  const client = vercelIp && isIP(vercelIp) ? vercelIp : req.ip || req.socket.remoteAddress || 'unknown';
  let bucket = analysisClients.get(client);
  if (!bucket || bucket.resetAt <= now) {
    if (!bucket && analysisClients.size >= 5000) return res.status(503).set('Retry-After', '60').json({ error: 'The analysis service is busy. Please try again in a minute.' });
    bucket = { count: 0, resetAt: now + RATE_WINDOW_MS };
    analysisClients.set(client, bucket);
  }
  if (++bucket.count > RATE_LIMIT) return res.status(429).set('Retry-After', String(Math.max(1, Math.ceil((bucket.resetAt - now) / 1000)))).json({ error: 'Too many analyses. Please wait a minute and try again.' });
  next();
});
app.use(express.json({ limit: requestLimitBytes }));
app.use(['/api/analyze', '/api/review'], (req, res, next) => {
  if (req.method === 'POST' && !req.is('application/json')) return res.status(415).json({ error: 'Send infrastructure as application/json.' });
  next();
});

// Keep browser-facing URLs product-oriented instead of exposing index.html.
const browserRoutes = new Set([
  '/infrastructure-posture',
  '/terraform-pr-reviewer',
  '/import-infrastructure',
  '/resource-explorer',
  '/cloud-guide'
]);

app.get(['/', '/index.html'], (_req, res) => {
  return res.redirect(302, '/infrastructure-posture');
});

app.get([...browserRoutes], (_req, res) => {
  return res.sendFile(path.join(publicDir, 'index.html'));
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'S4BLE analysis engine', version: '3.5.0', limits: { requestBytes: requestLimitBytes, sourceBytes: 7_000_000, resources: 2000, files: 100 } });
});

function sendAnalysisResult(res, result) {
  const payload = JSON.stringify(result);
  if (isVercel && Buffer.byteLength(payload, 'utf8') > 4_000_000) return res.status(413).json({ error: 'This analysis is too large for the hosting response limit. Split the workspace into smaller groups.' });
  return res.type('json').send(payload);
}

app.post('/api/analyze', async (req, res) => {
  try {
    const result = await analyzeRequest(req.body);
    sendAnalysisResult(res, result);
  } catch (error) {
    res.status(400).json({ error: error?.message || 'Analysis failed.' });
  }
});

app.post('/api/review', async (req, res) => {
  try {
    const result = await reviewRequest(req.body);
    sendAnalysisResult(res, result);
  } catch (error) {
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
}

app.use((_req, res) => {
  res.status(404).type('text').send('Page not found. Open /infrastructure-posture to return to S4BLE.');
});

app.use((error, _req, res, _next) => {
  // Parser errors may contain source snippets or request bodies. Never log them
  // or send them back to browsers, monitoring services, or shared caches.
  if (error?.type === 'entity.too.large') return res.status(413).json({ error: `The request is too large. Split the workspace into smaller groups; this host accepts ${isVercel ? '4' : '8'} MB per request.` });
  if (error?.type === 'entity.parse.failed') return res.status(400).json({ error: 'The request contains invalid JSON.' });
  if (error?.status === 415) return res.status(415).json({ error: 'Unsupported request encoding or content type.' });
  console.error('S4BLE request failed:', error?.name || 'Error');
  res.status(500).json({ error: 'The service could not complete this request. Please try again.' });
});

// Exporting the app lets Vercel detect this as an Express application.
export default app;

// Vercel owns the server lifecycle. Only open a local listener outside Vercel.
if (!isVercel && process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const server = app.listen(PORT, HOST, error => {
    if (error) { console.error(`Could not start S4BLE: ${error.message}`); process.exitCode = 1; return; }
    console.log(`S4BLE running on http://${HOST}:${PORT}`);
  });

  const shutdown = signal => {
    console.log(`${signal} received; shutting down S4BLE.`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 10_000).unref();
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}
