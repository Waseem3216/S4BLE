import express from 'express';
import helmet from 'helmet';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { analyzeRequest, reviewRequest } from './engine/analyzer.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const app = express();
const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';

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
app.use((error, _req, res, next) => {
  if (error instanceof SyntaxError && 'body' in error) {
    return res.status(400).json({ error: 'Invalid JSON request body.' });
  }
  return next(error);
});

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'Sable analysis engine', version: '3.2.0' });
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

app.use('/api', (_req, res) => res.status(404).json({ error: 'API route not found.' }));

app.use('/assets', express.static(path.join(__dirname, 'assets'), {
  etag: true,
  maxAge: '7d',
  immutable: false,
  dotfiles: 'deny'
}));
app.use(express.static(__dirname, {
  extensions: ['html'],
  etag: true,
  maxAge: 0,
  dotfiles: 'deny',
  index: 'index.html'
}));
app.use((_req, res) => res.sendFile(path.join(__dirname, 'index.html')));

const server = app.listen(PORT, HOST, () => {
  console.log(`Sable running on ${HOST}:${PORT}`);
});

const shutdown = signal => {
  console.log(`${signal} received; shutting down Sable.`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(1), 10_000).unref();
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
