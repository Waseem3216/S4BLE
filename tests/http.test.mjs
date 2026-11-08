import test from 'node:test';
import assert from 'node:assert/strict';
import app from '../server.mjs';
import { practiceExample } from '../public/product-core.js';

test('HTTP routes, assets, analysis, error responses and no-op review work together', async () => {
  const server = await new Promise((resolve, reject) => {
    const listener = app.listen(0, '127.0.0.1', error => error ? reject(error) : resolve(listener));
  });
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    for (const route of ['/infrastructure-posture', '/terraform-pr-reviewer', '/import-infrastructure', '/resource-explorer', '/cloud-guide']) {
      const response = await fetch(origin + route);
      assert.equal(response.status, 200, route);
      assert.match(await response.text(), /id="learnPage"/);
      assert.match(response.headers.get('content-security-policy'), /script-src 'self'/);
    }
    for (const file of ['/diagram-routing.js', '/product.js', '/product-core.js', '/styles.css', '/app.js', '/features.js']) assert.equal((await fetch(origin + file)).status, 200, file);
    assert.equal((await fetch(origin + '/', { redirect: 'manual' })).headers.get('location'), '/infrastructure-posture');
    assert.equal((await (await fetch(origin + '/api/health')).json()).version, '3.5.0');
    const post = (route, body) => fetch(origin + route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    assert.equal((await post('/api/analyze', { text: '{broken' })).status, 400);
    assert.equal((await fetch(origin + '/api/missing')).status, 404);
    assert.equal((await fetch(origin + '/missing.js')).status, 404);
    assert.equal((await fetch(origin + '/missing-page')).status, 404);
    const invalid = await fetch(origin + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{"secret":"DO_NOT_ECHO",broken}' });
    assert.equal(invalid.status, 400);
    assert.doesNotMatch(await invalid.text(), /DO_NOT_ECHO/);
    assert.equal(invalid.headers.get('cache-control'), 'no-store');
    const unsupported = await fetch(origin + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: 'source' });
    assert.equal(unsupported.status, 415);
    const oversized = await post('/api/analyze', { text: 'x'.repeat(8 * 1024 * 1024) });
    assert.equal(oversized.status, 413);
    assert.match((await oversized.json()).error, /too large/);
    const result = await (await post('/api/analyze', { text: practiceExample('aws').text })).json();
    assert.equal(result.analysis.resources.length, 4);
    assert.equal(result.analysis.findings.length, 5);
    const review = await (await post('/api/review', { text: JSON.stringify({ format_version: '1.0', planned_values: { root_module: { resources: [] } }, resource_changes: [] }), baseline: result.workspace })).json();
    assert.deepEqual(review.review.counts, { add: 0, change: 0, delete: 0 });
    let throttled = false;
    for (let i = 0; i < 61; i++) {
      const response = await fetch(origin + '/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': `198.51.100.${i}` }, body: '{}' });
      if (response.status === 429) {
        throttled = true;
        assert.ok(Number(response.headers.get('retry-after')) > 0);
        assert.match((await response.json()).error, /Too many analyses/);
        break;
      }
    }
    assert.ok(throttled, 'forged forwarding headers cannot bypass the per-client throttle');
  } finally {
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
  }
});
