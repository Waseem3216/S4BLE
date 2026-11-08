import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

test('custom numeric policies do not accept missing, null, boolean or blank values as zero', async () => {
  const source = (await readFile(new URL('../public/features.js', import.meta.url), 'utf8')).replace('window.SableFeatures = {', 'window.SableFeatures = { requirementPasses, validatePolicyPack,');
  const context = { window: {}, document: { readyState: 'loading' }, localStorage: { getItem: () => null } };
  vm.runInNewContext(source, context);
  const checks = context.window.SableFeatures;
  for (const value of [undefined, null, false, '', ' ', '${var.limit}']) assert.equal(checks.requirementPasses(value, { operator: 'max', value: 5 }), false);
  assert.equal(checks.requirementPasses('4', { operator: 'max', value: 5 }), true);
  assert.equal(checks.requirementPasses(6, { operator: 'min', value: 5 }), true);
  assert.throws(() => checks.validatePolicyPack({ rules: [{ id: 'size', require: { attribute: 'max_size', operator: 'max', value: null } }] }), /numeric value/);
});

test('shared download helper emits the requested file and keeps the Blob URL alive for the browser', async () => {
  const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
  const snippet = source.slice(source.indexOf('function downloadFile('), source.indexOf('function infrastructureFileFamily('));
  let blob, clicked = false, revoked = false, cleanup;
  const anchor = { click: () => { clicked = true; }, remove() {} };
  const context = { Blob, URL: { createObjectURL: value => { blob = value; return 'blob:test'; }, revokeObjectURL: () => { revoked = true; } }, document: { createElement: () => anchor, body: { appendChild() {} } }, setTimeout: callback => { cleanup = callback; } };
  vm.runInNewContext(snippet, context);
  context.downloadFile('inventory.csv', 'Name,Count\r\napp,1', 'text/csv');
  assert.equal(clicked, true);
  assert.equal(anchor.download, 'inventory.csv');
  assert.equal(await blob.text(), 'Name,Count\r\napp,1');
  assert.equal(revoked, false);
  cleanup();
  assert.equal(revoked, true);
});

async function featureHelpers(storage = {}, globals = {}) {
  const source = (await readFile(new URL('../public/features.js', import.meta.url), 'utf8')).replace('window.SableFeatures = {', 'window.SableFeatures = { state, requirementPasses, validatePolicyPack, getPolicyAttribute, resourceMatchesQuery, loadSavedViews, loadResourceNotes, readBaseline,');
  const context = {
    window: {}, document: { readyState: 'loading' },
    localStorage: { getItem: key => storage[key] ?? null },
    workspace: { workspace: 'Production', sourceType: 'snapshot' },
    currentAnalysis: { resources: [], findings: [] },
    resourceKey: resource => resource.id,
    CATEGORY_META: {}, BASELINE_KEY: 'baseline',
    ...globals
  };
  vm.runInNewContext(source, context);
  return context.window.SableFeatures;
}

test('policy checks cannot pass through missing, unresolved or inherited evidence', async () => {
  const api = await featureHelpers();
  assert.equal(api.requirementPasses(undefined, { operator: 'notEquals', value: 'public' }), false);
  assert.equal(api.requirementPasses('${var.access}', { operator: 'notEquals', value: 'public' }), false);
  assert.equal(api.requirementPasses('private', { operator: 'notEquals', value: 'public' }), true);
  assert.equal(api.requirementPasses({ b: 2, a: 1 }, { operator: 'equals', value: { a: 1, b: 2 } }), true);
  assert.equal(api.requirementPasses(undefined, { operator: 'exists', value: false }), true);
  assert.equal(api.getPolicyAttribute({ attributes: {} }, 'toString'), undefined);
  assert.equal(api.getPolicyAttribute({ attributes: {} }, '__proto__.constructor'), undefined);
  assert.throws(() => api.validatePolicyPack({ rules: [{ require: { attribute: 'access', operator: 'notEquals' } }] }), /require.value/);
  assert.throws(() => api.validatePolicyPack({ rules: [{ require: { attribute: '__proto__.constructor', operator: 'exists' } }] }), /invalid attribute/);
});

test('corrupt saved browser state cannot inject transient graph focus or break saved views', async () => {
  const api = await featureHelpers({
    'sable.featureState.v1': JSON.stringify({ lens: 'unknown', path: { nodes: null }, showConfirmed: false, showInferred: false }),
    'sable.savedViews.v1': JSON.stringify({ broken: null, string: 'invalid', valid: { name: 'Production network' } }),
    baseline: JSON.stringify({ resources: 'invalid' })
  });
  assert.equal(api.state.lens, 'all');
  assert.equal(api.state.path, null);
  assert.equal(api.state.showConfirmed, true);
  assert.deepEqual(Object.keys(api.loadSavedViews()), ['valid']);
  assert.equal(api.readBaseline(), null);
});

test('architecture resource search supports quoted field values and resource IDs', async () => {
  const api = await featureHelpers();
  const resource = { id: 'aws_instance.unique_address', name: 'App Server', type: 'aws_instance', category: 'compute', provider: 'AWS' };
  assert.equal(api.resourceMatchesQuery(resource, 'name:"app server" provider:aws'), true);
  assert.equal(api.resourceMatchesQuery(resource, 'unique_address'), true);
  assert.equal(api.resourceMatchesQuery(resource, 'name:"other server"'), false);
});

test('resource notes are isolated by workspace and source instead of sharing resource IDs', async () => {
  const storage = { 'sable.resourceNotes.v2': JSON.stringify({ '["Production","snapshot"]': { 'aws_instance.app': 'Production owner' }, '["Staging","snapshot"]': { 'aws_instance.app': 'Staging owner' } }) };
  const production = await featureHelpers(storage);
  const staging = await featureHelpers(storage, { workspace: { workspace: 'Staging', sourceType: 'snapshot' } });
  const unrelated = await featureHelpers(storage, { workspace: { workspace: 'Another account', sourceType: 'snapshot' } });
  assert.equal(production.loadResourceNotes()['aws_instance.app'], 'Production owner');
  assert.equal(staging.loadResourceNotes()['aws_instance.app'], 'Staging owner');
  assert.equal(unrelated.loadResourceNotes()['aws_instance.app'], undefined);
});
