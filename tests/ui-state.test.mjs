import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';
const source = await readFile(new URL('../public/app.js', import.meta.url), 'utf8');
function harness(storage = { getItem: () => null, setItem() {} }) {
  const elements = new Map();
  const element = key => { if (!elements.has(key)) elements.set(key, { value: '', textContent: '', disabled: false }); return elements.get(key); };
  const context = vm.createContext({ localStorage: storage, document: { addEventListener() {}, querySelector: element }, window: {}, console, setTimeout, clearTimeout, AbortController, Blob, URL, fetch: () => {} });
  vm.runInContext(source, context);
  vm.runInContext('renderImportPreview = () => {}; renderPrReview = () => {}; showToast = () => {};', context);
  return { context, element, run: code => vm.runInContext(code, context) };
}
test('blocked browser storage does not prevent application startup or theme reads', () => {
  const { run } = harness({ getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } });
  assert.equal(run('workspace.resources.length'), 0);
  assert.equal(run('currentAnalysis.resources.length'), 0);
  assert.equal(run('activeTheme'), 'light');
  assert.equal(run('writeLocalValue("theme", "dark")'), false);
});
test('malformed saved JSON structures fall back to a usable empty workspace', () => {
  for (const data of ['null', '[]', '{"resources":null}', '{"resources":[null]}']) {
    const { run } = harness({ getItem: () => data });
    assert.equal(run('workspace.resources.length'), 0);
    assert.equal(run('currentAnalysis.resources.length'), 0);
  }
});
test('clearing or editing input prevents a pending analysis from committing stale results', async () => {
  const { run, context, element } = harness();
  let resolve;
  context.pending = new Promise(done => { resolve = done; });
  run('requestAnalysis = () => pending; saveWorkspace = () => { throw new Error("stale result was committed"); };');
  element('#importInput').value = 'old input';
  const result = run('analyzeImportInput()');
  assert.equal(element('#analyzeImportBtn').disabled, true);
  run('invalidateImport()');
  resolve({ workspace: {}, analysis: { resources: [] } });
  await result;
  assert.equal(run('importBusy'), false);
  assert.equal(element('#importStatus').textContent, '');
});
test('reviewing changed input ignores an earlier pending review', async () => {
  const { run, context, element } = harness();
  let resolve;
  context.pending = new Promise(done => { resolve = done; });
  run('requestAnalysis = () => pending;');
  element('#prInput').value = 'old input';
  const result = run('reviewPrRisk()');
  run('invalidateReview()');
  resolve({ analysis: {}, review: { decision: 'Stale decision', riskScore: 100 } });
  await result;
  assert.equal(run('prReview.decision'), 'Waiting for input');
  assert.equal(run('reviewBusy'), false);
});
