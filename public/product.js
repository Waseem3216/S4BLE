import { lessons, reviewKey, matchingResources, filterInventory, resourceFacts, inventoryCsv, practiceExample } from './product-core.js';

const el = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const REVIEW_KEY = 'sable.reviewChecklist.v1';
let reviewed;
try { reviewed = JSON.parse(localStorage.getItem(REVIEW_KEY) || '{}') || {}; } catch { reviewed = {}; }
if (typeof reviewed !== 'object' || Array.isArray(reviewed)) reviewed = {};
let inventoryRows = [];
let checklistRows = [];
let labSequence = 0;
let labController = null;
const analysis = () => currentAnalysis || { resources: [], findings: [] };
const categoryName = category => CATEGORY_META[category]?.label || category;

function filters() {
  return { search: el('productResourceSearch').value, provider: el('productProvider').value, category: el('productCategory').value, risk: el('productRisk').value };
}
function options(id, values, label) {
  const select = el(id), previous = select.value;
  select.innerHTML = `<option value="all">All ${label}</option>${values.map(value => `<option value="${esc(value)}">${esc(label === 'categories' ? categoryName(value) : value)}</option>`).join('')}`;
  select.value = values.includes(previous) ? previous : 'all';
}
function renderInventory(refresh = false) {
  const { resources = [], findings = [] } = analysis();
  if (refresh) {
    options('productProvider', [...new Set(resources.map(r => r.provider))].sort(), 'providers');
    options('productCategory', [...new Set(resources.map(r => r.category))].sort(), 'categories');
  }
  el('productInventoryStats').innerHTML = [[resources.length, 'Imported resources'], [resources.filter(r => r.category === 'compute').length, 'Compute resources'], [new Set(findings.map(f => f.resource)).size, 'Resources with findings']].map(([count, label]) => `<div><strong>${count}</strong><span>${label}</span></div>`).join('');
  inventoryRows = filterInventory(resources, findings, filters());
  el('productInventoryCount').textContent = `${inventoryRows.length} of ${resources.length} resources · “Not supplied” means the import does not include a usable value.`;
  el('productExportInventory').disabled = !inventoryRows.length;
  el('productInventoryBody').innerHTML = inventoryRows.length ? inventoryRows.map((r, index) => {
    const facts = resourceFacts(r), count = findings.filter(f => f.resource === r.id).length;
    return `<tr><td><strong>${esc(r.name)}</strong><code>${esc(r.id)}</code><span>${esc(r.type)}</span></td><td>${esc(categoryName(r.category))}<span>${esc(r.provider)}${r.mode === 'data' ? ' · Data source' : ''}</span></td><td>${esc(facts.size)}<span>${esc(facts.location)}</span></td><td>${count ? `${count} detected` : 'None detected'}</td><td><button type="button" class="secondary-button" data-product-resource="${index}" aria-label="Inspect ${esc(r.name)}">Details</button></td></tr>`;
  }).join('') : `<tr><td colspan="5"><div class="iv-empty">${resources.length ? 'No resources match these filters.' : 'Import infrastructure to explore your resources. You can also download a practice example from the Cloud Guide.'}</div></td></tr>`;
}
function renderLessons() {
  const query = el('productGuideSearch').value.trim().toLowerCase();
  const filtered = lessons.filter(l => `${l.title} ${l.keywords} ${l.explanation} ${l.services}`.toLowerCase().includes(query));
  el('productLessons').innerHTML = filtered.map(lesson => {
    const matches = matchingResources(lesson, analysis().resources || []);
    return `<article class="panel product-lesson"><p class="eyebrow">${matches.length ? `${matches.length} related resource${matches.length === 1 ? "" : "s"} in your import` : lesson.id === 'evidence' ? 'How to read your results' : 'Cloud foundations'}</p><h2>${esc(lesson.title)}</h2><p>${esc(lesson.explanation)}</p><p class="product-equivalents">${esc(lesson.services)}</p><details><summary>What to check & why it matters</summary><p class="product-callout">${esc(lesson.misconception)}</p><ul>${lesson.checks.map(check => `<li>${esc(check)}</li>`).join('')}</ul><a href="${esc(lesson.source)}" target="_blank" rel="noopener noreferrer">${esc(lesson.sourceLabel)} ↗</a>${matches.length ? `<p>Examples in your import:</p><div class="product-resource-links">${matches.slice(0, 3).map(r => `<button class="secondary-button" type="button" data-product-open="${esc(r.id)}">${esc(r.name)}</button>`).join('')}</div>` : ''}</details></article>`;
  }).join('') || '<div class="panel product-intro">No concepts match. Try a term such as “network”, “IAM”, or “backup”.</div>';
}
function ensureChecklist() {
  if (el('productChecklist')) return;
  el('overviewPage').insertAdjacentHTML('beforeend', `<section class="panel product-checklist" id="productChecklist"><div class="panel-header"><div><p class="eyebrow">From findings to next steps</p><h2>Review checklist</h2></div><button class="secondary-button" id="productExportChecklist" type="button">Export checklist</button></div><p>Track which findings you have reviewed in this browser. Reviewing a finding does not resolve it or change its evidence score. Re-import the updated infrastructure to check a fix.</p><div class="product-filters"><label>Show<select class="select-input" id="productChecklistFilter"><option value="open">Needs review</option><option value="all">All findings</option><option value="reviewed">Reviewed</option></select></label><span id="productChecklistCount" role="status"></span></div><div id="productChecklistRows"></div></section>`);
  el('productChecklistFilter').addEventListener('change', renderChecklist);
  el('productExportChecklist').addEventListener('click', exportChecklist);
  el('productChecklistRows').addEventListener('change', event => {
    const input = event.target.closest('[data-review-index]');
    if (!input) return;
    const item = checklistRows[Number(input.dataset.reviewIndex)];
    if (!item) return;
    const key = reviewKey(workspace, item), next = { ...reviewed };
    if (input.checked) next[key] = new Date().toISOString(); else delete next[key];
    try { localStorage.setItem(REVIEW_KEY, JSON.stringify(next)); reviewed = next; }
    catch { showToast('Review progress could not be saved in this browser.'); }
    renderChecklist();
  });
}
function renderChecklist() {
  const findings = analysis().findings || [], filter = el('productChecklistFilter').value;
  const count = findings.filter(f => reviewed[reviewKey(workspace, f)]).length;
  el('productChecklistCount').textContent = `${count} of ${findings.length} findings reviewed`;
  el('productExportChecklist').disabled = !findings.length;
  checklistRows = findings.filter(f => filter === 'all' || (filter === 'reviewed') === Boolean(reviewed[reviewKey(workspace, f)]));
  el('productChecklistRows').innerHTML = checklistRows.map((f, index) => `<article class="product-action"><label><input type="checkbox" data-review-index="${index}" ${reviewed[reviewKey(workspace, f)] ? 'checked' : ''} /><span>Reviewed</span></label><div><span class="severity-pill ${esc(f.severity)}">${esc(f.severity)}</span><h3>${esc(f.title)}</h3><code>${esc(f.resource)}</code><p>${esc(f.recommendation)}</p><details><summary>Evidence & verification</summary><p>${esc(f.description)}</p><pre class="iv-config">${esc(JSON.stringify(f.evidence, null, 2))}</pre><p>${esc(f.limitations || 'Verify effective behavior in the cloud, then import new evidence to reassess this finding.')}</p><button class="secondary-button" type="button" data-product-open="${esc(f.resource)}">Inspect resource</button></details></div></article>`).join('') || `<div class="iv-empty">${!analysis().resources?.length ? 'Import infrastructure to build a review checklist.' : !findings.length ? 'No findings from applicable checks. Review coverage and runtime assumptions before drawing conclusions.' : 'No findings in this review filter.'}</div>`;
}
function exportChecklist() {
  const lines = ['# S4BLE review checklist', '', `Workspace: ${workspace.workspace}`, 'Review progress is local to this browser and does not verify remediation.', '', ...(analysis().findings || []).flatMap(f => [`- [${reviewed[reviewKey(workspace, f)] ? 'x' : ' '}] ${f.severity.toUpperCase()} · ${f.title}`, `  Resource: ${f.resource}`, `  Next step: ${f.recommendation}`, `  Evidence: ${JSON.stringify(f.evidence)}`, ''])];
  downloadFile('s4ble-review-checklist.md', lines.join('\n'), 'text/markdown');
}
function example() { return practiceExample(el('productLabExample').value, el('productLabVariant').value === 'after'); }
function renderLab() {
  labSequence++;
  labController?.abort();
  const selected = example();
  el('productLabSource').textContent = selected.text;
  el('productLabDescription').textContent = selected.description;
  el('productLabResult').textContent = 'Ready. Analyze this configuration to see its findings.';
  el('productRunLab').disabled = false;
  if (el('productOpenLab')) el('productOpenLab').disabled = false;
}
async function runLab(openWorkspace = false) {
  const sequence = ++labSequence, selected = example();
  labController?.abort();
  const controller = new AbortController();
  labController = controller;
  const timeout = setTimeout(() => controller.abort(), 45_000);
  el('productRunLab').disabled = true;
  el('productOpenLab').disabled = true;
  el('productLabResult').textContent = 'Analyzing the practice configuration…';
  try {
    const response = await fetch('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ text: selected.text }), signal: controller.signal });
    let result;
    try { result = await response.json(); } catch { throw new Error('The analysis service returned an unexpected response. Please try again.'); }
    if (!response.ok) throw new Error(result.error || 'The example could not be analyzed.');
    if (sequence !== labSequence) return;
    if (!result.analysis || !Array.isArray(result.analysis.findings)) throw new Error('The analysis service returned an incomplete result. Please try again.');
    const { findings, score, metadata = {} } = result.analysis;
    const coverage = metadata.coverage || {};
    if (openWorkspace) {
      if (!result.workspace || !Array.isArray(result.analysis.resources)) throw new Error('The sample workspace is incomplete. Please try again.');
      saveWorkspace(result.workspace, result.analysis);
      navigate('overview');
      showToast('Example workspace opened. Import your infrastructure whenever you are ready.');
    }
    el('productLabResult').innerHTML = `<h3>${findings.length} finding${findings.length === 1 ? '' : 's'} · Evidence Score ${Number.isFinite(score) ? `${score}/100` : 'Not rated'}</h3><p>${Number(coverage.supportedResources) || 0} of ${Number(coverage.postureResourceCount) || 0} resources have an applicable rule family. This is a static example, not a live environment check.</p>${findings.length ? findings.map(f => `<details class="product-lab-finding"><summary>${esc(f.severity.toUpperCase())} · ${esc(f.title)}</summary><p>${esc(f.description)}</p><p><strong>Next step:</strong> ${esc(f.recommendation)}</p><code>${esc(f.resource)}</code></details>`).join('') : '<p>No issues detected by applicable rules in this example. This does not certify the configuration. Check the remaining controls and runtime behavior.</p>'}`;
  } catch (error) {
    if (sequence === labSequence) el('productLabResult').textContent = `Could not run the example: ${error.name === 'AbortError' ? 'The request timed out. Please try again.' : error.message}`;
  } finally {
    clearTimeout(timeout);
    if (sequence === labSequence) { el('productRunLab').disabled = false; el('productOpenLab').disabled = false; }
  }
}
function renderAll() { ensureChecklist(); renderInventory(true); renderLessons(); renderChecklist(); }
window.SableProduct = { renderAll };
function initProduct() {
  ensureChecklist();
  ['productResourceSearch', 'productProvider', 'productCategory', 'productRisk'].forEach(id => el(id).addEventListener(id === 'productResourceSearch' ? 'input' : 'change', () => renderInventory()));
  el('productGuideSearch').addEventListener('input', renderLessons);
  el('productExportInventory').addEventListener('click', () => downloadFile('s4ble-resource-inventory.csv', inventoryCsv(inventoryRows, analysis().findings || []), 'text/csv;charset=utf-8'));
  el('productInventoryBody').addEventListener('click', event => {
    const button = event.target.closest('[data-product-resource]');
    if (button) window.SableFeatures?.onResourceSelected(inventoryRows[Number(button.dataset.productResource)]?.id);
  });
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-product-open]');
    if (button) window.SableFeatures?.onResourceSelected(button.dataset.productOpen);
    const answer = event.target.closest('[data-product-answer]');
    if (answer) el('productQuizFeedback').textContent = `${answer.dataset.productAnswer === 'no' ? 'Correct.' : 'Not quite.'} Public addressing alone is not enough. Routes, firewall rules, attached interfaces, and a listening service determine the usable path; authentication then controls application access.`;
  });
  ['productLabExample', 'productLabVariant'].forEach(id => el(id).addEventListener('change', renderLab));
  el('productDownloadLab').insertAdjacentHTML('afterend', '<button class="secondary-button" id="productOpenLab" type="button">Open example workspace</button>');
  el('productRunLab').addEventListener('click', () => runLab());
  el('productOpenLab').addEventListener('click', () => runLab(true));
  el('productDownloadLab').addEventListener('click', () => { const selected = example(); downloadFile(selected.filename, selected.text, 'application/json'); });
  renderAll(); renderLab();
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initProduct); else initProduct();
