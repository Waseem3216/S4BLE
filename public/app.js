'use strict';

const STORAGE_KEY = 'sable.workspace.v1';
const ANALYSIS_KEY = 'sable.analysis.v1';
const BASELINE_KEY = 'sable.baseline.v1';
const THEME_KEY = 'sable.theme.v1';
const ZOOM_KEY = 'sable.architectureZoom.v1';
const CIRCLE_LENGTH = 302;
const ZOOM_MIN = 0.35;
const ZOOM_MAX = 2.2;
const ZOOM_STEP = 0.05;

const APP_ROUTES = Object.freeze({
  overview: {
    path: '/infrastructure-posture',
    eyebrow: 'Cloud Infrastructure Review',
    heading: 'Infrastructure Posture Overview',
    title: 'Infrastructure Posture | S4BLE'
  },
  reviewer: {
    path: '/terraform-pr-reviewer',
    eyebrow: 'Pull Request Risk Review',
    heading: 'Terraform PR Risk Reviewer',
    title: 'Terraform PR Risk Reviewer | S4BLE'
  },
  inventory: { path: '/resource-explorer', eyebrow: 'Understand Your Environment', heading: 'Resource Explorer', title: 'Resource Explorer | S4BLE' },
  learn: { path: '/cloud-guide', eyebrow: 'Learn with Your Infrastructure', heading: 'Cloud Guide', title: 'Cloud Guide | S4BLE' },
  importer: {
    path: '/import-infrastructure',
    eyebrow: 'Workspace Import',
    heading: 'Import Terraform / JSON / YAML',
    title: 'Import Infrastructure | S4BLE'
  }
});

const ROUTE_BY_PATH = Object.freeze(Object.fromEntries(
  Object.entries(APP_ROUTES).map(([route, config]) => [config.path, route])
));
const MAX_INFRA_FILES = 100;
const MAX_INFRA_BYTES = 7_000_000;
const SUPPORTED_INFRA_EXTENSIONS = ['.tf', '.tf.json', '.json', '.yaml', '.yml'];

const CATEGORY_META = {
  network: { label: 'Network Edge', icon: '◇', order: 1 },
  security: { label: 'Identity & Security', icon: '◈', order: 2 },
  compute: { label: 'Compute Runtime', icon: '▣', order: 3 },
  data: { label: 'Data Layer', icon: '◍', order: 4 },
  storage: { label: 'Storage & Backup', icon: '▤', order: 5 },
  observability: { label: 'Observability', icon: '◎', order: 6 },
  other: { label: 'Other Resources', icon: '□', order: 7 }
};


let workspace = loadWorkspace();
let currentAnalysis = loadAnalysis();
let currentPreview = null;
let pendingImportFiles = [];
let pendingReviewFiles = [];
let previewSequence = 0;
let importSequence = 0;
let reviewSequence = 0;
let serviceRequestLimit = 8 * 1024 * 1024;
let importBusy = false;
let reviewBusy = false;
const fileReadSequence = { import: 0, review: 0 };
let prReview = { findings: [], diffs: [], riskScore: null, decision: 'Waiting for input', counts: { add: 0, change: 0, delete: 0 }, analysis: null };
let selectedArchitectureCategory = null;
let architectureGraphMode = 'internal';
let architectureConnectionMode = 'trace';
let selectedExplorerResourceId = null;
let architectureZoom = clampNumber(Number(readLocalValue(ZOOM_KEY)) || 1, ZOOM_MIN, ZOOM_MAX);
let activeTheme = readLocalValue(THEME_KEY) || 'light';

const $ = selector => document.querySelector(selector);
const $$ = selector => Array.from(document.querySelectorAll(selector));

const SABLE_LOADER_MIN_MS = 180;
let sableLoaderStart = 0;
let sableLoaderFrame = null;

function beginSableLoader() {
  sableLoaderStart = performance.now();
  document.body.classList.add('loading');
  const loader = $('#sableLoader');
  if (!loader) return;
  loader.hidden = false;
  loader.classList.remove('is-hidden');
  updateSableLoader(0, 'Starting Sable…');
  const messages = [
    'Starting Sable…',
    'Preparing your workspace…',
    'Loading analysis tools…',
    'Ready to import infrastructure…'
  ];
  const tick = now => {
    if (!$('#sableLoader') || $('#sableLoader').classList.contains('is-hidden')) return;
    const elapsed = now - sableLoaderStart;
    const percent = Math.min(94, 10 + (elapsed / SABLE_LOADER_MIN_MS) * 84);
    const messageIndex = Math.min(messages.length - 1, Math.floor((percent / 100) * messages.length));
    updateSableLoader(percent, messages[messageIndex]);
    sableLoaderFrame = requestAnimationFrame(tick);
  };
  sableLoaderFrame = requestAnimationFrame(tick);
}

function updateSableLoader(percent, message) {
  const stage = $('#sableLoaderStage');
  const bar = $('#sableLoaderBar');
  const label = $('#sableLoaderStatus');
  const percentLabel = $('#sableLoaderPercent');
  if (stage) stage.style.setProperty('--loader-progress', String(Math.max(0, Math.min(100, percent))));
  if (bar) bar.style.width = `${Math.max(0, Math.min(100, percent))}%`;
  if (label && message) label.textContent = message;
  if (percentLabel) percentLabel.textContent = `${Math.round(percent)}%`;
}

function finishSableLoader() {
  const loader = $('#sableLoader');
  if (!loader) {
    document.body.classList.remove('loading');
    return;
  }
  const wait = Math.max(0, SABLE_LOADER_MIN_MS - (performance.now() - sableLoaderStart));
  window.setTimeout(() => {
    if (sableLoaderFrame) cancelAnimationFrame(sableLoaderFrame);
    updateSableLoader(100, 'Workspace ready.');
    loader.classList.add('is-hidden');
    document.body.classList.remove('loading');
    window.setTimeout(() => { loader.hidden = true; }, 450);
  }, wait);
}

async function init() {
  beginSableLoader();
  applyTheme(activeTheme);
  bindNavigation();
  initializeRouteFromLocation();
  bindThemeControls();
  bindImportPage();
  bindOverviewPage();
  bindReviewerPage();
  applyArchitectureZoom();
  renderAll();
  try {
    if (workspace.resources.length && !currentAnalysis.resources.length) showToast('A saved workspace needs refreshing. Select Refresh analysis to update its findings.');
    fetch('/api/health').then(response => response.json()).then(health => { if (Number.isFinite(health.limits?.requestBytes)) serviceRequestLimit = health.limits.requestBytes; }).catch(() => {});
  } finally {
    finishSableLoader();
  }
}

document.addEventListener('DOMContentLoaded', init);

function bindNavigation() {
  $$('#navStack .nav-item').forEach(button => {
    button.addEventListener('click', () => navigate(button.dataset.route));
  });
  $$('[data-route-target]').forEach(button => {
    button.addEventListener('click', () => navigate(button.dataset.routeTarget));
  });
  $('#openImportPickerBtn')?.addEventListener('click', openInfrastructureFilePicker);
  $$('[data-open-import-picker]').forEach(button => {
    button.addEventListener('click', openInfrastructureFilePicker);
  });
  $('#exportMarkdownBtn').addEventListener('click', exportWorkspaceReport);
  $('#refreshWorkspaceBtn')?.addEventListener('click', async () => {
    const button = $('#refreshWorkspaceBtn'); button.disabled = true; button.textContent = 'Refreshing…';
    try { await hydrateSavedWorkspace(); } finally { button.disabled = false; button.textContent = 'Refresh analysis'; }
  });
  $('#clearWorkspaceBtn')?.addEventListener('click', clearWorkspaceData);
  $('#tryExampleBtn')?.addEventListener('click', () => navigate('learn'));
  window.addEventListener('popstate', () => {
    const route = routeFromPath(window.location.pathname);
    navigate(route, { historyMode: 'none' });
  });
}

function routeFromPath(pathname = window.location.pathname) {
  const normalized = pathname.length > 1 ? pathname.replace(/\/+$/, '') : pathname;
  if (normalized === '/' || normalized === '/index.html') return 'overview';
  return ROUTE_BY_PATH[normalized] || 'overview';
}

function initializeRouteFromLocation() {
  const route = routeFromPath(window.location.pathname);
  const canonicalPath = APP_ROUTES[route].path;
  navigate(route, {
    historyMode: window.location.pathname === canonicalPath ? 'none' : 'replace'
  });
}


function bindThemeControls() {
  $$('[data-theme-choice]').forEach(button => {
    button.addEventListener('click', () => applyTheme(button.dataset.themeChoice || 'dark'));
  });
}

function applyTheme(theme) {
  activeTheme = theme === 'light' ? 'light' : 'dark';
  document.body.dataset.theme = activeTheme;
  writeLocalValue(THEME_KEY, activeTheme);
  $$('[data-theme-choice]').forEach(button => {
    button.classList.toggle('active', button.dataset.themeChoice === activeTheme);
    button.setAttribute('aria-pressed', String(button.dataset.themeChoice === activeTheme));
  });
  requestAnimationFrame(() => {
    drawArchitectureConnections();
    renderArchitectureExplorer();
  });
}

function clampNumber(value, min, max) {
  const number = Number(value);
  if (Number.isNaN(number)) return min;
  return Math.min(max, Math.max(min, number));
}

function getCssVar(name, fallback) {
  return getComputedStyle(document.body).getPropertyValue(name).trim() || fallback;
}

function bindOverviewPage() {
  const footer = $('#architectureExplorer .explorer-footer');
  if (footer && !$('#relationshipPanelToggle')) {
    const toggle = document.createElement('button');
    toggle.id = 'relationshipPanelToggle';
    toggle.type = 'button';
    toggle.className = 'relationship-panel-toggle';
    toggle.textContent = 'Show relationship evidence and selection details';
    toggle.setAttribute('aria-expanded', 'false');
    toggle.addEventListener('click', () => {
      const open = footer.classList.toggle('is-open');
      toggle.setAttribute('aria-expanded', String(open));
      toggle.textContent = open ? 'Hide relationship evidence and selection details' : 'Show relationship evidence and selection details';
    });
    footer.before(toggle);
  }
  $('#findingSeverityFilter').addEventListener('change', renderFindings);
  $('#resourceSearch').addEventListener('input', renderResourceTable);
  $('#maximizeArchitectureBtn').addEventListener('click', event => {
    event.stopPropagation();
    toggleArchitectureMaximized();
  });
  const zoomRange = $('#architectureZoomRange');
  if (zoomRange) {
    zoomRange.addEventListener('input', event => setArchitectureZoom(Number(event.target.value) / 100));
  }
  $('#zoomInBtn')?.addEventListener('click', event => {
    event.stopPropagation();
    setArchitectureZoom(architectureZoom + ZOOM_STEP);
  });
  $('#zoomOutBtn')?.addEventListener('click', event => {
    event.stopPropagation();
    setArchitectureZoom(architectureZoom - ZOOM_STEP);
  });
  $('#zoomResetBtn')?.addEventListener('click', event => {
    event.stopPropagation();
    setArchitectureZoom(1);
  });
  $('#fitExplorerBtn')?.addEventListener('click', event => {
    event.stopPropagation();
    fitExplorerView();
  });

  const architectureCanvas = $('#architectureCanvas');
  const explorerStage = $('#explorerStage');
  architectureCanvas?.addEventListener('wheel', handleArchitectureWheel, { passive: false });
  bindDiagramPanning(architectureCanvas, '#explorerStage');
  bindDiagramPanning(explorerStage);
  explorerStage?.addEventListener('scroll', syncExplorerLaneHeaders, { passive: true });

  $('#architecturePreviewMaximizeBtn')?.addEventListener('click', event => {
    event.stopPropagation();
    toggleArchitectureMaximized(true);
  });

  const closeExplorerBtn = $('#closeExplorerBtn');
  if (closeExplorerBtn) {
    closeExplorerBtn.addEventListener('click', event => {
      event.stopPropagation();
      const category = selectedArchitectureCategory;
      selectedArchitectureCategory = null;
      selectedExplorerResourceId = null;
      renderArchitecture();
      $$('.arch-category-node').find(node => node.dataset.category === category)?.focus({ preventScroll: true });
    });
  }

  $('#connectionModeBtn')?.addEventListener('click', () => {
    architectureConnectionMode = architectureConnectionMode === 'trace' ? 'all' : 'trace';
    renderArchitectureExplorer();
  });

  $$('.explorer-mode').forEach(button => {
    button.addEventListener('click', event => {
      event.stopPropagation();
      architectureGraphMode = button.dataset.graphMode || 'internal';
      selectedExplorerResourceId = null;
      renderArchitecture();
    });
  });

  window.addEventListener('resize', () => {
    drawArchitectureConnections();
    renderArchitectureExplorer();
  });
  document.addEventListener('keydown', event => {
    const panel = $('#architecturePanel');
    // A details drawer or tool dialog owns keyboard focus above the map.
    if ($('#ivModal:not(.hidden)') || $('#ivDetailsDrawer.open')) return;
    if (event.key === 'Tab' && panel.classList.contains('maximized')) {
      const controls = [...panel.querySelectorAll('button, input, select, a[href], [tabindex="0"]')].filter(element => !element.disabled && element.getClientRects().length);
      const first = controls[0], last = controls.at(-1);
      if (event.shiftKey && (document.activeElement === first || !panel.contains(document.activeElement))) { event.preventDefault(); last?.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || !panel.contains(document.activeElement))) { event.preventDefault(); first?.focus(); }
    }
    if (event.key === 'Escape' && selectedArchitectureCategory) {
      selectedArchitectureCategory = null;
      selectedExplorerResourceId = null;
      renderArchitecture();
      return;
    }
    if (event.key === 'Escape' && $('#architecturePanel').classList.contains('maximized')) {
      toggleArchitectureMaximized(false);
    }
  });
}


function fitExplorerView() {
  const viewport = selectedArchitectureCategory ? $('#explorerStage') : $('#architectureCanvas');
  if (!viewport) return;

  const contentWidth = selectedArchitectureCategory
    ? Number(viewport.dataset.contentWidth) || viewport.scrollWidth
    : viewport.scrollWidth;
  const contentHeight = selectedArchitectureCategory
    ? Number(viewport.dataset.contentHeight) || viewport.scrollHeight
    : viewport.scrollHeight;

  if (!contentWidth || !contentHeight) return;
  const widthRatio = Math.max(0.01, (viewport.clientWidth - 36) / contentWidth);
  const heightRatio = Math.max(0.01, (viewport.clientHeight - 36) / contentHeight);
  const targetZoom = clampNumber(architectureZoom * Math.min(widthRatio, heightRatio), ZOOM_MIN, 1);
  setArchitectureZoom(targetZoom);
  // Zoom updates its scroll anchor on the next two frames. Center after that.
  requestAnimationFrame(() => requestAnimationFrame(() => requestAnimationFrame(() => centerDiagramViewport(viewport))));
}

function handleArchitectureWheel(event) {
  if (!event.ctrlKey && !event.metaKey) return;
  event.preventDefault();
  const viewport = selectedArchitectureCategory ? $('#explorerStage') : $('#architectureCanvas');
  if (!viewport) return;
  const rect = viewport.getBoundingClientRect();
  const anchor = {
    viewport,
    x: Math.max(0, Math.min(viewport.clientWidth, event.clientX - rect.left)),
    y: Math.max(0, Math.min(viewport.clientHeight, event.clientY - rect.top))
  };
  const factor = Math.exp(-event.deltaY * 0.0032);
  setArchitectureZoom(architectureZoom * factor, anchor);
}

function bindDiagramPanning(viewport, ignoreSelector = '') {
  if (!viewport || viewport.dataset.panBound === 'true') return;
  viewport.dataset.panBound = 'true';
  let state = null;

  viewport.addEventListener('pointerdown', event => {
    if (event.button !== 0 || event.pointerType === 'touch') return;
    if (ignoreSelector && event.target.closest(ignoreSelector)) return;
    if (event.target.closest('button, input, select, textarea, a, label, .resource-map-node, .arch-node, .explorer-toolbar, .explorer-footer')) return;
    state = {
      pointerId: event.pointerId,
      x: event.clientX,
      y: event.clientY,
      left: viewport.scrollLeft,
      top: viewport.scrollTop
    };
    viewport.setPointerCapture?.(event.pointerId);
    viewport.classList.add('is-panning');
    event.preventDefault();
  });

  viewport.addEventListener('pointermove', event => {
    if (!state || event.pointerId !== state.pointerId) return;
    viewport.scrollLeft = state.left - (event.clientX - state.x);
    viewport.scrollTop = state.top - (event.clientY - state.y);
  });

  const stop = event => {
    if (!state || (event?.pointerId != null && event.pointerId !== state.pointerId)) return;
    if (event?.pointerId != null) viewport.releasePointerCapture?.(event.pointerId);
    state = null;
    viewport.classList.remove('is-panning');
  };
  viewport.addEventListener('pointerup', stop);
  viewport.addEventListener('pointercancel', stop);
  viewport.addEventListener('lostpointercapture', stop);
}

function centerDiagramViewport(viewport) {
  if (!viewport) return;
  viewport.scrollLeft = Math.max(0, (viewport.scrollWidth - viewport.clientWidth) / 2);
  viewport.scrollTop = Math.max(0, (viewport.scrollHeight - viewport.clientHeight) / 2);
}

function bindImportPage() {
  const importInput = $('#importInput');
  const dropzone = $('#dropzone');
  const fileInput = $('#fileInput');
  const chooseFilesButton = $('#chooseImportFilesBtn');

  const openPicker = () => {
    if (!fileInput) return;
    fileInput.value = '';
    fileInput.click();
  };

  chooseFilesButton?.addEventListener('click', openPicker);
  $('#clearImportBtn').addEventListener('click', () => {
    invalidateImport();
    importInput.value = '';
    fileInput.value = '';
    pendingImportFiles = [];
    currentPreview = null;
    updateImportFileSummary([]);
    renderImportPreview();
    syncPrimaryActions();
    importInput.focus();
  });
  $('#analyzeImportBtn').addEventListener('click', () => analyzeImportInput(true));
  $('#downloadSnapshotBtn').addEventListener('click', downloadNormalizedSnapshot);

  importInput.addEventListener('input', () => {
    invalidateImport();
    pendingImportFiles = [];
    currentPreview = null;
    updateImportFileSummary([], importInput.value.trim() ? 'Using pasted source. Select Analyze workspace to process it.' : 'No files selected.');
    renderImportPreview();
  });

  dropzone.addEventListener('click', event => {
    if (event.target === fileInput) return;
    openPicker();
  });
  dropzone.addEventListener('keydown', event => {
    if (event.key !== 'Enter' && event.key !== ' ') return;
    event.preventDefault();
    openPicker();
  });
  fileInput.addEventListener('change', event => handleFilesSelect(event.target.files, importInput, previewImportInput, 'import'));

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, event => {
      event.preventDefault();
      dropzone.classList.add('dragging');
    });
  });
  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, event => {
      event.preventDefault();
      dropzone.classList.remove('dragging');
    });
  });
  dropzone.addEventListener('drop', event => {
    handleFilesSelect(event.dataTransfer.files, importInput, previewImportInput, 'import');
  });
}

function openInfrastructureFilePicker() {
  navigate('importer');
  const fileInput = $('#fileInput');
  if (!fileInput) return;
  fileInput.value = '';
  fileInput.click();
}

function bindReviewerPage() {
  $('#clearPrBtn').addEventListener('click', () => {
    invalidateReview();
    $('#prFileInput').value = '';
    $('#prInput').value = '';
    pendingReviewFiles = [];
    prReview = { findings: [], diffs: [], riskScore: null, decision: 'Waiting for input', counts: { add: 0, change: 0, delete: 0 }, analysis: null };
    renderPrReview();
  });
  $('#reviewPrBtn').addEventListener('click', reviewPrRisk);
  $('#setBaselineBtn').addEventListener('click', () => {
    if (!currentAnalysis.resources?.length) {
      showToast('Import and analyze infrastructure before saving a baseline.');
      return;
    }
    if (!writeLocalJson(BASELINE_KEY, createLocalBaselineSnapshot())) {
      showToast('This browser could not save the baseline locally.');
      return;
    }
    window.SableFeatures?.renderAll?.();
    showToast(`Baseline saved with ${currentAnalysis.resources.length} resources.`);
  });
  $('#exportPrReportBtn').addEventListener('click', exportPrReport);
  $('#prInput').addEventListener('input', () => { invalidateReview(); pendingReviewFiles = []; renderPrReview(); });
  $('#prFileInput').addEventListener('change', event => handleFilesSelect(event.target.files, $('#prInput'), reviewPrRisk, 'review'));
}

function navigate(route, { historyMode = 'push' } = {}) {
  const config = APP_ROUTES[route] || APP_ROUTES.overview;
  const resolvedRoute = APP_ROUTES[route] ? route : 'overview';

  if ($('#architecturePanel')?.classList.contains('maximized')) toggleArchitectureMaximized(false);

  $$('.nav-item').forEach(item => {
    const active = item.dataset.route === resolvedRoute;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page'); else item.removeAttribute('aria-current');
  });

  $$('.page').forEach(page => page.classList.remove('active'));
  $(`#${resolvedRoute}Page`)?.classList.add('active');
  $('#routeEyebrow').textContent = config.eyebrow;
  $('#routeTitle').textContent = config.heading;
  document.title = config.title;
  window.scrollTo({ top: 0, behavior: 'instant' });

  if (historyMode !== 'none') {
    const nextUrl = `${config.path}${window.location.search}${window.location.hash}`;
    if (historyMode === 'replace') {
      window.history.replaceState({ route: resolvedRoute }, '', nextUrl);
    } else if (window.location.pathname !== config.path) {
      window.history.pushState({ route: resolvedRoute }, '', nextUrl);
    }
  }

  requestAnimationFrame(() => {
    const activeNav = $(`.nav-item[data-route="${resolvedRoute}"]`);
    if (activeNav && window.innerWidth <= 940) {
      activeNav.scrollIntoView({ behavior: 'smooth', block: 'nearest', inline: 'center' });
    }
  });
}

function loadWorkspace() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) { const value = JSON.parse(saved); if (value && Array.isArray(value.resources) && value.resources.every(r => r && typeof r === 'object')) return value; }
  } catch (error) {
    console.warn('Could not load saved workspace', error);
  }
  return { workspace: 'No workspace loaded', importedAt: null, sourceType: 'empty', analysisMode: 'empty', resources: [] };
}

function loadAnalysis() {
  try {
    const saved = localStorage.getItem(ANALYSIS_KEY);
    if (saved) { const value = JSON.parse(saved); if (value && value.metadata?.engineVersion === '3.5.0' && Array.isArray(value.resources) && Array.isArray(value.findings) && Array.isArray(value.grouped) && value.counts && value.graph && value.metadata && value.resources.every(r => r && typeof r.id === 'string') && value.findings.every(f => f && typeof f.title === 'string' && ['critical', 'high', 'medium', 'low'].includes(f.severity))) return value; }
  } catch (error) {
    console.warn('Could not load saved analysis', error);
  }
  return emptyAnalysis();
}

async function hydrateSavedWorkspace() {
  if (!workspace?.resources?.length) return;
  const sequence = ++importSequence;
  try {
    const result = await requestAnalysis(JSON.stringify({ workspace: workspace.workspace, resources: workspace.resources, relationships: workspace.explicitLinks || [] }), []);
    if (sequence !== importSequence) return;
    saveWorkspace(result.workspace, result.analysis);
    showToast('Saved workspace analysis refreshed.');
  } catch (error) {
    if (sequence !== importSequence) return;
    showToast(error.message || 'Could not refresh the saved workspace.');
  }
}

function saveWorkspace(nextWorkspace, nextAnalysis, rerender = true) {
  workspace = nextWorkspace;
  currentAnalysis = nextAnalysis || emptyAnalysis();
  selectedArchitectureCategory = null;
  selectedExplorerResourceId = null;
  const savedWorkspace = writeLocalJson(STORAGE_KEY, workspace);
  const savedAnalysis = writeLocalJson(ANALYSIS_KEY, currentAnalysis);
  if (!savedWorkspace || !savedAnalysis) showToast('Analysis is ready, but this browser could not save it. Export a report before closing.');
  if (rerender) renderAll();
  else syncPrimaryActions();
}

async function requestAnalysis(text, files = [], endpoint = '/api/analyze') {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 45_000);
  try {
    const body = JSON.stringify({ text: files.length ? '' : String(text || ''), files, explicitType: 'auto', includeInferred: true, baseline: endpoint === '/api/review' ? readLocalJson(BASELINE_KEY) || workspace : undefined });
    if (new Blob([body]).size > serviceRequestLimit) throw new Error('This import exceeds the hosting request limit, including the saved baseline and JSON formatting. Try a smaller workspace.');
    const response = await fetch(endpoint, {
      method: 'POST', signal: controller.signal,
      headers: { 'Content-Type': 'application/json' },
      body
    });
    if (response.status === 413) throw new Error('This import is too large for the hosting service. Try fewer files or a smaller workspace.');
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(payload.error || `Analysis could not complete (HTTP ${response.status}). Please try again.`);
    if (!payload.workspace || !Array.isArray(payload.analysis?.resources)) throw new Error('The analysis service returned an incomplete result. Please try again.');
    return payload;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('Analysis took too long. Try a smaller import or retry in a moment.');
    if (error instanceof TypeError) throw new Error('Cannot reach the analysis service. Check your connection and try again.');
    throw error;
  } finally { clearTimeout(timeout); }
}

function invalidateImport() {
  previewSequence++; importSequence++; fileReadSequence.import++; importBusy = false;
  $('#importStatus').textContent = '';
  syncPrimaryActions();
}

function invalidateReview() {
  reviewSequence++; fileReadSequence.review++; reviewBusy = false;
  prReview = { findings: [], diffs: [], riskScore: null, decision: 'Waiting for input', counts: { add: 0, change: 0, delete: 0 }, analysis: null };
  $('#reviewStatus').textContent = '';
  syncPrimaryActions();
}

function clearWorkspaceData() {
  if (!window.confirm('Clear the saved workspace, baseline, notes, policies, and review progress from this browser? Export anything you want to keep first.')) return;
  try {
    Object.keys(localStorage).filter(key => key.startsWith('sable.') && key !== THEME_KEY).forEach(key => localStorage.removeItem(key));
  } catch { showToast('Browser storage could not be cleared. Use your browser’s site-data settings.'); return; }
  window.location.reload();
}

function emptyAnalysis() {
  return {
    resources: [], findings: [], grouped: Object.entries(CATEGORY_META).map(([category, meta]) => ({ ...meta, category, resources: [], findings: [] })),
    score: null, rating: 'Not rated', counts: { critical: 0, high: 0, medium: 0, low: 0 }, graph: { links: [], inferredLinks: [] }, diagnostics: [],
    metadata: { analysisMode: 'empty', authoritative: false, machineReadable: false, evidenceLevel: 'none', runtimeVerified: false, scope: 'none', scoreModel: '', coverage: { importedResources: 0, supportedResources: 0, unsupportedResources: 0, supportedPercent: 0, applicableControlFamilies: 0 } }
  };
}

function normalizeResource(resource) {
  const type = String(resource?.type || 'unknown');
  const name = String(resource?.name || 'unnamed');
  return {
    id: String(resource?.id || resource?.address || `${type}.${name}`),
    address: resource?.address || resource?.id || `${type}.${name}`,
    type,
    name,
    provider: resource?.provider || 'Other',
    mode: resource?.mode || 'managed',
    category: resource?.category || 'other',
    action: resource?.action || 'present',
    attributes: resource?.attributes || {},
    source: resource?.source || { kind: 'normalized' }
  };
}

function dedupeResources(resources) {
  const map = new Map();
  (resources || []).forEach(resource => {
    const normalized = normalizeResource(resource);
    map.set(normalized.id, normalized);
  });
  return Array.from(map.values());
}

function countFindings(findings) {
  return (findings || []).reduce((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0 });
}

function setArchitectureZoom(value, anchor = null) {
  const oldZoom = architectureZoom;
  const nextZoom = Math.round(clampNumber(value, ZOOM_MIN, ZOOM_MAX) * 20) / 20;
  if (Math.abs(nextZoom - oldZoom) < 0.001) return;

  const viewport = anchor?.viewport || (selectedArchitectureCategory ? $('#explorerStage') : $('#architectureCanvas'));
  const pointX = anchor?.x ?? ((viewport?.clientWidth || 0) / 2);
  const pointY = anchor?.y ?? ((viewport?.clientHeight || 0) / 2);
  const scrollLeft = viewport?.scrollLeft || 0;
  const scrollTop = viewport?.scrollTop || 0;

  architectureZoom = nextZoom;
  writeLocalValue(ZOOM_KEY, String(architectureZoom));
  applyArchitectureZoom();
  requestAnimationFrame(() => {
    drawArchitectureConnections();
    renderArchitectureExplorer();
    requestAnimationFrame(() => {
      const activeViewport = selectedArchitectureCategory ? $('#explorerStage') : $('#architectureCanvas');
      if (!activeViewport || oldZoom <= 0) return;
      const ratio = architectureZoom / oldZoom;
      activeViewport.scrollLeft = Math.max(0, (scrollLeft + pointX) * ratio - pointX);
      activeViewport.scrollTop = Math.max(0, (scrollTop + pointY) * ratio - pointY);
    });
  });
}

function applyArchitectureZoom() {
  const percent = Math.round(architectureZoom * 100);
  document.documentElement.style.setProperty('--architecture-zoom', String(architectureZoom));
  const range = $('#architectureZoomRange');
  const valueButton = $('#zoomResetBtn');
  if (range) range.value = String(percent);
  if (valueButton) valueButton.textContent = `${percent}%`;
}

function renderAll() {
  renderSidebar();
  renderWorkspaceBanner();
  renderOverview();
  renderImportPreview();
  renderPrReview();
  window.SableFeatures?.renderAll?.();
  window.SableProduct?.renderAll?.();
}

function renderSidebar() {
  $('#workspaceName').textContent = summarizeWorkspaceTitle(workspace);
  const count = workspace.resources?.length || 0;
  $('#workspaceSummary').textContent = count
    ? `${count} resources · ${humanizeToken(workspace.sourceType || 'workspace')}`
    : 'No infrastructure imported yet.';
}

function renderWorkspaceBanner() {
  const title = $('#workspaceDisplayName');
  if (!title) return;
  const count = workspace.resources?.length || 0;
  title.textContent = summarizeWorkspaceTitle(workspace);
  $('#workspaceDescription').textContent = buildWorkspaceDescription(workspace, currentAnalysis, count);
  $('#workspaceSourceType').textContent = count ? humanizeToken(workspace.sourceType || 'workspace') : '—';
  $('#workspaceAnalysisMode').textContent = count ? humanizeToken(currentAnalysis.metadata?.analysisMode || workspace.analysisMode || 'analysis') : '—';
  $('#workspaceResourceCount').textContent = String(count);
  $('#refreshWorkspaceBtn').hidden = !(count && !currentAnalysis.resources.length);
}

function summarizeWorkspaceTitle(workspaceData = {}) {
  const raw = String(workspaceData.workspace || '').replace(/\s+/g, ' ').trim();
  const source = String(workspaceData.sourceType || '');
  if (!raw) return 'No workspace loaded';
  if (raw.length <= 68) return raw;
  if (source.startsWith('cloudformation')) return 'CloudFormation stack';
  if (source.startsWith('terraform')) return 'Terraform workspace';
  if (source.startsWith('kubernetes')) return 'Kubernetes manifests';
  if (source.startsWith('snapshot')) return 'Imported snapshot';
  return `${raw.slice(0, 65)}…`;
}

function buildWorkspaceDescription(workspaceData = {}, analysis = emptyAnalysis(), count = 0) {
  if (!count) return 'No infrastructure imported yet.';
  const source = humanizeToken(workspaceData.sourceType || 'workspace');
  const mode = humanizeToken(analysis.metadata?.analysisMode || workspaceData.analysisMode || 'analysis');
  const evidence = evidenceModeLabel(analysis.metadata);
  return `${count} resources imported from ${source}. ${mode}. ${evidence}.`;
}

function evidenceModeLabel(metadata = {}) {
  const level = metadata.evidenceLevel || '';
  if (level === 'planned-values') return 'Terraform planned-value evidence';
  if (level === 'state-snapshot') return 'Terraform state-snapshot evidence';
  if (level === 'declaration-only') return 'Declarative source evidence only';
  if (level === 'user-supplied') return 'User-supplied snapshot evidence';
  if (metadata.machineReadable) return 'Machine-readable imported evidence';
  return 'Static imported evidence';
}

function humanizeToken(value = '') {
  return String(value)
    .replace(/[._-]+/g, ' ')
    .trim()
    .replace(/\b\w/g, char => char.toUpperCase());
}

function renderOverview() {
  const hasResources = Boolean(currentAnalysis.resources?.length);
  const hasScore = hasResources && Number.isFinite(currentAnalysis.score);
  $('#healthScore').textContent = hasScore ? currentAnalysis.score : '—';
  $('#scoreRingText').textContent = hasScore ? `${currentAnalysis.score}%` : 'N/R';
  $('#scoreRing').style.strokeDashoffset = String(hasScore ? CIRCLE_LENGTH - (CIRCLE_LENGTH * currentAnalysis.score) / 100 : CIRCLE_LENGTH);
  $('#healthNarrative').textContent = buildHealthNarrative(currentAnalysis.score, currentAnalysis.counts, currentAnalysis.resources.length, currentAnalysis.metadata, currentAnalysis.rating);
  $('#criticalCount').textContent = currentAnalysis.counts.critical || 0;
  $('#highCount').textContent = currentAnalysis.counts.high || 0;
  $('#mediumCount').textContent = currentAnalysis.counts.medium || 0;
  $('#lowCount').textContent = currentAnalysis.counts.low || 0;
  renderArchitecture();
  renderFindings();
  renderResourceTable();
  syncPrimaryActions();
}

function buildHealthNarrative(score, counts, resourceCount, metadata = {}, rating = '') {
  if (!resourceCount) return 'Import Terraform, JSON, or YAML to run evidence-backed infrastructure checks.';
  const coverage = metadata.coverage || {};
  const coverageText = Number.isFinite(coverage.supportedPercent) ? `${coverage.supportedPercent}% of imported resources have an applicable built-in rule family` : 'rule coverage is unavailable';
  const mode = evidenceModeLabel(metadata);
  if (!Number.isFinite(score)) return `${mode}. Not rated because no built-in posture controls apply to the imported resource types. Architecture mapping and parser diagnostics are still available.`;
  if ((counts.critical || 0) > 0) return `${mode}. ${rating || 'Critical findings detected'}. Score ${score}/100 reflects only the controls S4BLE can assess; ${coverageText}.`;
  if ((counts.high || 0) > 0) return `${mode}. ${rating || 'High-priority findings detected'}. Score ${score}/100 is a triage index, not proof of cloud security; ${coverageText}.`;
  if ((counts.medium || 0) > 0 || (counts.low || 0) > 0) return `${mode}. ${rating || 'Review recommended'}. Score ${score}/100 covers explicit findings only; ${coverageText}.`;
  return `${mode}. No confirmed issues were detected by the controls currently assessed. This is not a guarantee that the environment is secure; ${coverageText}.`;
}

function renderArchitecture() {
  applyArchitectureZoom();
  const grid = $('#architectureGrid');
  const explorer = $('#architectureExplorer');
  const empty = $('#architectureEmpty');
  const hasResources = currentAnalysis.resources.length > 0;
  const architecturePanel = $('#architecturePanel');
  architecturePanel?.classList.toggle('explorer-open', Boolean(hasResources && selectedArchitectureCategory));
  $('#architecturePreviewMaximizeBtn')?.classList.toggle('hidden', !hasResources);

  grid.innerHTML = '';
  $('#connectionLayer').innerHTML = '';
  empty.classList.toggle('hidden', hasResources);

  if (!hasResources) {
    explorer?.classList.add('hidden');
    grid.classList.remove('hidden');
    return;
  }

  if (selectedArchitectureCategory) {
    grid.classList.add('hidden');
    explorer?.classList.remove('hidden');
    renderArchitectureExplorer();
    return;
  }

  explorer?.classList.add('hidden');
  grid.classList.remove('hidden');

  currentAnalysis.grouped
    .filter(group => group.resources.length || group.findings.length)
    .forEach(group => {
      const topResources = group.resources.slice(0, 3).map(resource => resource.name).join(', ');
      const node = document.createElement('button');
      node.type = 'button';
      node.setAttribute('aria-label', `Open ${group.label || group.category}: ${group.resources.length} resources and ${group.findings.length} findings`);
      node.className = `arch-node arch-category-node arch-pos-${group.category}`;
      node.dataset.category = group.category;
      node.innerHTML = `
        <div class="arch-node-header">
          <div>
            <h3>${escapeHtml(group.label || CATEGORY_META[group.category]?.label || group.category)}</h3>
            <div class="count">${group.resources.length} resources · ${group.findings.length} findings</div>
          </div>
          <div class="node-icon" aria-hidden="true">${escapeHtml(CATEGORY_META[group.category]?.icon || group.icon || '□')}</div>
        </div>
        <div class="node-risk-row">
          ${renderRiskChips(countFindings(group.findings))}
        </div>
        <div class="category-preview">
          <span>${topResources ? escapeHtml(topResources) : 'No resources detected'}</span>
          <strong>Explore resources <span aria-hidden="true">↗</span></strong>
        </div>
      `;
      node.addEventListener('click', () => {
        selectedArchitectureCategory = group.category;
        architectureGraphMode = 'internal';
        selectedExplorerResourceId = null;
        renderArchitecture();
        $('#explorerStage')?.focus({ preventScroll: true });
      });
      grid.appendChild(node);
    });

  requestAnimationFrame(() => {
    drawArchitectureConnections();
    renderArchitectureExplorer();
  });
}

function renderRiskChips(counts) {
  const chips = ['critical', 'high', 'medium', 'low']
    .filter(severity => counts[severity])
    .map(severity => `<span class="risk-chip severity-pill ${severity}">${severity}: ${counts[severity]}</span>`)
    .join('');
  return chips || '<span class="risk-chip">no findings</span>';
}

function drawArchitectureConnections() {
  if (selectedArchitectureCategory) return;
  const svg = $('#connectionLayer');
  const panel = $('#architectureCanvas');
  const nodes = $$('.arch-node');
  svg.innerHTML = '';
  // Remove the previous SVG extent before measuring a zoomed-out board.
  svg.style.width = '0px';
  svg.style.height = '0px';
  if (nodes.length < 2) return;

  const panelRect = panel.getBoundingClientRect();
  const width = Math.max(panel.scrollWidth, panel.clientWidth, Math.ceil(panelRect.width));
  const height = Math.max(panel.scrollHeight, panel.clientHeight, Math.ceil(panelRect.height));
  svg.style.width = `${width}px`;
  svg.style.height = `${height}px`;
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  ensureArrowMarker(svg, 'categoryArrow', getCssVar('--wire-muted', 'rgba(65,70,82,.55)'), 8);

  const nodeRects = new Map();
  nodes.forEach(node => {
    const rect = node.getBoundingClientRect();
    nodeRects.set(node.dataset.category, rectToCanvasRect(rect, panelRect, panel.scrollLeft, panel.scrollTop));
  });

  const groupedPairs = new Map();
  getCategoryRelationshipPairs(currentAnalysis.resources).forEach(pair => {
    const key = [pair.source, pair.target].sort().join('|') + ':' + pair.inferred;
    const existing = groupedPairs.get(key);
    if (existing) { existing.bidirectional = true; existing.count += pair.count; }
    else groupedPairs.set(key, { ...pair });
  });
  const pairs = [...groupedPairs.values()];
  const endpoints = allocateConnectionPorts(pairs, nodeRects, item => item.source, item => item.target);
  const obstacles = Array.from(nodeRects.entries()).map(([key, rect]) => ({ key, ...rect }));

  const occupied = [];
  pairs.forEach((pair, index) => {
    const endpoint = endpoints[index];
    if (!endpoint) return;
    const points = SableRouting.route(endpoint.from, endpoint.to, obstacles, width, height, index, occupied);
    if (!points) return;
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    path.setAttribute('d', roundedOrthogonalPath(points, 12));
    path.setAttribute('class', `connection-line category-connection-line ${pair.inferred ? 'inferred' : 'confirmed'}`);
    path.setAttribute('marker-end', 'url(#categoryArrow)');
    if (pair.bidirectional) path.setAttribute('marker-start', 'url(#categoryArrow)');
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${CATEGORY_META[pair.source]?.label || pair.source} ${pair.bidirectional ? '↔' : '→'} ${CATEGORY_META[pair.target]?.label || pair.target} · ${pair.count} ${pair.inferred ? 'inferred' : 'confirmed'} relationships`;
    path.appendChild(title);
    appendConnectionHalo(svg, path);
    svg.appendChild(path);
    if (pair.count > 1) appendConnectionCount(svg, points, pair.count);
  });
}

function appendConnectionHalo(svg, path) {
  const halo = path.cloneNode(false);
  halo.removeAttribute('marker-end');
  halo.removeAttribute('marker-start');
  halo.removeAttribute('data-source');
  halo.removeAttribute('data-target');
  halo.setAttribute('class', 'connection-halo');
  svg.appendChild(halo);
}

function appendConnectionCount(svg, points, count) {
  const segments = points.slice(1).map((end, i) => ({ start: points[i], end, length: Math.abs(end.x - points[i].x) + Math.abs(end.y - points[i].y) }));
  const segment = segments.sort((a, b) => b.length - a.length)[0];
  if (!segment || segment.length < 90) return;
  const x = (segment.start.x + segment.end.x) / 2;
  const y = (segment.start.y + segment.end.y) / 2;
  const group = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  group.setAttribute('class', 'connection-count');
  const pill = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
  const width = String(count).length * 7 + 18;
  pill.setAttribute('x', String(x - width / 2));
  pill.setAttribute('y', String(y - 10));
  pill.setAttribute('width', String(width));
  pill.setAttribute('height', '20');
  pill.setAttribute('rx', '10');
  const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  label.setAttribute('x', String(x));
  label.setAttribute('y', String(y));
  label.textContent = String(count);
  group.append(pill, label);
  svg.appendChild(group);
}

function rectToCanvasRect(rect, containerRect, scrollLeft = 0, scrollTop = 0) {
  const left = rect.left - containerRect.left + scrollLeft;
  const top = rect.top - containerRect.top + scrollTop;
  return {
    left,
    top,
    right: left + rect.width,
    bottom: top + rect.height,
    width: rect.width,
    height: rect.height,
    cx: left + rect.width / 2,
    cy: top + rect.height / 2
  };
}

function choosePortSide(rect, otherRect) {
  const dx = otherRect.cx - rect.cx;
  const dy = otherRect.cy - rect.cy;
  if (Math.abs(dx) >= Math.abs(dy)) return dx >= 0 ? 'right' : 'left';
  return dy >= 0 ? 'bottom' : 'top';
}

function allocateConnectionPorts(items, rects, getSource, getTarget) {
  const endpointMeta = items.map((item, index) => {
    const source = getSource(item);
    const target = getTarget(item);
    const sourceRect = rects.get(source);
    const targetRect = rects.get(target);
    if (!sourceRect || !targetRect) return null;
    return {
      index,
      source,
      target,
      sourceRect,
      targetRect,
      sourceSide: choosePortSide(sourceRect, targetRect),
      targetSide: choosePortSide(targetRect, sourceRect)
    };
  });

  const buckets = new Map();
  endpointMeta.filter(Boolean).forEach(meta => {
    [['source', meta.source, meta.sourceSide, meta.targetRect], ['target', meta.target, meta.targetSide, meta.sourceRect]].forEach(([role, key, side, other]) => {
      const bucketKey = `${key}:${side}`;
      if (!buckets.has(bucketKey)) buckets.set(bucketKey, []);
      buckets.get(bucketKey).push({ meta, role, other });
    });
  });

  buckets.forEach(group => {
    group.sort((a, b) => {
      const side = a.role === 'source' ? a.meta.sourceSide : a.meta.targetSide;
      return (side === 'left' || side === 'right') ? a.other.cy - b.other.cy : a.other.cx - b.other.cx;
    });
    group.forEach((entry, slot) => {
      entry.meta[`${entry.role}Slot`] = slot;
      entry.meta[`${entry.role}Total`] = group.length;
    });
  });

  return endpointMeta.map(meta => {
    if (!meta) return null;
    return {
      from: pointOnRectSide(meta.sourceRect, meta.sourceSide, meta.sourceSlot || 0, meta.sourceTotal || 1, 2),
      to: pointOnRectSide(meta.targetRect, meta.targetSide, meta.targetSlot || 0, meta.targetTotal || 1, 2),
      meta
    };
  });
}

function pointOnRectSide(rect, side, slotIndex = 0, slotTotal = 1, gap = 0) {
  const fraction = (slotIndex + 1) / (slotTotal + 1);
  if (side === 'left' || side === 'right') {
    return {
      x: side === 'right' ? rect.right + gap : rect.left - gap,
      y: rect.top + Math.max(18, Math.min(rect.height - 18, rect.height * fraction)),
      side
    };
  }
  return {
    x: rect.left + Math.max(22, Math.min(rect.width - 22, rect.width * fraction)),
    y: side === 'bottom' ? rect.bottom + gap : rect.top - gap,
    side
  };
}

function cleanOrthogonalPoints(points) {
  const cleaned = [];
  points.forEach(point => {
    const last = cleaned[cleaned.length - 1];
    if (!last || Math.abs(last.x - point.x) > 0.5 || Math.abs(last.y - point.y) > 0.5) cleaned.push({ ...point });
  });
  for (let i = cleaned.length - 2; i > 0; i -= 1) {
    const prev = cleaned[i - 1];
    const cur = cleaned[i];
    const next = cleaned[i + 1];
    if ((Math.abs(prev.x - cur.x) < 0.5 && Math.abs(cur.x - next.x) < 0.5) ||
        (Math.abs(prev.y - cur.y) < 0.5 && Math.abs(cur.y - next.y) < 0.5)) cleaned.splice(i, 1);
  }
  return cleaned;
}

function roundedOrthogonalPath(points, radius = 10) {
  const pts = cleanOrthogonalPoints(points);
  if (!pts.length) return '';
  if (pts.length === 1) return `M ${pts[0].x} ${pts[0].y}`;
  let d = `M ${pts[0].x} ${pts[0].y}`;
  for (let i = 1; i < pts.length - 1; i += 1) {
    const prev = pts[i - 1];
    const cur = pts[i];
    const next = pts[i + 1];
    const inLen = Math.abs(cur.x - prev.x) + Math.abs(cur.y - prev.y);
    const outLen = Math.abs(next.x - cur.x) + Math.abs(next.y - cur.y);
    const r = Math.min(radius, inLen / 2, outLen / 2);
    const before = {
      x: cur.x + (prev.x === cur.x ? 0 : (prev.x < cur.x ? -r : r)),
      y: cur.y + (prev.y === cur.y ? 0 : (prev.y < cur.y ? -r : r))
    };
    const after = {
      x: cur.x + (next.x === cur.x ? 0 : (next.x < cur.x ? -r : r)),
      y: cur.y + (next.y === cur.y ? 0 : (next.y < cur.y ? -r : r))
    };
    d += ` L ${before.x} ${before.y} Q ${cur.x} ${cur.y} ${after.x} ${after.y}`;
  }
  const last = pts[pts.length - 1];
  d += ` L ${last.x} ${last.y}`;
  return d;
}

function renderArchitectureExplorer() {
  const explorer = $('#architectureExplorer');
  if (!explorer || !selectedArchitectureCategory || !currentAnalysis.resources.length) return;

  const categoryMeta = CATEGORY_META[selectedArchitectureCategory] || CATEGORY_META.other;
  const graph = buildArchitectureGraph(currentAnalysis.resources);
  const selectedKeys = new Set(currentAnalysis.resources
    .filter(resource => resource.category === selectedArchitectureCategory)
    .map(resourceKey));

  let visibleKeys = new Set(selectedKeys);
  let visibleLinks = graph.links.filter(link => selectedKeys.has(link.source) && selectedKeys.has(link.target));

  if (architectureGraphMode === 'context') {
    graph.links.forEach(link => {
      if (selectedKeys.has(link.source) || selectedKeys.has(link.target)) {
        visibleKeys.add(link.source);
        visibleKeys.add(link.target);
      }
    });
    visibleLinks = graph.links.filter(link =>
      visibleKeys.has(link.source) &&
      visibleKeys.has(link.target) &&
      (selectedKeys.has(link.source) || selectedKeys.has(link.target))
    );
  }

  const visibleResources = Array.from(visibleKeys)
    .map(key => graph.resourceMap.get(key))
    .filter(Boolean)
    .sort((a, b) => (CATEGORY_META[a.category]?.order || 99) - (CATEGORY_META[b.category]?.order || 99) || a.type.localeCompare(b.type) || a.name.localeCompare(b.name));

  $('#explorerEyebrow').textContent = architectureGraphMode === 'context' ? 'Cloud context topology' : 'Category topology';
  $('#explorerTitle').textContent = `${categoryMeta.label} dependency map`;
  $('#explorerSummary').textContent = architectureGraphMode === 'context'
    ? `Showing ${categoryMeta.label} resources plus directly connected resources in other cloud categories.`
    : `Showing only resources inside ${categoryMeta.label} so the internal relationships are easier to read.`;

  $$('.explorer-mode').forEach(button => {
    button.classList.toggle('active', button.dataset.graphMode === architectureGraphMode);
    button.setAttribute('aria-pressed', String(button.dataset.graphMode === architectureGraphMode));
  });

  const layout = renderExplorerNodes(visibleResources, selectedKeys);
  renderExplorerLanes(visibleResources, layout.lanes, layout.width, layout.height);
  renderExplorerConnections(visibleLinks, layout.positions, layout.width, layout.height);
  syncExplorerLaneHeaders();
  renderRelationshipList(visibleLinks, graph.resourceMap);
  renderResourceInspector(graph.resourceMap);
  $('#explorerEmpty').classList.toggle('hidden', visibleLinks.length > 0);
  window.SableFeatures?.afterArchitectureRender?.({ graph, visibleResources, visibleLinks, layout, selectedKeys });
}

function renderExplorerLanes(resources, laneLayouts = [], width = 0, height = 0) {
  const laneContainer = $('#explorerLanes');
  const headerContainer = $('#explorerLaneHeaders');
  const categories = getVisibleCategories(resources);
  laneContainer.innerHTML = '';
  if (headerContainer) headerContainer.innerHTML = '';
  if (!categories.length) return;

  laneContainer.style.width = `${width}px`;
  laneContainer.style.height = `${height}px`;
  if (headerContainer) {
    headerContainer.style.width = `${width}px`;
  }

  categories.forEach(category => {
    const layout = laneLayouts.find(item => item.category === category);
    if (!layout) return;

    const lane = document.createElement('div');
    lane.className = `explorer-lane ${category === selectedArchitectureCategory ? 'active' : ''}`;
    lane.style.left = `${layout.left}px`;
    lane.style.width = `${layout.width}px`;
    laneContainer.appendChild(lane);

    if (headerContainer) {
      const header = document.createElement('div');
      header.className = `explorer-lane-header ${category === selectedArchitectureCategory ? 'active' : ''}`;
      header.style.left = `${layout.left}px`;
      header.style.width = `${layout.width}px`;
      header.innerHTML = `<span>${escapeHtml(CATEGORY_META[category]?.label || category)}</span>`;
      headerContainer.appendChild(header);
    }
  });

  syncExplorerLaneHeaders();
}

function syncExplorerLaneHeaders() {
  const stage = $('#explorerStage');
  const headerContainer = $('#explorerLaneHeaders');
  if (!stage || !headerContainer) return;
  headerContainer.style.transform = `translateY(${stage.scrollTop}px)`;
}

function renderExplorerNodes(resources, selectedKeys) {
  const layer = $('#explorerNodeLayer');
  const stage = $('#explorerStage');
  const categories = getVisibleCategories(resources);
  const nodeWidth = 252 * architectureZoom;
  const nodeHeight = 116 * architectureZoom;
  const horizontalGap = 88 * architectureZoom;
  const rowGap = 196 * architectureZoom;
  const lanePad = 64 * architectureZoom;
  // Lane headings stay readable while the resource map scales beneath them.
  const topPad = 64 + 30 * architectureZoom;
  const maxRowsPerColumn = 6;
  const positions = new Map();
  const grouped = new Map(categories.map(category => [category, []]));
  resources.forEach(resource => grouped.get(resource.category || 'other')?.push(resource));

  const laneLayouts = [];
  let cursorX = 0;
  let maxVisibleRows = 1;
  categories.forEach((category, laneIndex) => {
    const items = grouped.get(category) || [];
    const columns = Math.max(1, Math.ceil(items.length / maxRowsPerColumn));
    const rows = Math.min(maxRowsPerColumn, Math.max(1, items.length));
    const laneWidth = Math.max(
      Math.round(360 * architectureZoom),
      lanePad * 2 + columns * nodeWidth + Math.max(0, columns - 1) * horizontalGap
    );
    laneLayouts.push({ category, laneIndex, left: cursorX, right: cursorX + laneWidth, width: laneWidth, columns, rows });
    cursorX += laneWidth;
    maxVisibleRows = Math.max(maxVisibleRows, rows);
  });

  const contentHeight = topPad + (maxVisibleRows - 1) * rowGap + nodeHeight + 64 * architectureZoom;
  stage.dataset.contentWidth = String(cursorX);
  stage.dataset.contentHeight = String(contentHeight);
  const stageWidth = Math.max(stage.clientWidth || 1080, cursorX);
  const stageHeight = Math.max(stage.clientHeight || 560, contentHeight);

  layer.innerHTML = '';
  layer.style.width = `${stageWidth}px`;
  layer.style.height = `${stageHeight}px`;
  stage.style.setProperty('--explorer-stage-width', `${stageWidth}px`);
  stage.style.setProperty('--explorer-stage-height', `${stageHeight}px`);

  laneLayouts.forEach(layout => {
    const items = grouped.get(layout.category) || [];
    items.forEach((resource, itemIndex) => {
      const subColumn = Math.floor(itemIndex / maxRowsPerColumn);
      const rowIndex = itemIndex % maxRowsPerColumn;
      const x = layout.left + lanePad + subColumn * (nodeWidth + horizontalGap);
      const y = topPad + rowIndex * rowGap;
      const key = resourceKey(resource);
      const risk = getResourceRiskSummary(resource);
      const node = document.createElement('button');
      node.type = 'button';
      node.className = `resource-map-node ${risk.maxSeverity || 'clean'} ${selectedKeys.has(key) ? 'focus-category' : 'context-resource'} ${selectedExplorerResourceId === key ? 'selected' : ''}`;
      node.dataset.resourceKey = key;
      node.setAttribute('aria-pressed', String(selectedExplorerResourceId === key));
      node.setAttribute('aria-label', `${resource.name}, ${resource.type}, ${risk.total} findings. Inspect resource.`);
      node.style.left = `${x}px`;
      node.style.top = `${y}px`;
      node.style.width = `${nodeWidth}px`;
      node.style.height = `${nodeHeight}px`;
      node.style.setProperty('--node-zoom', String(architectureZoom));
      node.innerHTML = `
        <strong title="${escapeHtml(resource.name)}">${escapeHtml(resource.name)}</strong>
        <span title="${escapeHtml(resource.type)}">${escapeHtml(resource.type)}</span>
        <small>${risk.total ? `${risk.total} finding${risk.total === 1 ? '' : 's'}` : 'no findings'}</small>
      `;
      node.addEventListener('click', event => {
        event.stopPropagation();
        selectedExplorerResourceId = key;
        renderArchitectureExplorer();
        $$('.resource-map-node').find(item => item.dataset.resourceKey === key)?.focus({ preventScroll: true });
        window.SableFeatures?.onResourceSelected?.(key);
      });
      layer.appendChild(node);
      positions.set(key, {
        x, y, width: nodeWidth, height: nodeHeight,
        left: x, right: x + nodeWidth, top: y, bottom: y + nodeHeight,
        cx: x + nodeWidth / 2, cy: y + nodeHeight / 2,
        laneLeft: layout.left, laneRight: layout.right, laneIndex: layout.laneIndex,
        subColumn, category: layout.category, resource
      });
    });
  });

  return { positions, width: stageWidth, height: stageHeight, lanes: laneLayouts };
}

function renderExplorerConnections(links, positions, width, height) {
  const svg = $('#explorerConnections');
  svg.innerHTML = '';
  svg.style.width = `${width}px`;
  svg.style.height = `${height}px`;
  svg.setAttribute('viewBox', `0 0 ${width} ${height}`);
  svg.classList.toggle('has-selection', Boolean(selectedExplorerResourceId));
  ensureArrowMarker(svg, 'explorerArrow', getCssVar('--wire-muted', 'rgba(65,70,82,.55)'), 8);
  ensureArrowMarker(svg, 'explorerFocusArrow', getCssVar('--wire', 'rgba(54,87,255,.88)'), 9);

  const featureFocus = window.SableFeatures?.focusResourceIds?.();
  const trace = architectureConnectionMode === 'trace';
  const displayedLinks = links.filter(link => {
    if (featureFocus?.size) return featureFocus.has(link.source) && featureFocus.has(link.target);
    if (!trace) return true;
    if (selectedExplorerResourceId) return link.source === selectedExplorerResourceId || link.target === selectedExplorerResourceId;
    return links.length <= 24;
  });
  const modeButton = $('#connectionModeBtn');
  modeButton.textContent = trace ? 'Show all connections' : 'Trace selected resource';
  modeButton.setAttribute('aria-pressed', String(!trace));
  const status = $('#connectionStatus');
  status.textContent = `${displayedLinks.length} of ${links.length} connections shown. ` +
    (trace && !selectedExplorerResourceId && links.length > 24 ? 'Select a resource to trace its direct links, or choose Show all connections. ' : '') +
    'Arrows follow imported dependencies; they do not represent live traffic.';
  const routeItems = displayedLinks
    .map((link, index) => ({ link, index, from: positions.get(link.source), to: positions.get(link.target) }))
    .filter(item => item.from && item.to && item.link.source !== item.link.target);

  const portBuckets = new Map();
  routeItems.forEach(item => {
    const sameColumn = Math.abs(item.from.cx - item.to.cx) < 1;
    item.sourceSide = sameColumn || item.to.cx > item.from.cx ? 'right' : 'left';
    item.targetSide = sameColumn || item.to.cx < item.from.cx ? 'right' : 'left';
    addPortBucket(portBuckets, item, 'source', item.link.source, item.sourceSide, item.to.cy);
    addPortBucket(portBuckets, item, 'target', item.link.target, item.targetSide, item.from.cy);
  });
  allocatePortBuckets(portBuckets);

  const obstacles = Array.from(positions.entries()).map(([key, rect]) => ({ key, ...rect }));

  const occupied = [];
  let unrouted = 0;
  routeItems.forEach(item => {
    const fromPoint = explorerPortPoint(item.from, item.sourceSide, item.sourceSlot, item.sourceTotal, 3);
    const toPoint = explorerPortPoint(item.to, item.targetSide, item.targetSlot, item.targetTotal, 2);
    const points = SableRouting.route(fromPoint, toPoint, obstacles, width, height, item.index, occupied);
    if (!points) { unrouted++; return; }

    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    const focused = selectedExplorerResourceId && (item.link.source === selectedExplorerResourceId || item.link.target === selectedExplorerResourceId);
    const confidenceClass = item.link.confidence === 'inferred' ? 'inferred' : 'confirmed';
    path.setAttribute('d', roundedOrthogonalPath(points, 10));
    path.setAttribute('class', `explorer-link ${confidenceClass} ${focused ? 'focused' : ''}`);
    path.dataset.source = item.link.source;
    path.dataset.target = item.link.target;
    path.dataset.label = item.link.label || 'dependency';
    path.dataset.confidence = item.link.confidence || 'confirmed';
    path.setAttribute('marker-end', focused ? 'url(#explorerFocusArrow)' : 'url(#explorerArrow)');
    const title = document.createElementNS('http://www.w3.org/2000/svg', 'title');
    title.textContent = `${item.link.source} → ${item.link.target} (${item.link.confidence || 'confirmed'}: ${item.link.label || 'dependency'})`;
    path.appendChild(title);
    appendConnectionHalo(svg, path);
    svg.appendChild(path);
  });
  if (unrouted) status.textContent = `${displayedLinks.length - unrouted} of ${links.length} connections drawn. ${unrouted} overlapping routes omitted; relationship evidence remains available. ` + status.textContent.split('. ').slice(1).join('. ');
}

function addPortBucket(buckets, item, role, key, side, sortValue) {
  const bucketKey = `${key}:${side}`;
  if (!buckets.has(bucketKey)) buckets.set(bucketKey, []);
  buckets.get(bucketKey).push({ item, role, sortValue });
}

function allocatePortBuckets(buckets) {
  buckets.forEach(group => {
    group.sort((a, b) => a.sortValue - b.sortValue);
    group.forEach((entry, slot) => {
      entry.item[`${entry.role}Slot`] = slot;
      entry.item[`${entry.role}Total`] = group.length;
    });
  });
}

function explorerPortPoint(node, side, slot = 0, total = 1, gap = 0) {
  const fraction = (slot + 1) / (total + 1);
  const padding = Math.min(18, node.height * 0.18);
  const y = node.top + Math.max(padding, Math.min(node.height - padding, node.height * fraction));
  return {
    x: side === 'right' ? node.right + gap : node.left - gap,
    y,
    side
  };
}

function renderRelationshipList(links, resourceMap) {
  const container = $('#relationshipList');
  const visible = selectedExplorerResourceId
    ? links.filter(link => link.source === selectedExplorerResourceId || link.target === selectedExplorerResourceId)
    : links;
  if (!visible.length) {
    container.innerHTML = '<div class="relationship-empty">No relationships found in the imported evidence for this selection. Cloud context can include clearly labeled inferred relationships.</div>';
    return;
  }
  let limit = 12;
  const draw = () => {
    container.innerHTML = `<p class="relationship-summary">${selectedExplorerResourceId ? 'Selected resource · ' : ''}${visible.length} relationship${visible.length === 1 ? '' : 's'}</p>` + visible.slice(0, limit).map(link => {
      const source = resourceMap.get(link.source);
      const target = resourceMap.get(link.target);
      return `
        <div class="relationship-row" data-source="${escapeHtml(link.source)}" data-target="${escapeHtml(link.target)}" data-label="${escapeHtml(link.label || 'dependency')}" data-confidence="${escapeHtml(link.confidence || 'confirmed')}">
          <span title="${escapeHtml(source?.name || link.source)}">${escapeHtml(source?.name || link.source)}</span>
          <strong aria-hidden="true">→</strong>
          <span title="${escapeHtml(target?.name || link.target)}">${escapeHtml(target?.name || link.target)}</span>
          <small>${escapeHtml(link.label || 'dependency')} · ${escapeHtml(link.confidence || 'confirmed')}</small>
          <button class="relationship-evidence-button" type="button" aria-label="Evidence for ${escapeHtml(source?.name || link.source)} to ${escapeHtml(target?.name || link.target)}">Evidence</button>
        </div>
      `;
    }).join('');
    if (visible.length > limit) {
      const more = document.createElement('button');
      more.type = 'button';
      more.className = 'secondary-button relationship-more';
      more.textContent = `Show more relationships (${visible.length - limit} remaining)`;
      more.addEventListener('click', () => { limit += 24; draw(); });
      container.appendChild(more);
    }
  };
  draw();
}

function renderResourceInspector(resourceMap) {
  const inspector = $('#resourceInspector');
  if (!selectedExplorerResourceId || !resourceMap.has(selectedExplorerResourceId)) {
    const count = resourceMap.size;
    inspector.innerHTML = `
      <strong>Select a resource</strong>
      <span>Click any resource box to inspect its category, risk, and detected relationships. ${count} total resources are available in this workspace.</span>
    `;
    return;
  }
  const resource = resourceMap.get(selectedExplorerResourceId);
  const risk = getResourceRiskSummary(resource);
  const related = buildArchitectureGraph(currentAnalysis.resources).links.filter(link => link.source === selectedExplorerResourceId || link.target === selectedExplorerResourceId);
  inspector.innerHTML = `
    <strong>${escapeHtml(resource.name)}</strong>
    <span>${escapeHtml(resource.type)} · ${escapeHtml(CATEGORY_META[resource.category]?.label || resource.category)}</span>
    <div class="inspector-chips">${renderRiskChips(risk.counts)}</div>
    <p>${related.length ? `${related.length} detected relationship${related.length === 1 ? '' : 's'} connect this resource to the current architecture.` : 'No explicit references were found for this resource yet.'}</p>
  `;
}

function getVisibleCategories(resources) {
  const categories = Array.from(new Set(resources.map(resource => resource.category || 'other')));
  return categories.sort((a, b) => (CATEGORY_META[a]?.order || 99) - (CATEGORY_META[b]?.order || 99));
}

function buildArchitectureGraph(resources) {
  const normalized = (resources || []).map(normalizeResource);
  const resourceMap = new Map(normalized.map(resource => [resourceKey(resource), resource]));
  const confirmed = (currentAnalysis.graph?.links || []).filter(link => resourceMap.has(link.source) && resourceMap.has(link.target));
  const inferred = architectureGraphMode === 'context'
    ? (currentAnalysis.graph?.inferredLinks || []).filter(link => resourceMap.has(link.source) && resourceMap.has(link.target))
    : [];
  let links = [...confirmed, ...inferred];
  if (window.SableFeatures?.filterLinks) links = window.SableFeatures.filterLinks(links);
  return { resources: normalized, resourceMap, links };
}

function getCategoryRelationshipPairs(resources) {
  const graph = buildArchitectureGraph(resources);
  const pairs = new Map();
  graph.links.forEach(link => {
    const source = graph.resourceMap.get(link.source);
    const target = graph.resourceMap.get(link.target);
    if (!source || !target || source.category === target.category) return;
    const key = `${source.category}=>${target.category}:${link.confidence === 'inferred' ? 'inferred' : 'confirmed'}`;
    if (!pairs.has(key)) pairs.set(key, { source: source.category, target: target.category, count: 0, inferred: true });
    const pair = pairs.get(key);
    pair.count += 1;
    if (link.confidence !== 'inferred') pair.inferred = false;
  });
  return Array.from(pairs.values()).sort((a, b) => b.count - a.count);
}

function resourceKey(resource) {
  return String(resource?.id || resource?.address || `${resource?.type}.${resource?.name}`);
}

function formatResourceType(type = '') {
  return String(type).replace(/^aws_/, '').replace(/^azurerm_/, '').replace(/^google_/, '').replace(/^kubernetes_/, '').replace(/_/g, ' ').toUpperCase();
}

function getResourceRiskSummary(resource) {
  const label = resourceKey(resource);
  const findings = currentAnalysis.findings.filter(finding => finding.resource === label);
  const counts = countFindings(findings);
  const order = ['critical', 'high', 'medium', 'low'];
  const maxSeverity = order.find(severity => counts[severity] > 0) || '';
  return { counts, total: findings.length, maxSeverity };
}

function ensureArrowMarker(svg, id, color, size = 8) {
  let defs = svg.querySelector('defs');
  if (!defs) {
    defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
    svg.appendChild(defs);
  }
  if (defs.querySelector(`#${id}`)) return;
  const marker = document.createElementNS('http://www.w3.org/2000/svg', 'marker');
  marker.setAttribute('id', id);
  marker.setAttribute('viewBox', '0 0 10 10');
  marker.setAttribute('refX', '9');
  marker.setAttribute('refY', '5');
  marker.setAttribute('markerWidth', String(size));
  marker.setAttribute('markerHeight', String(size));
  marker.setAttribute('markerUnits', 'userSpaceOnUse');
  marker.setAttribute('orient', 'auto-start-reverse');
  const arrow = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  arrow.setAttribute('d', 'M 1 1 L 9 5 L 1 9 Z');
  arrow.setAttribute('fill', color);
  marker.appendChild(arrow);
  defs.appendChild(marker);
}

let architectureReturnFocus = null;
function toggleArchitectureMaximized(force) {
  const panel = $('#architecturePanel');
  const shouldMaximize = typeof force === 'boolean' ? force : !panel.classList.contains('maximized');
  if (shouldMaximize && !panel.classList.contains('maximized')) architectureReturnFocus = document.activeElement;
  panel.classList.toggle('maximized', shouldMaximize);
  if (shouldMaximize) {
    panel.setAttribute('role', 'dialog');
    panel.setAttribute('aria-modal', 'true');
    panel.setAttribute('aria-label', 'Resource topology');
    $('#maximizeArchitectureBtn')?.focus({ preventScroll: true });
  } else {
    panel.removeAttribute('role');
    panel.removeAttribute('aria-modal');
    panel.removeAttribute('aria-label');
    architectureReturnFocus?.focus?.({ preventScroll: true });
  }
  document.body.classList.toggle('architecture-modal-open', shouldMaximize);
  $('#maximizeArchitectureBtn').textContent = shouldMaximize ? '×' : '⛶';
  $('#maximizeArchitectureBtn').setAttribute('aria-label', shouldMaximize ? 'Minimize architecture view' : 'Maximize architecture view');
  $('#architecturePreviewMaximizeBtn')?.setAttribute('aria-hidden', String(shouldMaximize));
  requestAnimationFrame(() => {
    drawArchitectureConnections();
    renderArchitectureExplorer();
    requestAnimationFrame(() => {
      const viewport = selectedArchitectureCategory ? $('#explorerStage') : $('#architectureCanvas');
      if (shouldMaximize && selectedArchitectureCategory && viewport) {
        viewport.focus?.({ preventScroll: true });
      }
    });
  });
}

function renderFindings() {
  const container = $('#findingList');
  const filter = $('#findingSeverityFilter').value;
  const findings = currentAnalysis.findings.filter(finding => filter === 'all' || finding.severity === filter);
  const hasResources = currentAnalysis.resources.length > 0;
  const emptyText = hasResources
    ? (filter === 'all' ? 'No findings were detected by the built-in controls that apply to this imported scope.' : `No ${filter} findings were detected by the built-in controls that apply to this imported scope.`)
    : 'Import infrastructure to analyze risk.';
  renderFindingList(container, findings, emptyText, hasResources ? 'No findings detected by assessed controls' : 'Nothing to show');
}

function renderFindingList(container, findings, emptyText, emptyTitle = 'Nothing to show') {
  container.innerHTML = '';
  if (!findings.length) {
    container.innerHTML = `<div class="empty-state"><strong>${escapeHtml(emptyTitle)}</strong>${escapeHtml(emptyText)}</div>`;
    return;
  }
  const template = $('#findingTemplate');
  findings.sort(compareFindings).forEach(finding => {
    const node = template.content.cloneNode(true);
    const pill = node.querySelector('.severity-pill');
    pill.textContent = finding.severity;
    pill.classList.add(finding.severity);
    const findingMeta = [finding.ruleId || 'S4BLE rule', finding.resource, finding.confidence || 'confirmed', finding.kind || null, finding.reviewStatus || null].filter(Boolean);
    node.querySelector('.finding-resource').textContent = findingMeta.join(' · ');
    node.querySelector('h3').textContent = finding.title;
    node.querySelector('p').textContent = finding.description;
    const evidence = finding.evidence ? ` Evidence: ${formatEvidence(finding.evidence)}.` : '';
    const limitations = finding.limitations ? ` Limitation: ${finding.limitations}` : '';
    node.querySelector('.recommendation').textContent = `${finding.recommendation}${evidence}${limitations}`;
    const resourceExists = currentAnalysis.resources.some(resource => resourceKey(resource) === finding.resource);
    if (resourceExists) {
      const card = node.querySelector('.finding-card');
      card.dataset.openResource = finding.resource;
      card.tabIndex = 0;
      card.setAttribute('role', 'button');
      card.setAttribute('aria-label', `Open ${finding.resource} in the architecture`);
      card.title = 'Open the affected resource';
    }
    container.appendChild(node);
  });
}

function formatEvidence(evidence) {
  if (!evidence || typeof evidence !== 'object') return String(evidence || '');
  return Object.entries(evidence).map(([key, value]) => `${key}=${typeof value === 'object' ? JSON.stringify(value) : value}`).join(', ');
}

function compareFindings(a, b) {
  const order = { critical: 0, high: 1, medium: 2, low: 3 };
  return order[a.severity] - order[b.severity] || a.title.localeCompare(b.title);
}

function renderResourceTable() {
  const tbody = $('#resourceTableBody');
  const query = $('#resourceSearch').value.toLowerCase().trim();
  const rows = currentAnalysis.resources.filter(resource => {
    const text = `${resource.type} ${resource.name} ${resource.category}`.toLowerCase();
    return !query || text.includes(query);
  });
  tbody.innerHTML = '';
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="4"><div class="empty-state"><strong>No resources</strong>Import infrastructure or change your search.</div></td></tr>';
    return;
  }
  rows.forEach(resource => {
    const riskCount = currentAnalysis.findings.filter(finding => finding.resource === resourceKey(resource)).length;
    const tr = document.createElement('tr');
    tr.dataset.resourceKey = resourceKey(resource);
    tr.tabIndex = 0;
    tr.setAttribute('role', 'button');
    tr.setAttribute('aria-label', `Open ${resource.name} resource details`);
    tr.title = 'Open this resource in the architecture';
    tr.innerHTML = `
      <td class="resource-name-cell"><strong>${escapeHtml(resource.name)}</strong></td>
      <td class="resource-type-cell"><code>${escapeHtml(resource.type)}</code></td>
      <td>${escapeHtml(CATEGORY_META[resource.category]?.label || resource.category)}</td>
      <td>${riskCount ? `${riskCount} findings` : 'No findings'}</td>
    `;
    tbody.appendChild(tr);
  });
}

async function previewImportInput() {
  const text = $('#importInput').value;
  const sequence = ++previewSequence;
  if (!text.trim() && !pendingImportFiles.length) {
    currentPreview = null;
    renderImportPreview();
    return;
  }
  $('#detectedType').textContent = 'Analyzing…';
  try {
    const result = await requestAnalysis(text, pendingImportFiles);
    if (sequence !== previewSequence) return;
    currentPreview = result;
    renderImportPreview();
  } catch (error) {
    if (sequence !== previewSequence) return;
    currentPreview = { error: error.message };
    renderImportPreview();
  }
}

async function analyzeImportInput(navigateToOverview = false) {
  if (importBusy) return;
  const text = $('#importInput').value;
  const sequence = ++importSequence;
  previewSequence++;
  importBusy = true;
  currentPreview = null;
  $('#importStatus').textContent = 'Analyzing your infrastructure…';
  syncPrimaryActions();
  try {
    const result = await requestAnalysis(text, pendingImportFiles);
    if (sequence !== importSequence) return;
    saveWorkspace(result.workspace, result.analysis);
    currentPreview = result;
    renderImportPreview();
    $('#importStatus').textContent = `Analysis complete: ${result.analysis.resources.length} resources.`;
    showToast(`Analyzed ${result.analysis.resources.length} resources.`);
    if (navigateToOverview) navigate('overview');
  } catch (error) {
    if (sequence !== importSequence) return;
    currentPreview = { error: error.message };
    renderImportPreview();
    $('#importStatus').textContent = error.message;
    showToast(error.message);
  } finally { if (sequence === importSequence) { importBusy = false; syncPrimaryActions(); } }
}

function renderImportPreview() {
  const preview = currentPreview;
  if (!preview) {
    const ready = Boolean($('#importInput').value.trim() || pendingImportFiles.length);
    $('#detectedType').textContent = ready ? 'Ready to analyze' : 'No input';
    $('#previewResourceCount').textContent = '0';
    $('#previewFindingCount').textContent = '0';
    $('#previewCategoryCount').textContent = '0';
    $('#jsonPreview').textContent = ready ? 'Select Analyze workspace to process the selected input.' : 'No parsed output yet.';
    updateAccuracyNote(null);
    syncPrimaryActions();
    return;
  }
  if (preview.error) {
    $('#detectedType').textContent = 'Parse error';
    $('#previewResourceCount').textContent = '0';
    $('#previewFindingCount').textContent = '0';
    $('#previewCategoryCount').textContent = '0';
    $('#jsonPreview').textContent = preview.error;
    updateAccuracyNote({ error: preview.error });
    syncPrimaryActions();
    return;
  }
  const analysis = preview.analysis || emptyAnalysis();
  const workspacePreview = preview.workspace || {};
  const mode = analysis.metadata?.analysisMode || workspacePreview.analysisMode || workspacePreview.sourceType || 'detected';
  $('#detectedType').textContent = `${mode} · ${humanizeToken(analysis.metadata?.evidenceLevel || (analysis.metadata?.machineReadable ? 'machine-readable' : 'declaration-only'))}`;
  $('#previewResourceCount').textContent = String(analysis.resources.length);
  $('#previewFindingCount').textContent = String(analysis.findings.length);
  $('#previewCategoryCount').textContent = String(new Set(analysis.resources.map(resource => resource.category)).size);
  $('#jsonPreview').textContent = JSON.stringify({
    workspace: workspacePreview.workspace,
    sourceType: workspacePreview.sourceType,
    analysisMode: mode,
    authoritative: analysis.metadata?.authoritative,
    machineReadable: analysis.metadata?.machineReadable,
    evidenceLevel: analysis.metadata?.evidenceLevel,
    runtimeVerified: analysis.metadata?.runtimeVerified,
    evidenceScore: analysis.score,
    rating: analysis.rating,
    ruleCoverage: analysis.metadata?.coverage,
    diagnostics: analysis.diagnostics,
    resources: analysis.resources,
    relationships: analysis.graph,
    findings: analysis.findings
  }, null, 2);
  updateAccuracyNote(analysis);
  syncPrimaryActions();
}

function updateAccuracyNote(analysis) {
  const note = $('#analysisAccuracyNote');
  if (!note) return;
  if (!analysis) {
    note.textContent = 'For the strongest Terraform evidence, import terraform show -json from a saved plan. Raw .tf, CloudFormation templates, Kubernetes manifests, and snapshots are declaration-level analysis and cannot prove live cloud reachability or runtime state.';
    return;
  }
  if (analysis.error) {
    note.textContent = analysis.error;
    return;
  }
  const level = analysis.metadata?.evidenceLevel || 'declaration-only';
  const coverage = analysis.metadata?.coverage;
  const coverageText = coverage ? ` Built-in rule coverage applies to ${coverage.supportedResources}/${coverage.importedResources} imported resources (${coverage.supportedPercent}%).` : '';
  if (level === 'planned-values') {
    note.textContent = `Evidence mode: Terraform planned values and change actions. This is high-confidence evidence for the supplied plan, but S4BLE does not query the live cloud control plane or organization/account policies.${coverageText}`;
  } else if (level === 'state-snapshot') {
    note.textContent = `Evidence mode: Terraform state snapshot. Values are read from the supplied state, but S4BLE cannot prove the state is current or drift-free without querying the cloud provider.${coverageText}`;
  } else if (level === 'declaration-only') {
    note.textContent = `Evidence mode: declarative source only. Findings are limited to properties explicitly present in the imported source; provider defaults, runtime mutations, remote module internals, and live-state controls are not invented.${coverageText}`;
  } else {
    note.textContent = `Evidence mode: imported snapshot declarations. S4BLE does not independently verify those values against a cloud control plane.${coverageText}`;
  }
}

async function reviewPrRisk() {
  if (reviewBusy) return;
  const text = $('#prInput').value.trim();
  if (!text && !pendingReviewFiles.length) {
    showToast('Paste Terraform source or Terraform plan JSON before reviewing.');
    return;
  }
  const sequence = ++reviewSequence;
  reviewBusy = true;
  $('#reviewStatus').textContent = 'Reviewing infrastructure changes…';
  syncPrimaryActions();
  try {
    const result = await requestAnalysis(text, pendingReviewFiles, '/api/review');
    if (sequence !== reviewSequence) return;
    prReview = {
      findings: result.review?.findings || result.analysis?.findings || [],
      introducedFindings: result.review?.introducedFindings || [],
      existingFindings: result.review?.existingFindings || [],
      resolvedFindings: result.review?.resolvedFindings || [],
      diffs: result.review?.diffs || [],
      baselineResources: result.review?.baselineResources || [],
      counts: result.review?.counts || { add: 0, change: 0, delete: 0 },
      riskScore: result.review?.riskScore ?? 0,
      decision: result.review?.decision || 'Waiting for input',
      analysis: result.analysis || null
    };
    renderPrReview();
    $('#reviewStatus').textContent = 'Review complete. Inspect the findings and change impact below.';
    showToast('PR review completed.');
  } catch (error) {
    if (sequence !== reviewSequence) return;
    $('#reviewStatus').textContent = error.message;
    showToast(error.message);
  } finally { if (sequence === reviewSequence) { reviewBusy = false; syncPrimaryActions(); } }
}

function renderPrReview() {
  $('#approvalDecision').textContent = prReview.decision;
  $('#prRiskScore').textContent = Number.isFinite(prReview.riskScore) ? String(prReview.riskScore) : '—';
  $('#prAddCount').textContent = prReview.counts.add || 0;
  $('#prChangeCount').textContent = prReview.counts.change || 0;
  $('#prDeleteCount').textContent = prReview.counts.delete || 0;
  renderFindingList($('#prFindingList'), prReview.findings || [], prReview.analysis ? 'No findings on the changed resources assessed in this review.' : 'Run a PR review to generate comments.', prReview.analysis ? 'No change-related findings' : 'Nothing to show');
  renderDiffList();
  window.SableFeatures?.renderReviewer?.();
  syncPrimaryActions();
}

function renderDiffList() {
  const container = $('#prDiffList');
  container.innerHTML = '';
  if (!prReview.diffs.length) {
    container.innerHTML = prReview.analysis ? '<div class="empty-state"><strong>No resource changes detected</strong>The reviewed input contains no managed resource changes.</div>' : '<div class="empty-state"><strong>No diff yet</strong>Run a PR review to see resource impact.</div>';
    return;
  }
  prReview.diffs.forEach(diff => {
    const card = document.createElement('article');
    card.className = 'diff-card';
    card.innerHTML = `
      <div>
        <h3>${escapeHtml(diff.resource)}</h3>
        <p>${escapeHtml(diff.description)}</p>
      </div>
      <span class="diff-tag ${diff.action === 'replace' ? 'change' : diff.action}">${escapeHtml(diff.action)}</span>
    `;
    container.appendChild(card);
  });
}

function exportWorkspaceReport() {
  if (!currentAnalysis.resources?.length) {
    showToast('Import infrastructure before exporting a posture report.');
    return;
  }
  const report = buildMarkdownReport('Infrastructure Posture Report', currentAnalysis, workspace);
  downloadFile('sable-health-report.md', report, 'text/markdown');
}

function exportPrReport() {
  if (!prReview.analysis && !prReview.diffs?.length && !prReview.findings?.length) {
    showToast('Run a PR review before exporting the report.');
    return;
  }
  const lines = [
    '# Terraform PR Risk Review',
    '',
    `Decision: **${prReview.decision}**`,
    `Change Risk Score: **${prReview.riskScore}/100**`,
    '',
    '## Change Counts',
    `- Add: ${prReview.counts.add || 0}`,
    `- Change: ${prReview.counts.change || 0}`,
    `- Delete: ${prReview.counts.delete || 0}`,
    '',
    '## Resource Diff',
    ...(prReview.diffs.length ? prReview.diffs.map(diff => `- **${diff.action.toUpperCase()}** ${diff.resource}: ${diff.description}`) : ['No diff detected.']),
    '',
    '## Findings on changed resources',
    ...(prReview.findings.length ? prReview.findings.sort(compareFindings).map(finding => `- **${finding.severity.toUpperCase()}** [${finding.confidence || 'confirmed'}] [${finding.reviewStatus || 'change-related'}] ${finding.ruleId || 'S4BLE'} ${finding.resource}: ${finding.title}: ${finding.recommendation}${finding.limitations ? ` Limitation: ${finding.limitations}` : ''}`) : ['No findings on changed resources.']),
    '',
    `Introduced/newly-detectable findings: **${prReview.introducedFindings?.length || 0}**`,
    `Pre-existing findings on changed resources: **${prReview.existingFindings?.length || 0}**`,
    `Resolved findings: **${prReview.resolvedFindings?.length || 0}**`
  ];
  downloadFile('sable-pr-review.md', lines.join('\n'), 'text/markdown');
}

function buildMarkdownReport(title, analysis, workspaceObj) {
  const lines = [
    `# ${title}`,
    '',
    `Workspace: **${workspaceObj.workspace || 'Unnamed'}**`,
    `Imported: **${workspaceObj.importedAt || 'N/A'}**`,
    `Source: **${workspaceObj.sourceType || 'N/A'}**`,
    '',
    `S4BLE Evidence Score: **${Number.isFinite(analysis.score) ? `${analysis.score}/100` : 'Not rated'}**`,
    `Rating: **${analysis.rating || 'N/A'}**`,
    `Analysis Mode: **${analysis.metadata?.analysisMode || 'N/A'}**`,
    `Evidence Level: **${analysis.metadata?.evidenceLevel || 'N/A'}**`,
    `Runtime Verified: **${analysis.metadata?.runtimeVerified ? 'Yes' : 'No'}**`,
    `Resources: **${analysis.resources.length}**`,
    `Built-in Rule Coverage: **${analysis.metadata?.coverage ? `${analysis.metadata.coverage.supportedResources}/${analysis.metadata.coverage.importedResources} resources (${analysis.metadata.coverage.supportedPercent}%)` : 'N/A'}**`,
    '',
    '## Finding Summary',
    `- Critical: ${analysis.counts.critical || 0}`,
    `- High: ${analysis.counts.high || 0}`,
    `- Medium: ${analysis.counts.medium || 0}`,
    `- Low: ${analysis.counts.low || 0}`,
    '',
    '## Findings',
    ...(analysis.findings.length ? analysis.findings.sort(compareFindings).map(finding => `- **${finding.severity.toUpperCase()}** [${finding.confidence || 'confirmed'}] ${finding.ruleId || 'S4BLE'} ${finding.resource}: ${finding.title}: ${finding.recommendation}${finding.limitations ? ` Limitation: ${finding.limitations}` : ''}`) : ['No findings.']),
    '',
    '## Resource Inventory',
    ...analysis.resources.map(resource => `- ${resource.type}.${resource.name} (${resource.category})`)
  ];
  return lines.join('\n');
}

function downloadNormalizedSnapshot() {
  if (currentPreview?.error) {
    showToast('Fix the import error before downloading a normalized snapshot.');
    return;
  }
  const sourceWorkspace = currentPreview && !currentPreview.error ? currentPreview.workspace : workspace;
  const sourceAnalysis = currentPreview && !currentPreview.error ? currentPreview.analysis : currentAnalysis;
  const resources = sourceAnalysis?.resources || sourceWorkspace?.resources || [];
  if (!resources.length) {
    showToast('Analyze infrastructure before downloading a normalized snapshot.');
    return;
  }
  const snapshot = {
    workspace: sourceWorkspace?.workspace || 'Sable snapshot',
    sourceType: sourceWorkspace?.sourceType || 'normalized',
    analysisMode: sourceAnalysis?.metadata?.analysisMode || sourceWorkspace?.analysisMode,
    resources,
    relationships: sourceAnalysis?.graph?.links || [],
    diagnostics: sourceAnalysis?.diagnostics || []
  };
  downloadFile('sable-normalized-snapshot.json', JSON.stringify(snapshot, null, 2), 'application/json');
}


function createLocalBaselineSnapshot() {
  return {
    workspace: workspace.workspace || 'Baseline',
    savedAt: new Date().toISOString(),
    sourceType: workspace.sourceType || currentAnalysis.metadata?.analysisMode || 'normalized',
    analysisMode: currentAnalysis.metadata?.analysisMode || workspace.analysisMode || 'normalized-snapshot',
    resources: (currentAnalysis.resources || []).map(resource => normalizeResource(resource)),
    relationships: (currentAnalysis.graph?.links || []).map(link => ({ ...link })),
    explicitLinks: (currentAnalysis.graph?.links || []).map(link => ({ ...link }))
  };
}

function syncPrimaryActions() {
  const hasWorkspace = Boolean(currentAnalysis.resources?.length);
  const importText = $('#importInput')?.value?.trim() || '';
  const reviewText = $('#prInput')?.value?.trim() || '';
  const hasImportInput = Boolean(importText || pendingImportFiles.length);
  const hasReviewInput = Boolean(reviewText || pendingReviewFiles.length);
  const validPreview = Boolean(currentPreview && !currentPreview.error && currentPreview.analysis?.resources?.length);

  if ($('#exportMarkdownBtn')) $('#exportMarkdownBtn').disabled = !hasWorkspace;
  if ($('#setBaselineBtn')) $('#setBaselineBtn').disabled = !hasWorkspace;
  if ($('#reviewPrBtn')) $('#reviewPrBtn').disabled = !hasReviewInput || reviewBusy;
  if ($('#reviewPrBtn')) $('#reviewPrBtn').textContent = reviewBusy ? 'Reviewing…' : 'Review PR risk';
  if ($('#exportPrReportBtn')) $('#exportPrReportBtn').disabled = !(prReview.analysis || prReview.diffs?.length || prReview.findings?.length);
  if ($('#analyzeImportBtn')) $('#analyzeImportBtn').disabled = !hasImportInput || importBusy;
  if ($('#analyzeImportBtn')) $('#analyzeImportBtn').textContent = importBusy ? 'Analyzing…' : 'Analyze workspace';
  if ($('#clearImportBtn')) $('#clearImportBtn').disabled = !hasImportInput && !currentPreview;

  const snapshotBtn = $('#downloadSnapshotBtn');
  if (snapshotBtn) {
    snapshotBtn.disabled = Boolean(currentPreview?.error) || (!validPreview && !hasWorkspace);
    snapshotBtn.textContent = validPreview
      ? 'Download analyzed snapshot'
      : hasWorkspace && !currentPreview
        ? 'Download current workspace snapshot'
        : 'Download normalized snapshot';
  }
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

function infrastructureFileFamily(name = '') {
  const lower = String(name).toLowerCase();
  if (lower.endsWith('.tf') || lower.endsWith('.tf.json')) return 'terraform';
  if (lower.endsWith('.yaml') || lower.endsWith('.yml')) return 'yaml';
  if (lower.endsWith('.json')) return 'json';
  return null;
}

function validateInfrastructureFiles(files) {
  if (!files.length) throw new Error('Choose at least one Terraform, JSON, or YAML file.');
  if (files.length > MAX_INFRA_FILES) throw new Error(`A maximum of ${MAX_INFRA_FILES} files can be imported at once.`);

  const unsupported = files.filter(file => !infrastructureFileFamily(file.name));
  if (unsupported.length) {
    throw new Error(`Unsupported file type: ${unsupported.map(file => file.name).join(', ')}. Supported extensions are ${SUPPORTED_INFRA_EXTENSIONS.join(', ')}.`);
  }

  const totalBytes = files.reduce((sum, file) => sum + Number(file.size || 0), 0);
  if (totalBytes > MAX_INFRA_BYTES) throw new Error('The selected files exceed the 7 MB analysis limit. Split the workspace or import Terraform plan/state JSON.');

  const families = new Set(files.map(file => infrastructureFileFamily(file.name)));
  if (families.size > 1) {
    throw new Error('Import one infrastructure format at a time. Select Terraform files together, YAML files together, or one JSON document.');
  }

}

function updateImportFileSummary(files = [], overrideText = '') {
  const summary = $('#importFileSummary');
  if (!summary) return;
  if (overrideText) {
    summary.textContent = overrideText;
    return;
  }
  if (!files.length) {
    summary.textContent = 'No files selected.';
    return;
  }
  const totalBytes = files.reduce((sum, file) => sum + Number(file.size || file.content?.length || 0), 0);
  const sizeLabel = totalBytes >= 1_000_000
    ? `${(totalBytes / 1_000_000).toFixed(1)} MB`
    : `${Math.max(1, Math.round(totalBytes / 1000))} KB`;
  summary.textContent = `${files.length} file${files.length === 1 ? '' : 's'} selected · ${sizeLabel} · ${files.map(file => file.name).join(', ')}`;
}

async function handleFilesSelect(fileList, targetTextarea, callback, context = 'import') {
  const files = Array.from(fileList || []);
  if (!files.length) return;
  if (context === 'review') invalidateReview(); else invalidateImport();
  const readSequence = fileReadSequence[context];
  try {
    validateInfrastructureFiles(files);
    const loaded = await Promise.all(files.map(file => new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve({ name: file.name, content: String(reader.result || ''), size: file.size || 0 });
      reader.onerror = () => reject(new Error(`Could not read ${file.name}.`));
      reader.readAsText(file);
    })));

    if (readSequence !== fileReadSequence[context]) return;
    if (context === 'review') {
      pendingReviewFiles = loaded.map(({ name, content }) => ({ name, content }));
    } else {
      pendingImportFiles = loaded.map(({ name, content }) => ({ name, content }));
      updateImportFileSummary(loaded);
    }

    syncPrimaryActions();
    targetTextarea.value = loaded.length === 1
      ? loaded[0].content
      : loaded.map(file => `# ---- ${file.name} ----\n${file.content}`).join('\n\n');

    syncPrimaryActions();
    if (context === 'import') { currentPreview = null; renderImportPreview(); }
    // Analysis is an explicit action; selecting a file never submits it.
    const picker = context === 'review' ? $('#prFileInput') : $('#fileInput');
    if (picker) picker.value = '';
    showToast(`Loaded ${loaded.length} file${loaded.length === 1 ? '' : 's'} from this device.`);
  } catch (error) {
    if (readSequence !== fileReadSequence[context]) return;
    showToast(error.message);
  }
}

function cryptoId() {
  if (window.crypto?.getRandomValues) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return array[0].toString(16);
  }
  return Math.random().toString(16).slice(2);
}

function debounce(fn, delay) {
  let timeout;
  return (...args) => {
    clearTimeout(timeout);
    timeout = setTimeout(() => fn(...args), delay);
  };
}

function safeParse(value) {
  try { return value ? JSON.parse(value) : null; } catch { return null; }
}

function readLocalValue(key) {
  try { return localStorage.getItem(key); } catch { return null; }
}

function writeLocalValue(key, value) {
  try { localStorage.setItem(key, value); return true; } catch { return false; }
}

function readLocalJson(key) {
  try { return safeParse(localStorage.getItem(key)); } catch { return null; }
}

function writeLocalJson(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#039;', '"': '&quot;'
  }[char]));
}

function showToast(message) {
  const toast = $('#toast');
  toast.textContent = message;
  toast.classList.add('show');
  clearTimeout(showToast.timeout);
  showToast.timeout = setTimeout(() => toast.classList.remove('show'), 2600);
}
