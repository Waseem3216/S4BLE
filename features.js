'use strict';

(() => {
  const VIEW_KEY = 'sable.savedViews.v1';
  const POLICY_KEY = 'sable.policyPack.v1';
  const FEATURE_KEY = 'sable.featureState.v1';
  const NOTES_KEY = 'sable.resourceNotes.v1';

  const state = loadJson(FEATURE_KEY, {
    lens: 'all',
    showConfirmed: true,
    showInferred: true,
    blast: null,
    path: null,
    incident: false
  });

  let lastArchitecture = null;
  let drawerResourceId = null;
  let drawerRelationship = null;
  let searchActiveIndex = -1;
  let policyShowAll = false;
  const POLICY_VISIBLE_LIMIT = 6;
  const VALID_POLICY_OPERATORS = new Set(['exists', 'equals', 'notEquals', 'min', 'max', 'includes']);

  const esc = value => String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');

  function loadJson(key, fallback) {
    try {
      const raw = localStorage.getItem(key);
      return raw ? { ...fallback, ...JSON.parse(raw) } : { ...fallback };
    } catch {
      return { ...fallback };
    }
  }

  function storageSet(key, value) {
    try {
      localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value));
      return true;
    } catch {
      showToast('This browser could not save the setting locally. Storage may be unavailable or full.');
      return false;
    }
  }

  function storageRemove(key) {
    try { localStorage.removeItem(key); return true; }
    catch { showToast('This browser could not remove the saved setting.'); return false; }
  }

  function saveFeatureState() {
    storageSet(FEATURE_KEY, {
      lens: state.lens,
      showConfirmed: state.showConfirmed,
      showInferred: state.showInferred
    });
  }

  function ensureUi() {
    if (document.querySelector('#ivArchitectureCommandbar')) return;

    const architectureCanvas = document.querySelector('#architectureCanvas');
    if (architectureCanvas) {
      architectureCanvas.insertAdjacentHTML('beforebegin', `
        <div class="iv-commandbar" id="ivArchitectureCommandbar">
          <div class="iv-search-wrap">
            <label class="sr-only" for="ivArchitectureSearch">Search architecture</label>
            <input id="ivArchitectureSearch" class="iv-search" type="search" autocomplete="off" placeholder="Search resources…" aria-describedby="ivSearchHelp" />
            <div class="iv-search-help" id="ivSearchHelp">Try a name or filters such as <code>type:rds</code>, <code>risk:high</code>, or <code>category:network</code>.</div>
            <div class="iv-search-results hidden" id="ivSearchResults" role="listbox" aria-label="Architecture search results"></div>
          </div>
          <label class="iv-field-inline">Lens
            <select id="ivLensSelect" class="iv-select">
              <option value="all">Architecture</option>
              <option value="network">Network</option>
              <option value="security">Security</option>
              <option value="reliability">Reliability</option>
              <option value="observability">Observability</option>
              <option value="changes">Changes</option>
            </select>
          </label>
          <div class="iv-confidence" role="group" aria-label="Relationship confidence filters">
            <label><input id="ivConfirmedToggle" type="checkbox" checked /> Confirmed <span id="ivConfirmedCount"></span></label>
            <label><input id="ivInferredToggle" type="checkbox" checked /> Inferred <span id="ivInferredCount"></span></label>
          </div>
          <label class="iv-field-inline iv-saved-view-field">View
            <select id="ivSavedViewSelect" class="iv-select"><option value="">Saved views</option></select>
          </label>
          <details class="iv-tools-menu">
            <summary>Tools</summary>
            <div class="iv-tools-popover">
              <button type="button" data-iv-action="path">Find path</button>
              <button type="button" data-iv-action="blast">Blast radius</button>
              <button type="button" data-iv-action="incident">Incident view</button>
              <button type="button" data-iv-action="save-view">Save current view</button>
              <button type="button" data-iv-action="delete-view">Delete selected view</button>
              <button type="button" data-iv-action="export-view">Export architecture report</button>
              <button type="button" data-iv-action="clear-focus">Clear highlights</button>
            </div>
          </details>
          <div class="iv-command-status" id="ivCommandStatus" aria-live="polite"></div>
        </div>
      `);
    }

    const workspaceBanner = document.querySelector('#workspaceBanner');
    if (workspaceBanner) {
      workspaceBanner.insertAdjacentHTML('afterend', `
        <section class="panel iv-coverage-panel" id="ivCoveragePanel">
          <div class="panel-header compact">
            <div>
              <p class="eyebrow">Analysis coverage</p>
              <h2>What Sable knows from this import</h2>
            </div>
            <div class="panel-actions iv-baseline-actions">
              <span class="iv-baseline-status" id="ivBaselineStatus">No baseline saved</span>
              <button type="button" class="secondary-button" id="ivSetBaselineBtn">Save baseline</button>
              <button type="button" class="secondary-button" id="ivCompareBaselineBtn">Compare</button>
              <button type="button" class="ghost-button" id="ivClearBaselineBtn">Clear</button>
            </div>
          </div>
          <div class="iv-coverage-summary" id="ivCoverageSummary"></div>
          <details class="iv-coverage-details" id="ivCoverageDetails">
            <summary>View full coverage and parser diagnostics</summary>
            <div class="iv-coverage-grid" id="ivCoverageGrid"></div>
            <div class="iv-diagnostics">
              <div id="ivDiagnosticsList"></div>
            </div>
          </details>
        </section>
      `);
    }

    const overviewPage = document.querySelector('#overviewPage');
    if (overviewPage) {
      overviewPage.insertAdjacentHTML('beforeend', `
        <section class="panel iv-policy-panel" id="ivPolicyPanel">
          <div class="panel-header compact">
            <div>
              <p class="eyebrow">Local guardrails</p>
              <h2>Custom policy pack</h2>
            </div>
            <div class="panel-actions">
              <label class="file-button">Import JSON policy<input id="ivPolicyFile" type="file" accept=".json,application/json" /></label>
              <button class="ghost-button" type="button" id="ivClearPolicyBtn">Clear</button>
            </div>
          </div>
          <div class="iv-policy-summary" id="ivPolicySummary">No local policy pack loaded. Custom policies stay only in this browser.</div>
          <div class="iv-policy-results" id="ivPolicyResults"></div>
        </section>
      `);
    }

    const reviewerPage = document.querySelector('#reviewerPage');
    if (reviewerPage) {
      reviewerPage.insertAdjacentHTML('beforeend', `
        <section class="panel iv-pr-architecture-panel" id="ivPrArchitecturePanel">
          <div class="panel-header compact">
            <div>
              <p class="eyebrow">Architecture impact</p>
              <h2>Before / proposed / overlay</h2>
            </div>
            <div class="iv-pr-controls">
              <label class="iv-check-inline"><input type="checkbox" id="ivPrChangedOnly" checked /> Changes only</label>
              <div class="iv-segmented" role="group" aria-label="Architecture diff view">
                <button type="button" data-pr-view="current">Current</button>
                <button type="button" data-pr-view="proposed">Proposed</button>
                <button type="button" data-pr-view="overlay" class="active">Overlay</button>
              </div>
            </div>
          </div>
          <div class="iv-pr-impact-summary" id="ivPrArchitectureSummary"></div>
          <div class="iv-pr-architecture" id="ivPrArchitecture"></div>
        </section>
      `);
    }

    document.body.insertAdjacentHTML('beforeend', `
      <div class="iv-drawer-backdrop hidden" id="ivDrawerBackdrop"></div>
      <aside class="iv-drawer" id="ivDetailsDrawer" aria-label="Infrastructure details" aria-hidden="true">
        <div class="iv-drawer-header">
          <div>
            <p class="eyebrow" id="ivDrawerEyebrow">Resource details</p>
            <h2 id="ivDrawerTitle">Select a resource</h2>
          </div>
          <button type="button" class="icon-button" id="ivDrawerClose" aria-label="Close details">×</button>
        </div>
        <div class="iv-drawer-tabs" id="ivDrawerTabs">
          <button type="button" data-tab="overview" class="active">Overview</button>
          <button type="button" data-tab="relationships">Relationships</button>
          <button type="button" data-tab="configuration">Configuration</button>
          <button type="button" data-tab="findings">Findings</button>
          <button type="button" data-tab="evidence">Evidence</button>
        </div>
        <div class="iv-drawer-body" id="ivDrawerBody"></div>
      </aside>

      <div class="iv-modal-backdrop hidden" id="ivModalBackdrop"></div>
      <section class="iv-modal hidden" id="ivModal" role="dialog" aria-modal="true" aria-labelledby="ivModalTitle">
        <div class="iv-modal-header">
          <h2 id="ivModalTitle">Sable tool</h2>
          <button type="button" class="icon-button" id="ivModalClose" aria-label="Close dialog">×</button>
        </div>
        <div class="iv-modal-body" id="ivModalBody"></div>
      </section>
    `);

    bindUi();
    refreshSavedViews();
    syncControls();
  }

  function bindUi() {
    const search = document.querySelector('#ivArchitectureSearch');
    search?.addEventListener('input', () => renderSearchResults(search.value));
    search?.addEventListener('keydown', event => {
      const options = Array.from(document.querySelectorAll('#ivSearchResults [data-resource-id]'));
      if (event.key === 'Escape') { closeSearchResults(); return; }
      if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
        if (!options.length) return;
        event.preventDefault();
        const delta = event.key === 'ArrowDown' ? 1 : -1;
        searchActiveIndex = (searchActiveIndex + delta + options.length) % options.length;
        options.forEach((item, index) => item.classList.toggle('active', index === searchActiveIndex));
        options[searchActiveIndex]?.scrollIntoView({ block: 'nearest' });
        return;
      }
      if (event.key === 'Enter') {
        event.preventDefault();
        const choice = options[searchActiveIndex] || options[0];
        if (choice) choice.click();
      }
    });

    document.querySelector('#ivLensSelect')?.addEventListener('change', event => {
      state.lens = event.target.value;
      saveFeatureState();
      applyVisualState();
      syncControls();
    });
    document.querySelector('#ivConfirmedToggle')?.addEventListener('change', event => {
      state.showConfirmed = event.target.checked;
      if (!state.showConfirmed && !state.showInferred) state.showInferred = true;
      syncControls();
      saveFeatureState();
      renderArchitecture();
    });
    document.querySelector('#ivInferredToggle')?.addEventListener('change', event => {
      state.showInferred = event.target.checked;
      if (!state.showConfirmed && !state.showInferred) state.showConfirmed = true;
      syncControls();
      saveFeatureState();
      renderArchitecture();
    });
    document.querySelector('#ivSavedViewSelect')?.addEventListener('change', event => {
      if (event.target.value) loadSavedView(event.target.value);
      else syncControls();
    });

    document.querySelector('#ivArchitectureCommandbar')?.addEventListener('click', event => {
      const button = event.target.closest('[data-iv-action]');
      if (!button) return;
      const action = button.dataset.ivAction;
      document.querySelector('.iv-tools-menu')?.removeAttribute('open');
      if (action === 'path') openPathModal();
      if (action === 'blast') selectedExplorerResourceId ? runBlastRadius(selectedExplorerResourceId, false) : openImpactPicker(false);
      if (action === 'incident') selectedExplorerResourceId ? runBlastRadius(selectedExplorerResourceId, true) : openImpactPicker(true);
      if (action === 'save-view') openSaveViewModal();
      if (action === 'delete-view') deleteSelectedView();
      if (action === 'export-view') exportArchitectureReport();
      if (action === 'clear-focus') clearGraphFocus();
    });

    document.addEventListener('click', event => {
      const result = event.target.closest('#ivSearchResults [data-resource-id]');
      if (result) {
        focusResource(result.dataset.resourceId, true);
        closeSearchResults();
        return;
      }
      const resourceNode = event.target.closest('.resource-map-node[data-resource-key]');
      if (resourceNode) {
        drawerRelationship = null;
        openResourceDrawer(resourceNode.dataset.resourceKey);
        return;
      }
      const tableRow = event.target.closest('#resourceTableBody tr[data-resource-key]');
      if (tableRow) {
        focusResource(tableRow.dataset.resourceKey, true);
        return;
      }
      const genericResource = event.target.closest('[data-open-resource]');
      if (genericResource) {
        focusResource(genericResource.dataset.openResource, true);
        closeModal();
        return;
      }
      const prResource = event.target.closest('[data-pr-resource]');
      if (prResource) {
        openPrResourceModal(prResource.dataset.prResource);
        return;
      }
      const evidenceButton = event.target.closest('.relationship-evidence-button');
      if (evidenceButton) {
        const row = evidenceButton.closest('.relationship-row');
        const link = findLink(row?.dataset.source, row?.dataset.target, row?.dataset.label);
        if (link) openRelationshipDrawer(link);
        return;
      }
      const path = event.target.closest('.explorer-link[data-source]');
      if (path) {
        const link = findLink(path.dataset.source, path.dataset.target, path.dataset.label);
        if (link) openRelationshipDrawer(link);
        return;
      }
      if (!event.target.closest('.iv-search-wrap')) closeSearchResults();
    });

    document.querySelector('#ivDrawerClose')?.addEventListener('click', closeDrawer);
    document.querySelector('#ivDrawerBackdrop')?.addEventListener('click', closeDrawer);
    document.querySelector('#ivDrawerTabs')?.addEventListener('click', event => {
      const button = event.target.closest('[data-tab]');
      if (!button) return;
      document.querySelectorAll('#ivDrawerTabs button').forEach(item => item.classList.toggle('active', item === button));
      renderDrawer(button.dataset.tab);
    });
    document.querySelector('#ivDrawerBody')?.addEventListener('click', event => {
      const action = event.target.closest('[data-drawer-action]')?.dataset.drawerAction;
      if (action === 'blast') runBlastRadius(drawerResourceId, false);
      if (action === 'incident') runBlastRadius(drawerResourceId, true);
      if (action === 'path-from') openPathModal(drawerResourceId, '');
      if (action === 'clear-impact') { clearGraphFocus(); openResourceDrawer(state.blast?.root || drawerResourceId); }
      const relationIndex = event.target.closest('[data-open-relation]')?.dataset.openRelation;
      if (relationIndex != null && drawerResourceId) {
        const links = relatedLinks(drawerResourceId);
        if (links[Number(relationIndex)]) openRelationshipDrawer(links[Number(relationIndex)]);
      }
      if (action === 'save-note' && drawerResourceId) {
        const textarea = document.querySelector('#ivResourceNote');
        const notes = loadResourceNotes();
        const value = String(textarea?.value || '').trim();
        if (value) notes[drawerResourceId] = value; else delete notes[drawerResourceId];
        storageSet(NOTES_KEY, notes);
        showToast(value ? 'Resource note saved locally.' : 'Resource note removed.');
      }
    });

    document.querySelector('#ivModalClose')?.addEventListener('click', closeModal);
    document.querySelector('#ivModalBackdrop')?.addEventListener('click', closeModal);
    document.addEventListener('keydown', event => {
      const row = event.target.closest?.('#resourceTableBody tr[data-resource-key]');
      if (row && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault();
        focusResource(row.dataset.resourceKey, true);
        return;
      }
      const openable = event.target.closest?.('[data-open-resource][role="button"]');
      if (openable && (event.key === 'Enter' || event.key === ' ')) {
        event.preventDefault();
        focusResource(openable.dataset.openResource, true);
        closeModal();
        return;
      }
      if (event.key === 'Escape') {
        if (!document.querySelector('#ivModal')?.classList.contains('hidden')) closeModal();
        else if (document.querySelector('#ivDetailsDrawer')?.classList.contains('open')) closeDrawer();
      }
    });

    document.querySelector('#ivSetBaselineBtn')?.addEventListener('click', saveLocalBaseline);
    document.querySelector('#ivCompareBaselineBtn')?.addEventListener('click', compareLocalBaseline);
    document.querySelector('#ivClearBaselineBtn')?.addEventListener('click', clearLocalBaseline);

    document.querySelector('#ivPolicyFile')?.addEventListener('change', event => importPolicyFile(event.target.files?.[0]));
    document.querySelector('#ivClearPolicyBtn')?.addEventListener('click', () => {
      storageRemove(POLICY_KEY);
      policyShowAll = false;
      renderPolicyPanel();
    });

    document.querySelector('#ivPrArchitecturePanel')?.addEventListener('click', event => {
      const button = event.target.closest('[data-pr-view]');
      if (!button) return;
      document.querySelectorAll('[data-pr-view]').forEach(item => item.classList.toggle('active', item === button));
      renderPrArchitecture(button.dataset.prView);
    });
    document.querySelector('#ivPrChangedOnly')?.addEventListener('change', () => renderPrArchitecture(document.querySelector('[data-pr-view].active')?.dataset.prView || 'overlay'));
    document.querySelector('#ivPolicyResults')?.addEventListener('click', event => {
      const more = event.target.closest('[data-policy-show-all]');
      if (!more) return;
      policyShowAll = !policyShowAll;
      renderPolicyPanel();
    });
  }

  function syncControls() {
    const lens = document.querySelector('#ivLensSelect');
    if (lens) lens.value = state.lens || 'all';
    const confirmed = document.querySelector('#ivConfirmedToggle');
    const inferred = document.querySelector('#ivInferredToggle');
    if (confirmed) confirmed.checked = state.showConfirmed !== false;
    if (inferred) inferred.checked = state.showInferred !== false;
    const confirmedCount = currentAnalysis.graph?.links?.length || 0;
    const inferredCount = currentAnalysis.graph?.inferredLinks?.length || 0;
    const confirmedLabel = document.querySelector('#ivConfirmedCount');
    const inferredLabel = document.querySelector('#ivInferredCount');
    if (confirmedLabel) confirmedLabel.textContent = `(${confirmedCount})`;
    if (inferredLabel) inferredLabel.textContent = `(${inferredCount})`;
    const hasResources = Boolean(currentAnalysis.resources?.length);
    const compare = document.querySelector('#ivCompareBaselineBtn');
    const clear = document.querySelector('#ivClearBaselineBtn');
    const save = document.querySelector('#ivSetBaselineBtn');
    const baseline = readBaseline();
    if (save) save.disabled = !hasResources;
    if (compare) compare.disabled = !hasResources || !baseline?.resources?.length;
    if (clear) clear.disabled = !baseline?.resources?.length;
    document.querySelectorAll('[data-iv-action="save-view"], [data-iv-action="export-view"], [data-iv-action="path"], [data-iv-action="blast"], [data-iv-action="incident"]').forEach(button => { button.disabled = !hasResources; });
    document.querySelector('[data-iv-action="delete-view"]')?.toggleAttribute('disabled', !document.querySelector('#ivSavedViewSelect')?.value);
    document.querySelector('[data-iv-action="clear-focus"]')?.toggleAttribute('disabled', !activeFocusSet());
    updateCommandStatus();
  }

  function updateCommandStatus() {
    const status = document.querySelector('#ivCommandStatus');
    if (!status) return;
    const resources = currentAnalysis.resources || [];
    const visible = resources.filter(matchesLens);
    const lensName = document.querySelector('#ivLensSelect option:checked')?.textContent || 'Architecture';
    const relationships = filterLinks([...(currentAnalysis.graph?.links || []), ...(currentAnalysis.graph?.inferredLinks || [])]).length;
    status.textContent = resources.length
      ? `${lensName}: ${visible.length} of ${resources.length} resources · ${relationships} enabled relationships`
      : 'Import infrastructure to search and explore the architecture.';
  }

  function filterLinks(links) {
    return (links || []).filter(link => {
      const inferred = link.confidence === 'inferred';
      return inferred ? state.showInferred !== false : state.showConfirmed !== false;
    });
  }

  function renderAllFeatures() {
    ensureUi();
    renderCoverage();
    renderPolicyPanel();
    refreshSavedViews();
    renderPrArchitecture(document.querySelector('[data-pr-view].active')?.dataset.prView || 'overlay');
    syncControls();
    window.requestAnimationFrame(applyVisualState);
  }

  function afterArchitectureRender(payload) {
    ensureUi();
    lastArchitecture = payload;
    bindMinimapScroll();
    renderMinimap(payload);
    applyVisualState();
  }

  function applyVisualState() {
    const resources = new Map((currentAnalysis.resources || []).map(resource => [resourceKey(resource), resource]));
    document.querySelectorAll('.resource-map-node[data-resource-key]').forEach(node => {
      const id = node.dataset.resourceKey;
      const resource = resources.get(id);
      const lensMatch = resource ? matchesLens(resource) : true;
      const focusMatch = focusIncludes(id);
      node.classList.toggle('iv-lens-dim', !lensMatch);
      node.classList.toggle('iv-focus-dim', Boolean(activeFocusSet()) && !focusMatch);
      node.classList.toggle('iv-focus-hit', Boolean(activeFocusSet()) && focusMatch);
    });
    document.querySelectorAll('.explorer-link[data-source]').forEach(path => {
      const source = path.dataset.source;
      const target = path.dataset.target;
      const sourceResource = resources.get(source);
      const targetResource = resources.get(target);
      const lensMatch = (sourceResource && matchesLens(sourceResource)) || (targetResource && matchesLens(targetResource));
      const focusSet = activeFocusSet();
      const focusEdge = focusSet && focusSet.has(source) && focusSet.has(target);
      path.classList.toggle('iv-lens-dim', !lensMatch);
      path.classList.toggle('iv-focus-dim', Boolean(focusSet) && !focusEdge);
      path.classList.toggle('iv-focus-hit', Boolean(focusSet) && focusEdge);
    });
    renderFocusBanner();
  }

  function matchesLens(resource) {
    const lens = state.lens || 'all';
    if (lens === 'all') return true;
    if (lens === 'network') return resource.category === 'network';
    if (lens === 'security') return resource.category === 'security' || findingsFor(resourceKey(resource)).some(f => ['critical', 'high'].includes(f.severity));
    if (lens === 'reliability') return ['compute', 'data', 'storage'].includes(resource.category) || findingsFor(resourceKey(resource)).some(f => /backup|multi-az|capacity|availability|reliab/i.test(`${f.title} ${f.description}`));
    if (lens === 'observability') return resource.category === 'observability';
    if (lens === 'changes') return resource.action && resource.action !== 'present';
    return true;
  }

  function renderSearchResults(query) {
    const container = document.querySelector('#ivSearchResults');
    if (!container) return;
    const trimmed = String(query || '').trim();
    searchActiveIndex = -1;
    if (!trimmed) {
      closeSearchResults();
      return;
    }
    const allResults = (currentAnalysis.resources || []).filter(resource => resourceMatchesQuery(resource, trimmed));
    const results = allResults.slice(0, 12);
    container.innerHTML = results.length ? `${results.map(resource => {
      const risk = getResourceRiskSummary(resource);
      const severity = risk.maxSeverity ? `<em class="iv-search-risk ${esc(risk.maxSeverity)}">${esc(risk.maxSeverity)}</em>` : '';
      return `<button type="button" role="option" data-resource-id="${esc(resourceKey(resource))}" aria-label="Open ${esc(resource.name)}">
        <div><strong>${esc(resource.name)}</strong>${severity}</div>
        <span>${esc(resource.type)} · ${esc(CATEGORY_META[resource.category]?.label || resource.category)}${resource.action && resource.action !== 'present' ? ` · ${esc(resource.action)}` : ''}</span>
      </button>`;
    }).join('')}${allResults.length > results.length ? `<div class="iv-search-count">Showing 12 of ${allResults.length} matches. Refine the search to narrow results.</div>` : ''}` : '<div class="iv-search-empty">No matching resources. Try a broader term or remove a filter.</div>';
    container.classList.remove('hidden');
  }

  function resourceMatchesQuery(resource, query) {
    const tokens = query.match(/(?:[^\s"]+|"[^"]*")+/g) || [];
    const findings = findingsFor(resourceKey(resource));
    return tokens.every(rawToken => {
      const token = rawToken.replace(/^"|"$/g, '');
      const sep = token.indexOf(':');
      if (sep > 0) {
        const field = token.slice(0, sep).toLowerCase();
        const value = token.slice(sep + 1).toLowerCase();
        if (field === 'type') return resource.type.toLowerCase().includes(value);
        if (field === 'category') return String(resource.category).toLowerCase().includes(value) || String(CATEGORY_META[resource.category]?.label || '').toLowerCase().includes(value);
        if (field === 'provider') return String(resource.provider).toLowerCase().includes(value);
        if (field === 'name') return String(resource.name).toLowerCase().includes(value);
        if (field === 'risk') return findings.some(f => f.severity === value);
        if (field === 'changed') return (value === 'true') === Boolean(resource.action && resource.action !== 'present');
      }
      const haystack = `${resource.name} ${resource.type} ${resource.provider} ${resource.category} ${resource.address || ''}`.toLowerCase();
      return haystack.includes(token.toLowerCase());
    });
  }

  function closeSearchResults() {
    searchActiveIndex = -1;
    document.querySelector('#ivSearchResults')?.classList.add('hidden');
  }

  function focusResource(id, openDrawer = false) {
    const resource = (currentAnalysis.resources || []).find(item => resourceKey(item) === id);
    if (!resource) return;
    selectedArchitectureCategory = resource.category || 'other';
    architectureGraphMode = 'context';
    selectedExplorerResourceId = id;
    renderArchitecture();
    window.requestAnimationFrame(() => {
      centerNode(id);
      if (openDrawer) openResourceDrawer(id);
    });
  }

  function centerNode(id) {
    const node = Array.from(document.querySelectorAll('.resource-map-node[data-resource-key]')).find(item => item.dataset.resourceKey === id);
    const stage = document.querySelector('#explorerStage');
    if (!node || !stage) return;
    stage.scrollLeft = Math.max(0, node.offsetLeft + node.offsetWidth / 2 - stage.clientWidth / 2);
    stage.scrollTop = Math.max(0, node.offsetTop + node.offsetHeight / 2 - stage.clientHeight / 2);
    node.focus({ preventScroll: true });
    updateMinimapViewport();
  }

  function findLink(source, target, label = '') {
    const all = [...(currentAnalysis.graph?.links || []), ...(currentAnalysis.graph?.inferredLinks || [])];
    return all.find(link => link.source === source && link.target === target && (!label || link.label === label)) || all.find(link => link.source === source && link.target === target);
  }

  function relatedLinks(id) {
    return filterLinks([...(currentAnalysis.graph?.links || []), ...(currentAnalysis.graph?.inferredLinks || [])]).filter(link => link.source === id || link.target === id);
  }

  function setDrawerMode(mode) {
    const tabs = document.querySelector('#ivDrawerTabs');
    if (tabs) tabs.classList.toggle('hidden', mode === 'relationship');
  }

  function openResourceDrawer(id) {
    drawerResourceId = id;
    drawerRelationship = null;
    const resource = (currentAnalysis.resources || []).find(item => resourceKey(item) === id);
    if (!resource) return;
    setDrawerMode('resource');
    openDrawer();
    document.querySelector('#ivDrawerEyebrow').textContent = 'Resource details';
    document.querySelector('#ivDrawerTitle').textContent = resource.name;
    document.querySelectorAll('#ivDrawerTabs button').forEach(button => button.classList.toggle('active', button.dataset.tab === 'overview'));
    renderDrawer('overview');
  }

  function openRelationshipDrawer(link) {
    drawerRelationship = link;
    drawerResourceId = null;
    setDrawerMode('relationship');
    openDrawer();
    const source = getResource(link.source);
    const target = getResource(link.target);
    document.querySelector('#ivDrawerEyebrow').textContent = 'Relationship evidence';
    document.querySelector('#ivDrawerTitle').textContent = `${source?.name || link.source} → ${target?.name || link.target}`;
    renderDrawer('evidence');
  }

  function openDrawer() {
    document.querySelector('#ivDetailsDrawer')?.classList.add('open');
    document.querySelector('#ivDetailsDrawer')?.setAttribute('aria-hidden', 'false');
    document.querySelector('#ivDrawerBackdrop')?.classList.remove('hidden');
  }

  function closeDrawer() {
    document.querySelector('#ivDetailsDrawer')?.classList.remove('open');
    document.querySelector('#ivDetailsDrawer')?.setAttribute('aria-hidden', 'true');
    document.querySelector('#ivDrawerBackdrop')?.classList.add('hidden');
    setDrawerMode('resource');
  }

  function renderDrawer(tab = 'overview') {
    const body = document.querySelector('#ivDrawerBody');
    if (!body) return;
    if (drawerRelationship) {
      body.innerHTML = renderRelationshipEvidence(drawerRelationship);
      return;
    }
    const resource = getResource(drawerResourceId);
    if (!resource) {
      body.innerHTML = '<div class="iv-empty">Select a resource from the architecture.</div>';
      return;
    }
    if (tab === 'overview') body.innerHTML = renderResourceOverview(resource);
    if (tab === 'relationships') body.innerHTML = renderResourceRelationships(resource);
    if (tab === 'configuration') body.innerHTML = `<pre class="iv-config">${esc(JSON.stringify(resource.attributes || {}, null, 2))}</pre>`;
    if (tab === 'findings') body.innerHTML = renderResourceFindings(resource);
    if (tab === 'evidence') body.innerHTML = renderResourceEvidence(resource);
  }

  function renderResourceOverview(resource) {
    const ownership = extractOwnership(resource);
    const risk = getResourceRiskSummary(resource);
    const links = relatedLinks(resourceKey(resource));
    return `
      <div class="iv-detail-grid">
        ${detail('Type', resource.type)}
        ${detail('Provider', resource.provider)}
        ${detail('Category', CATEGORY_META[resource.category]?.label || resource.category)}
        ${detail('Action', resource.action || 'present')}
        ${detail('Findings', risk.total)}
        ${detail('Relationships', links.length)}
      </div>
      <section class="iv-drawer-section">
        <h3>Ownership and context</h3>
        ${Object.keys(ownership).length ? `<div class="iv-detail-list">${Object.entries(ownership).map(([key, value]) => detail(key, value)).join('')}</div>` : '<p>No owner/team/service metadata was found in imported tags or labels.</p>'}
      </section>
      <section class="iv-drawer-section">
        <h3>Operational actions</h3>
        <div class="iv-drawer-actions">
          <button type="button" class="secondary-button" data-drawer-action="blast">Show blast radius</button>
          <button type="button" class="secondary-button" data-drawer-action="path-from">Find path from here</button>
          <button type="button" class="secondary-button" data-drawer-action="incident">Incident view</button>
        </div>
      </section>
      <section class="iv-drawer-section">
        <h3>Local note</h3>
        <textarea id="ivResourceNote" class="iv-note" maxlength="2000" placeholder="Add a local architecture note for this resource...">${esc(loadResourceNotes()[resourceKey(resource)] || '')}</textarea>
        <div class="iv-drawer-actions"><button type="button" class="secondary-button" data-drawer-action="save-note">Save local note</button></div>
        <p>This note is stored only in this browser and is included in exported architecture reports.</p>
      </section>`;
  }

  function loadResourceNotes() {
    try { return JSON.parse(localStorage.getItem(NOTES_KEY) || '{}') || {}; } catch { return {}; }
  }

  function renderResourceRelationships(resource) {
    const id = resourceKey(resource);
    const links = relatedLinks(id);
    if (!links.length) return '<div class="iv-empty">No relationships are available under the current confidence filters.</div>';
    return `<div class="iv-drawer-list">${links.map((link, index) => {
      const source = getResource(link.source);
      const target = getResource(link.target);
      return `<button type="button" class="iv-relation-card" data-open-relation="${index}">
        <span>${esc(source?.name || link.source)}</span><strong>→</strong><span>${esc(target?.name || link.target)}</span>
        <small>${esc(link.label || 'dependency')} · ${esc(link.confidence || 'confirmed')}</small>
      </button>`;
    }).join('')}</div>`;
  }

  function renderResourceFindings(resource) {
    const findings = findingsFor(resourceKey(resource));
    if (!findings.length) return '<div class="iv-empty">No findings detected for this resource in the imported scope.</div>';
    return `<div class="iv-drawer-list">${findings.map(finding => `
      <article class="iv-finding-detail">
        <div><span class="severity-pill ${esc(finding.severity)}">${esc(finding.severity)}</span><small>${esc(finding.confidence || 'confirmed')}</small></div>
        <h3>${esc(finding.title)}</h3>
        <p>${esc(finding.description)}</p>
        <strong>Recommendation</strong><p>${esc(finding.recommendation)}</p>
        <div class="iv-control-context"><span>Control context, not certification:</span>${controlContext(finding).map(item => `<em>${esc(item)}</em>`).join('')}</div>
      </article>`).join('')}</div>`;
  }

  function renderResourceEvidence(resource) {
    const links = relatedLinks(resourceKey(resource));
    return `
      <section class="iv-drawer-section"><h3>Resource source</h3><pre class="iv-config">${esc(JSON.stringify(resource.source || {}, null, 2))}</pre></section>
      <section class="iv-drawer-section"><h3>Relationship evidence</h3>
        ${links.length ? links.map(link => renderRelationshipEvidence(link, true)).join('') : '<p>No relationship evidence is available under the current filters.</p>'}
      </section>`;
  }

  function renderRelationshipEvidence(link, compact = false) {
    const source = getResource(link.source);
    const target = getResource(link.target);
    return `<article class="iv-evidence-card ${compact ? 'compact' : ''}">
      <div class="iv-evidence-route"><button type="button" data-open-resource="${esc(link.source)}">${esc(source?.name || link.source)}</button><strong>→</strong><button type="button" data-open-resource="${esc(link.target)}">${esc(target?.name || link.target)}</button></div>
      <div class="iv-detail-grid">
        ${detail('Confidence', link.confidence || 'confirmed')}
        ${detail('Relationship', link.label || 'dependency')}
      </div>
      <h3>Why this connection exists</h3>
      <pre class="iv-config">${esc(JSON.stringify(link.evidence || { source: 'Imported relationship evidence' }, null, 2))}</pre>
      <div class="iv-drawer-actions iv-evidence-actions">
        <button type="button" class="secondary-button" data-open-resource="${esc(link.source)}">Open source resource</button>
        <button type="button" class="secondary-button" data-open-resource="${esc(link.target)}">Open target resource</button>
      </div>
      <p class="iv-muted">Confirmed relationships originate from declared/imported references. Inferred relationships are explicitly marked and are never presented as confirmed facts.</p>
    </article>`;
  }

  function detail(label, value) {
    return `<div class="iv-detail"><span>${esc(label)}</span><strong>${esc(value ?? 'Unknown')}</strong></div>`;
  }

  function getResource(id) {
    return (currentAnalysis.resources || []).find(resource => resourceKey(resource) === id);
  }

  function findingsFor(id) {
    return (currentAnalysis.findings || []).filter(finding => finding.resource === id);
  }

  function extractOwnership(resource) {
    const attrs = resource.attributes || {};
    const flattened = {};
    const candidates = [attrs.tags, attrs.labels, attrs.metadata?.labels];
    if (Array.isArray(attrs.Tags)) {
      const tags = {};
      attrs.Tags.forEach(item => { if (item?.Key) tags[item.Key] = item.Value; });
      candidates.push(tags);
    }
    candidates.filter(Boolean).forEach(obj => {
      if (typeof obj !== 'object' || Array.isArray(obj)) return;
      Object.entries(obj).forEach(([key, value]) => { flattened[key.toLowerCase().replace(/[^a-z0-9]/g, '')] = value; });
    });
    const mapping = {
      Owner: ['owner', 'ownedby'], Team: ['team', 'squad'], Service: ['service', 'application', 'app'],
      Environment: ['environment', 'env'], Repository: ['repository', 'repo'], 'Cost center': ['costcenter'], 'On-call': ['oncall', 'oncallteam']
    };
    const out = {};
    Object.entries(mapping).forEach(([label, keys]) => {
      const key = keys.find(candidate => flattened[candidate] != null);
      if (key) out[label] = flattened[key];
    });
    return out;
  }

  function controlContext(finding) {
    const text = `${finding.title} ${finding.description}`.toLowerCase();
    const out = [];
    if (/iam|permission|privilege/.test(text)) out.push('AWS Well-Architected: Security / Identity management');
    if (/encrypt|kms|secret/.test(text)) out.push('AWS Well-Architected: Security / Data protection');
    if (/backup|multi-az|availability|capacity/.test(text)) out.push('AWS Well-Architected: Reliability');
    if (/public|internet|firewall|security group|nsg/.test(text)) out.push('CIS-style network exposure control');
    if (!out.length) out.push('Sable operational guardrail');
    return out;
  }

  function openImpactPicker(incident = false) {
    const resources = currentAnalysis.resources || [];
    if (!resources.length) {
      showToast('Import infrastructure before running dependency impact analysis.');
      return;
    }
    const modeLabel = incident ? 'Incident view' : 'Blast radius';
    openModal(`Choose resource for ${modeLabel.toLowerCase()}`, `
      <form id="ivImpactForm" class="iv-form-stack">
        <label>Resource<select id="ivImpactResource">${resourceOptions(resources, selectedExplorerResourceId || '')}</select></label>
        <p class="iv-form-help">Sable follows the currently enabled confirmed/inferred relationships. This is dependency analysis, not a runtime outage prediction.</p>
        <div class="iv-modal-actions"><button type="button" class="secondary-button" data-modal-close>Cancel</button><button type="submit" class="primary-button">Run ${modeLabel}</button></div>
      </form>`);
    document.querySelector('[data-modal-close]')?.addEventListener('click', closeModal);
    document.querySelector('#ivImpactForm')?.addEventListener('submit', event => {
      event.preventDefault();
      const id = document.querySelector('#ivImpactResource')?.value;
      closeModal();
      runBlastRadius(id, incident);
    });
  }

  function runBlastRadius(id = selectedExplorerResourceId, incident = false) {
    if (!id || !getResource(id)) {
      openImpactPicker(incident);
      return;
    }
    const graph = graphForAnalysis();
    const downstream = walkGraph(id, graph.links, false);
    const upstream = walkGraph(id, graph.links, true);
    const all = new Set([id, ...downstream, ...upstream]);
    state.path = null;
    const byName = (a, b) => (getResource(a)?.name || a).localeCompare(getResource(b)?.name || b);
    state.blast = { root: id, upstream: Array.from(upstream).sort(byName), downstream: Array.from(downstream).sort(byName), all: Array.from(all).sort(byName) };
    state.incident = Boolean(incident);
    focusResource(id, true);
    window.requestAnimationFrame(() => {
      applyVisualState();
      renderBlastSummary();
    });
  }

  function walkGraph(start, links, reverse) {
    const adjacency = new Map();
    links.forEach(link => {
      const from = reverse ? link.target : link.source;
      const to = reverse ? link.source : link.target;
      if (!adjacency.has(from)) adjacency.set(from, []);
      adjacency.get(from).push(to);
    });
    const visited = new Set();
    const queue = [start];
    while (queue.length) {
      const current = queue.shift();
      for (const next of adjacency.get(current) || []) {
        if (next === start || visited.has(next)) continue;
        visited.add(next);
        queue.push(next);
      }
    }
    return visited;
  }

  function renderBlastSummary() {
    if (!state.blast) return;
    const root = getResource(state.blast.root);
    const body = document.querySelector('#ivDrawerBody');
    if (!body || !root) return;
    document.querySelector('#ivDrawerEyebrow').textContent = state.incident ? 'Incident view' : 'Blast radius';
    document.querySelector('#ivDrawerTitle').textContent = root.name;
    const impactFindings = (currentAnalysis.findings || []).filter(finding => state.blast.all.includes(finding.resource));
    const highRisk = impactFindings.filter(finding => ['critical', 'high'].includes(finding.severity)).length;
    const categories = new Set(state.blast.all.map(id => getResource(id)?.category).filter(Boolean));
    body.innerHTML = `
      <div class="iv-impact-summary ${state.incident ? 'incident' : ''}">
        <strong>${state.blast.all.length}</strong><span>resources in the dependency impact set</span>
      </div>
      <div class="iv-detail-grid">${detail('Upstream', state.blast.upstream.length)}${detail('Downstream', state.blast.downstream.length)}${detail('Direct links', relatedLinks(state.blast.root).length)}${detail('Categories', categories.size)}${detail('High / critical findings', highRisk)}${detail('Mode', state.incident ? 'Incident' : 'Blast radius')}</div>
      <section class="iv-drawer-section"><h3>Upstream dependencies</h3><p>Resources that can lead into the selected resource through the enabled relationship graph.</p>${resourceLinkList(state.blast.upstream)}</section>
      <section class="iv-drawer-section"><h3>Downstream dependencies</h3><p>Resources reachable from the selected resource through the enabled relationship graph.</p>${resourceLinkList(state.blast.downstream)}</section>
      <div class="iv-drawer-actions"><button type="button" class="secondary-button" data-drawer-action="clear-impact">Clear impact focus</button></div>
      <p class="iv-muted">Impact is calculated from the currently enabled confirmed/inferred relationship set. It is not a runtime outage prediction.</p>`;
  }

  function resourceLinkList(ids) {
    if (!ids.length) return '<p>None found.</p>';
    return `<div class="iv-chip-list">${ids.map(id => `<button type="button" data-open-resource="${esc(id)}">${esc(getResource(id)?.name || id)}</button>`).join('')}</div>`;
  }

  function graphForAnalysis() {
    const links = filterLinks([...(currentAnalysis.graph?.links || []), ...(currentAnalysis.graph?.inferredLinks || [])]);
    return { resources: currentAnalysis.resources || [], links };
  }

  function openPathModal(defaultSource = selectedExplorerResourceId || '', defaultTarget = '') {
    const resources = currentAnalysis.resources || [];
    if (!resources.length) {
      showToast('Import infrastructure before finding a path.');
      return;
    }
    const sourceDefault = defaultSource || resourceKey(resources[0]);
    const targetDefault = defaultTarget || resourceKey(resources.find(resource => resourceKey(resource) !== sourceDefault) || resources[0]);
    openModal('Find relationship path', `
      <form id="ivPathForm" class="iv-form-stack">
        <div class="iv-path-picker-row">
          <label>From<select id="ivPathSource">${resourceOptions(resources, sourceDefault)}</select></label>
          <button type="button" class="secondary-button iv-swap-button" id="ivSwapPathBtn" aria-label="Swap source and target">⇄ Swap</button>
          <label>To<select id="ivPathTarget">${resourceOptions(resources, targetDefault)}</select></label>
        </div>
        <label class="iv-check"><input type="checkbox" id="ivPathDirected" checked /> Respect relationship direction</label>
        <p class="iv-form-help">The path uses the currently enabled relationship confidence filters: ${state.showConfirmed !== false ? 'confirmed' : ''}${state.showConfirmed !== false && state.showInferred !== false ? ' + ' : ''}${state.showInferred !== false ? 'inferred' : ''}.</p>
        <div class="iv-modal-actions"><button type="button" class="secondary-button" data-modal-close>Cancel</button><button type="submit" class="primary-button">Find path</button></div>
      </form>
      <div id="ivPathResult" aria-live="polite"></div>`);
    document.querySelector('[data-modal-close]')?.addEventListener('click', closeModal);
    document.querySelector('#ivSwapPathBtn')?.addEventListener('click', () => {
      const source = document.querySelector('#ivPathSource');
      const target = document.querySelector('#ivPathTarget');
      if (!source || !target) return;
      [source.value, target.value] = [target.value, source.value];
    });
    document.querySelector('#ivPathForm')?.addEventListener('submit', event => {
      event.preventDefault();
      const source = document.querySelector('#ivPathSource').value;
      const target = document.querySelector('#ivPathTarget').value;
      const directed = document.querySelector('#ivPathDirected').checked;
      const result = shortestPath(source, target, graphForAnalysis().links, directed);
      const output = document.querySelector('#ivPathResult');
      if (!result) {
        state.path = null;
        output.innerHTML = '<div class="iv-empty">No path exists under the current confidence filters. Try enabling inferred relationships or turn off direction if that matches your investigation.</div>';
        applyVisualState();
        return;
      }
      state.blast = null;
      state.incident = false;
      state.path = { nodes: result.nodes, edges: result.edges, directed };
      const steps = result.nodes.map((id, index) => {
        const edge = result.edges[index];
        const resource = getResource(id);
        return `<div class="iv-path-step"><button type="button" data-path-resource="${esc(id)}"><strong>${esc(resource?.name || id)}</strong><small>${esc(resource?.type || id)}</small></button>${edge ? `<span class="iv-path-edge ${esc(edge.confidence || 'confirmed')}">→ <em>${esc(edge.label || 'dependency')}</em><small>${esc(edge.confidence || 'confirmed')}</small></span>` : ''}</div>`;
      }).join('');
      output.innerHTML = `<div class="iv-path-result"><div class="iv-path-result-header"><strong>${Math.max(0, result.nodes.length - 1)} hop${result.nodes.length - 1 === 1 ? '' : 's'}</strong><span>${directed ? 'Directed path' : 'Direction ignored'}</span></div><div class="iv-path-steps">${steps}</div></div>`;
      output.querySelectorAll('[data-path-resource]').forEach(button => button.addEventListener('click', () => { closeModal(); focusResource(button.dataset.pathResource, true); }));
      focusResource(source, false);
      window.requestAnimationFrame(applyVisualState);
    });
  }

  function resourceOptions(resources, selected) {
    return resources.slice().sort((a,b) => a.name.localeCompare(b.name)).map(resource => `<option value="${esc(resourceKey(resource))}" ${resourceKey(resource) === selected ? 'selected' : ''}>${esc(resource.name)} — ${esc(resource.type)}</option>`).join('');
  }

  function shortestPath(source, target, links, directed = true) {
    if (!source || !target || source === target) return source === target ? { nodes: [source], edges: [] } : null;
    const adjacency = new Map();
    links.forEach(link => {
      if (!adjacency.has(link.source)) adjacency.set(link.source, []);
      adjacency.get(link.source).push({ to: link.target, link });
      if (!directed) {
        if (!adjacency.has(link.target)) adjacency.set(link.target, []);
        adjacency.get(link.target).push({ to: link.source, link });
      }
    });
    const queue = [source];
    const previous = new Map([[source, null]]);
    while (queue.length) {
      const current = queue.shift();
      if (current === target) break;
      for (const edge of adjacency.get(current) || []) {
        if (previous.has(edge.to)) continue;
        previous.set(edge.to, { node: current, link: edge.link });
        queue.push(edge.to);
      }
    }
    if (!previous.has(target)) return null;
    const nodes = [];
    const edges = [];
    let cursor = target;
    while (cursor) {
      nodes.unshift(cursor);
      const entry = previous.get(cursor);
      if (!entry) break;
      edges.unshift(entry.link);
      cursor = entry.node;
    }
    return { nodes, edges };
  }

  function activeFocusSet() {
    if (state.path?.nodes?.length) return new Set(state.path.nodes);
    if (state.blast?.all?.length) return new Set(state.blast.all);
    return null;
  }

  function focusIncludes(id) {
    const set = activeFocusSet();
    return !set || set.has(id);
  }

  function clearGraphFocus() {
    state.path = null;
    state.blast = null;
    state.incident = false;
    applyVisualState();
    renderFocusBanner();
  }

  function renderFocusBanner() {
    let banner = document.querySelector('#ivFocusBanner');
    const commandbar = document.querySelector('#ivArchitectureCommandbar');
    if (!commandbar) return;
    if (!banner) {
      commandbar.insertAdjacentHTML('afterend', '<div class="iv-focus-banner hidden" id="ivFocusBanner"></div>');
      banner = document.querySelector('#ivFocusBanner');
    }
    if (!state.path && !state.blast) {
      banner.classList.add('hidden');
      banner.innerHTML = '';
      return;
    }
    banner.classList.remove('hidden');
    if (state.path) banner.innerHTML = `<strong>Path focus</strong><span>${state.path.nodes.length} resources · ${state.path.nodes.length - 1} hops</span><button type="button" data-clear-focus>Clear</button>`;
    else banner.innerHTML = `<strong>${state.incident ? 'Incident view' : 'Blast radius'}</strong><span>${state.blast.all.length} resources · ${state.blast.upstream.length} upstream · ${state.blast.downstream.length} downstream</span><button type="button" data-clear-focus>Clear</button>`;
    banner.querySelector('[data-clear-focus]')?.addEventListener('click', clearGraphFocus);
  }

  function bindMinimapScroll() {
    const stage = document.querySelector('#explorerStage');
    if (!stage || stage.dataset.ivMinimapBound === 'true') return;
    stage.dataset.ivMinimapBound = 'true';
    stage.addEventListener('scroll', updateMinimapViewport, { passive: true });
  }

  function renderMinimap(payload) {
    const explorer = document.querySelector('#architectureExplorer');
    const stage = document.querySelector('#explorerStage');
    if (!explorer || !stage || !payload?.layout?.positions) return;
    let wrap = explorer.querySelector('#ivMinimap');
    if (!wrap) {
      explorer.insertAdjacentHTML('beforeend', '<div class="iv-minimap" id="ivMinimap"><canvas width="190" height="118" aria-label="Architecture mini-map"></canvas><span>Map</span></div>');
      wrap = explorer.querySelector('#ivMinimap');
      const canvas = wrap.querySelector('canvas');
      const moveToEvent = event => {
        if (!lastArchitecture) return;
        const rect = canvas.getBoundingClientRect();
        const x = Math.max(0, Math.min(rect.width, event.clientX - rect.left)) / rect.width * lastArchitecture.layout.width;
        const y = Math.max(0, Math.min(rect.height, event.clientY - rect.top)) / rect.height * lastArchitecture.layout.height;
        stage.scrollLeft = Math.max(0, x - stage.clientWidth / 2);
        stage.scrollTop = Math.max(0, y - stage.clientHeight / 2);
      };
      let dragging = false;
      canvas.addEventListener('pointerdown', event => {
        if (event.button !== 0) return;
        dragging = true;
        canvas.setPointerCapture?.(event.pointerId);
        canvas.classList.add('dragging');
        moveToEvent(event);
        event.preventDefault();
      });
      canvas.addEventListener('pointermove', event => { if (dragging) moveToEvent(event); });
      const stop = event => {
        if (!dragging) return;
        dragging = false;
        canvas.classList.remove('dragging');
        canvas.releasePointerCapture?.(event.pointerId);
      };
      canvas.addEventListener('pointerup', stop);
      canvas.addEventListener('pointercancel', stop);
    }
    drawMinimap();
  }

  function drawMinimap() {
    if (!lastArchitecture) return;
    const canvas = document.querySelector('#ivMinimap canvas');
    const stage = document.querySelector('#explorerStage');
    if (!canvas || !stage) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;
    const cssW = 190, cssH = 118;
    if (canvas.width !== Math.round(cssW * dpr)) {
      canvas.width = Math.round(cssW * dpr); canvas.height = Math.round(cssH * dpr); canvas.style.width = `${cssW}px`; canvas.style.height = `${cssH}px`;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--surface').trim() || '#fff';
    ctx.fillRect(0,0,cssW,cssH);
    const sx = cssW / Math.max(1, lastArchitecture.layout.width);
    const sy = cssH / Math.max(1, lastArchitecture.layout.height);
    ctx.fillStyle = getComputedStyle(document.body).getPropertyValue('--muted').trim() || '#7a7a7a';
    lastArchitecture.layout.positions.forEach(pos => ctx.fillRect(pos.x * sx, pos.y * sy, Math.max(2, pos.width * sx), Math.max(2, pos.height * sy)));
    ctx.strokeStyle = getComputedStyle(document.body).getPropertyValue('--cobalt').trim() || '#3657ff';
    ctx.lineWidth = 2;
    ctx.strokeRect(stage.scrollLeft * sx, stage.scrollTop * sy, Math.min(cssW, stage.clientWidth * sx), Math.min(cssH, stage.clientHeight * sy));
  }

  function updateMinimapViewport() { window.requestAnimationFrame(drawMinimap); }

  function readBaseline() {
    try { return JSON.parse(localStorage.getItem(BASELINE_KEY) || 'null'); }
    catch { return null; }
  }

  function saveLocalBaseline() {
    if (!(currentAnalysis.resources || []).length) {
      showToast('Import and analyze infrastructure before saving a baseline.');
      return;
    }
    const snapshot = typeof createLocalBaselineSnapshot === 'function'
      ? createLocalBaselineSnapshot()
      : {
          workspace: workspace.workspace || 'Baseline',
          savedAt: new Date().toISOString(),
          resources: (currentAnalysis.resources || []).map(resource => normalizeResource(resource)),
          relationships: currentAnalysis.graph?.links || []
        };
    if (!storageSet(BASELINE_KEY, snapshot)) return;
    renderCoverage();
    syncControls();
    showToast(`Baseline saved with ${snapshot.resources.length} resources.`);
  }

  function clearLocalBaseline() {
    const baseline = readBaseline();
    if (!baseline?.resources?.length) return;
    openModal('Clear saved baseline?', `<p class="iv-modal-copy">This removes the baseline stored in this browser. It does not change the current imported workspace.</p><div class="iv-modal-actions"><button type="button" class="secondary-button" data-modal-close>Cancel</button><button type="button" class="danger-button" id="ivConfirmClearBaseline">Clear baseline</button></div>`);
    document.querySelector('[data-modal-close]')?.addEventListener('click', closeModal);
    document.querySelector('#ivConfirmClearBaseline')?.addEventListener('click', () => {
      if (storageRemove(BASELINE_KEY)) {
        closeModal();
        renderCoverage();
        syncControls();
        showToast('Saved baseline cleared.');
      }
    });
  }

  function renderCoverage() {
    const grid = document.querySelector('#ivCoverageGrid');
    const summary = document.querySelector('#ivCoverageSummary');
    const diagnostics = document.querySelector('#ivDiagnosticsList');
    const baselineStatus = document.querySelector('#ivBaselineStatus');
    if (!grid || !diagnostics || !summary) return;
    const resources = currentAnalysis.resources || [];
    const confirmed = currentAnalysis.graph?.links?.length || 0;
    const inferred = currentAnalysis.graph?.inferredLinks?.length || 0;
    const diagnosticItems = currentAnalysis.diagnostics || [];
    const unresolved = diagnosticItems.filter(item => /unsupported|unknown|unresolved|failed|missing/i.test(`${item.code || ''} ${item.message || ''}`)).length;
    const authority = currentAnalysis.metadata?.authoritative ? 'Authoritative for imported scope' : resources.length ? 'Static source analysis' : 'No analysis yet';
    const providers = (currentAnalysis.metadata?.providersDetected || []).join(', ') || 'None detected';
    const baseline = readBaseline();

    summary.innerHTML = [
      ['Resources', resources.length],
      ['Confirmed links', confirmed],
      ['Findings', currentAnalysis.findings?.length || 0],
      ['Evidence mode', authority]
    ].map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('');

    grid.innerHTML = [
      ['Resources', resources.length], ['Confirmed links', confirmed], ['Inferred links', inferred], ['Findings', currentAnalysis.findings?.length || 0],
      ['Diagnostics', diagnosticItems.length], ['Unresolved / unsupported', unresolved], ['Analysis mode', currentAnalysis.metadata?.analysisMode || 'empty'], ['Providers', providers]
    ].map(([label, value]) => `<div><span>${esc(label)}</span><strong>${esc(value)}</strong></div>`).join('');

    diagnostics.innerHTML = `
      <p><strong>Scope:</strong> ${esc(currentAnalysis.metadata?.scope || 'none')}</p>
      <p><strong>Authority:</strong> ${esc(authority)}</p>
      <p><strong>Relationship policy:</strong> ${esc(currentAnalysis.metadata?.relationshipPolicy || 'Confirmed links come from imported evidence; inferred links are separate.')}</p>
      ${diagnosticItems.length ? `<ul>${diagnosticItems.map(item => `<li class="${esc(item.level || 'info')}"><strong>${esc(item.code || item.level || 'diagnostic')}</strong> ${esc(item.message || '')}</li>`).join('')}</ul>` : '<p>No parser diagnostics were reported.</p>'}`;

    if (baselineStatus) {
      baselineStatus.textContent = baseline?.resources?.length
        ? `Baseline: ${baseline.resources.length} resources${baseline.savedAt ? ` · ${new Date(baseline.savedAt).toLocaleString()}` : ''}`
        : 'No baseline saved';
      baselineStatus.title = baseline?.workspace ? `Saved from ${baseline.workspace}` : '';
    }
    syncControls();
  }

  function currentWorkspaceSignature() {
    const ids = (currentAnalysis.resources || []).map(resourceKey).sort();
    const source = `${workspace.workspace || ''}|${workspace.sourceType || ''}|${ids.join('|')}`;
    let hash = 5381;
    for (let i = 0; i < source.length; i += 1) hash = ((hash << 5) + hash) ^ source.charCodeAt(i);
    return `ws-${(hash >>> 0).toString(36)}-${ids.length}`;
  }

  function refreshSavedViews() {
    const select = document.querySelector('#ivSavedViewSelect');
    if (!select) return;
    const views = loadSavedViews();
    const current = select.value;
    const signature = currentWorkspaceSignature();
    const compatible = Object.entries(views).filter(([, view]) => !view.workspaceSignature || view.workspaceSignature === signature);
    select.innerHTML = '<option value="">Saved views</option>' + compatible.map(([id, view]) => `<option value="${esc(id)}">${esc(view.name)}${view.workspaceSignature ? '' : ' · legacy'}</option>`).join('');
    if (compatible.some(([id]) => id === current)) select.value = current;
    syncControls();
  }

  function loadSavedViews() {
    try {
      const parsed = JSON.parse(localStorage.getItem(VIEW_KEY) || '{}');
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
    } catch { return {}; }
  }

  function openSaveViewModal() {
    if (!(currentAnalysis.resources || []).length) { showToast('Import infrastructure before saving a view.'); return; }
    openModal('Save architecture view', `<form id="ivSaveViewForm" class="iv-form-stack"><label>View name<input id="ivViewName" required maxlength="60" placeholder="Production network" /></label><p class="iv-form-help">The saved view remembers the current category, lens, confidence filters, zoom, selection, and pan position for this workspace.</p><div class="iv-modal-actions"><button type="button" class="secondary-button" data-modal-close>Cancel</button><button type="submit" class="primary-button">Save view</button></div></form>`);
    document.querySelector('[data-modal-close]')?.addEventListener('click', closeModal);
    document.querySelector('#ivViewName')?.focus();
    document.querySelector('#ivSaveViewForm')?.addEventListener('submit', event => {
      event.preventDefault();
      const name = document.querySelector('#ivViewName').value.trim();
      if (!name) return;
      const id = `view-${Date.now()}`;
      const viewport = selectedArchitectureCategory ? document.querySelector('#explorerStage') : document.querySelector('#architectureCanvas');
      const views = loadSavedViews();
      views[id] = {
        name,
        workspaceSignature: currentWorkspaceSignature(),
        category: selectedArchitectureCategory,
        graphMode: architectureGraphMode,
        zoom: architectureZoom,
        lens: state.lens,
        showConfirmed: state.showConfirmed,
        showInferred: state.showInferred,
        selectedResource: selectedExplorerResourceId,
        scrollLeft: viewport?.scrollLeft || 0,
        scrollTop: viewport?.scrollTop || 0,
        savedAt: new Date().toISOString()
      };
      if (!storageSet(VIEW_KEY, views)) return;
      refreshSavedViews();
      document.querySelector('#ivSavedViewSelect').value = id;
      closeModal();
      syncControls();
      showToast(`Saved view “${name}”.`);
    });
  }

  function loadSavedView(id) {
    const view = loadSavedViews()[id];
    if (!view) { showToast('That saved view is no longer available.'); refreshSavedViews(); return; }
    const signature = currentWorkspaceSignature();
    if (view.workspaceSignature && view.workspaceSignature !== signature) {
      showToast('That view belongs to a different imported workspace.');
      refreshSavedViews();
      return;
    }
    const ids = new Set((currentAnalysis.resources || []).map(resourceKey));
    const categories = new Set((currentAnalysis.resources || []).map(resource => resource.category || 'other'));
    selectedArchitectureCategory = view.category && categories.has(view.category) ? view.category : null;
    architectureGraphMode = view.graphMode === 'context' ? 'context' : 'internal';
    selectedExplorerResourceId = view.selectedResource && ids.has(view.selectedResource) ? view.selectedResource : null;
    architectureZoom = clampNumber(Number(view.zoom) || 1, ZOOM_MIN, ZOOM_MAX);
    storageSet(ZOOM_KEY, String(architectureZoom));
    state.lens = ['all', 'network', 'security', 'reliability', 'observability', 'changes'].includes(view.lens) ? view.lens : 'all';
    state.showConfirmed = view.showConfirmed !== false;
    state.showInferred = view.showInferred !== false;
    syncControls();
    saveFeatureState();
    applyArchitectureZoom();
    renderArchitecture();
    window.requestAnimationFrame(() => {
      const viewport = selectedArchitectureCategory ? document.querySelector('#explorerStage') : document.querySelector('#architectureCanvas');
      if (viewport) { viewport.scrollLeft = Number(view.scrollLeft) || 0; viewport.scrollTop = Number(view.scrollTop) || 0; }
      applyVisualState();
    });
  }

  function deleteSelectedView() {
    const select = document.querySelector('#ivSavedViewSelect');
    const id = select?.value;
    if (!id) { showToast('Choose a saved view first.'); return; }
    const views = loadSavedViews();
    const name = views[id]?.name || 'this view';
    openModal('Delete saved view?', `<p class="iv-modal-copy">Delete <strong>${esc(name)}</strong> from this browser?</p><div class="iv-modal-actions"><button type="button" class="secondary-button" data-modal-close>Cancel</button><button type="button" class="danger-button" id="ivConfirmDeleteView">Delete view</button></div>`);
    document.querySelector('[data-modal-close]')?.addEventListener('click', closeModal);
    document.querySelector('#ivConfirmDeleteView')?.addEventListener('click', () => {
      delete views[id];
      if (!storageSet(VIEW_KEY, views)) return;
      closeModal();
      refreshSavedViews();
      showToast('Saved view deleted.');
    });
  }

  function exportArchitectureReport() {
    if (!(currentAnalysis.resources || []).length) {
      showToast('Import infrastructure before exporting an architecture report.');
      return;
    }
    const graph = graphForAnalysis();
    const visible = graph.resources.filter(matchesLens);
    const ids = new Set(visible.map(resourceKey));
    const links = graph.links.filter(link => ids.has(link.source) && ids.has(link.target));
    const notes = loadResourceNotes();
    const html = `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sable Architecture Report</title><style>body{font:15px system-ui;margin:40px;color:#16181d;line-height:1.45}table{border-collapse:collapse;width:100%;margin:16px 0}th,td{border:1px solid #d7d9df;padding:9px;text-align:left;vertical-align:top}th{background:#f4f5f7}code{font:12px ui-monospace,monospace;overflow-wrap:anywhere}.meta{display:flex;gap:24px;flex-wrap:wrap}.tag{display:inline-block;border:1px solid #c8cad1;padding:3px 7px;border-radius:4px}@media(max-width:700px){body{margin:20px}table{font-size:12px}}</style></head><body><h1>Sable Architecture Report</h1><div class="meta"><p><strong>Workspace:</strong> ${esc(workspace.workspace || 'Workspace')}</p><p><strong>Lens:</strong> ${esc(state.lens)}</p><p><strong>Resources:</strong> ${visible.length}</p><p><strong>Relationships:</strong> ${links.length}</p></div><p>This export reflects the active architecture lens and relationship confidence filters at export time.</p><h2>Resources</h2><table><thead><tr><th>Name</th><th>Type</th><th>Category</th><th>Provider</th><th>Local note</th></tr></thead><tbody>${visible.map(r=>`<tr><td>${esc(r.name)}</td><td><code>${esc(r.type)}</code></td><td>${esc(CATEGORY_META[r.category]?.label||r.category)}</td><td>${esc(r.provider)}</td><td>${esc(notes[resourceKey(r)] || '')}</td></tr>`).join('')}</tbody></table><h2>Relationships</h2>${links.length ? `<table><thead><tr><th>Source</th><th>Target</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>${links.map(l=>`<tr><td>${esc(getResource(l.source)?.name||l.source)}</td><td>${esc(getResource(l.target)?.name||l.target)}</td><td>${esc(l.confidence||'confirmed')}</td><td><code>${esc(JSON.stringify(l.evidence||{}))}</code></td></tr>`).join('')}</tbody></table>` : '<p>No relationships are visible under the current filters.</p>'}<p>Generated by Sable. This report contains only the imported analysis scope.</p></body></html>`;
    download('sable-architecture-report.html', html, 'text/html');
  }

  function compareLocalBaseline() {
    const baseline = readBaseline();
    if (!baseline?.resources?.length) { showToast('No baseline exists yet. Save one first.'); return; }
    const currentResources = currentAnalysis.resources || [];
    if (!currentResources.length) { showToast('Import and analyze infrastructure before comparing it with a baseline.'); return; }
    const currentMap = new Map(currentResources.map(r => [resourceKey(r), normalizeResource(r)]));
    const baselineMap = new Map((baseline.resources || []).map(r => [resourceKey(r), normalizeResource(r)]));
    const added = Array.from(currentMap.keys()).filter(key => !baselineMap.has(key));
    const removed = Array.from(baselineMap.keys()).filter(key => !currentMap.has(key));
    const changed = Array.from(currentMap.keys()).filter(key => baselineMap.has(key) && stable(currentMap.get(key)?.attributes) !== stable(baselineMap.get(key)?.attributes));
    const unchanged = Array.from(currentMap.keys()).filter(key => baselineMap.has(key) && !changed.includes(key)).length;
    const totalChanges = added.length + changed.length + removed.length;
    const intro = totalChanges
      ? `<div class="iv-diff-callout"><strong>${totalChanges} infrastructure change${totalChanges === 1 ? '' : 's'} detected</strong><span>Click an added or changed resource to inspect it in the current architecture.</span></div>`
      : '<div class="iv-empty iv-success-empty"><strong>No declared resource changes detected</strong>The current imported representation matches the saved baseline for resource identity and normalized attributes.</div>';
    openModal('Baseline comparison', `${intro}<div class="iv-detail-grid">${detail('Added', added.length)}${detail('Changed', changed.length)}${detail('Removed', removed.length)}${detail('Unchanged', unchanged)}${detail('Current resources', currentMap.size)}${detail('Baseline resources', baselineMap.size)}</div><div class="iv-diff-columns"><section><h3>Added</h3>${resourceLinkList(added)}</section><section><h3>Changed</h3>${resourceLinkList(changed)}</section><section><h3>Removed</h3>${removed.length ? `<div class="iv-baseline-removed-list">${removed.map(id=>`<div><strong>${esc(baselineMap.get(id)?.name||id)}</strong><small>${esc(baselineMap.get(id)?.type||'resource')}</small></div>`).join('')}</div>`:'<p>None.</p>'}</section></div><p class="iv-muted">This compares the current imported representation with the saved baseline. It does not claim live-cloud drift unless the imported inputs themselves represent live cloud state.</p>`);
  }

  function stable(value) {
    if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
    if (value && typeof value === 'object') return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${stable(value[key])}`).join(',')}}`;
    return JSON.stringify(value);
  }

  async function importPolicyFile(file) {
    if (!file) return;
    const input = document.querySelector('#ivPolicyFile');
    try {
      if (file.size > 1_000_000) throw new Error('Policy files must be smaller than 1 MB.');
      const pack = JSON.parse(await file.text());
      const validated = validatePolicyPack(pack);
      if (!storageSet(POLICY_KEY, validated)) return;
      policyShowAll = false;
      renderPolicyPanel();
      showToast(`Loaded policy pack “${validated.name}” with ${validated.rules.length} rules.`);
    } catch (error) {
      showToast(`Policy import failed: ${error.message}`);
    } finally {
      if (input) input.value = '';
    }
  }

  function renderPolicyPanel() {
    const summary = document.querySelector('#ivPolicySummary');
    const results = document.querySelector('#ivPolicyResults');
    if (!summary || !results) return;
    let pack;
    try { pack = JSON.parse(localStorage.getItem(POLICY_KEY) || 'null'); } catch { pack = null; }
    if (!pack?.rules?.length) {
      summary.innerHTML = '<strong>No custom policy pack loaded.</strong><span>Import a JSON policy pack to evaluate your own deterministic guardrails against the current workspace.</span>';
      results.innerHTML = '';
      return;
    }
    let validated;
    try { validated = validatePolicyPack(pack); }
    catch (error) {
      summary.innerHTML = `<strong>Policy pack needs attention.</strong><span>${esc(error.message)}</span>`;
      results.innerHTML = '<div class="iv-empty">Clear this policy pack and import a valid JSON policy file.</div>';
      return;
    }
    const violations = evaluatePolicyPack(validated);
    const shown = policyShowAll ? violations : violations.slice(0, POLICY_VISIBLE_LIMIT);
    summary.innerHTML = `<strong>${esc(validated.name)}</strong><span>${validated.rules.length} rule${validated.rules.length === 1 ? '' : 's'} evaluated against ${currentAnalysis.resources?.length || 0} resources · ${violations.length} violation${violations.length === 1 ? '' : 's'}.</span>`;
    if (!violations.length) {
      results.innerHTML = `<div class="iv-empty iv-success-empty"><strong>No custom-policy violations found</strong>${currentAnalysis.resources?.length ? 'All matching resources passed the loaded policy rules.' : 'Import infrastructure to evaluate this policy pack.'}</div>`;
      return;
    }
    results.innerHTML = `${shown.map(v => `<article class="iv-policy-violation"><span class="severity-pill ${esc(v.rule.severity || 'medium')}">${esc(v.rule.severity || 'medium')}</span><div class="iv-policy-copy"><strong>${esc(v.rule.title || v.rule.id)}</strong><p>${esc(v.resource.name)} · ${esc(v.resource.type)}</p><div class="iv-policy-evidence"><span><b>Check</b>${esc(v.requirement.attribute)} ${esc(formatPolicyRequirement(v.requirement))}</span><span><b>Actual</b>${esc(formatPolicyValue(v.actual))}</span></div><small>${esc(v.message)}</small><button type="button" class="text-button" data-open-resource="${esc(resourceKey(v.resource))}">Open resource</button></div></article>`).join('')}${violations.length > POLICY_VISIBLE_LIMIT ? `<button type="button" class="iv-show-more" data-policy-show-all>${policyShowAll ? 'Show fewer violations' : `Show all ${violations.length} violations`}</button>` : ''}`;
  }

  function evaluatePolicyPack(pack) {
    const out = [];
    (currentAnalysis.resources || []).forEach(resource => {
      (pack.rules || []).forEach(rule => {
        if (!policyMatchesResource(rule.match || {}, resource)) return;
        const requirement = rule.require || {};
        const value = getPolicyAttribute(resource, requirement.attribute || '');
        if (!requirementPasses(value, requirement)) {
          out.push({
            resource,
            rule,
            requirement,
            actual: value,
            message: `${requirement.attribute} ${formatPolicyRequirement(requirement)}, but the imported value is ${formatPolicyValue(value)}.`
          });
        }
      });
    });
    return out;
  }

  function policyMatchesResource(match, resource) {
    if (match.typeIncludes && !String(resource.type || '').toLowerCase().includes(String(match.typeIncludes).toLowerCase())) return false;
    if (match.nameIncludes && !String(resource.name || '').toLowerCase().includes(String(match.nameIncludes).toLowerCase())) return false;
    if (match.category && String(resource.category || '').toLowerCase() !== String(match.category).toLowerCase()) return false;
    if (match.provider && String(resource.provider || '').toLowerCase() !== String(match.provider).toLowerCase()) return false;
    return true;
  }

  function validatePolicyPack(pack) {
    if (!pack || typeof pack !== 'object' || Array.isArray(pack)) throw new Error('Policy JSON must be an object.');
    if (!Array.isArray(pack.rules) || !pack.rules.length) throw new Error('Policy JSON must contain at least one rule in a rules array.');
    if (pack.rules.length > 100) throw new Error('A policy pack can contain at most 100 rules.');
    const ids = new Set();
    const rules = pack.rules.map((rule, index) => {
      if (!rule || typeof rule !== 'object' || Array.isArray(rule)) throw new Error(`Rule ${index + 1} must be an object.`);
      const id = String(rule.id || `CUSTOM-${index + 1}`).trim();
      if (ids.has(id)) throw new Error(`Duplicate rule id: ${id}.`);
      ids.add(id);
      const require = rule.require || {};
      const attribute = String(require.attribute || '').trim();
      const operator = String(require.operator || 'exists');
      if (!attribute) throw new Error(`Rule ${id} is missing require.attribute.`);
      if (!VALID_POLICY_OPERATORS.has(operator)) throw new Error(`Rule ${id} uses unsupported operator “${operator}”.`);
      if (['min', 'max'].includes(operator) && !Number.isFinite(Number(require.value))) throw new Error(`Rule ${id} requires a numeric value for ${operator}.`);
      const severity = String(rule.severity || 'medium').toLowerCase();
      if (!['critical', 'high', 'medium', 'low'].includes(severity)) throw new Error(`Rule ${id} has unsupported severity “${severity}”.`);
      const match = rule.match && typeof rule.match === 'object' && !Array.isArray(rule.match) ? rule.match : {};
      return {
        id,
        title: String(rule.title || id),
        severity,
        match: {
          ...(match.typeIncludes ? { typeIncludes: String(match.typeIncludes) } : {}),
          ...(match.nameIncludes ? { nameIncludes: String(match.nameIncludes) } : {}),
          ...(match.category ? { category: String(match.category) } : {}),
          ...(match.provider ? { provider: String(match.provider) } : {})
        },
        require: { attribute, operator, value: require.value }
      };
    });
    return { name: String(pack.name || 'Custom policy pack').trim().slice(0, 100) || 'Custom policy pack', rules };
  }

  function getPolicyAttribute(resource, path) {
    const attributes = resource?.attributes || {};
    const direct = getPath(attributes, path);
    if (direct !== undefined) return direct;
    const parts = String(path || '').split('.').filter(Boolean);
    if (parts.length >= 2 && parts[0].toLowerCase() === 'tags') {
      const tagKey = parts.slice(1).join('.');
      const tags = attributes.tags ?? attributes.Tags ?? resource.tags ?? resource.labels;
      if (Array.isArray(tags)) {
        const item = tags.find(tag => String(tag?.Key ?? tag?.key ?? '').toLowerCase() === tagKey.toLowerCase());
        if (item) return item.Value ?? item.value;
      }
      if (tags && typeof tags === 'object') {
        const key = Object.keys(tags).find(k => k.toLowerCase() === tagKey.toLowerCase());
        if (key) return tags[key];
      }
    }
    return undefined;
  }

  function formatPolicyRequirement(requirement) {
    const op = requirement.operator || 'exists';
    const value = formatPolicyValue(requirement.value);
    if (op === 'exists') return requirement.value === false ? 'must be absent' : 'must exist';
    if (op === 'equals') return `must equal ${value}`;
    if (op === 'notEquals') return `must not equal ${value}`;
    if (op === 'min') return `must be at least ${value}`;
    if (op === 'max') return `must be at most ${value}`;
    if (op === 'includes') return `must include ${value}`;
    return `${op} ${value}`;
  }

  function formatPolicyValue(value) {
    if (value === undefined) return 'not present';
    if (value === null) return 'null';
    if (typeof value === 'string') return value || '(empty string)';
    try { return JSON.stringify(value); } catch { return String(value); }
  }

  function getPath(object, path) {
    const parts = String(path || '').split('.').filter(Boolean);
    let value = object;
    for (const part of parts) {
      if (value == null) return undefined;
      if (value[part] !== undefined) value = value[part];
      else {
        const key = Object.keys(value).find(k => k.toLowerCase() === part.toLowerCase());
        value = key ? value[key] : undefined;
      }
    }
    return value;
  }

  function requirementPasses(value, requirement) {
    const op = requirement.operator || 'exists';
    const expected = requirement.value;
    if (op === 'exists') return expected === false ? value == null : value != null;
    if (op === 'equals') return value === expected;
    if (op === 'notEquals') return value !== expected;
    if (op === 'min') return Number(value) >= Number(expected);
    if (op === 'max') return Number(value) <= Number(expected);
    if (op === 'includes') return Array.isArray(value) ? value.includes(expected) : String(value || '').includes(String(expected));
    return true;
  }

  function renderPrArchitecture(mode = 'overlay') {
    const container = document.querySelector('#ivPrArchitecture');
    const summary = document.querySelector('#ivPrArchitectureSummary');
    if (!container) return;
    const proposed = prReview?.analysis?.resources || [];
    const baseline = readBaseline();
    const current = baseline?.resources?.length ? baseline.resources : (currentAnalysis.resources || workspace.resources || []);
    const diffs = prReview?.diffs || [];
    const changedOnly = document.querySelector('#ivPrChangedOnly')?.checked !== false;
    if (!proposed.length && !diffs.length) {
      if (summary) summary.innerHTML = '';
      container.innerHTML = '<div class="iv-empty"><strong>No PR architecture yet</strong>Run a PR review to visualize the resources affected by the proposed infrastructure change.</div>';
      return;
    }
    const currentMap = new Map(current.map(r => [resourceKey(r), normalizeResource(r)]));
    const proposedMap = new Map(proposed.map(r => [resourceKey(r), normalizeResource(r)]));
    const actionMap = new Map(diffs.map(diff => [diff.resource, diff.action]));
    let resources = [];
    if (mode === 'current') resources = Array.from(currentMap.values()).map(r => ({ ...r, _diff: actionMap.get(resourceKey(r)) === 'delete' ? 'delete' : (actionMap.get(resourceKey(r)) || 'present') }));
    if (mode === 'proposed') resources = Array.from(proposedMap.values()).map(r => ({ ...r, _diff: actionMap.get(resourceKey(r)) || r.action || 'present' }));
    if (mode === 'overlay') {
      const ids = new Set([...currentMap.keys(), ...proposedMap.keys(), ...actionMap.keys()]);
      resources = Array.from(ids).map(id => {
        const resource = proposedMap.get(id) || currentMap.get(id);
        return resource ? { ...resource, _diff: actionMap.get(id) || (proposedMap.has(id) ? 'present' : 'delete') } : null;
      }).filter(Boolean);
    }
    const changedActions = new Set(['add', 'change', 'replace', 'delete']);
    if (changedOnly) resources = resources.filter(resource => changedActions.has(resource._diff));
    const counts = diffs.reduce((acc, diff) => {
      const action = diff.action === 'replace' ? 'change' : diff.action;
      if (action in acc) acc[action] += 1;
      return acc;
    }, { add: 0, change: 0, delete: 0 });
    if (summary) summary.innerHTML = `<div class="iv-pr-summary-cards"><div><strong>${counts.add}</strong><span>Added</span></div><div><strong>${counts.change}</strong><span>Changed</span></div><div><strong>${counts.delete}</strong><span>Removed</span></div><div><strong>${resources.length}</strong><span>${changedOnly ? 'Shown changes' : 'Shown resources'}</span></div></div><div class="iv-pr-legend"><span class="add">+ Added</span><span class="change">~ Changed</span><span class="delete">− Removed</span><span class="present">· Unchanged</span></div>`;
    if (!resources.length) {
      container.innerHTML = `<div class="iv-empty"><strong>No resources match this view</strong>${changedOnly ? 'There are no changed resources available in this current/proposed view. Turn off “Changes only” to see unchanged resources.' : 'No resources are available for this view.'}</div>`;
      return;
    }
    const groups = new Map();
    resources.forEach(r => { const c = r.category || 'other'; if (!groups.has(c)) groups.set(c, []); groups.get(c).push(r); });
    container.innerHTML = Array.from(groups.entries()).sort((a,b)=>(CATEGORY_META[a[0]]?.order||99)-(CATEGORY_META[b[0]]?.order||99)).map(([category, items]) => {
      const sorted = [...items].sort((a,b) => actionOrder(a._diff)-actionOrder(b._diff) || String(a.name).localeCompare(String(b.name)));
      const visible = sorted.slice(0, 60);
      return `<section class="iv-pr-lane"><h3>${esc(CATEGORY_META[category]?.label || category)} <span>${items.length}</span></h3><div>${visible.map(r => `<button type="button" class="iv-pr-node ${esc(r._diff)}" data-pr-resource="${esc(resourceKey(r))}" title="Inspect ${esc(r.name)}"><span>${diffSymbol(r._diff)}</span><strong>${esc(r.name)}</strong><small>${esc(r.type)}</small></button>`).join('')}${items.length > visible.length ? `<div class="iv-pr-more">+${items.length - visible.length} more resources in this category. Use “Changes only” or inspect the imported architecture for the full inventory.</div>` : ''}</div></section>`;
    }).join('');
  }

  function actionOrder(action) {
    return ({ add: 0, replace: 1, change: 1, delete: 2, present: 3 })[action] ?? 4;
  }

  function openPrResourceModal(id) {
    const baseline = readBaseline();
    const current = baseline?.resources?.length ? baseline.resources : (currentAnalysis.resources || workspace.resources || []);
    const proposed = prReview?.analysis?.resources || [];
    const before = current.find(resource => resourceKey(resource) === id);
    const after = proposed.find(resource => resourceKey(resource) === id);
    const diff = (prReview?.diffs || []).find(item => item.resource === id);
    if (!before && !after && !diff) { showToast('That PR resource is no longer available.'); return; }
    const resource = normalizeResource(after || before || { id, type: diff?.type || 'resource', name: id });
    const action = diff?.action || resource.action || 'present';
    const changes = diffAttributeRows(before?.attributes || {}, after?.attributes || {});
    const config = (value, emptyText) => value ? `<pre class="iv-config iv-pr-config">${esc(JSON.stringify(value.attributes || {}, null, 2))}</pre>` : `<div class="iv-empty">${esc(emptyText)}</div>`;
    openModal(`PR resource · ${resource.name}`, `<div class="iv-detail-grid">${detail('Action', action)}${detail('Type', resource.type)}${detail('Category', CATEGORY_META[resource.category]?.label || resource.category)}${detail('Provider', resource.provider || 'unknown')}</div>${diff?.description ? `<div class="iv-diff-callout"><strong>Review evidence</strong><span>${esc(diff.description)}</span></div>` : ''}${changes.length ? `<section class="iv-modal-section"><h3>Changed attributes</h3><div class="iv-attribute-diff">${changes.slice(0, 24).map(change => `<div><code>${esc(change.path)}</code><span><b>Before</b>${esc(formatPolicyValue(change.before))}</span><span><b>After</b>${esc(formatPolicyValue(change.after))}</span></div>`).join('')}</div>${changes.length > 24 ? `<p class="iv-muted">Showing the first 24 of ${changes.length} changed attribute paths.</p>` : ''}</section>` : ''}<div class="iv-pr-compare-grid"><section><h3>Current / baseline</h3>${config(before, 'Resource does not exist in the current/baseline representation.')}</section><section><h3>Proposed</h3>${config(after, 'Resource does not exist in the proposed representation.')}</section></div>${after && getResource(id) ? `<div class="iv-modal-actions"><button type="button" class="primary-button" data-open-resource="${esc(id)}">Open in architecture</button></div>` : ''}`);
  }

  function diffAttributeRows(before, after, prefix = '') {
    const rows = [];
    const beforeObj = before && typeof before === 'object' ? before : {};
    const afterObj = after && typeof after === 'object' ? after : {};
    const keys = new Set([...Object.keys(beforeObj), ...Object.keys(afterObj)]);
    for (const key of Array.from(keys).sort()) {
      const path = prefix ? `${prefix}.${key}` : key;
      const a = beforeObj[key];
      const b = afterObj[key];
      if (stable(a) === stable(b)) continue;
      const canRecurse = a && b && typeof a === 'object' && typeof b === 'object' && !Array.isArray(a) && !Array.isArray(b);
      if (canRecurse) rows.push(...diffAttributeRows(a, b, path));
      else rows.push({ path, before: a, after: b });
      if (rows.length > 80) break;
    }
    return rows;
  }

  function diffSymbol(action) { return action === 'add' ? '+' : action === 'delete' ? '−' : ['change','replace'].includes(action) ? '~' : '·'; }

  function renderReviewer() {
    ensureUi();
    renderPrArchitecture(document.querySelector('[data-pr-view].active')?.dataset.prView || 'overlay');
  }

  function openModal(title, content) {
    ensureUi();
    document.querySelector('#ivModalTitle').textContent = title;
    document.querySelector('#ivModalBody').innerHTML = content;
    document.querySelector('#ivModal').classList.remove('hidden');
    document.querySelector('#ivModalBackdrop').classList.remove('hidden');
  }

  function closeModal() {
    document.querySelector('#ivModal')?.classList.add('hidden');
    document.querySelector('#ivModalBackdrop')?.classList.add('hidden');
  }

  function download(filename, content, type) {
    if (typeof downloadFile === 'function') {
      downloadFile(filename, content, type);
      return;
    }
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  window.SableFeatures = {
    renderAll: renderAllFeatures,
    renderReviewer,
    afterArchitectureRender,
    filterLinks,
    onResourceSelected: id => openResourceDrawer(id)
  };

  // The feature object must exist before app.js's DOMContentLoaded init runs.
  if (document.readyState !== 'loading') renderAllFeatures();
})();
