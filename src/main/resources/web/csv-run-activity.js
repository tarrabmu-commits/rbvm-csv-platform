(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_RUN_ACTIVITY_UI_V1';
  const ENRICHMENT_JOB_CONTRACT = 'CSV_FIRST_ENRICHMENT_JOB_HTTP_V1';
  const ANALYSIS_CONTRACT = 'CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1';
  const PRIORITY_CONTRACT = 'CSV_FIRST_MVP_PRIORITY_HTTP_V1';
  const RISK_CONTRACT = 'CSV_FIRST_RISK_HTTP_V1';
  const READINESS_CONTRACT = 'CSV_FIRST_RISK_READINESS_V1';
  const REPORT_CONTRACT = 'CSV_FIRST_RISK_REPORT_V1';
  const previousFetch = window.fetch.bind(window);
  const STAGE_ORDER = ['UPLOAD', 'ENRICHMENT', 'ASSET_CONTEXT', 'ANALYSIS', 'PRIORITY', 'RISK'];
  const STAGE_LABELS = {
    UPLOAD: 'CSV scope',
    ENRICHMENT: 'Public intelligence',
    ASSET_CONTEXT: 'Asset context',
    ANALYSIS: 'Contextual analysis',
    PRIORITY: 'Treatment priority',
    RISK: 'Risk method',
  };
  const state = new Map();
  let activeRunId = '';
  let priorityUrl = '';
  let analysisId = '';
  let queued = false;
  let elapsedTimer = null;

  document.documentElement.dataset.csvFirstRunActivityUi = CONTRACT;

  function fresh(status = 'waiting', detail = 'Waiting for the previous step') {
    return {status, detail, startedAt: null, completedAt: null};
  }

  function reset(runId = '') {
    state.clear();
    STAGE_ORDER.forEach(stage => state.set(stage, fresh()));
    activeRunId = runId;
    priorityUrl = '';
    analysisId = '';
    if (runId) {
      setStage('UPLOAD', 'complete', 'CSV accepted; run scope is fixed to the uploaded assets.');
      setStage('ENRICHMENT', 'running', 'Checking the background public-intelligence job…');
      setStage('ASSET_CONTEXT', 'ready', 'Provide Asset Criticality and Internet Facing for every CSV asset.');
    } else {
      setStage('UPLOAD', 'ready', 'Choose a customer vulnerability CSV to begin.');
    }
  }

  function setStage(stage, status, detail, timing = {}) {
    const current = state.get(stage) || fresh();
    const now = Date.now();
    const nextDetail = detail || current.detail;
    const suppliedStart = timing.startedAt && Number.isFinite(Number(timing.startedAt)) ? Number(timing.startedAt) : null;
    const suppliedComplete = timing.completedAt && Number.isFinite(Number(timing.completedAt)) ? Number(timing.completedAt) : null;
    let startedAt = suppliedStart || current.startedAt;
    let completedAt = suppliedComplete || current.completedAt;
    if (status === 'running' && current.status !== 'running') startedAt = suppliedStart || now;
    if (status === 'complete' && current.status !== 'complete') completedAt = suppliedComplete || now;
    if (status === 'failed' && current.status !== 'failed') completedAt = suppliedComplete || now;
    if (status === 'ready' || status === 'waiting') completedAt = null;
    const unchanged = current.status === status
      && current.detail === nextDetail
      && Number(current.startedAt || 0) === Number(startedAt || 0)
      && Number(current.completedAt || 0) === Number(completedAt || 0);
    if (unchanged) return;
    state.set(stage, {status, detail: nextDetail, startedAt, completedAt});
    schedule();
  }

  function runIdFromLocation() {
    return new URLSearchParams(location.search).get('runId') || '';
  }

  function pageSupportsActivity() {
    const path = location.pathname.replace(/\/+$/, '') || '/';
    const params = new URLSearchParams(location.search);
    return (path === '/' && params.get('view') === 'imports') || path === '/assets';
  }

  function asUrl(input) {
    try { return new URL(typeof input === 'string' ? input : input.url, location.href); }
    catch (_) { return null; }
  }

  function requestMethod(input, options) {
    if (options?.method) return String(options.method).toUpperCase();
    if (typeof Request !== 'undefined' && input instanceof Request) return String(input.method || 'GET').toUpperCase();
    return 'GET';
  }

  function parseBody(options) {
    const body = options?.body;
    if (typeof body !== 'string') return null;
    try { return JSON.parse(body); } catch (_) { return null; }
  }

  async function jsonClone(response) {
    try { return await response.clone().json(); } catch (_) { return null; }
  }

  function normalizePath(url) { return url?.pathname || ''; }

  function isEnrichmentCreate(path, method) {
    return method === 'POST' && path === '/api/v1/csv-first-enrichment-jobs';
  }

  function enrichmentRun(path) {
    const match = path.match(/^\/api\/v1\/csv-first-enrichment-jobs\/([0-9a-fA-F-]{36})$/);
    return match ? match[1] : '';
  }

  function customerContextRun(path) {
    const match = path.match(/^\/api\/v1\/csv-first-customer-assets\/([0-9a-fA-F-]{36})$/);
    return match ? match[1] : '';
  }

  function analysisRun(path) {
    const match = path.match(/^\/api\/v1\/csv-first-customer-assets\/([0-9a-fA-F-]{36})\/analyses$/);
    return match ? match[1] : '';
  }

  function riskPath(path) {
    return /^\/api\/v1\/csv-first-risks\/[0-9a-fA-F-]{36}\/[0-9a-fA-F-]{36}\/[A-Z0-9_]+$/.test(path);
  }

  function riskReportPath(path) {
    return /^\/api\/v1\/csv-first-risks\/[0-9a-fA-F-]{36}\/[0-9a-fA-F-]{36}\/[A-Z0-9_]+\/report$/.test(path);
  }

  function readinessPath(path) {
    return /^\/api\/v1\/csv-first-risk-readiness\/[0-9a-fA-F-]{36}\/[0-9a-fA-F-]{36}$/.test(path);
  }

  function stageFromJob(data) {
    const status = String(data?.status || '').toUpperCase();
    const stage = String(data?.stage || '').toUpperCase();
    const startedAt = data?.createdAt ? new Date(data.createdAt).getTime() : null;
    const completedAt = data?.completedAt ? new Date(data.completedAt).getTime() : null;
    if (status === 'COMPLETE') {
      setStage('ENRICHMENT', 'complete', 'Local CVSS, EPSS, KEV and CISA/CVE Program evidence are ready.', {startedAt, completedAt});
    } else if (status === 'FAILED') {
      setStage('ENRICHMENT', 'failed', data?.detail || stage.replaceAll('_', ' ') || 'Public-intelligence enrichment failed.', {startedAt, completedAt});
    } else if (stage === 'WAITING_FOR_WORKER') {
      setStage('ENRICHMENT', 'running', 'Queued for the local enrichment worker.', {startedAt});
    } else {
      setStage('ENRICHMENT', 'running', 'Matching the CSV CVEs against local CVSS, EPSS, KEV and CISA/CVE Program intelligence.', {startedAt});
    }
  }

  function readinessDetail(data) {
    const methods = Array.isArray(data?.methods) ? data.methods : [];
    if (!methods.length) return 'Risk readiness checked. Choose a method to calculate.';
    const totalRows = methods.reduce((max, method) => Math.max(max, Number(method.computableRows || 0) + Number(method.nonComputableRows || 0)), 0);
    const fullyReady = methods.filter(method => Number(method.nonComputableRows || 0) === 0 && Number(method.computableRows || 0) > 0).length;
    return `${methods.length} methods checked for ${totalRows} finding rows · ${fullyReady} fully ready. Choose one method to calculate.`;
  }

  function reportDetail(data) {
    const result = data?.result || {};
    const computed = Number(result.computedRows || 0);
    const blocked = Number(result.nonComputableRows || 0);
    return `${data?.methodId || 'Selected method'} complete · ${computed} computed · ${blocked} non-computable.`;
  }

  window.fetch = async (input, options = {}) => {
    const url = asUrl(input);
    const path = normalizePath(url);
    const method = requestMethod(input, options);
    const enrichmentId = enrichmentRun(path);
    const contextId = customerContextRun(path);
    const analysesId = analysisRun(path);
    const isPriority = method === 'POST' && priorityUrl && url && new URL(priorityUrl, location.href).pathname === path;

    if (isEnrichmentCreate(path, method)) {
      setStage('UPLOAD', 'complete', 'CSV parsed and asset identities accepted; the run population is fixed.');
      setStage('ENRICHMENT', 'running', 'Starting the background public-intelligence enrichment job…');
    } else if (enrichmentId && method === 'GET') {
      if (activeRunId && enrichmentId === activeRunId) setStage('ENRICHMENT', 'running', state.get('ENRICHMENT')?.detail || 'Checking enrichment status…');
    } else if (contextId && method === 'PUT') {
      const bundle = parseBody(options);
      const count = Array.isArray(bundle?.assets) ? bundle.assets.length : null;
      setStage('ASSET_CONTEXT', 'running', count ? `Saving Criticality + Internet Facing for ${count} CSV assets…` : 'Saving customer-declared asset context…');
    } else if (analysesId && method === 'POST') {
      setStage('ANALYSIS', 'running', 'Freezing the saved customer context into an immutable contextual analysis…');
      setStage('PRIORITY', 'waiting', 'Waiting for the immutable analysis.');
      setStage('RISK', 'waiting', 'Waiting for the immutable analysis.');
    } else if (isPriority) {
      setStage('PRIORITY', 'running', 'Materializing the server-side Pareto treatment-priority frontier…');
    } else if (readinessPath(path) && method === 'GET') {
      setStage('RISK', 'running', 'Checking required evidence for all four selectable risk methods…');
    } else if (riskPath(path) && method === 'POST') {
      const methodId = path.split('/').pop();
      setStage('RISK', 'running', `Calculating ${methodId} from the exact immutable analysis…`);
    }

    let response;
    try {
      response = await previousFetch(input, options);
    } catch (error) {
      if (isEnrichmentCreate(path, method) || enrichmentId) setStage('ENRICHMENT', 'failed', `Request failed: ${error.message}`);
      else if (contextId && method === 'PUT') setStage('ASSET_CONTEXT', 'failed', `Save failed: ${error.message}`);
      else if (analysesId && method === 'POST') setStage('ANALYSIS', 'failed', `Analysis failed: ${error.message}`);
      else if (isPriority) setStage('PRIORITY', 'failed', `Priority calculation failed: ${error.message}`);
      else if (readinessPath(path) || riskPath(path)) setStage('RISK', 'failed', `Risk operation failed: ${error.message}`);
      throw error;
    }

    const data = await jsonClone(response);
    if (isEnrichmentCreate(path, method)) {
      if (response.ok && data?.contractId === ENRICHMENT_JOB_CONTRACT) {
        activeRunId = String(data.runId || activeRunId);
        stageFromJob(data);
      } else if (!response.ok) setStage('ENRICHMENT', 'failed', data?.detail || `Enrichment job could not start (HTTP ${response.status}).`);
    } else if (enrichmentId && method === 'GET' && response.ok && data?.contractId === ENRICHMENT_JOB_CONTRACT) {
      if (!activeRunId || enrichmentId === activeRunId) {
        activeRunId = enrichmentId;
        stageFromJob(data);
      }
    } else if (contextId && method === 'PUT') {
      if (response.ok) {
        const bundle = parseBody(options);
        const count = Array.isArray(bundle?.assets) ? bundle.assets.length : null;
        setStage('ASSET_CONTEXT', 'complete', count ? `${count} CSV assets saved with customer-declared Criticality and Internet Facing.` : 'Customer asset context saved.');
      } else setStage('ASSET_CONTEXT', 'failed', data?.detail || `Customer context save failed (HTTP ${response.status}).`);
    } else if (analysesId && method === 'POST') {
      if (response.ok && data?.contractId === ANALYSIS_CONTRACT) {
        analysisId = String(data.analysisId || '');
        priorityUrl = String(data.priority || '');
        setStage('ANALYSIS', 'complete', `Immutable analysis ${shortId(analysisId)} created from the saved run evidence.`);
        setStage('PRIORITY', 'ready', 'Analysis is ready; treatment priority will be materialized next.');
      } else if (!response.ok) setStage('ANALYSIS', 'failed', data?.detail || `Contextual analysis failed (HTTP ${response.status}).`);
    } else if (isPriority) {
      if (response.ok && data?.contractId === PRIORITY_CONTRACT) {
        const ranked = data?.rankedRows ?? data?.rows;
        setStage('PRIORITY', 'complete', ranked != null ? `Pareto treatment priority materialized for ${ranked} rankable finding rows.` : 'Pareto treatment priority materialized.');
      } else if (!response.ok) setStage('PRIORITY', 'failed', data?.detail || `Priority calculation failed (HTTP ${response.status}).`);
    } else if (readinessPath(path) && method === 'GET') {
      if (response.ok && data?.contractId === READINESS_CONTRACT) setStage('RISK', 'ready', readinessDetail(data));
      else if (!response.ok) setStage('RISK', 'failed', data?.detail || `Risk readiness failed (HTTP ${response.status}).`);
    } else if (riskPath(path) && method === 'POST') {
      if (response.ok && data?.contractId === RISK_CONTRACT && data?.status === 'COMPLETE') {
        setStage('RISK', 'complete', `${data.methodId || 'Selected risk method'} calculated on native scale ${data.nativeScale || 'defined by the method'}.`);
      } else if (!response.ok) setStage('RISK', 'failed', data?.detail || `Risk calculation failed (HTTP ${response.status}).`);
    } else if (riskReportPath(path) && method === 'GET' && response.ok && data?.contractId === REPORT_CONTRACT) {
      setStage('RISK', 'complete', reportDetail(data));
    }
    return response;
  };

  function shortId(value) {
    const text = String(value || '');
    return text.length > 12 ? `${text.slice(0, 8)}…` : text || '—';
  }

  function statusLabel(status) {
    return {complete: 'Completed', running: 'Running', ready: 'Ready', waiting: 'Waiting', failed: 'Blocked'}[status] || 'Waiting';
  }

  function statusGlyph(status) {
    return {complete: '✓', running: '●', ready: '◉', waiting: '○', failed: '!'}[status] || '○';
  }

  function elapsedText(entry) {
    if (!entry?.startedAt || entry.status !== 'running') return '';
    const seconds = Math.max(0, Math.floor((Date.now() - Number(entry.startedAt)) / 1000));
    if (seconds < 60) return `${seconds}s`;
    return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  }

  function currentHeadline() {
    const failed = STAGE_ORDER.find(stage => state.get(stage)?.status === 'failed');
    if (failed) return `${STAGE_LABELS[failed]} needs attention`;
    const running = STAGE_ORDER.find(stage => state.get(stage)?.status === 'running');
    if (running) return `${STAGE_LABELS[running]} is running`;
    const ready = [...STAGE_ORDER].reverse().find(stage => state.get(stage)?.status === 'ready');
    if (ready) return `${STAGE_LABELS[ready]} is ready for your input`;
    if (STAGE_ORDER.every(stage => state.get(stage)?.status === 'complete')) return 'Run complete';
    return 'Run progress';
  }

  function element(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value == null || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else node.setAttribute(key, String(value));
    }
    children.flat().forEach(child => { if (child != null && child !== false) node.append(child instanceof Node ? child : document.createTextNode(String(child))); });
    return node;
  }

  function step(stage) {
    const entry = state.get(stage) || fresh();
    const timing = elapsedText(entry);
    return element('li', {class: `csv-activity-step is-${entry.status}`, 'data-activity-stage': stage},
      element('div', {class: 'csv-activity-step-head'},
        element('span', {class: 'csv-activity-glyph', 'aria-hidden': 'true', text: statusGlyph(entry.status)}),
        element('div', {}, element('strong', {text: STAGE_LABELS[stage]}), element('span', {class: 'csv-activity-state', text: statusLabel(entry.status)}))),
      element('p', {text: entry.detail}),
      timing ? element('small', {text: `Elapsed ${timing}`}) : null
    );
  }

  function activityHost() {
    if (!pageSupportsActivity()) return null;
    const root = document.getElementById('page-content');
    const header = root?.querySelector('.page-header');
    if (!root || !header) return null;
    let panel = root.querySelector('[data-csv-run-activity]');
    if (!panel) {
      panel = element('section', {'data-csv-run-activity': 'true', class: 'panel csv-activity-panel', role: 'status', 'aria-live': 'polite', 'aria-atomic': 'false'},
        element('div', {class: 'panel-header'},
          element('div', {}, element('div', {class: 'csv-activity-eyebrow', text: 'Live workflow'}), element('h2', {class: 'panel-title', text: 'Run progress'}), element('p', {class: 'panel-subtitle', 'data-activity-headline': 'true'})),
          element('div', {class: 'csv-activity-live', 'aria-label': 'Live run status', text: '● Live'})),
        element('div', {class: 'panel-body'}, element('ol', {class: 'csv-activity-steps', 'data-activity-steps': 'true'}))
      );
      header.insertAdjacentElement('afterend', panel);
    }
    return panel;
  }

  function suppressLegacyEnrichmentPanel() {
    const panel = document.querySelector('[data-csv-first-job-status]');
    if (panel) {
      panel.hidden = true;
      panel.setAttribute('aria-hidden', 'true');
      panel.dataset.supersededByRunActivity = 'true';
    }
  }

  function updateContextFromEditor() {
    const panel = document.querySelector('[data-customer-asset-setup]');
    if (!panel || !activeRunId) return;
    if (panel.dataset.customerBundlePersisted === 'true') {
      let count = null;
      try { count = typeof panel.rbvmCustomerAssetCount === 'function' ? Number(panel.rbvmCustomerAssetCount()) : null; } catch (_) {}
      setStage('ASSET_CONTEXT', 'complete', count ? `${count} CSV assets have saved Criticality and Internet Facing.` : 'Customer asset context is saved.');
      return;
    }
    try {
      if (typeof panel.rbvmReadCustomerAssets === 'function') {
        const assets = panel.rbvmReadCustomerAssets();
        if (Array.isArray(assets) && assets.length) {
          const incomplete = assets.filter(asset => String(asset.assetCriticality || 'UNKNOWN') === 'UNKNOWN' || String(asset.internetFacing || 'UNKNOWN') === 'UNKNOWN').length;
          setStage('ASSET_CONTEXT', 'ready', incomplete ? `${incomplete} of ${assets.length} CSV assets still need Criticality and/or Internet Facing.` : `${assets.length} CSV assets are filled in; save customer context to continue.`);
        }
      }
    } catch (_) {
      // The editor may be between bounded-page renders; the save path remains authoritative.
    }
  }

  function render() {
    const locationRun = runIdFromLocation();
    if (locationRun && locationRun !== activeRunId) reset(locationRun);
    else if (!locationRun && location.pathname.replace(/\/+$/, '') === '/' && activeRunId) reset('');
    if (!state.size) reset(locationRun);
    updateContextFromEditor();
    const panel = activityHost();
    if (!panel) return;
    const headline = panel.querySelector('[data-activity-headline]');
    const steps = panel.querySelector('[data-activity-steps]');
    if (headline) headline.textContent = `${currentHeadline()}${activeRunId ? ` · run ${shortId(activeRunId)}` : ''}. Status comes from the current browser action and server responses; no percentage is fabricated.`;
    if (steps) steps.replaceChildren(...STAGE_ORDER.map(step));
    suppressLegacyEnrichmentPanel();
    const anyRunning = STAGE_ORDER.some(stage => state.get(stage)?.status === 'running');
    if (anyRunning && elapsedTimer === null) elapsedTimer = window.setInterval(() => schedule(), 1000);
    if (!anyRunning && elapsedTimer !== null) { window.clearInterval(elapsedTimer); elapsedTimer = null; }
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; render(); });
  }

  document.addEventListener('change', event => {
    const target = event.target;
    if (target instanceof HTMLInputElement && target.type === 'file' && target.closest('[data-csv-first-import]') && target.files?.length) {
      setStage('UPLOAD', 'ready', `${target.files[0].name} selected. Start enrichment to parse the CSV scope.`);
    }
    if (target instanceof Element && target.matches('[data-customer-field="assetCriticality"], [data-customer-field="internetFacing"]')) schedule();
  }, true);

  document.addEventListener('input', event => {
    const target = event.target;
    if (target instanceof Element && target.matches('[data-customer-field="assetCriticality"], [data-customer-field="internetFacing"]')) schedule();
  }, true);

  document.addEventListener('click', event => {
    const target = event.target instanceof Element ? event.target.closest('button') : null;
    if (!target) return;
    const label = target.textContent.trim();
    if (label === 'Enrich CSV & continue to Assets') setStage('UPLOAD', 'running', 'Reading the CSV, validating CVEs and identifying the fixed asset population…');
    else if (label === 'Review Findings') {
      setStage('ANALYSIS', 'running', 'Creating the immutable contextual analysis from saved customer context…');
      setStage('PRIORITY', 'waiting', 'Waiting for contextual analysis.');
      setStage('RISK', 'waiting', 'Waiting for contextual analysis.');
    } else if (label === 'Calculate selected risk') setStage('RISK', 'running', 'Submitting the explicitly selected risk method to the server…');
  }, true);

  new MutationObserver(schedule).observe(document.getElementById('rbvm-app') || document.documentElement, {childList: true, subtree: true, attributes: true, attributeFilter: ['data-customer-bundle-persisted']});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  reset(runIdFromLocation());
  schedule();
})();
