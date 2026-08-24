(() => {
  'use strict';

  const CONTRACT = 'CSV_RUN_DECISION_VISUALS_MOUNT_V2';
  const UUID = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
  let queued = false;
  let generation = 0;

  document.documentElement.dataset.csvRunDecisionVisualsMount = CONTRACT;

  const h = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key in node && !key.startsWith('aria') && !key.startsWith('data-')) node[key] = value;
      else node.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  };

  function visualRows(rows) {
    return rows.map(row => {
      const value = {...row};
      if (!String(value.EPSS_Probability || '').trim()) value.EPSS_Probability = 'MISSING';
      if (value.CVSS4_Context_Score_Status !== 'CALCULATED_FIRST_REFERENCE_COMPATIBLE' || !String(value.CVSS4_Context_Score || '').trim()) value.CVSS4_Context_Score = 'MISSING';
      if (value.RBVM_MVP_Priority_Status !== 'RANKED_RELATIVE_ONLY') {
        value.RBVM_MVP_Priority_Dominates = 'MISSING';
        value.RBVM_MVP_Priority_Dominated_By = 'MISSING';
      }
      return value;
    });
  }

  function identifiers(panel) {
    const runId = new URLSearchParams(location.search).get('runId') || '';
    if (!new RegExp(`^${UUID}$`).test(runId)) return null;
    const subtitle = panel.querySelector('.panel-subtitle')?.textContent || '';
    const match = subtitle.match(new RegExp(`analysis\\s+(${UUID})`, 'i'));
    if (!match) return null;
    return {runId, analysisId: match[1]};
  }

  async function loadJson(path, label) {
    const response = await fetch(path, {cache: 'no-store'});
    if (!response.ok) throw new Error(`${label} could not be loaded (HTTP ${response.status}).`);
    return response.json();
  }

  async function mount(panel) {
    if (panel.dataset.runvizState === 'loading' || panel.dataset.runvizState === 'ready') return;
    const ids = identifiers(panel);
    if (!ids || !window.rbvmCsvRunVisuals?.render) return;
    const stack = panel.querySelector('.panel-body > .stack');
    const metrics = stack?.querySelector('.metrics');
    if (!stack || !metrics) return;

    panel.dataset.runvizState = 'loading';
    const current = ++generation;
    const loading = h('div', {class: 'runviz-loading', text: 'Loading bounded decision visualizations…'});
    metrics.insertAdjacentElement('afterend', loading);

    try {
      let rows = Array.isArray(panel.rbvmPriorityPreviewRows) ? panel.rbvmPriorityPreviewRows : null;
      let report = panel.rbvmPriorityReport || null;
      let admission = panel.rbvmMethodAdmission || null;
      const priorityRoot = `/api/v1/csv-first-priorities/${encodeURIComponent(ids.runId)}/${encodeURIComponent(ids.analysisId)}`;
      const analysisRoot = `/api/v1/csv-first-enrichments/${encodeURIComponent(ids.runId)}/analyses/${encodeURIComponent(ids.analysisId)}`;

      // The review panel owns a bounded priority preview. Reuse that exact array instead of
      // downloading/parsing the immutable priority CSV a second time. Only compact JSON
      // reports are fetched as a compatibility fallback for older review panels.
      const requests = [];
      if (!report) requests.push(loadJson(`${priorityRoot}/report`, 'MVP priority report').then(value => { report = value; }));
      if (!admission) requests.push(loadJson(`${analysisRoot}/method-admission`, 'Method-admission report').then(value => { admission = value; }));
      await Promise.all(requests);
      if (!rows) {
        loading.replaceWith(h('div', {class: 'callout callout-warning', text: 'Decision visualization rows are unavailable. Reopen Review Findings to build the bounded preview; complete immutable artifacts remain downloadable.'}));
        panel.dataset.runvizState = 'ready';
        return;
      }
      if (current !== generation || !panel.isConnected) return;
      const visual = window.rbvmCsvRunVisuals.render(visualRows(rows), report, admission);
      if (panel.rbvmPriorityPreviewTruncated === true) visual.prepend(h('div', {class: 'callout callout-info', text: `Visual plots use the same bounded ${rows.length}-row browser preview. Report-level counts remain sourced from the complete immutable priority report.`}));
      loading.replaceWith(visual);
      panel.dataset.runvizState = 'ready';
    } catch (error) {
      if (current !== generation || !panel.isConnected) return;
      loading.replaceWith(h('div', {class: 'callout callout-warning', text: `Decision visualizations could not be loaded: ${error.message}`}));
      panel.dataset.runvizState = 'ready';
    }
  }

  function scan() { for (const panel of document.querySelectorAll('[data-csv-run-review]')) mount(panel); }
  function schedule() { if (queued) return; queued = true; queueMicrotask(() => { queued = false; scan(); }); }
  const observerRoot = document.getElementById('rbvm-app') || document.documentElement;
  new MutationObserver(schedule).observe(observerRoot, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
