(() => {
  'use strict';

  const CONTRACT = 'CSV_RUN_DECISION_VISUALS_MOUNT_V1';
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

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let cell = '';
    let quoted = false;
    for (let index = 0; index < text.length; index++) {
      const ch = text[index];
      if (quoted) {
        if (ch === '"') {
          if (text[index + 1] === '"') { cell += '"'; index++; }
          else quoted = false;
        } else cell += ch;
        continue;
      }
      if (ch === '"') quoted = true;
      else if (ch === ',') { row.push(cell); cell = ''; }
      else if (ch === '\n') {
        row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
        rows.push(row); row = []; cell = '';
      } else cell += ch;
    }
    if (quoted) throw new Error('Priority CSV contains an unterminated quoted field.');
    if (cell.length || row.length) {
      row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
      rows.push(row);
    }
    const meaningful = rows.filter(values => values.some(value => String(value).trim() !== ''));
    if (meaningful.length < 2) throw new Error('Priority CSV contains no finding rows.');
    const headers = meaningful[0].map((value, index) => index === 0 ? String(value).replace(/^\uFEFF/, '') : String(value));
    return meaningful.slice(1).map(values => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ''])));
  }

  function visualRows(rows) {
    return rows.map(row => {
      const value = {...row};
      if (!String(value.EPSS_Probability || '').trim()) value.EPSS_Probability = 'MISSING';
      if (value.CVSS4_Context_Score_Status !== 'CALCULATED_FIRST_REFERENCE_COMPATIBLE'
          || !String(value.CVSS4_Context_Score || '').trim()) {
        value.CVSS4_Context_Score = 'MISSING';
      }
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
    const loading = h('div', {class: 'runviz-loading', text: 'Loading immutable decision visualizations…'});
    metrics.insertAdjacentElement('afterend', loading);

    const priorityRoot = `/api/v1/csv-first-priorities/${encodeURIComponent(ids.runId)}/${encodeURIComponent(ids.analysisId)}`;
    const analysisRoot = `/api/v1/csv-first-enrichments/${encodeURIComponent(ids.runId)}/analyses/${encodeURIComponent(ids.analysisId)}`;
    try {
      const [csvResponse, report, admission] = await Promise.all([
        fetch(`${priorityRoot}/csv`, {cache: 'no-store'}),
        loadJson(`${priorityRoot}/report`, 'MVP priority report'),
        loadJson(`${analysisRoot}/method-admission`, 'Method-admission report'),
      ]);
      if (!csvResponse.ok) throw new Error(`Priority-ranked CSV could not be loaded (HTTP ${csvResponse.status}).`);
      const rows = visualRows(parseCsv(await csvResponse.text()));
      if (current !== generation || !panel.isConnected) return;
      const visual = window.rbvmCsvRunVisuals.render(rows, report, admission);
      loading.replaceWith(visual);
      panel.dataset.runvizState = 'ready';
    } catch (error) {
      if (current !== generation || !panel.isConnected) return;
      loading.replaceWith(h('div', {class: 'callout callout-warning', text: `Decision visualizations could not be loaded: ${error.message}`}));
      panel.dataset.runvizState = 'ready';
    }
  }

  function scan() {
    for (const panel of document.querySelectorAll('[data-csv-run-review]')) mount(panel);
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      scan();
    });
  }

  new MutationObserver(schedule).observe(document.documentElement, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
