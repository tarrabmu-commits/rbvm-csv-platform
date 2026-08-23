(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_ENRICHMENT_JOB_STATUS_UI_V1';
  const ROOT = '/api/v1/csv-first-enrichment-jobs';
  let queued = false;
  let timer = null;
  let activeRunId = '';

  document.documentElement.dataset.csvFirstJobStatusUi = CONTRACT;

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

  function runId() {
    if (location.pathname.replace(/\/+$/, '') !== '/assets') return '';
    return new URLSearchParams(location.search).get('runId') || '';
  }

  function elapsed(createdAt) {
    const value = createdAt ? new Date(createdAt) : null;
    if (!value || Number.isNaN(value.getTime())) return '—';
    const seconds = Math.max(0, Math.floor((Date.now() - value.getTime()) / 1000));
    if (seconds < 60) return `${seconds}s`;
    const minutes = Math.floor(seconds / 60);
    return `${minutes}m ${seconds % 60}s`;
  }

  function metric(label, value) {
    return h('div', {class: 'metric'}, h('div', {class: 'metric-label', text: label}), h('div', {class: 'metric-value', text: value}));
  }

  function reviewControl(enabled, message = '') {
    const button = document.querySelector('[data-review-findings-button]');
    if (!button) return;
    button.disabled = !enabled;
    if (message) button.title = message;
    else button.removeAttribute('title');
  }

  function stageLabel(value) {
    const labels = {
      WAITING_FOR_WORKER: 'Queued',
      COLLECTING_PUBLIC_INTELLIGENCE: 'Collecting NVD · EPSS · KEV · CVE Program',
      COMPLETE: 'Ready for contextual analysis',
      TIMEOUT: 'Timed out',
      ENRICHMENT_FAILED: 'Enrichment failed',
      INTERRUPTED: 'Interrupted',
      INTERNAL_ERROR: 'Internal error',
    };
    return labels[value] || String(value || 'Unknown').replaceAll('_', ' ');
  }

  function render(panel, data) {
    const body = panel.querySelector('.panel-body');
    if (!body) return;
    const status = String(data.status || 'UNKNOWN').toUpperCase();
    const complete = status === 'COMPLETE';
    const failed = status === 'FAILED';
    body.replaceChildren(
      h('div', {class: 'csv-job-status-grid'},
        metric('Job status', status),
        metric('Stage', stageLabel(data.stage)),
        metric('Elapsed', elapsed(data.createdAt))
      ),
      complete
        ? h('div', {class: 'callout callout-info', text: 'Public intelligence enrichment is complete. Review Findings is now available.'})
        : failed
          ? h('div', {class: 'callout callout-warning', text: data.detail || 'Public intelligence enrichment failed.'})
          : h('div', {class: 'csv-job-progress', role: 'progressbar', 'aria-label': 'Public intelligence enrichment in progress'}, h('span')),
      !complete && !failed
        ? h('p', {class: 'csv-job-note', text: 'The browser is free while enrichment continues in the background. Provider work is intentionally shown as indeterminate until provider-level progress is available.'})
        : null
    );
    reviewControl(complete, complete ? '' : failed ? 'Enrichment failed; resolve the job before contextual analysis.' : 'Public intelligence enrichment is still running.');
  }

  async function refresh(panel, id) {
    try {
      const response = await fetch(`${ROOT}/${encodeURIComponent(id)}`, {cache: 'no-store'});
      if (response.status === 404) {
        panel.remove();
        reviewControl(true);
        stopTimer();
        return;
      }
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();
      if (data.contractId !== 'CSV_FIRST_ENRICHMENT_JOB_HTTP_V1' || data.runId !== id) {
        throw new Error('Unexpected enrichment-job status contract.');
      }
      render(panel, data);
      if (data.status === 'QUEUED' || data.status === 'RUNNING') {
        stopTimer();
        timer = window.setTimeout(() => refresh(panel, id), 1500);
      } else stopTimer();
    } catch (error) {
      const body = panel.querySelector('.panel-body');
      if (body) body.replaceChildren(h('div', {class: 'callout callout-warning', text: `Enrichment status could not be loaded: ${error.message}`}));
      reviewControl(false, 'Enrichment status is unavailable.');
      stopTimer();
    }
  }

  function stopTimer() {
    if (timer !== null) window.clearTimeout(timer);
    timer = null;
  }

  function patch() {
    const id = runId();
    if (!id) {
      activeRunId = '';
      stopTimer();
      return;
    }
    const root = document.getElementById('page-content');
    const header = root?.querySelector('.page-header');
    if (!root || !header) return;
    let panel = root.querySelector('[data-csv-first-job-status]');
    if (activeRunId === id && panel) {
      const state = panel.dataset.jobState || '';
      if (state !== 'COMPLETE') reviewControl(false, 'Public intelligence enrichment is still running.');
      return;
    }

    activeRunId = id;
    stopTimer();
    if (!panel) {
      panel = h('section', {'data-csv-first-job-status': 'true', class: 'panel csv-job-panel'},
        h('div', {class: 'panel-header'}, h('div', {}, h('h2', {class: 'panel-title', text: 'Public Intelligence Enrichment'}), h('p', {class: 'panel-subtitle', text: 'Background CSV-run job · NVD, FIRST EPSS, CISA KEV, CVE Program/SSVC and provenance.'}))),
        h('div', {class: 'panel-body'}, h('div', {class: 'csv-job-progress', role: 'progressbar', 'aria-label': 'Loading enrichment job status'}, h('span')))
      );
      header.insertAdjacentElement('afterend', panel);
    }
    reviewControl(false, 'Checking public intelligence enrichment status.');
    refresh(panel, id);
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; patch(); });
  }

  new MutationObserver(schedule).observe(document.getElementById('rbvm-app') || document.documentElement, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
