(() => {
  'use strict';

  const CONTRACT = 'RBVM_DASHBOARD_V3';
  const PAGE_SIZE = 100;
  const MAX_PAGES = 60;
  let generation = 0;
  let queued = false;

  document.documentElement.dataset.dashboardContract = CONTRACT;

  const h = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
      else if (key in node && !key.startsWith('aria') && !key.startsWith('data-')) node[key] = value;
      else node.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  };

  const num = value => Number(value ?? 0).toLocaleString('en-US');
  const upper = value => String(value || 'UNKNOWN').trim().toUpperCase();
  const title = value => String(value || '').toLowerCase().replace(/(^|[_\s-])\w/g, part => part.toUpperCase()).replaceAll('_', ' ');

  async function json(path) {
    const response = await fetch(path, {cache: 'no-store'});
    if (!response.ok) throw new Error(`Dashboard source failed (HTTP ${response.status})`);
    return response.json();
  }

  async function allCases() {
    const rows = [];
    const seen = new Set();
    let cursor = null;
    for (let page = 0; page < MAX_PAGES; page++) {
      const params = new URLSearchParams({limit: String(PAGE_SIZE)});
      if (cursor) params.set('cursor', cursor);
      const payload = await json(`/api/v1/cases?${params}`);
      for (const row of payload.cases || []) {
        const key = row.caseId || `${row.assetName}|${row.cveId}`;
        if (!seen.has(key)) {
          seen.add(key);
          rows.push(row);
        }
      }
      cursor = payload.nextCursor || null;
      if (!cursor) break;
    }
    return rows;
  }

  async function allManagedAssets() {
    const rows = [];
    let after = null;
    try {
      for (let page = 0; page < MAX_PAGES; page++) {
        const params = new URLSearchParams({limit: String(PAGE_SIZE), lifecycle: 'ALL'});
        if (after) params.set('afterId', after);
        const payload = await json(`/api/v1/managed-assets?${params}`);
        rows.push(...(payload.assets || []));
        after = payload.nextAfterId || null;
        if (!after) break;
      }
    } catch (_) {
      return [];
    }
    return rows;
  }

  function countBy(rows, getter) {
    const out = new Map();
    for (const row of rows) {
      const key = getter(row) || 'UNKNOWN';
      out.set(key, (out.get(key) || 0) + 1);
    }
    return out;
  }

  function topCounts(rows, getter, limit = 10) {
    return [...countBy(rows, getter).entries()]
      .map(([label, value]) => ({label, value}))
      .sort((a, b) => b.value - a.value || String(a.label).localeCompare(String(b.label)))
      .slice(0, limit);
  }

  function ageDays(value) {
    if (!value) return null;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return null;
    return Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 86400000));
  }

  function metric(label, value, meta = '') {
    return h('div', {class: 'dashboard-metric'},
      h('div', {class: 'dashboard-metric-label', text: label}),
      h('div', {class: 'dashboard-metric-value', text: value}),
      meta ? h('div', {class: 'dashboard-metric-meta', text: meta}) : null
    );
  }

  function panel(name, subtitle, body, wide = false) {
    return h('section', {class: `dashboard-card${wide ? ' dashboard-card-wide' : ''}`},
      h('div', {class: 'dashboard-card-header'},
        h('h2', {text: name}),
        subtitle ? h('p', {text: subtitle}) : null
      ),
      h('div', {class: 'dashboard-card-body'}, body)
    );
  }

  function barList(items, emptyText = 'No data available') {
    if (!items.length || !items.some(item => Number(item.value) > 0)) {
      return h('p', {class: 'dashboard-muted', text: emptyText});
    }
    const max = Math.max(1, ...items.map(item => Number(item.value) || 0));
    return h('div', {class: 'dashboard-bars'}, ...items.map(item => {
      const value = Number(item.value) || 0;
      const fill = h('span', {class: `dashboard-bar-fill ${item.css || ''}`.trim()});
      fill.style.width = `${Math.max(value ? 2 : 0, value / max * 100)}%`;
      return h('div', {class: 'dashboard-bar-row'},
        h('span', {class: 'dashboard-bar-label', text: item.label}),
        h('span', {class: 'dashboard-bar-track'}, fill),
        h('strong', {text: num(value)})
      );
    }));
  }

  function splitMeter(items) {
    const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
    if (!total) return h('p', {class: 'dashboard-muted', text: 'No assessed findings available.'});
    const meter = h('div', {class: 'dashboard-split-meter', role: 'img', 'aria-label': items.map(item => `${item.label} ${item.value}`).join(', ')});
    for (const item of items) {
      const segment = h('span', {class: `dashboard-split-segment ${item.css || ''}`.trim(), title: `${item.label}: ${item.value}`});
      segment.style.width = `${Number(item.value || 0) / total * 100}%`;
      meter.append(segment);
    }
    return h('div', {}, meter, h('div', {class: 'dashboard-legend'}, ...items.map(item =>
      h('span', {}, h('i', {class: `dashboard-legend-dot ${item.css || ''}`.trim()}), `${item.label}: ${num(item.value)}`)
    )));
  }

  function coverage(cases, predicate) {
    if (!cases.length) return 0;
    return Math.round(cases.filter(predicate).length / cases.length * 100);
  }

  function severityRows(cases) {
    const counts = countBy(cases, row => upper(row.currentSeverity));
    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(key => ({
      label: title(key),
      value: counts.get(key) || 0,
      css: `dashboard-severity-${key.toLowerCase()}`,
    }));
  }

  function agingRows(cases) {
    const ages = cases.map(row => ageDays(row.firstObservedAt)).filter(Number.isFinite);
    const ranges = [
      ['0–7 days', 0, 7],
      ['8–30 days', 8, 30],
      ['31–90 days', 31, 90],
      ['91–180 days', 91, 180],
      ['180+ days', 181, Infinity],
    ];
    return ranges.map(([label, min, max]) => ({label, value: ages.filter(value => value >= min && value <= max).length}));
  }

  function criticalityRows(assets) {
    const counts = countBy(assets, asset => upper(asset.currentRevision?.businessCriticality));
    return ['MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'].map(key => ({label: title(key), value: counts.get(key) || 0}));
  }

  function renderDashboard(host, summary, cases, assets) {
    const intel = summary.vulnerabilityIntelligence || {};
    const uniqueCves = new Set(cases.map(row => row.cveId).filter(Boolean)).size;
    const knownExploited = cases.filter(row => row.vulnerabilityIntelligence?.knownExploited === true);
    const notListedOrUnknown = Math.max(0, cases.length - knownExploited.length);
    const criticalHighKev = knownExploited.filter(row => ['CRITICAL', 'HIGH'].includes(upper(row.currentSeverity)));
    const cvssCoverage = coverage(cases, row => row.vulnerabilityIntelligence?.cvssBaseScore != null);
    const epssCoverage = coverage(cases, row => row.vulnerabilityIntelligence?.epssProbability != null);
    const kevCoverage = coverage(cases, row => typeof row.vulnerabilityIntelligence?.knownExploited === 'boolean');
    const missionCritical = assets.filter(asset => upper(asset.currentRevision?.businessCriticality) === 'MISSION_CRITICAL').length;

    host.replaceChildren(
      h('div', {class: 'dashboard-kpis'},
        metric('Current findings', num(summary.openCases ?? cases.length), 'Canonical current cases'),
        metric('Unique CVEs', num(uniqueCves), 'Distinct vulnerability IDs'),
        metric('Exposure instances', num(summary.exposures ?? cases.length), 'Asset × CVE × product'),
        metric('Affected assets', num(summary.assets ?? new Set(cases.map(row => row.assetName)).size), 'Observed assets'),
        metric('Known exploited', num(intel.knownExploitedVulnerabilities ?? new Set(knownExploited.map(row => row.cveId)).size), 'CISA KEV-backed'),
        metric('Mission critical assets', num(missionCritical), assets.length ? 'Customer-managed context' : 'Managed asset context unavailable')
      ),
      h('div', {class: 'dashboard-grid'},
        panel('Current exposure by severity', 'Technical severity distribution; not Organizational Risk.', barList(severityRows(cases))),
        panel('Known exploited signal', 'KEV-listed findings are separated from findings not established as KEV-listed.', splitMeter([
          {label: 'KEV listed', value: knownExploited.length, css: 'dashboard-signal-danger'},
          {label: 'Not listed / not established', value: notListedOrUnknown, css: 'dashboard-signal-neutral'},
        ])),
        panel('Most affected assets', 'Current finding concentration by observed asset.', barList(topCounts(cases, row => row.assetName || 'Unknown', 10))),
        panel('Critical/High + KEV concentration', 'High technical severity intersected with known exploitation; still not a risk score.', barList(topCounts(criticalHighKev, row => row.assetName || 'Unknown', 10), 'No Critical/High KEV-listed findings are currently available.')),
        panel('Finding age distribution', 'Current findings grouped from explicit first-observed timestamps.', barList(agingRows(cases))),
        panel('Managed asset criticality', 'Customer-declared asset importance; not derived from vulnerability severity.', assets.length ? barList(criticalityRows(assets)) : h('p', {class: 'dashboard-muted', text: 'Managed asset context is not available in this runtime.'})),
        panel('Evidence coverage', 'Missing evidence is shown explicitly and is never converted to zero.', h('div', {class: 'dashboard-coverage'},
          metric('CVSS available', `${cvssCoverage}%`),
          metric('EPSS available', `${epssCoverage}%`),
          metric('KEV assessed', `${kevCoverage}%`)
        )),
        panel('Operational trend', 'The legacy VA dashboard tracked New / Remediated / Total over time.', h('div', {class: 'dashboard-callout'},
          h('strong', {text: 'Historical aggregation required'}),
          h('p', {text: 'The current canonical API does not expose a defensible historical backlog series. RBVM will not reconstruct or fabricate New / Remediated / Total from current-state survivors.'}),
          h('a', {href: '/?view=analytics&tab=trend', class: 'button button-secondary', text: 'Open Trend Analytics'})
        )),
        panel('Dashboard semantics', 'Adapted from the VA dashboard without carrying forward unsafe shortcuts.', h('ul', {class: 'dashboard-notes'},
          h('li', {text: '“Exploitable” is represented as CISA KEV known-exploited evidence, not a local CVE text list.'}),
          h('li', {text: 'Asset Criticality remains customer-declared context and is not inferred from CVSS severity.'}),
          h('li', {text: 'No SLA compliance is shown until an explicit RBVM treatment/SLA policy is approved.'}),
          h('li', {text: 'No CVSS × EPSS multiplication, weighted score, or hidden risk label is calculated.'})
        ), true)
      )
    );
  }

  async function patch() {
    const root = document.getElementById('page-content');
    const heading = root?.querySelector('.page-title');
    if (!root || heading?.textContent.trim() !== 'Overview') return;
    if (root.querySelector('[data-rbvm-dashboard-v3]')) return;

    const currentGeneration = ++generation;
    const header = root.querySelector('.page-header');
    if (!header) return;
    for (const sibling of [...root.children]) {
      if (sibling !== header) sibling.remove();
    }

    const host = h('section', {'data-rbvm-dashboard-v3': 'true', class: 'dashboard-root'},
      h('div', {class: 'dashboard-loading', text: 'Loading operational dashboard…'})
    );
    root.append(host);

    try {
      const [summary, cases, assets] = await Promise.all([
        json('/api/v1/catalog/summary'),
        allCases(),
        allManagedAssets(),
      ]);
      if (currentGeneration !== generation || !host.isConnected) return;
      renderDashboard(host, summary, cases, assets);
    } catch (error) {
      if (currentGeneration !== generation || !host.isConnected) return;
      host.replaceChildren(h('div', {class: 'callout callout-warning', text: `Dashboard could not be loaded: ${error.message}`}));
    }
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      patch();
    });
  }

  new MutationObserver(schedule).observe(document.documentElement, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
