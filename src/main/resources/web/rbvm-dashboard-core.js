(() => {
  'use strict';

  const CONTRACT = 'RBVM_DASHBOARD_CORE_V1';
  let queued = false;
  let generation = 0;
  document.documentElement.dataset.dashboardCoreContract = CONTRACT;

  const h = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'style') node.style.cssText = String(value);
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
  const pct = value => Number.isFinite(Number(value)) ? `${(Number(value) * 100).toFixed(1)}%` : '—';

  async function json(path) {
    const response = await fetch(path, {cache: 'no-store'});
    if (!response.ok) throw new Error(`Dashboard source failed (HTTP ${response.status})`);
    return response.json();
  }

  function metric(label, value, meta = '') {
    return h('div', {class: 'metric'}, h('div', {class: 'metric-label', text: label}), h('div', {class: 'metric-value', text: value}), meta ? h('div', {class: 'metric-meta', text: meta}) : null);
  }
  function card(title, subtitle, body, wide = false) {
    return h('section', {class: `panel dashboard-core-card${wide ? ' dashboard-core-wide' : ''}`},
      h('div', {class: 'panel-header'}, h('div', {}, h('h2', {class: 'panel-title', text: title}), h('p', {class: 'panel-subtitle', text: subtitle}))),
      h('div', {class: 'panel-body'}, body));
  }
  function counts(rows, getter) {
    const map = new Map();
    for (const row of rows) {
      const key = getter(row) || 'UNKNOWN';
      map.set(key, (map.get(key) || 0) + 1);
    }
    return map;
  }
  function bars(items) {
    const max = Math.max(1, ...items.map(item => Number(item.value) || 0));
    return h('div', {class: 'dashboard-core-bars'}, ...items.map(item => {
      const value = Number(item.value) || 0;
      return h('div', {class: 'dashboard-core-bar-row'},
        h('span', {text: item.label}),
        h('span', {class: 'dashboard-core-bar-track'}, h('span', {class: `dashboard-core-bar-fill ${item.css || ''}`, style: `width:${value ? Math.max(3, value / max * 100) : 0}%`})),
        h('strong', {text: item.format ? item.format(value) : num(value)}));
    }));
  }
  function ring(label, value) {
    const normalized = Math.max(0, Math.min(100, Number(value) || 0));
    return h('div', {class: 'dashboard-core-ring', style: `--value:${normalized}`},
      h('div', {class: 'dashboard-core-ring-face'}, h('strong', {text: `${Math.round(normalized)}%`}), h('span', {text: label})));
  }

  function render(host, summary, page) {
    const rows = page.cases || [];
    const intelSummary = summary.vulnerabilityIntelligence || {};
    const severity = counts(rows, row => upper(row.currentSeverity));
    const kev = rows.filter(row => row.vulnerabilityIntelligence?.knownExploited === true);
    const cvssCoverage = rows.length ? rows.filter(row => row.vulnerabilityIntelligence?.cvssBaseScore != null).length / rows.length * 100 : 0;
    const epssCoverage = rows.length ? rows.filter(row => row.vulnerabilityIntelligence?.epssProbability != null).length / rows.length * 100 : 0;
    const kevCoverage = rows.length ? rows.filter(row => typeof row.vulnerabilityIntelligence?.knownExploited === 'boolean').length / rows.length * 100 : 0;
    const topAssets = [...counts(rows, row => row.assetName || 'Unknown').entries()].map(([label, value]) => ({label, value})).sort((a,b) => b.value - a.value || labelCompare(a.label,b.label)).slice(0,10);
    const topEpss = rows.map(row => ({label: `${row.cveId || 'Unknown'} · ${row.assetName || 'Unknown'}`, value: Number(row.vulnerabilityIntelligence?.epssProbability), kev: row.vulnerabilityIntelligence?.knownExploited === true})).filter(item => Number.isFinite(item.value)).sort((a,b) => b.value - a.value).slice(0,10).map(item => ({...item, value: item.value * 100, format: value => `${value.toFixed(1)}%`, css: item.kev ? 'dashboard-core-danger' : ''}));

    host.replaceChildren(
      h('div', {class: 'dashboard-core-scope'}, h('strong', {text: 'Current canonical catalog'}), h('span', {text: 'CSV-first runs remain run-scoped until explicit canonical handoff.'})),
      h('div', {class: 'metrics dashboard-core-kpis'},
        metric('Current findings', num(summary.openCases ?? 0), 'Full canonical catalog'),
        metric('Exposure instances', num(summary.exposures ?? 0), 'Full canonical catalog'),
        metric('Affected assets', num(summary.assets ?? 0), 'Full canonical catalog'),
        metric('Known exploited CVEs', num(intelSummary.knownExploitedVulnerabilities ?? 0), 'CISA KEV · full catalog'),
        metric('Enriched CVEs', num(intelSummary.enrichedVulnerabilities ?? 0), 'Public intelligence coverage'),
        metric('Stale CVEs', num(intelSummary.staleVulnerabilities ?? 0), 'Needs intelligence refresh')
      ),
      h('div', {class: 'dashboard-core-grid'},
        card('Current page decision signals', `Visuals below use the bounded first ${rows.length} findings only; they are never presented as full-catalog aggregates.`, bars(['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].map(key => ({label:key, value:severity.get(key)||0})))),
        card('Confirmed exploitation on current page', 'CISA KEV evidence remains separate from technical severity.', bars([{label:'KEV listed', value:kev.length, css:'dashboard-core-danger'},{label:'Not listed / not established', value:Math.max(0, rows.length-kev.length)}])),
        card('Evidence readiness on current page', 'Missing evidence remains missing; it is never converted to zero.', h('div', {class:'dashboard-core-rings'}, ring('CVSS',cvssCoverage), ring('EPSS',epssCoverage), ring('KEV',kevCoverage))),
        card('Most affected assets on current page', 'Operational concentration only; not mission impact or Organizational Risk.', topAssets.length ? bars(topAssets) : h('p',{text:'No current findings available.'})),
        card('Highest EPSS on current page', 'Native FIRST EPSS probability; no threshold or multiplication is introduced.', topEpss.length ? bars(topEpss) : h('p',{text:'No EPSS values available.'})),
        card('Product boundary', 'One dashboard, one scope, explicit evidence semantics.', h('div',{class:'callout callout-info',text:'Treatment Priority remains an explicit run-level decision output. Organizational Risk remains NON_COMPUTABLE unless an admitted methodology has all required evidence.'}), true)
      )
    );
  }

  function labelCompare(a,b) { return String(a).localeCompare(String(b)); }

  async function patch() {
    const root = document.getElementById('page-content');
    const heading = root?.querySelector('.page-title');
    if (!root || heading?.textContent.trim() !== 'Overview') return;
    if (root.dataset.dashboardCore === 'ready' || root.dataset.dashboardCore === 'loading') return;
    // Wait until the core SPA completed its own Overview render so this single
    // enhancement does not race the route renderer.
    if (root.querySelector('.skeleton')) return;

    root.dataset.dashboardCore = 'loading';
    const current = ++generation;
    heading.textContent = 'Dashboard';
    const description = root.querySelector('.page-description');
    if (description) description.textContent = 'Current canonical catalog with bounded decision visuals and explicit run/catalog scope.';
    const header = root.querySelector('.page-header');
    for (const child of [...root.children]) if (child !== header) child.remove();
    const host = h('div', {class:'dashboard-core-root'}, h('div',{class:'skeleton'}));
    root.append(host);
    try {
      const [summary, page] = await Promise.all([
        json('/api/v1/catalog/summary'),
        json('/api/v1/cases?limit=100')
      ]);
      if (current !== generation || !host.isConnected) return;
      render(host, summary, page);
      root.dataset.dashboardCore = 'ready';
    } catch (error) {
      if (current !== generation || !host.isConnected) return;
      host.replaceChildren(h('div',{class:'callout callout-warning',text:`Dashboard could not be loaded: ${error.message}`}));
      root.dataset.dashboardCore = 'ready';
    }
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; patch(); });
  }
  new MutationObserver(schedule).observe(document.getElementById('rbvm-app') || document.documentElement, {childList:true,subtree:true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
