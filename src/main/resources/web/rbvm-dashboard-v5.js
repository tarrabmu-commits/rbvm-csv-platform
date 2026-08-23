(() => {
  'use strict';

  const CONTRACT = 'RBVM_DASHBOARD_V5_LIFECYCLE_VIEW';
  const PAGE_SIZE = 100;
  const MAX_PAGES = 60;
  const WEEKS = 12;
  let queued = false;
  let generation = 0;

  document.documentElement.dataset.dashboardV5Contract = CONTRACT;

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

  const svg = (tag, attrs = {}, ...children) => {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      node.setAttribute(key, String(value));
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child);
    }
    return node;
  };

  const num = value => Number(value ?? 0).toLocaleString('en-US');
  const title = value => String(value || '').toLowerCase().replace(/(^|[_\s-])\w/g, part => part.toUpperCase()).replaceAll('_', ' ');

  async function json(path) {
    const response = await fetch(path, {cache: 'no-store'});
    if (!response.ok) throw new Error(`Dashboard V5 source failed (HTTP ${response.status})`);
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

  function panel(name, subtitle, body, badge = '') {
    return h('section', {class: 'v4-card v5-card'},
      h('div', {class: 'v4-card-header'},
        h('div', {}, h('h2', {text: name}), h('p', {text: subtitle})),
        badge ? h('span', {class: 'v4-standard-badge', text: badge}) : null
      ),
      h('div', {class: 'v4-card-body'}, body)
    );
  }

  function countBy(rows, getter) {
    const out = new Map();
    for (const row of rows) {
      const key = getter(row) || 'UNKNOWN';
      out.set(key, (out.get(key) || 0) + 1);
    }
    return out;
  }

  function donut(items, centerValue, centerLabel, ariaLabel) {
    const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
    if (!total) return h('p', {class: 'v4-muted', text: 'No data available.'});
    const r = 70;
    const circumference = 2 * Math.PI * r;
    let offset = 0;
    const chart = svg('svg', {viewBox: '0 0 220 220', class: 'v5-donut', role: 'img', 'aria-label': ariaLabel});
    chart.append(svg('circle', {cx: 110, cy: 110, r, fill: 'none', 'stroke-width': 26, class: 'v5-donut-track'}));
    for (const item of items) {
      const value = Number(item.value || 0);
      if (!value) continue;
      const length = circumference * value / total;
      const segment = svg('circle', {
        cx: 110, cy: 110, r, fill: 'none', 'stroke-width': 26,
        class: `v5-donut-segment ${item.css || ''}`.trim(),
        'stroke-dasharray': `${length} ${circumference - length}`,
        'stroke-dashoffset': -offset,
        transform: 'rotate(-90 110 110)'
      });
      segment.append(svg('title', {}, document.createTextNode(`${item.label}: ${num(value)}`)));
      chart.append(segment);
      offset += length;
    }
    chart.append(svg('text', {x: 110, y: 104, 'text-anchor': 'middle', class: 'v5-donut-value'}, document.createTextNode(String(centerValue))));
    chart.append(svg('text', {x: 110, y: 127, 'text-anchor': 'middle', class: 'v5-donut-label'}, document.createTextNode(centerLabel)));
    return h('div', {class: 'v5-donut-wrap'}, chart,
      h('div', {class: 'v5-legend'}, ...items.map(item =>
        h('span', {}, h('i', {class: `v5-legend-dot ${item.css || ''}`.trim()}), `${item.label} · ${num(item.value)}`)
      ))
    );
  }

  function workflowState(cases) {
    const counts = countBy(cases, row => String(row.status || 'UNKNOWN').toUpperCase());
    const items = [
      ['OPEN', 'Open', 'v5-status-open'],
      ['SOURCE_RESOLVED', 'Source resolved', 'v5-status-source-resolved'],
      ['ACCEPTED_RISK', 'Accepted risk', 'v5-status-accepted-risk'],
      ['FALSE_POSITIVE', 'False positive', 'v5-status-false-positive'],
      ['CLOSED_MANUAL', 'Closed manual', 'v5-status-closed-manual'],
      ['UNKNOWN', 'Unknown', 'v5-status-unknown'],
    ].map(([key, label, css]) => ({label, value: counts.get(key) || 0, css}));
    return donut(items, num(cases.length), 'retained cases', 'Current canonical case workflow state');
  }

  function startOfUtcWeek(input) {
    const value = new Date(input);
    const day = (value.getUTCDay() + 6) % 7;
    value.setUTCHours(0, 0, 0, 0);
    value.setUTCDate(value.getUTCDate() - day);
    return value;
  }

  function weekKey(value) {
    return startOfUtcWeek(value).toISOString().slice(0, 10);
  }

  function weekLabel(value) {
    return new Intl.DateTimeFormat('en-GB', {day: 'numeric', month: 'short', timeZone: 'UTC'}).format(value);
  }

  function cohortSeries(cases) {
    const thisWeek = startOfUtcWeek(new Date());
    const weeks = [];
    for (let index = WEEKS - 1; index >= 0; index--) {
      const start = new Date(thisWeek);
      start.setUTCDate(start.getUTCDate() - index * 7);
      weeks.push({key: weekKey(start), start, label: weekLabel(start), value: 0});
    }
    const byKey = new Map(weeks.map(row => [row.key, row]));
    let older = 0;
    let invalid = 0;
    for (const row of cases) {
      const parsed = row.firstObservedAt ? new Date(row.firstObservedAt) : null;
      if (!parsed || Number.isNaN(parsed.getTime())) {
        invalid++;
        continue;
      }
      const target = byKey.get(weekKey(parsed));
      if (target) target.value++;
      else if (parsed < weeks[0].start) older++;
    }
    return {weeks, older, invalid};
  }

  function cohortChart(cases) {
    const {weeks, older, invalid} = cohortSeries(cases);
    const width = 760, height = 300, left = 44, right = 18, top = 24, bottom = 52;
    const plotW = width - left - right, plotH = height - top - bottom;
    const max = Math.max(1, ...weeks.map(row => row.value));
    const chart = svg('svg', {viewBox: `0 0 ${width} ${height}`, class: 'v5-cohort-chart', role: 'img', 'aria-label': 'First-observed finding cohorts by week'});

    for (let step = 0; step <= 4; step++) {
      const value = Math.round(max * step / 4);
      const y = top + plotH - plotH * value / max;
      chart.append(svg('line', {x1: left, y1: y, x2: left + plotW, y2: y, class: 'v5-grid-line'}));
      chart.append(svg('text', {x: left - 9, y: y + 4, 'text-anchor': 'end', class: 'v5-axis-text'}, document.createTextNode(String(value))));
    }

    const gap = 8;
    const barW = Math.max(8, plotW / weeks.length - gap);
    weeks.forEach((row, index) => {
      const slot = plotW / weeks.length;
      const x = left + index * slot + (slot - barW) / 2;
      const barH = plotH * row.value / max;
      const y = top + plotH - barH;
      const rect = svg('rect', {x, y, width: barW, height: Math.max(row.value ? 3 : 0, barH), rx: 4, class: 'v5-cohort-bar'});
      rect.append(svg('title', {}, document.createTextNode(`Week of ${row.label}: ${row.value} first-observed finding(s)`)));
      chart.append(rect);
      if (index % 2 === 0 || index === weeks.length - 1) {
        chart.append(svg('text', {x: left + index * slot + slot / 2, y: height - 24, 'text-anchor': 'middle', class: 'v5-axis-text'}, document.createTextNode(row.label)));
      }
    });
    chart.append(svg('text', {x: left + plotW / 2, y: height - 4, 'text-anchor': 'middle', class: 'v5-axis-label'}, document.createTextNode('Week first observed')));

    return h('div', {class: 'v5-cohort-wrap'}, chart,
      h('div', {class: 'v5-chart-notes'},
        h('span', {text: `${num(weeks.reduce((sum, row) => sum + row.value, 0))} first observed in the last ${WEEKS} weeks`}),
        h('span', {text: `${num(older)} retained cases first observed earlier`}),
        invalid ? h('span', {text: `${num(invalid)} rows missing a usable first-observed timestamp`}) : null
      )
    );
  }

  function intelligenceFreshness(summary, cases) {
    const intelSummary = summary.vulnerabilityIntelligence || {};
    const windowHours = Number(intelSummary.freshnessWindowHours || 168);
    const cutoff = Date.now() - windowHours * 3600000;
    const byCve = new Map();
    for (const row of cases) {
      if (!row.cveId || byCve.has(row.cveId)) continue;
      byCve.set(row.cveId, row.vulnerabilityIntelligence || null);
    }
    let fresh = 0, stale = 0, missing = 0;
    for (const value of byCve.values()) {
      if (!value?.observedAt) {
        missing++;
        continue;
      }
      const parsed = new Date(value.observedAt);
      if (Number.isNaN(parsed.getTime())) {
        missing++;
        continue;
      }
      if (parsed.getTime() >= cutoff) fresh++;
      else stale++;
    }
    const items = [
      {label: `Fresh ≤ ${Math.round(windowHours / 24)}d`, value: fresh, css: 'v5-fresh'},
      {label: 'Stale', value: stale, css: 'v5-stale'},
      {label: 'Missing', value: missing, css: 'v5-missing'},
    ];
    return donut(items, num(byCve.size), 'unique CVEs', 'Vulnerability intelligence freshness');
  }

  function kevDueReference(cases) {
    const unique = new Map();
    for (const row of cases) {
      const intel = row.vulnerabilityIntelligence;
      if (!row.cveId || intel?.knownExploited !== true || unique.has(row.cveId)) continue;
      unique.set(row.cveId, intel.kevDueDate || null);
    }
    if (!unique.size) return h('p', {class: 'v4-muted', text: 'No KEV-listed CVEs are currently available.'});
    const now = new Date();
    now.setHours(0, 0, 0, 0);
    const buckets = [
      {label: 'Past CISA reference date', value: 0, css: 'v5-due-past'},
      {label: '0–7 days', value: 0, css: 'v5-due-soon'},
      {label: '8–30 days', value: 0, css: 'v5-due-next'},
      {label: '31+ days', value: 0, css: 'v5-due-later'},
      {label: 'No usable due date', value: 0, css: 'v5-missing'},
    ];
    for (const due of unique.values()) {
      if (!due) {
        buckets[4].value++;
        continue;
      }
      const parsed = new Date(`${due}T00:00:00`);
      if (Number.isNaN(parsed.getTime())) {
        buckets[4].value++;
        continue;
      }
      const days = Math.floor((parsed.getTime() - now.getTime()) / 86400000);
      if (days < 0) buckets[0].value++;
      else if (days <= 7) buckets[1].value++;
      else if (days <= 30) buckets[2].value++;
      else buckets[3].value++;
    }
    return h('div', {class: 'v5-reference'},
      h('div', {class: 'v5-reference-bars'}, ...buckets.map(item => {
        const total = unique.size || 1;
        const fill = h('span', {class: `v5-reference-fill ${item.css}`});
        fill.style.width = `${item.value / total * 100}%`;
        return h('div', {class: 'v5-reference-row'}, h('span', {text: item.label}), h('span', {class: 'v5-reference-track'}, fill), h('strong', {text: num(item.value)}));
      })),
      h('p', {class: 'v5-reference-note', text: 'CISA KEV due dates originate from U.S. federal BOD 22-01 remediation requirements. They are shown as external reference dates only and are not treated as the customer’s SLA.'})
    );
  }

  function legacyGuardrail(summary) {
    const intel = summary.vulnerabilityIntelligence || {};
    if (!intel.priorityDistributionDeprecated && !intel.priorityDistributionSemantics) return null;
    return h('div', {class: 'v5-semantic-guardrail'},
      h('strong', {text: 'Legacy priority heuristic isolated'}),
      h('p', {text: 'The historical V2 intelligence priorityTier/priorityDistribution remains available only for backward compatibility. Dashboard treatment priority does not consume it; RBVM_MVP_PRIORITY_POLICY_V1 or another explicitly admitted methodology must provide the decision output.'}),
      intel.priorityDistributionSemantics ? h('code', {text: intel.priorityDistributionSemantics}) : null
    );
  }

  async function patch() {
    const root = document.getElementById('page-content');
    const heading = root?.querySelector('.page-title');
    if (!root || heading?.textContent.trim() !== 'Overview') return;
    const host = root.querySelector('[data-rbvm-dashboard-v3][data-rbvm-dashboard-v4="true"]');
    const grid = host?.querySelector('.v4-grid');
    if (!host || !grid || host.dataset.rbvmDashboardV5 === 'true' || host.dataset.rbvmDashboardV5 === 'loading') return;

    host.dataset.rbvmDashboardV5 = 'loading';
    const currentGeneration = ++generation;
    const loading = panel('Lifecycle & time evidence', 'Loading standards-safe workflow and temporal views…', h('div', {class: 'v5-loading', text: 'Loading…'}), 'NIST SP 800-40');
    grid.append(loading);

    try {
      const [summary, cases] = await Promise.all([json('/api/v1/catalog/summary'), allCases()]);
      if (generation !== currentGeneration || !host.isConnected) return;
      loading.remove();
      grid.append(
        panel('Current workflow state', 'Current canonical disposition only. “Source resolved” and manual closure are not silently re-labeled as verified remediation.', workflowState(cases), 'NIST CSF / SP 800-40'),
        panel('First-observed cohorts', `Weekly first-observed counts for retained canonical cases. This is detection cadence, not an Active/New/Remediated backlog reconstruction.`, cohortChart(cases), 'NIST SP 800-40'),
        panel('Intelligence freshness', 'Freshness of vulnerability intelligence using the canonical freshness window; stale and missing evidence remain visible.', intelligenceFreshness(summary, cases), 'NIST CSF 2.0'),
        panel('CISA KEV due-date reference', 'External KEV reference dates for confirmed-exploitation CVEs; not a customer SLA or internal treatment deadline.', kevDueReference(cases), 'CISA KEV'),
        panel('Semantic guardrail', 'Backward compatibility is kept without allowing the historic threshold classifier to masquerade as the current RBVM priority method.', legacyGuardrail(summary) || h('p', {class: 'v4-muted', text: 'No legacy heuristic semantics were exposed by this runtime.'}), 'RBVM policy')
      );
      host.dataset.rbvmDashboardV5 = 'true';
    } catch (error) {
      loading.querySelector('.v4-card-body')?.replaceChildren(h('div', {class: 'callout callout-warning', text: `Lifecycle visuals could not be loaded: ${error.message}`}));
      host.dataset.rbvmDashboardV5 = 'true';
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
