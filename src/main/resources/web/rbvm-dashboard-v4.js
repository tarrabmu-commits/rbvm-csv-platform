(() => {
  'use strict';

  const CONTRACT = 'RBVM_DASHBOARD_V4_STANDARDS_VIEW';
  const PAGE_SIZE = 100;
  const MAX_PAGES = 60;
  let generation = 0;
  let queued = false;

  document.documentElement.dataset.dashboardV4Contract = CONTRACT;

  const h = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'style') node.style.cssText = String(value);
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
  const pct = value => `${Math.round(Number(value || 0) * 100)}%`;
  const upper = value => String(value || 'UNKNOWN').trim().toUpperCase();
  const title = value => String(value || '').toLowerCase().replace(/(^|[_\s-])\w/g, part => part.toUpperCase()).replaceAll('_', ' ');
  const clamp = (value, min, max) => Math.min(max, Math.max(min, value));

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

  function metric(label, value, meta = '', tone = '') {
    return h('div', {class: `v4-metric ${tone ? `v4-metric-${tone}` : ''}`.trim()},
      h('div', {class: 'v4-metric-label', text: label}),
      h('div', {class: 'v4-metric-value', text: value}),
      meta ? h('div', {class: 'v4-metric-meta', text: meta}) : null
    );
  }

  function panel(name, subtitle, body, options = {}) {
    return h('section', {class: `v4-card${options.wide ? ' v4-card-wide' : ''}${options.hero ? ' v4-card-hero' : ''}`},
      h('div', {class: 'v4-card-header'},
        h('div', {},
          h('h2', {text: name}),
          subtitle ? h('p', {text: subtitle}) : null
        ),
        options.badge ? h('span', {class: 'v4-standard-badge', text: options.badge}) : null
      ),
      h('div', {class: 'v4-card-body'}, body)
    );
  }

  function barList(items, emptyText = 'No data available', format = value => num(value)) {
    if (!items.length || !items.some(item => Number(item.value) > 0)) return h('p', {class: 'v4-muted', text: emptyText});
    const max = Math.max(1, ...items.map(item => Number(item.value) || 0));
    return h('div', {class: 'v4-bars'}, ...items.map(item => {
      const value = Number(item.value) || 0;
      const fill = h('span', {class: `v4-bar-fill ${item.css || ''}`.trim()});
      fill.style.width = `${Math.max(value ? 2 : 0, value / max * 100)}%`;
      return h('div', {class: 'v4-bar-row'},
        h('span', {class: 'v4-bar-label', title: item.label, text: item.label}),
        h('span', {class: 'v4-bar-track'}, fill),
        h('strong', {text: format(value)})
      );
    }));
  }

  function donut(items, centerLabel, centerValue, ariaLabel) {
    const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
    if (!total) return h('p', {class: 'v4-muted', text: 'No data available.'});
    const radius = 74;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const chart = svg('svg', {viewBox: '0 0 220 220', class: 'v4-donut', role: 'img', 'aria-label': ariaLabel});
    chart.append(svg('circle', {cx: 110, cy: 110, r: radius, class: 'v4-donut-track', fill: 'none', 'stroke-width': 28}));
    for (const item of items) {
      const value = Number(item.value || 0);
      if (!value) continue;
      const length = circumference * value / total;
      const circle = svg('circle', {
        cx: 110, cy: 110, r: radius, fill: 'none', 'stroke-width': 28,
        class: `v4-donut-segment ${item.css || ''}`.trim(),
        'stroke-dasharray': `${length} ${circumference - length}`,
        'stroke-dashoffset': -offset,
        transform: 'rotate(-90 110 110)'
      });
      circle.append(svg('title', {}, document.createTextNode(`${item.label}: ${num(value)}`)));
      chart.append(circle);
      offset += length;
    }
    chart.append(svg('text', {x: 110, y: 103, 'text-anchor': 'middle', class: 'v4-donut-value'}, document.createTextNode(String(centerValue))));
    chart.append(svg('text', {x: 110, y: 126, 'text-anchor': 'middle', class: 'v4-donut-label'}, document.createTextNode(centerLabel)));
    const legend = h('div', {class: 'v4-legend'}, ...items.map(item => h('span', {}, h('i', {class: `v4-legend-dot ${item.css || ''}`.trim()}), `${item.label} · ${num(item.value)}`)));
    return h('div', {class: 'v4-donut-wrap'}, chart, legend);
  }

  function readinessRing(label, value, meta = '') {
    const score = clamp(Number(value || 0), 0, 100);
    const radius = 38;
    const circumference = 2 * Math.PI * radius;
    const chart = svg('svg', {viewBox: '0 0 110 110', class: 'v4-ring', role: 'img', 'aria-label': `${label} coverage ${score}%`});
    chart.append(svg('circle', {cx: 55, cy: 55, r: radius, class: 'v4-ring-track', fill: 'none', 'stroke-width': 10}));
    chart.append(svg('circle', {cx: 55, cy: 55, r: radius, class: 'v4-ring-value', fill: 'none', 'stroke-width': 10, 'stroke-linecap': 'round', transform: 'rotate(-90 55 55)', 'stroke-dasharray': `${circumference * score / 100} ${circumference}`}));
    chart.append(svg('text', {x: 55, y: 60, 'text-anchor': 'middle', class: 'v4-ring-text'}, document.createTextNode(`${score}%`)));
    return h('div', {class: 'v4-readiness-item'}, chart, h('strong', {text: label}), meta ? h('span', {text: meta}) : null);
  }

  function severityRows(cases) {
    const counts = countBy(cases, row => upper(row.currentSeverity));
    return ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(key => ({label: title(key), value: counts.get(key) || 0, css: `v4-severity-${key.toLowerCase()}`}));
  }

  function criticalityRows(assets) {
    const counts = countBy(assets, asset => upper(asset.currentRevision?.businessCriticality));
    return ['MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'].map(key => ({label: title(key), value: counts.get(key) || 0, css: `v4-criticality-${key.toLowerCase().replaceAll('_', '-')}`}));
  }

  function agingRows(cases) {
    const ages = cases.map(row => ageDays(row.firstObservedAt)).filter(Number.isFinite);
    const ranges = [['0–7 days',0,7],['8–30 days',8,30],['31–90 days',31,90],['91–180 days',91,180],['180+ days',181,Infinity]];
    return ranges.map(([label,min,max]) => ({label, value: ages.filter(value => value >= min && value <= max).length}));
  }

  function epssTopRows(cases) {
    return cases
      .map(row => ({label: `${row.cveId || 'Unknown'} · ${row.assetName || 'Unknown asset'}`, value: Number(row.vulnerabilityIntelligence?.epssProbability), kev: row.vulnerabilityIntelligence?.knownExploited === true}))
      .filter(row => Number.isFinite(row.value))
      .sort((a, b) => b.value - a.value || a.label.localeCompare(b.label))
      .slice(0, 10)
      .map(row => ({...row, value: row.value * 100, css: row.kev ? 'v4-signal-kev' : 'v4-signal-epss'}));
  }

  function heatmapKevSeverity(cases) {
    const severities = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'];
    const columns = [
      {key:'KEV', label:'KEV listed', test: row => row.vulnerabilityIntelligence?.knownExploited === true},
      {key:'OTHER', label:'Not listed / not established', test: row => row.vulnerabilityIntelligence?.knownExploited !== true},
    ];
    const values = severities.flatMap(sev => columns.map(col => cases.filter(row => upper(row.currentSeverity) === sev && col.test(row)).length));
    const max = Math.max(1, ...values);
    const grid = h('div', {class: 'v4-heatmap', role: 'table', 'aria-label': 'Technical severity by CISA KEV status'});
    grid.append(h('div', {class:'v4-heatmap-corner'}));
    for (const col of columns) grid.append(h('div', {class:'v4-heatmap-heading', text: col.label}));
    for (const sev of severities) {
      grid.append(h('div', {class:'v4-heatmap-row-label', text: title(sev)}));
      for (const col of columns) {
        const value = cases.filter(row => upper(row.currentSeverity) === sev && col.test(row)).length;
        const intensity = value / max;
        grid.append(h('div', {class:`v4-heatmap-cell ${col.key === 'KEV' ? 'v4-heatmap-kev' : ''}`.trim(), style:`--heat:${intensity.toFixed(4)}`, title:`${title(sev)} · ${col.label}: ${value}`}, h('strong', {text:num(value)})));
      }
    }
    return grid;
  }

  function scatterCvssEpss(cases) {
    const points = cases.map(row => ({
      cve: row.cveId || 'Unknown', asset: row.assetName || 'Unknown asset',
      x: Number(row.vulnerabilityIntelligence?.epssProbability),
      y: Number(row.vulnerabilityIntelligence?.cvssBaseScore),
      kev: row.vulnerabilityIntelligence?.knownExploited === true,
    })).filter(row => Number.isFinite(row.x) && Number.isFinite(row.y));
    if (!points.length) return h('p', {class:'v4-muted', text:'No findings currently have both CVSS and EPSS available.'});

    const width = 720, height = 360, left = 58, right = 24, top = 24, bottom = 48;
    const plotW = width - left - right, plotH = height - top - bottom;
    const chart = svg('svg', {viewBox:`0 0 ${width} ${height}`, class:'v4-scatter', role:'img', 'aria-label':'EPSS probability by CVSS technical severity'});
    for (let i = 0; i <= 5; i++) {
      const x = left + plotW * i / 5;
      chart.append(svg('line', {x1:x,y1:top,x2:x,y2:top+plotH,class:'v4-grid-line'}));
      chart.append(svg('text', {x,y:height-18,'text-anchor':'middle',class:'v4-axis-text'}, document.createTextNode(`${i*20}%`)));
    }
    for (let i = 0; i <= 5; i++) {
      const value = i * 2;
      const y = top + plotH - plotH * value / 10;
      chart.append(svg('line', {x1:left,y1:y,x2:left+plotW,y2:y,class:'v4-grid-line'}));
      chart.append(svg('text', {x:left-12,y:y+4,'text-anchor':'end',class:'v4-axis-text'}, document.createTextNode(String(value))));
    }
    chart.append(svg('text', {x:left+plotW/2,y:height-2,'text-anchor':'middle',class:'v4-axis-label'}, document.createTextNode('EPSS probability · next 30 days')));
    chart.append(svg('text', {x:14,y:top+plotH/2,'text-anchor':'middle',class:'v4-axis-label',transform:`rotate(-90 14 ${top+plotH/2})`}, document.createTextNode('CVSS technical severity')));
    for (const point of points) {
      const cx = left + plotW * clamp(point.x,0,1);
      const cy = top + plotH - plotH * clamp(point.y,0,10)/10;
      const circle = svg('circle', {cx,cy,r:point.kev?6:4.5,class:point.kev?'v4-scatter-point v4-scatter-kev':'v4-scatter-point'});
      circle.append(svg('title', {}, document.createTextNode(`${point.cve} · ${point.asset}\nEPSS ${pct(point.x)} · CVSS ${point.y.toFixed(1)}${point.kev?' · KEV listed':''}`)));
      chart.append(circle);
    }
    return h('div', {class:'v4-scatter-wrap'}, chart, h('div', {class:'v4-legend'}, h('span', {}, h('i',{class:'v4-legend-dot v4-signal-epss'}), 'Not KEV-listed / not established'), h('span', {}, h('i',{class:'v4-legend-dot v4-signal-kev'}), 'CISA KEV listed')));
  }

  function priorityValue(row) {
    const candidates = [row.mvpPriorityFront, row.priorityFront, row.mvpPriority?.front, row.priority?.front];
    for (const value of candidates) {
      if (Number.isInteger(Number(value)) && Number(value) > 0) return Number(value);
    }
    return null;
  }

  function priorityPanel(cases) {
    const explicit = cases.map(row => ({row, front:priorityValue(row)})).filter(item => item.front !== null);
    if (!explicit.length) {
      return h('div', {class:'v4-boundary'},
        h('strong', {text:'No canonical priority field exposed here'}),
        h('p', {text:'The dashboard does not infer treatment priority from CVSS, EPSS, KEV, age, or Asset Criticality. Priority visualization is enabled only when an explicit MVP priority output is available in the consumed API.'})
      );
    }
    const counts = countBy(explicit, item => `Front ${item.front}`);
    const rows = [...counts.entries()].map(([label,value])=>({label,value})).sort((a,b)=>Number(a.label.replace('Front ',''))-Number(b.label.replace('Front ','')));
    return barList(rows);
  }

  function renderV4(host, summary, cases, assets) {
    const intel = summary.vulnerabilityIntelligence || {};
    const uniqueCves = new Set(cases.map(row => row.cveId).filter(Boolean)).size;
    const knownExploited = cases.filter(row => row.vulnerabilityIntelligence?.knownExploited === true);
    const cvssCoverage = cases.length ? Math.round(cases.filter(row => row.vulnerabilityIntelligence?.cvssBaseScore != null).length / cases.length * 100) : 0;
    const epssCoverage = cases.length ? Math.round(cases.filter(row => row.vulnerabilityIntelligence?.epssProbability != null).length / cases.length * 100) : 0;
    const kevCoverage = cases.length ? Math.round(cases.filter(row => typeof row.vulnerabilityIntelligence?.knownExploited === 'boolean').length / cases.length * 100) : 0;
    const missionCritical = assets.filter(asset => upper(asset.currentRevision?.businessCriticality) === 'MISSION_CRITICAL').length;
    const severity = severityRows(cases);
    const criticality = criticalityRows(assets);
    const kevItems = [
      {label:'KEV listed',value:knownExploited.length,css:'v4-signal-kev'},
      {label:'Not listed / not established',value:Math.max(0,cases.length-knownExploited.length),css:'v4-signal-neutral'},
    ];

    host.replaceChildren(
      h('div', {class:'v4-header'},
        h('div', {}, h('div',{class:'v4-eyebrow',text:'RBVM · standards-oriented operational view'}), h('h2',{text:'Vulnerability decision dashboard'}), h('p',{text:'Technical severity, exploitation evidence, exploitation probability, mission context, treatment priority, and evidence readiness are shown as separate decision dimensions.'})),
        h('div',{class:'v4-frameworks'}, h('span',{text:'NIST CSF 2.0'}), h('span',{text:'NIST IR 8286'}), h('span',{text:'CISA KEV / SSVC'}), h('span',{text:'FIRST CVSS / EPSS'}))
      ),
      h('div',{class:'v4-kpis'},
        metric('Current findings',num(summary.openCases ?? cases.length),'Current canonical cases','primary'),
        metric('Unique CVEs',num(uniqueCves),'Distinct vulnerability IDs'),
        metric('Known exploited',num(intel.knownExploitedVulnerabilities ?? new Set(knownExploited.map(row=>row.cveId)).size),'CISA KEV confirmed exploitation','danger'),
        metric('CVSS coverage',`${cvssCoverage}%`,'Technical severity evidence'),
        metric('EPSS coverage',`${epssCoverage}%`,'30-day exploitation probability'),
        metric('Mission critical assets',num(missionCritical),assets.length?'Customer-managed context':'Context unavailable')
      ),
      h('div',{class:'v4-grid'},
        panel('Technical severity','CVSS/source severity is a technical characteristic, not Organizational Risk.',donut(severity,'findings',num(cases.length),'Technical severity distribution'),{badge:'FIRST CVSS'}),
        panel('Confirmed exploitation','CISA KEV is displayed as historical exploitation evidence and a prioritization input.',donut(kevItems,'KEV listed',num(knownExploited.length),'CISA KEV distribution'),{badge:'CISA KEV'}),
        panel('CVSS × EPSS decision landscape','Two independent signals shown together without multiplying them. Each point is a current finding.',scatterCvssEpss(cases),{wide:true,badge:'FIRST CVSS + EPSS'}),
        panel('Severity × confirmed exploitation','A matrix of technical severity against KEV status. This is an evidence intersection, not a risk score.',heatmapKevSeverity(cases),{badge:'CISA / FIRST'}),
        panel('Highest EPSS probabilities','Current findings ranked by the native EPSS probability; no organization-wide threshold is invented.',barList(epssTopRows(cases),'No EPSS values are currently available.',value=>`${value.toFixed(1)}%`),{badge:'FIRST EPSS'}),
        panel('Most affected assets','Finding concentration by observed asset. Concentration is operational exposure, not mission impact.',barList(topCounts(cases,row=>row.assetName||'Unknown',12)),{badge:'NIST CSF'}),
        panel('Finding age distribution','Operational backlog age from explicit first-observed timestamps; age is not silently converted to priority.',barList(agingRows(cases)),{badge:'NIST SP 800-40'}),
        panel('Asset criticality','Customer-declared asset importance remains separate from vulnerability severity and threat signals.',assets.length?donut(criticality,'managed assets',num(assets.length),'Managed asset criticality distribution'):h('p',{class:'v4-muted',text:'Managed asset context is unavailable in this runtime.'}),{badge:'NIST IR 8286D'}),
        panel('Decision readiness','Coverage is shown so missing evidence remains visible instead of becoming an implicit zero.',h('div',{class:'v4-readiness'},readinessRing('CVSS',cvssCoverage,'Technical severity'),readinessRing('EPSS',epssCoverage,'Exploitation probability'),readinessRing('KEV',kevCoverage,'Confirmed exploitation')),{badge:'NIST CSF 2.0'}),
        panel('Treatment priority','Priority is a decision output, not a synonym for severity or risk.',priorityPanel(cases),{badge:'SSVC / RBVM policy'}),
        panel('Historical response trend','NIST patch management emphasizes identifying, prioritizing, applying, and verifying remediation. A defensible trend requires historical state.',h('div',{class:'v4-boundary'},h('strong',{text:'Historical aggregation API required'}),h('p',{text:'New / Remediated / Active and remediation effectiveness are intentionally not reconstructed from current-state survivors. Once immutable historical state is exposed, this section becomes the verified response trend.'})),{badge:'NIST SP 800-40'}),
        panel('Interpretation boundary','The dashboard communicates decision evidence without manufacturing an enterprise risk value.',h('ul',{class:'v4-notes'},
          h('li',{text:'CVSS: technical severity and environment-specific severity input.'}),
          h('li',{text:'KEV: confirmed exploitation in the wild; direct exploitation evidence takes precedence over prediction.'}),
          h('li',{text:'EPSS: forward-looking probability of exploitation in the next 30 days.'}),
          h('li',{text:'Asset Criticality: customer/mission context; never inferred from severity.'}),
          h('li',{text:'Treatment Priority: explicit decision output only; no hidden weighting.'}),
          h('li',{text:'Organizational Risk: not claimed until likelihood, impact, risk appetite/tolerance, and methodology support it.'})
        ),{wide:true,badge:'NIST IR 8286'})
      )
    );
  }

  async function patch() {
    const root = document.getElementById('page-content');
    const heading = root?.querySelector('.page-title');
    if (!root || heading?.textContent.trim() !== 'Overview') return;
    const v3 = root.querySelector('[data-rbvm-dashboard-v3]');
    if (!v3 || v3.dataset.rbvmDashboardV4 === 'true') return;
    v3.dataset.rbvmDashboardV4 = 'true';
    v3.classList.add('v4-root');
    v3.replaceChildren(h('div',{class:'v4-loading',text:'Loading standards-oriented dashboard…'}));
    const currentGeneration = ++generation;
    try {
      const [summary,cases,assets] = await Promise.all([json('/api/v1/catalog/summary'),allCases(),allManagedAssets()]);
      if (generation !== currentGeneration || !v3.isConnected) return;
      renderV4(v3,summary,cases,assets);
    } catch (error) {
      if (generation !== currentGeneration || !v3.isConnected) return;
      v3.replaceChildren(h('div',{class:'callout callout-warning',text:`Dashboard V4 could not be loaded: ${error.message}`}));
    }
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; patch(); });
  }

  new MutationObserver(schedule).observe(document.documentElement,{childList:true,subtree:true});
  window.addEventListener('DOMContentLoaded',schedule);
  window.addEventListener('popstate',schedule);
  schedule();
})();
