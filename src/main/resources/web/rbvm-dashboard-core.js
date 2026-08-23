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
  const svg = (tag, attrs = {}, ...children) => {
    const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
    for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
    for (const child of children.flat()) if (child != null) node.append(child);
    return node;
  };
  const num = value => Number(value ?? 0).toLocaleString('en-US');
  const upper = value => String(value || 'UNKNOWN').trim().toUpperCase();

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
        h('span', {text: item.label, title: item.label}),
        h('span', {class: 'dashboard-core-bar-track'}, h('span', {class: `dashboard-core-bar-fill ${item.css || ''}`, style: `width:${value ? Math.max(3, value / max * 100) : 0}%`})),
        h('strong', {text: item.format ? item.format(value) : num(value)}));
    }));
  }
  function ring(label, value) {
    const normalized = Math.max(0, Math.min(100, Number(value) || 0));
    return h('div', {class: 'dashboard-core-ring', style: `--value:${normalized}`},
      h('div', {class: 'dashboard-core-ring-face'}, h('strong', {text: `${Math.round(normalized)}%`}), h('span', {text: label})));
  }
  function donut(items, centerValue, centerLabel, ariaLabel) {
    const total = items.reduce((sum, item) => sum + Number(item.value || 0), 0);
    if (!total) return h('p', {class: 'chart-summary', text: 'No current findings available.'});
    const radius = 68;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const chart = svg('svg', {viewBox: '0 0 210 210', class: 'dashboard-core-donut', role: 'img', 'aria-label': ariaLabel});
    chart.append(svg('circle', {cx:105, cy:105, r:radius, class:'dashboard-core-donut-track', fill:'none', 'stroke-width':26}));
    for (const item of items) {
      const value = Number(item.value || 0);
      if (!value) continue;
      const length = circumference * value / total;
      const segment = svg('circle', {cx:105, cy:105, r:radius, fill:'none', 'stroke-width':26, class:`dashboard-core-donut-segment ${item.css || ''}`, 'stroke-dasharray':`${length} ${circumference-length}`, 'stroke-dashoffset':-offset, transform:'rotate(-90 105 105)'});
      segment.append(svg('title', {}, document.createTextNode(`${item.label}: ${value}`)));
      chart.append(segment);
      offset += length;
    }
    chart.append(svg('text', {x:105,y:101,'text-anchor':'middle',class:'dashboard-core-donut-value'}, document.createTextNode(String(centerValue))));
    chart.append(svg('text', {x:105,y:123,'text-anchor':'middle',class:'dashboard-core-donut-label'}, document.createTextNode(centerLabel)));
    return h('div',{class:'dashboard-core-donut-wrap'},chart,h('div',{class:'dashboard-core-legend'},...items.map(item=>h('span',{},h('i',{class:`dashboard-core-legend-dot ${item.css || ''}`}),`${item.label} · ${num(item.value)}`))));
  }
  function scatter(rows) {
    const points = rows.map(row => ({cve:row.cveId||'Unknown',asset:row.assetName||'Unknown',x:Number(row.vulnerabilityIntelligence?.epssProbability),y:Number(row.vulnerabilityIntelligence?.cvssBaseScore),kev:row.vulnerabilityIntelligence?.knownExploited===true})).filter(point=>Number.isFinite(point.x)&&Number.isFinite(point.y));
    if (!points.length) return h('p',{class:'chart-summary',text:'No current-page findings have both CVSS and EPSS evidence.'});
    const width=700,height=330,left=54,right=22,top=20,bottom=44,plotW=width-left-right,plotH=height-top-bottom;
    const chart=svg('svg',{viewBox:`0 0 ${width} ${height}`,class:'dashboard-core-scatter',role:'img','aria-label':'CVSS technical severity by EPSS probability'});
    for(let i=0;i<=5;i++){
      const x=left+plotW*i/5;
      chart.append(svg('line',{x1:x,y1:top,x2:x,y2:top+plotH,class:'dashboard-core-grid-line'}));
      chart.append(svg('text',{x,y:height-16,'text-anchor':'middle',class:'dashboard-core-axis'},document.createTextNode(`${i*20}%`)));
      const value=i*2,y=top+plotH-plotH*value/10;
      chart.append(svg('line',{x1:left,y1:y,x2:left+plotW,y2:y,class:'dashboard-core-grid-line'}));
      chart.append(svg('text',{x:left-10,y:y+4,'text-anchor':'end',class:'dashboard-core-axis'},document.createTextNode(String(value))));
    }
    for(const point of points){
      const cx=left+plotW*Math.max(0,Math.min(1,point.x));
      const cy=top+plotH-plotH*Math.max(0,Math.min(10,point.y))/10;
      const dot=svg('circle',{cx,cy,r:point.kev?6:4.5,class:point.kev?'dashboard-core-point dashboard-core-point-kev':'dashboard-core-point'});
      dot.append(svg('title',{},document.createTextNode(`${point.cve} · ${point.asset}\nEPSS ${(point.x*100).toFixed(1)}% · CVSS ${point.y.toFixed(1)}${point.kev?' · KEV listed':''}`)));
      chart.append(dot);
    }
    return h('div',{class:'dashboard-core-scatter-wrap'},chart,h('div',{class:'dashboard-core-scatter-labels'},h('span',{text:'X · FIRST EPSS probability'}),h('span',{text:'Y · CVSS technical severity'})));
  }

  function render(host, summary, page) {
    const rows = page.cases || [];
    const intelSummary = summary.vulnerabilityIntelligence || {};
    const severity = counts(rows, row => upper(row.currentSeverity));
    const severityItems = ['CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'].map(key=>({label:key,value:severity.get(key)||0,css:`dashboard-core-severity-${key.toLowerCase()}`}));
    const kev = rows.filter(row => row.vulnerabilityIntelligence?.knownExploited === true);
    const cvssCoverage = rows.length ? rows.filter(row => row.vulnerabilityIntelligence?.cvssBaseScore != null).length / rows.length * 100 : 0;
    const epssCoverage = rows.length ? rows.filter(row => row.vulnerabilityIntelligence?.epssProbability != null).length / rows.length * 100 : 0;
    const kevCoverage = rows.length ? rows.filter(row => typeof row.vulnerabilityIntelligence?.knownExploited === 'boolean').length / rows.length * 100 : 0;
    const topAssets = [...counts(rows, row => row.assetName || 'Unknown').entries()].map(([label, value]) => ({label, value})).sort((a,b) => b.value - a.value || String(a.label).localeCompare(String(b.label))).slice(0,10);
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
        card('Technical severity · current page', `Bounded first ${rows.length} findings; not Organizational Risk.`, donut(severityItems,num(rows.length),'findings','Technical severity distribution')),
        card('Confirmed exploitation · current page', 'CISA KEV remains separate from technical severity and prediction.', donut([{label:'KEV listed',value:kev.length,css:'dashboard-core-danger'},{label:'Not listed / not established',value:Math.max(0,rows.length-kev.length),css:'dashboard-core-neutral'}],num(kev.length),'KEV listed','Known exploitation distribution')),
        card('CVSS × EPSS decision landscape', 'Independent technical-severity and exploitation-probability signals; they are visualized together but never multiplied.', scatter(rows), true),
        card('Evidence readiness · current page', 'Missing evidence remains missing; it is never converted to zero.', h('div', {class:'dashboard-core-rings'}, ring('CVSS',cvssCoverage), ring('EPSS',epssCoverage), ring('KEV',kevCoverage))),
        card('Most affected assets · current page', 'Operational concentration only; not mission impact or Organizational Risk.', topAssets.length ? bars(topAssets) : h('p',{text:'No current findings available.'})),
        card('Highest EPSS · current page', 'Native FIRST EPSS probability; no threshold or multiplication is introduced.', topEpss.length ? bars(topEpss) : h('p',{text:'No EPSS values available.'})),
        card('Decision boundary', 'One dashboard, one explicit scope, no hidden scoring.', h('div',{class:'callout callout-info',text:'Treatment Priority remains an explicit run-level decision output. Organizational Risk remains NON_COMPUTABLE unless an admitted methodology has all required evidence.'}), true)
      )
    );
  }

  async function patch() {
    const root = document.getElementById('page-content');
    const heading = root?.querySelector('.page-title');
    if (!root || heading?.textContent.trim() !== 'Overview') return;
    if (root.querySelector('.dashboard-core-root') || root.dataset.dashboardCore === 'loading') return;
    if (root.querySelector('.skeleton')) return;

    root.dataset.dashboardCore = 'loading';
    const current = ++generation;
    heading.textContent = 'Dashboard';
    document.title = 'Dashboard · RBVM';
    const homeLabel = document.querySelector('.nav-link[data-route="/"] span:last-child');
    if (homeLabel) homeLabel.textContent = 'Dashboard';
    const description = root.querySelector('.page-description');
    if (description) description.textContent = 'Current canonical catalog with bounded decision visuals and explicit run/catalog scope.';
    const header = root.querySelector('.page-header');
    for (const child of [...root.children]) if (child !== header) child.remove();
    const host = h('div', {class:'dashboard-core-root'}, h('div',{class:'skeleton'}));
    root.append(host);
    try {
      const [summary, page] = await Promise.all([json('/api/v1/catalog/summary'), json('/api/v1/cases?limit=100')]);
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
