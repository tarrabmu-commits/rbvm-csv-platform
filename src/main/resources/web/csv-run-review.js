(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_FINDING_REVIEW_UI_V1';
  const PAGE_SIZE = 100;
  let queued = false;
  let loaded = null;

  document.documentElement.dataset.csvFirstFindingReviewUi = CONTRACT;

  const el = (tag, attrs = {}, ...children) => {
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

  const button = (label, kind = 'secondary') => el('button', {type: 'button', class: `button button-${kind}`, text: label});
  const callout = (text, kind = 'info') => el('div', {class: `callout callout-${kind}`, text});

  function normalize(value) {
    return String(value || '').normalize('NFKC').trim().toLowerCase();
  }

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
    if (quoted) throw new Error('Enriched CSV contains an unterminated quoted field.');
    if (cell.length || row.length) {
      row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
      rows.push(row);
    }
    const meaningful = rows.filter(values => values.some(value => String(value).trim() !== ''));
    if (meaningful.length < 2) throw new Error('Enriched CSV contains no finding rows.');
    const headers = meaningful[0].map((value, index) => index === 0 ? String(value).replace(/^\uFEFF/, '') : String(value));
    return meaningful.slice(1).map(values => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ''])));
  }

  function csvEscape(value) {
    const text = String(value ?? '');
    return /[",\n\r]/.test(text) ? `"${text.replaceAll('"', '""')}"` : text;
  }

  function downloadCsv(filename, rows) {
    if (!rows.length) return;
    const headers = Object.keys(rows[0]);
    const text = [headers, ...rows.map(row => headers.map(header => row[header] ?? ''))]
      .map(values => values.map(csvEscape).join(','))
      .join('\r\n') + '\r\n';
    const blob = new Blob([text], {type: 'text/csv;charset=utf-8'});
    const href = URL.createObjectURL(blob);
    const link = el('a', {href, download: filename});
    document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(href);
  }

  function customerContext(panel) {
    const assets = [];
    for (const details of panel.querySelectorAll('details.panel')) {
      const inputs = details.querySelectorAll('input[type="text"]');
      const selects = details.querySelectorAll('select');
      if (inputs.length < 2 || selects.length < 2) continue;
      assets.push({customerAssetKey: inputs[0].value.trim(), displayName: inputs[1].value.trim(), assetCriticality: selects[0].value, internetFacing: selects[1].value});
    }
    if (!assets.length) throw new Error('No customer assets are loaded.');
    const incomplete = assets.filter(asset => (!asset.customerAssetKey && !asset.displayName) || asset.assetCriticality === 'UNKNOWN' || asset.internetFacing === 'UNKNOWN');
    if (incomplete.length) throw new Error(`${incomplete.length} asset${incomplete.length === 1 ? '' : 's'} still need identity, Asset Criticality and Internet Facing before review.`);
    return assets;
  }

  function contextResolver(assets) {
    const byId = new Map();
    const byName = new Map();
    for (const asset of assets) {
      if (asset.customerAssetKey) byId.set(asset.customerAssetKey, asset);
      const name = normalize(asset.displayName);
      if (!name) continue;
      if (byName.has(name)) byName.set(name, null);
      else byName.set(name, asset);
    }
    return row => {
      const sourceId = String(row.Agent_ID || row.Asset_ID || '').trim();
      if (sourceId && byId.has(sourceId)) return {status: 'MATCHED_ID', asset: byId.get(sourceId)};
      const sourceName = normalize(row.Agent || row.Asset || row.Asset_Name || row.Hostname || row.Host);
      const named = sourceName ? byName.get(sourceName) : undefined;
      if (named) return {status: 'MATCHED_NAME', asset: named};
      if (named === null) return {status: 'AMBIGUOUS_NAME', asset: null};
      return {status: 'MISSING', asset: null};
    };
  }

  function joinRows(rows, assets) {
    const resolve = contextResolver(assets);
    return rows.map((row, index) => {
      const resolved = resolve(row);
      return {...row, Customer_Context_Status: resolved.status, Asset_Criticality: resolved.asset?.assetCriticality || '', Internet_Facing: resolved.asset?.internetFacing || '', CSV_Run_Row: String(index + 2)};
    });
  }

  function pct(value) {
    if (value === '' || value == null || Number.isNaN(Number(value))) return '—';
    return `${(Number(value) * 100).toFixed(1)}%`;
  }

  function cvssDisplay(row) {
    if (row.CVSS4_Calculated_Status === 'CALCULATED') {
      return `${row.CVSS4_Calculated_Nomenclature || 'CVSS'} ${row.CVSS4_Calculated_Score || '—'} ${row.CVSS4_Calculated_Severity || ''}`.trim();
    }
    if (row.CVSS4_Calculated_Status === 'AMBIGUOUS_THREAT_CONFLICT') return 'Threat conflict';
    if (row.CVSS4_Status === 'PRESENT') return `Base ${row.CVSS4_Base_Score || '—'} ${row.CVSS4_Base_Severity || ''}`.trim();
    return row.CVSS4_Status || '—';
  }

  function metric(label, value, detail = '') {
    return el('div', {class: 'metric'}, el('div', {class: 'metric-label', text: label}), el('div', {class: 'metric-value', text: value}), detail ? el('div', {class: 'metric-detail', text: detail}) : null);
  }

  function renderTable(host, allRows) {
    host.replaceChildren();
    const search = el('input', {type: 'search', class: 'search-input', placeholder: 'Search CVE, asset or product…', 'aria-label': 'Search CSV run findings'});
    const pageLabel = el('span');
    const previous = button('Previous', 'ghost');
    const next = button('Next', 'ghost');
    const tableHost = el('div');
    let page = 0;
    const render = () => {
      const query = normalize(search.value);
      const filtered = query ? allRows.filter(row => [row.CVE_ID, row.Agent, row.Agent_ID, row.Affected_Product].some(value => normalize(value).includes(query))) : allRows;
      const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
      if (page >= pages) page = pages - 1;
      const start = page * PAGE_SIZE;
      const rows = filtered.slice(start, start + PAGE_SIZE);
      const table = el('table', {class: 'data-table'},
        el('thead', {}, el('tr', {}, ...['Asset', 'CVE', 'Product', 'Scanner', 'CVSS4', 'EPSS', 'KEV', 'Exploitation', 'Automatable', 'Technical Impact', 'Criticality', 'Internet', 'Context'].map(label => el('th', {text: label})))),
        el('tbody', {}, ...rows.map(row => el('tr', {},
          el('td', {text: row.Agent || row.Agent_ID || '—'}), el('td', {class: 'mono', text: row.CVE_ID || '—'}),
          el('td', {text: row.Affected_Product || '—'}), el('td', {text: row.Severity || '—'}), el('td', {text: cvssDisplay(row)}),
          el('td', {text: pct(row.EPSS_Probability)}),
          el('td', {text: String(row.KEV_Listed || '').toLowerCase() === 'true' ? 'LISTED' : String(row.KEV_Listed || '').toLowerCase() === 'false' ? 'NOT LISTED' : '—'}),
          el('td', {text: row.CISA_Exploitation || '—'}), el('td', {text: row.CISA_Automatable || '—'}), el('td', {text: row.CISA_Technical_Impact || '—'}),
          el('td', {text: row.Asset_Criticality || '—'}), el('td', {text: row.Internet_Facing || '—'}), el('td', {text: row.Customer_Context_Status || '—'})
        )))
      );
      tableHost.replaceChildren(table);
      pageLabel.textContent = `${filtered.length} finding rows · page ${page + 1} of ${pages}`;
      previous.disabled = page <= 0; next.disabled = page + 1 >= pages;
    };
    search.addEventListener('input', () => { page = 0; render(); });
    previous.addEventListener('click', () => { if (page > 0) { page--; render(); } });
    next.addEventListener('click', () => { page++; render(); });
    host.append(el('div', {class: 'toolbar'}, search, el('div', {class: 'pagination'}, previous, pageLabel, next)), tableHost);
    render();
  }

  function reviewPanel(joined, runId) {
    const uniqueCves = new Set(joined.map(row => row.CVE_ID).filter(Boolean)).size;
    const uniqueAssets = new Set(joined.map(row => row.Agent || row.Agent_ID).filter(Boolean)).size;
    const cvssPresent = joined.filter(row => row.CVSS4_Status === 'PRESENT').length;
    const cvssAmbiguous = joined.filter(row => row.CVSS4_Status === 'AMBIGUOUS').length;
    const cvssCalculated = joined.filter(row => row.CVSS4_Calculated_Status === 'CALCULATED').length;
    const cvssThreatConflicts = joined.filter(row => row.CVSS4_Calculated_Status === 'AMBIGUOUS_THREAT_CONFLICT').length;
    const baseMismatches = joined.filter(row => row.CVSS4_Base_Score_Validation === 'MISMATCH').length;
    const epssPresent = joined.filter(row => row.EPSS_Probability !== '').length;
    const kevListed = joined.filter(row => String(row.KEV_Listed || '').toLowerCase() === 'true').length;
    const contextMissing = joined.filter(row => !String(row.Customer_Context_Status || '').startsWith('MATCHED')).length;
    const host = el('div');
    const download = button('Download review CSV');
    download.addEventListener('click', () => downloadCsv(`rbvm-finding-review-${runId}.csv`, joined));
    const close = button('Back to Assets', 'ghost');
    close.addEventListener('click', () => {
      document.querySelector('[data-csv-run-review]')?.remove();
      const setup = document.querySelector('[data-customer-asset-setup]');
      if (setup) setup.hidden = false;
      loaded = null;
    });
    const panel = el('section', {'data-csv-run-review': 'true', class: 'panel'},
      el('div', {class: 'panel-header'}, el('div', {}, el('h2', {class: 'panel-title', text: 'Finding Evidence Review — CSV Run'}), el('p', {class: 'panel-subtitle', text: 'Public vulnerability intelligence joined with customer-declared MVP asset context. Evidence review only; no risk score, priority or SLA is calculated.'})), el('div', {class: 'inline-actions'}, download, close)),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('CVSS v4 is technical severity. The displayed CVSS-B/CVSS-BT value is recalculated by the FIRST-reference-compatible engine; EPSS remains exploitation probability, KEV/SSVC remain threat evidence, and Asset Criticality + Internet Facing remain separate customer context.'),
        el('div', {class: 'metrics'}, metric('Finding rows', joined.length), metric('Unique CVEs', uniqueCves), metric('Assets', uniqueAssets),
          metric('CVSS4 present', cvssPresent, `${cvssAmbiguous} ambiguous`), metric('CVSS4 calculated', cvssCalculated, `${cvssThreatConflicts} threat conflicts · ${baseMismatches} base mismatches`),
          metric('EPSS present', epssPresent), metric('KEV listed', kevListed), metric('Context unmatched', contextMissing)), host))
    );
    renderTable(host, joined);
    return panel;
  }

  async function openReview(panel, buttonNode, status) {
    const runId = new URLSearchParams(location.search).get('runId') || '';
    if (!runId) {
      status.textContent = 'This Assets page is not associated with a CSV enrichment run.';
      status.className = 'status-message error';
      return;
    }
    buttonNode.disabled = true;
    try {
      status.textContent = 'Loading enriched findings for evidence review…'; status.className = 'status-message';
      const assets = customerContext(panel);
      const response = await fetch(`/api/v1/csv-first-enrichments/${encodeURIComponent(runId)}/csv`, {cache: 'no-store'});
      if (!response.ok) throw new Error(`Enriched CSV could not be loaded (HTTP ${response.status}).`);
      const joined = joinRows(parseCsv(await response.text()), assets);
      loaded = {runId, joined};
      document.querySelector('[data-csv-run-review]')?.remove();
      const review = reviewPanel(joined, runId);
      panel.insertAdjacentElement('afterend', review); panel.hidden = true;
      status.textContent = `Review ready for ${joined.length} finding rows.`; status.className = 'status-message success';
      review.scrollIntoView({block: 'start'});
    } catch (error) {
      status.textContent = error.message; status.className = 'status-message error';
    } finally { buttonNode.disabled = false; }
  }

  function patch() {
    const panel = document.querySelector('[data-customer-asset-setup]');
    if (!panel || panel.querySelector('[data-review-findings-button]')) return;
    const actions = panel.querySelector('.inline-actions');
    if (!actions) return;
    const status = panel.querySelector('.status-message') || el('div', {class: 'status-message'});
    const review = button('Review Findings', 'primary');
    review.dataset.reviewFindingsButton = 'true';
    review.addEventListener('click', () => openReview(panel, review, status));
    actions.append(review);
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; patch(); });
  }

  new MutationObserver(schedule).observe(document.documentElement, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
