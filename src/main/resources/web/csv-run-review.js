(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_FINDING_REVIEW_UI_V2';
  const BUNDLE_CONTRACT = 'RBVM_CUSTOMER_ASSET_BUNDLE_V3';
  const PAGE_SIZE = 100;
  const SECURITY_REQUIREMENTS = new Set(['X', 'L', 'M', 'H']);
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
    if (quoted) throw new Error('Analysis CSV contains an unterminated quoted field.');
    if (cell.length || row.length) {
      row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
      rows.push(row);
    }
    const meaningful = rows.filter(values => values.some(value => String(value).trim() !== ''));
    if (meaningful.length < 2) throw new Error('Analysis CSV contains no finding rows.');
    const headers = meaningful[0].map((value, index) => index === 0 ? String(value).replace(/^\uFEFF/, '') : String(value));
    return meaningful.slice(1).map((values, rowIndex) => ({
      ...Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ''])),
      CSV_Run_Row: String(rowIndex + 2),
    }));
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

  function customerBundle(panel) {
    const assets = [];
    for (const details of panel.querySelectorAll('details.panel')) {
      const inputs = details.querySelectorAll('input[type="text"]');
      const selects = details.querySelectorAll('select');
      if (inputs.length < 2 || selects.length < 2) continue;
      const asset = {
        customerAssetKey: inputs[0].value.trim(),
        displayName: inputs[1].value.trim(),
        assetCriticality: selects[0].value,
        internetFacing: selects[1].value,
        cvssConfidentialityRequirement: selects[2]?.value || 'X',
        cvssIntegrityRequirement: selects[3]?.value || 'X',
        cvssAvailabilityRequirement: selects[4]?.value || 'X',
      };
      assets.push(asset);
    }
    if (!assets.length) throw new Error('No customer assets are loaded.');
    const incomplete = assets.filter(asset =>
      (!asset.customerAssetKey && !asset.displayName)
      || asset.assetCriticality === 'UNKNOWN'
      || asset.internetFacing === 'UNKNOWN'
      || !SECURITY_REQUIREMENTS.has(asset.cvssConfidentialityRequirement)
      || !SECURITY_REQUIREMENTS.has(asset.cvssIntegrityRequirement)
      || !SECURITY_REQUIREMENTS.has(asset.cvssAvailabilityRequirement)
    );
    if (incomplete.length) {
      throw new Error(`${incomplete.length} asset${incomplete.length === 1 ? '' : 's'} still have incomplete or invalid customer context.`);
    }
    return {
      contractId: BUNDLE_CONTRACT,
      schemaVersion: 3,
      exportedAt: new Date().toISOString(),
      semantics: 'CUSTOMER_DECLARED_ASSET_AND_CVSS_V4_ENVIRONMENTAL_CONTEXT',
      note: 'CR/IR/AR are direct customer CVSS v4 Security Requirements. Asset Criticality is not mapped to CR/IR/AR and Internet Facing is not mapped to MAV.',
      assets,
    };
  }

  function pct(value) {
    if (value === '' || value == null || Number.isNaN(Number(value))) return '—';
    return `${(Number(value) * 100).toFixed(1)}%`;
  }

  function contextualCvssDisplay(row) {
    if (row.CVSS4_Context_Score_Status === 'CALCULATED_FIRST_REFERENCE_COMPATIBLE') {
      return `${row.CVSS4_Context_Nomenclature || 'CVSS'} ${row.CVSS4_Context_Score || '—'} ${row.CVSS4_Context_Severity || ''}`.trim();
    }
    if (row.CVSS4_Context_Score_Status === 'AMBIGUOUS_THREAT_CONFLICT') return 'Threat conflict';
    return row.CVSS4_Context_Score_Status || row.CVSS4_Status || '—';
  }

  function publicCvssDisplay(row) {
    if (row.CVSS4_Calculated_Status === 'CALCULATED') {
      return `${row.CVSS4_Calculated_Nomenclature || 'CVSS'} ${row.CVSS4_Calculated_Score || '—'} ${row.CVSS4_Calculated_Severity || ''}`.trim();
    }
    if (row.CVSS4_Calculated_Status === 'AMBIGUOUS_THREAT_CONFLICT') return 'Threat conflict';
    if (row.CVSS4_Status === 'PRESENT') return `Base ${row.CVSS4_Base_Score || '—'} ${row.CVSS4_Base_Severity || ''}`.trim();
    return row.CVSS4_Status || '—';
  }

  function securityRequirements(row) {
    return `C:${row.CVSS4_CR_Resolved || 'X'} I:${row.CVSS4_IR_Resolved || 'X'} A:${row.CVSS4_AR_Resolved || 'X'}`;
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
        el('thead', {}, el('tr', {}, ...[
          'Asset', 'CVE', 'Product', 'Scanner', 'Context CVSS', 'Public CVSS', 'CR / IR / AR',
          'EPSS', 'KEV', 'Exploitation', 'Automatable', 'Technical Impact', 'Criticality', 'Internet', 'Context'
        ].map(label => el('th', {text: label})))),
        el('tbody', {}, ...rows.map(row => el('tr', {},
          el('td', {text: row.Agent || row.Agent_ID || '—'}),
          el('td', {class: 'mono', text: row.CVE_ID || '—'}),
          el('td', {text: row.Affected_Product || '—'}),
          el('td', {text: row.Severity || '—'}),
          el('td', {text: contextualCvssDisplay(row)}),
          el('td', {text: publicCvssDisplay(row)}),
          el('td', {class: 'mono', text: securityRequirements(row)}),
          el('td', {text: pct(row.EPSS_Probability)}),
          el('td', {text: String(row.KEV_Listed || '').toLowerCase() === 'true' ? 'LISTED' : String(row.KEV_Listed || '').toLowerCase() === 'false' ? 'NOT LISTED' : '—'}),
          el('td', {text: row.CISA_Exploitation || '—'}),
          el('td', {text: row.CISA_Automatable || '—'}),
          el('td', {text: row.CISA_Technical_Impact || '—'}),
          el('td', {text: row.Asset_Criticality || '—'}),
          el('td', {text: row.Internet_Facing || '—'}),
          el('td', {text: row.Customer_Context_Status || '—'})
        )))
      );
      tableHost.replaceChildren(table);
      pageLabel.textContent = `${filtered.length} finding rows · page ${page + 1} of ${pages}`;
      previous.disabled = page <= 0;
      next.disabled = page + 1 >= pages;
    };
    search.addEventListener('input', () => { page = 0; render(); });
    previous.addEventListener('click', () => { if (page > 0) { page--; render(); } });
    next.addEventListener('click', () => { page++; render(); });
    host.append(el('div', {class: 'toolbar'}, search, el('div', {class: 'pagination'}, previous, pageLabel, next)), tableHost);
    render();
  }

  function reviewPanel(rows, runId, admission) {
    const uniqueCves = new Set(rows.map(row => row.CVE_ID).filter(Boolean)).size;
    const uniqueAssets = new Set(rows.map(row => row.Agent || row.Agent_ID).filter(Boolean)).size;
    const cvssPresent = rows.filter(row => row.CVSS4_Status === 'PRESENT').length;
    const contextualCalculated = rows.filter(row => row.CVSS4_Context_Score_Status === 'CALCULATED_FIRST_REFERENCE_COMPATIBLE').length;
    const bte = rows.filter(row => row.CVSS4_Context_Nomenclature === 'CVSS-BTE').length;
    const be = rows.filter(row => row.CVSS4_Context_Nomenclature === 'CVSS-BE').length;
    const epssPresent = rows.filter(row => row.EPSS_Probability !== '').length;
    const kevListed = rows.filter(row => String(row.KEV_Listed || '').toLowerCase() === 'true').length;
    const contextMissing = rows.filter(row => !String(row.Customer_Context_Status || '').startsWith('MATCHED')).length;
    const admissionState = admission?.selection?.state || 'UNKNOWN';
    const riskRows = Number(admission?.selection?.riskComputedRows || 0);
    const host = el('div');

    const download = button('Download contextual analysis CSV');
    download.addEventListener('click', () => downloadCsv(`rbvm-contextual-analysis-${runId}.csv`, rows));
    const downloadAdmission = button('Download method admission', 'secondary');
    downloadAdmission.addEventListener('click', () => {
      const link = el('a', {href: `/api/v1/csv-first-enrichments/${encodeURIComponent(runId)}/method-admission`, download: `rbvm-method-admission-${runId}.json`});
      document.body.append(link); link.click(); link.remove();
    });
    const close = button('Back to Assets', 'ghost');
    close.addEventListener('click', () => {
      document.querySelector('[data-csv-run-review]')?.remove();
      const setup = document.querySelector('[data-customer-asset-setup]');
      if (setup) setup.hidden = false;
      loaded = null;
    });

    const panel = el('section', {'data-csv-run-review': 'true', class: 'panel'},
      el('div', {class: 'panel-header'},
        el('div', {},
          el('h2', {class: 'panel-title', text: 'Finding Evidence Review — CSV Run'}),
          el('p', {class: 'panel-subtitle', text: 'Server-side contextual CVSS v4 joined with public threat intelligence and direct customer context. Organizational Risk is not inferred.'})
        ),
        el('div', {class: 'inline-actions'}, download, downloadAdmission, close)
      ),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('Contextual CVSS remains technical vulnerability severity. CR/IR/AR are direct customer CVSS v4 Security Requirements; Asset Criticality is not mapped to them, Internet Facing is not mapped to MAV, and EPSS is not multiplied by CVSS.'),
        callout(`Risk-method admission: ${admissionState}. Risk rows computed: ${riskRows}. Existing methods are not auto-selected by catalog order or score magnitude.`, admissionState === 'NO_V2_PRIMARY_METHOD_ADMITTED' ? 'warning' : 'info'),
        el('div', {class: 'metrics'},
          metric('Finding rows', rows.length),
          metric('Unique CVEs', uniqueCves),
          metric('Assets', uniqueAssets),
          metric('CVSS4 present', cvssPresent),
          metric('Contextual CVSS', contextualCalculated, `${be} BE · ${bte} BTE`),
          metric('EPSS present', epssPresent),
          metric('KEV listed', kevListed),
          metric('Context unmatched', contextMissing)
        ),
        host
      ))
    );
    renderTable(host, rows);
    return panel;
  }

  async function responseProblem(response, fallback) {
    try {
      const value = await response.json();
      return value.detail || value.title || fallback;
    } catch (_) {
      return fallback;
    }
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
      status.textContent = 'Calculating contextual CVSS and evaluating risk-method admission…';
      status.className = 'status-message';
      const bundle = customerBundle(panel);
      const response = await fetch(`/api/v1/csv-first-enrichments/${encodeURIComponent(runId)}/analysis`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json; charset=utf-8'},
        body: JSON.stringify(bundle),
        cache: 'no-store',
      });
      if (!response.ok) throw new Error(await responseProblem(response, `Contextual analysis failed (HTTP ${response.status}).`));
      const run = await response.json();
      if (run.contractId !== 'CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1') throw new Error('Unexpected contextual-analysis response contract.');

      const [analysisResponse, admissionResponse] = await Promise.all([
        fetch(run.analysisCsv, {cache: 'no-store'}),
        fetch(run.methodAdmission, {cache: 'no-store'}),
      ]);
      if (!analysisResponse.ok) throw new Error(`Contextual analysis CSV could not be loaded (HTTP ${analysisResponse.status}).`);
      if (!admissionResponse.ok) throw new Error(`Method-admission report could not be loaded (HTTP ${admissionResponse.status}).`);
      const rows = parseCsv(await analysisResponse.text());
      const admission = await admissionResponse.json();
      loaded = {runId, rows, admission};

      document.querySelector('[data-csv-run-review]')?.remove();
      const review = reviewPanel(rows, runId, admission);
      panel.insertAdjacentElement('afterend', review);
      panel.hidden = true;
      status.textContent = `Contextual review ready for ${rows.length} finding rows.`;
      status.className = 'status-message success';
      review.scrollIntoView({block: 'start'});
    } catch (error) {
      status.textContent = error.message;
      status.className = 'status-message error';
    } finally {
      buttonNode.disabled = false;
    }
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
