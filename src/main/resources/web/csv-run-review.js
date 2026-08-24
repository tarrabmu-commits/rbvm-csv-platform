(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_FINDING_REVIEW_UI_V4';
  const PRIORITY_CONTRACT = 'CSV_FIRST_MVP_PRIORITY_HTTP_V1';
  const PRIORITY_METHOD = 'RBVM_MVP_PRIORITY_POLICY_V1';
  const PRIORITY_EXPLAINABILITY = 'RBVM_MVP_PRIORITY_EXPLAINABILITY_V1';
  const PRIORITY_METHOD_SHA = '88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388';
  const PAGE_SIZE = 100;
  const PREVIEW_ROW_LIMIT = 500;
  let queued = false;

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
  const normalize = value => String(value || '').normalize('NFKC').trim().toLowerCase();
  const pct = value => value === '' || value == null || Number.isNaN(Number(value)) ? '—' : `${(Number(value) * 100).toFixed(1)}%`;

  function metric(label, value, detail = '') {
    return el('div', {class: 'metric'}, el('div', {class: 'metric-label', text: label}), el('div', {class: 'metric-value', text: value}), detail ? el('div', {class: 'metric-detail', text: detail}) : null);
  }

  function artifactButton(label, href, filename, kind = 'secondary') {
    const control = button(label, kind);
    control.addEventListener('click', () => {
      const link = el('a', {href, download: filename});
      document.body.append(link); link.click(); link.remove();
    });
    return control;
  }

  function contextualCvssDisplay(row) {
    if (row.CVSS4_Context_Score_Status === 'CALCULATED_FIRST_REFERENCE_COMPATIBLE') return `${row.CVSS4_Context_Nomenclature || 'CVSS'} ${row.CVSS4_Context_Score || '—'} ${row.CVSS4_Context_Severity || ''}`.trim();
    if (row.CVSS4_Context_Score_Status === 'AMBIGUOUS_THREAT_CONFLICT') return 'Threat conflict';
    return row.CVSS4_Context_Score_Status || row.CVSS4_Status || '—';
  }

  function publicCvssDisplay(row) {
    if (row.CVSS4_Calculated_Status === 'CALCULATED') return `${row.CVSS4_Calculated_Nomenclature || 'CVSS'} ${row.CVSS4_Calculated_Score || '—'} ${row.CVSS4_Calculated_Severity || ''}`.trim();
    if (row.CVSS4_Calculated_Status === 'AMBIGUOUS_THREAT_CONFLICT') return 'Threat conflict';
    if (row.CVSS4_Status === 'PRESENT') return `Base ${row.CVSS4_Base_Score || '—'} ${row.CVSS4_Base_Severity || ''}`.trim();
    return row.CVSS4_Status || '—';
  }

  function priorityDisplay(row) {
    if (row.RBVM_MVP_Priority_Status === 'RANKED_RELATIVE_ONLY' && row.RBVM_MVP_Priority_Front) return `Front ${row.RBVM_MVP_Priority_Front}`;
    if (row.RBVM_MVP_Priority_Status === 'UNRANKABLE_MISSING_EVIDENCE') return 'Unrankable';
    return row.RBVM_MVP_Priority_Status || '—';
  }

  function priorityWhy(row) {
    const text = String(row.RBVM_MVP_Priority_Explanation || row.RBVM_MVP_Priority_Blockers || 'No server-side priority explanation is available.').trim();
    return el('details', {class: 'priority-explanation'}, el('summary', {text: 'Why?'}), el('p', {text}));
  }

  async function parseCsvPreview(response, limit) {
    if (!response.body || typeof TextDecoder === 'undefined') {
      const text = await response.text();
      return parseCsvText(text, limit);
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder('utf-8');
    const parsed = [];
    let row = [], cell = '', quoted = false, pendingQuote = false, done = false, truncated = false;

    const emitRow = () => {
      row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
      cell = '';
      if (row.some(value => String(value).trim() !== '')) parsed.push(row);
      row = [];
      if (parsed.length >= limit + 1) { truncated = true; return true; }
      return false;
    };

    while (!done && !truncated) {
      const chunk = await reader.read();
      done = chunk.done;
      const text = decoder.decode(chunk.value || new Uint8Array(), {stream: !done});
      for (let index = 0; index < text.length; index++) {
        const ch = text[index];
        if (pendingQuote) {
          pendingQuote = false;
          if (ch === '"') { cell += '"'; continue; }
          quoted = false;
        }
        if (quoted) {
          if (ch === '"') {
            if (index + 1 < text.length) {
              if (text[index + 1] === '"') { cell += '"'; index++; }
              else quoted = false;
            } else pendingQuote = true;
          } else cell += ch;
          continue;
        }
        if (ch === '"') quoted = true;
        else if (ch === ',') { row.push(cell); cell = ''; }
        else if (ch === '\n') { if (emitRow()) break; }
        else cell += ch;
      }
    }
    if (truncated) await reader.cancel();
    if (!truncated && (cell.length || row.length)) emitRow();
    if (quoted || pendingQuote) throw new Error('Priority CSV contains an unterminated quoted field.');
    return rowsFromParsed(parsed, truncated);
  }

  function parseCsvText(text, limit) {
    const parsed = [];
    let row = [], cell = '', quoted = false;
    for (let index = 0; index < text.length; index++) {
      const ch = text[index];
      if (quoted) {
        if (ch === '"') { if (text[index + 1] === '"') { cell += '"'; index++; } else quoted = false; }
        else cell += ch;
        continue;
      }
      if (ch === '"') quoted = true;
      else if (ch === ',') { row.push(cell); cell = ''; }
      else if (ch === '\n') {
        row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell); cell = '';
        if (row.some(value => String(value).trim() !== '')) parsed.push(row);
        row = [];
        if (parsed.length >= limit + 1) return rowsFromParsed(parsed, true);
      } else cell += ch;
    }
    if (quoted) throw new Error('Priority CSV contains an unterminated quoted field.');
    if (cell.length || row.length) { row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell); if (row.some(value => String(value).trim() !== '')) parsed.push(row); }
    return rowsFromParsed(parsed, false);
  }

  function rowsFromParsed(parsed, truncated) {
    if (parsed.length < 2) throw new Error('Priority CSV contains no finding rows.');
    const headers = parsed[0].map((value, index) => index === 0 ? String(value).replace(/^\uFEFF/, '') : String(value));
    return {
      rows: parsed.slice(1).map((values, rowIndex) => ({...Object.fromEntries(headers.map((header, index) => [header, values[index] ?? ''])), CSV_Run_Row: String(rowIndex + 2)})),
      truncated,
    };
  }

  function renderTable(host, allRows, totalRows, truncated) {
    host.replaceChildren();
    const search = el('input', {type: 'search', class: 'search-input', placeholder: 'Search preview by CVE, asset or product…', 'aria-label': 'Search CSV run finding preview'});
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
      const rows = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
      const table = el('table', {class: 'data-table'},
        el('thead', {}, el('tr', {}, ...['Asset','CVE','MVP Priority','Why','Product','Scanner','Context CVSS','Public CVSS','EPSS','KEV','Criticality','Internet','Context'].map(label => el('th', {text: label})))),
        el('tbody', {}, ...rows.map(row => el('tr', {},
          el('td', {text: row.Agent || row.Agent_ID || '—'}), el('td', {class: 'mono', text: row.CVE_ID || '—'}),
          el('td', {text: priorityDisplay(row)}), el('td', {}, priorityWhy(row)), el('td', {text: row.Affected_Product || '—'}),
          el('td', {text: row.Severity || '—'}), el('td', {text: contextualCvssDisplay(row)}), el('td', {text: publicCvssDisplay(row)}),
          el('td', {text: pct(row.EPSS_Probability)}), el('td', {text: String(row.KEV_Listed || '').toLowerCase() === 'true' ? 'LISTED' : String(row.KEV_Listed || '').toLowerCase() === 'false' ? 'NOT LISTED' : '—'}),
          el('td', {text: row.Asset_Criticality || '—'}), el('td', {text: row.Internet_Facing || '—'}), el('td', {text: row.Customer_Context_Status || '—'})
        )))
      );
      tableHost.replaceChildren(table);
      const scope = truncated ? `previewing first ${allRows.length} of ${totalRows}` : `${allRows.length} of ${totalRows}`;
      pageLabel.textContent = `${scope} finding rows · page ${page + 1} of ${pages}`;
      previous.disabled = page <= 0; next.disabled = page + 1 >= pages;
    };
    search.addEventListener('input', () => { page = 0; render(); });
    previous.addEventListener('click', () => { if (page > 0) { page--; render(); } });
    next.addEventListener('click', () => { page++; render(); });
    host.append(el('div', {class: 'toolbar'}, search, el('div', {class: 'pagination'}, previous, pageLabel, next)), tableHost);
    render();
  }

  function reviewPanel(rows, truncated, run, admission, priority, priorityReport) {
    const runId = run.runId, analysisId = run.analysisId;
    const host = el('div');
    const close = button('Back to Assets', 'ghost');
    const panel = el('section', {'data-csv-run-review': 'true', class: 'panel'},
      el('div', {class: 'panel-header'}, el('div', {},
        el('h2', {class: 'panel-title', text: 'Finding Evidence Review — CSV Run'}),
        el('p', {class: 'panel-subtitle', text: `Immutable contextual analysis ${analysisId}. Saved V4 customer context + relative MVP treatment priority; Organizational Risk remains NON_COMPUTABLE.`})
      ), el('div', {class: 'inline-actions'},
        artifactButton('Download priority-ranked CSV', priority.priorityCsv, `rbvm-mvp-priority-${runId}-${analysisId}.csv`, 'primary'),
        artifactButton('Download priority report', priority.priorityReport, `rbvm-mvp-priority-report-${runId}-${analysisId}.json`),
        artifactButton('Download contextual analysis CSV', run.analysisCsv, `rbvm-contextual-analysis-${runId}-${analysisId}.csv`),
        artifactButton('Download method admission', run.methodAdmission, `rbvm-method-admission-${runId}-${analysisId}.json`), close
      )),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('The browser preview is deliberately bounded. Download artifacts remain complete and immutable; preview truncation never changes analysis or priority.', 'warning'),
        callout('MVP Priority is a relative Pareto frontier within this exact analysis. Front 1 is not Critical/High risk, an SLA, or Organizational Risk.'),
        el('div', {class: 'metrics'},
          metric('Finding rows', priorityReport.rows ?? '—'), metric('Priority ranked', priorityReport.rankedRows ?? '—', `Front 1: ${priorityReport.frontCounts?.['1'] || 0}`),
          metric('Priority unrankable', priorityReport.unrankableRows ?? '—', 'Missing evidence is not imputed'), metric('Preview rows', rows.length, truncated ? `bounded at ${PREVIEW_ROW_LIMIT}` : 'complete preview'),
          metric('Risk-method admission', admission?.selection?.state || 'UNKNOWN'), metric('Organizational Risk', 'NON_COMPUTABLE')
        ), host
      ))
    );
    panel.rbvmPriorityPreviewRows = rows;
    panel.rbvmPriorityPreviewTruncated = truncated;
    panel.rbvmPriorityReport = priorityReport;
    panel.rbvmMethodAdmission = admission;
    close.addEventListener('click', () => {
      panel.rbvmPriorityPreviewRows = null;
      panel.remove();
      const setup = document.querySelector('[data-customer-asset-setup]'); if (setup) setup.hidden = false;
    });
    renderTable(host, rows, Number(priorityReport.rows || rows.length), truncated);
    return panel;
  }

  async function responseProblem(response, fallback) {
    try { const value = await response.json(); return value.detail || value.title || fallback; } catch (_) { return fallback; }
  }

  async function openReview(panel, buttonNode, status) {
    const runId = new URLSearchParams(location.search).get('runId') || '';
    if (!runId) { status.textContent = 'This Assets page is not associated with a CSV enrichment run.'; status.className = 'status-message error'; return; }
    if (panel.dataset.customerBundlePersisted !== 'true') { status.textContent = 'Save the complete V4 customer bundle to this local run before reviewing findings.'; status.className = 'status-message error'; return; }
    buttonNode.disabled = true;
    try {
      status.textContent = 'Creating immutable contextual analysis from the saved V4 customer bundle…'; status.className = 'status-message';
      const response = await fetch(`/api/v1/csv-first-customer-assets/${encodeURIComponent(runId)}/analyses`, {method: 'POST', cache: 'no-store'});
      if (!response.ok) throw new Error(await responseProblem(response, `Contextual analysis failed (HTTP ${response.status}).`));
      const run = await response.json();
      if (run.contractId !== 'CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1' || run.immutable !== true || !run.analysisId || run.customerBundleSource !== 'SAVED_RUN_BUNDLE') throw new Error('Unexpected contextual-analysis response contract.');

      const priorityResponse = await fetch(run.priority, {method: 'POST', cache: 'no-store'});
      if (!priorityResponse.ok) throw new Error(await responseProblem(priorityResponse, `MVP priority derivation failed (HTTP ${priorityResponse.status}).`));
      const priority = await priorityResponse.json();
      if (priority.contractId !== PRIORITY_CONTRACT || priority.methodId !== PRIORITY_METHOD || priority.methodSha256 !== PRIORITY_METHOD_SHA || priority.organizationalRisk !== 'NON_COMPUTABLE') throw new Error('Unexpected MVP-priority response contract.');

      const [priorityCsvResponse, admissionResponse, priorityReportResponse] = await Promise.all([
        fetch(priority.priorityCsv, {cache: 'no-store'}), fetch(run.methodAdmission, {cache: 'no-store'}), fetch(priority.priorityReport, {cache: 'no-store'}),
      ]);
      if (!priorityCsvResponse.ok || !admissionResponse.ok || !priorityReportResponse.ok) throw new Error('One or more immutable analysis artifacts could not be loaded.');
      const [{rows, truncated}, admission, priorityReport] = await Promise.all([
        parseCsvPreview(priorityCsvResponse, PREVIEW_ROW_LIMIT), admissionResponse.json(), priorityReportResponse.json(),
      ]);
      if (priorityReport.methodId !== PRIORITY_METHOD || priorityReport.methodSha256 !== PRIORITY_METHOD_SHA || priorityReport.organizationalRiskComputed !== false || priorityReport.riskStatus !== 'NON_COMPUTABLE' || priorityReport.explainability?.contractId !== PRIORITY_EXPLAINABILITY) throw new Error('Unexpected MVP-priority report contract.');

      document.querySelector('[data-csv-run-review]')?.remove();
      const review = reviewPanel(rows, truncated, run, admission, priority, priorityReport);
      panel.insertAdjacentElement('afterend', review); panel.hidden = true;
      status.textContent = `Contextual review ${run.analysisId} ready. Browser preview is bounded; complete artifacts remain downloadable.`; status.className = 'status-message success';
      review.scrollIntoView({block: 'start'});
    } catch (error) { status.textContent = error.message; status.className = 'status-message error'; }
    finally { buttonNode.disabled = false; }
  }

  function patch() {
    const panel = document.querySelector('[data-customer-asset-setup]');
    if (!panel || panel.querySelector('[data-review-findings-button]')) return;
    const actions = panel.querySelector('.inline-actions'); if (!actions) return;
    const status = panel.querySelector('.status-message') || el('div', {class: 'status-message'});
    const review = button('Review Findings', 'primary'); review.dataset.reviewFindingsButton = 'true';
    review.addEventListener('click', () => openReview(panel, review, status)); actions.append(review);
  }

  function schedule() { if (queued) return; queued = true; queueMicrotask(() => { queued = false; patch(); }); }
  const observerRoot = document.getElementById('rbvm-app') || document.documentElement;
  new MutationObserver(schedule).observe(observerRoot, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule); window.addEventListener('popstate', schedule); schedule();
})();
