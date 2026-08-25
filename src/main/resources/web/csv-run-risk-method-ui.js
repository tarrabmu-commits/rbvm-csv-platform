(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_RISK_METHOD_SELECTION_UI_V1';
  const API_CONTRACT = 'CSV_FIRST_RISK_HTTP_V1';
  const READINESS_CONTRACT = 'CSV_FIRST_RISK_READINESS_V1';
  const REPORT_CONTRACT = 'CSV_FIRST_RISK_REPORT_V1';
  const PREVIEW_LIMIT = 300;
  const PAGE_SIZE = 50;
  const analysisByRun = new Map();
  const previousFetch = window.fetch.bind(window);
  let queued = false;

  document.documentElement.dataset.csvFirstRiskMethodUi = CONTRACT;

  const el = (tag, attrs = {}, ...children) => {
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

  const button = (label, kind = 'secondary') => el('button', {type: 'button', class: `button button-${kind}`, text: label});
  const callout = (text, kind = 'info') => el('div', {class: `callout callout-${kind}`, text});
  const metric = (label, value, detail = '') => el('div', {class: 'metric'},
    el('div', {class: 'metric-label', text: label}),
    el('div', {class: 'metric-value', text: value}),
    detail ? el('div', {class: 'metric-detail', text: detail}) : null);
  const badge = (text, css) => el('span', {class: `badge ${css}`, text});
  const normalize = value => String(value || '').normalize('NFKC').trim().toLowerCase();

  window.fetch = async (input, options = {}) => {
    const response = await previousFetch(input, options);
    try {
      const url = new URL(typeof input === 'string' ? input : input.url, location.href);
      const method = String(options?.method || 'GET').toUpperCase();
      if (response.ok && method === 'POST' && /^\/api\/v1\/csv-first-customer-assets\/[0-9a-fA-F-]{36}\/analyses$/.test(url.pathname)) {
        const payload = await response.clone().json();
        if (payload?.contractId === 'CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1' && payload.immutable === true && payload.runId && payload.analysisId) {
          analysisByRun.set(String(payload.runId), payload);
          schedule();
        }
      }
    } catch (_) {
      // Presentation enhancement only; never alter the underlying response.
    }
    return response;
  };

  async function api(path, options = {}) {
    const response = await previousFetch(path, {...options, cache: 'no-store'});
    let json = null;
    try { json = await response.clone().json(); } catch (_) {}
    if (!response.ok) {
      const error = new Error(json?.detail || json?.title || `HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return {response, json};
  }

  function artifactButton(label, href, filename, kind = 'secondary') {
    const control = button(label, kind);
    control.addEventListener('click', () => {
      const link = el('a', {href, download: filename});
      document.body.append(link);
      link.click();
      link.remove();
    });
    return control;
  }

  async function parseCsvPreview(response, limit) {
    if (!response.body || typeof TextDecoder === 'undefined') return parseCsvText(await response.text(), limit);
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
    if (quoted || pendingQuote) throw new Error('Risk CSV contains an unterminated quoted field.');
    return rowsFromParsed(parsed, truncated);
  }

  function parseCsvText(text, limit) {
    const parsed = [];
    let row = [], cell = '', quoted = false;
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
        cell = '';
        if (row.some(value => String(value).trim() !== '')) parsed.push(row);
        row = [];
        if (parsed.length >= limit + 1) return rowsFromParsed(parsed, true);
      } else cell += ch;
    }
    if (quoted) throw new Error('Risk CSV contains an unterminated quoted field.');
    if (cell.length || row.length) {
      row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
      if (row.some(value => String(value).trim() !== '')) parsed.push(row);
    }
    return rowsFromParsed(parsed, false);
  }

  function rowsFromParsed(parsed, truncated) {
    if (parsed.length < 2) throw new Error('Risk CSV contains no finding rows.');
    const headers = parsed[0].map((value, index) => index === 0 ? String(value).replace(/^\uFEFF/, '') : String(value));
    return {
      rows: parsed.slice(1).map(values => Object.fromEntries(headers.map((header, index) => [header, values[index] ?? '']))),
      truncated,
    };
  }

  function blockersText(blockers) {
    const entries = Object.entries(blockers || {});
    if (!entries.length) return 'No readiness blockers';
    return entries.map(([code, count]) => `${code} (${count})`).join(' · ');
  }

  function methodCard(method, readiness, name) {
    const input = el('input', {type: 'radio', name, value: method.methodId, 'aria-label': `${method.provider} risk method`});
    const total = Number(readiness?.computableRows || 0) + Number(readiness?.nonComputableRows || 0);
    const ready = Number(readiness?.computableRows || 0);
    const css = ready === total && total > 0 ? 'state-present' : ready > 0 ? 'state-ambiguous' : 'state-missing';
    const state = ready === total && total > 0 ? 'Ready' : ready > 0 ? 'Partial' : 'Blocked';
    const body = el('label', {class: 'panel', style: 'cursor:pointer'},
      el('div', {class: 'panel-body'},
        el('div', {class: 'inline-actions'}, input, el('strong', {text: method.provider}), badge(state, css)),
        el('div', {class: 'details-grid'},
          el('div', {class: 'detail'}, el('dt', {text: 'Method'}), el('dd', {class: 'mono', text: method.methodId})),
          el('div', {class: 'detail'}, el('dt', {text: 'Native scale'}), el('dd', {text: method.nativeScale})),
          el('div', {class: 'detail'}, el('dt', {text: 'Computable rows'}), el('dd', {text: `${ready}/${total}`})),
          el('div', {class: 'detail'}, el('dt', {text: 'Classification'}), el('dd', {text: method.classification}))),
        el('p', {class: 'panel-subtitle', text: blockersText(readiness?.blockers)})));
    return {input, body};
  }

  function riskWhy(row) {
    let value = row.Risk_Explanation_JSON || '';
    try { value = JSON.stringify(JSON.parse(value), null, 2); } catch (_) {}
    const body = el('pre', {class: 'mono', style: 'white-space:pre-wrap;overflow-wrap:anywhere', text: value || 'No server-side explanation available.'});
    return el('details', {class: 'priority-explanation'}, el('summary', {text: 'Why?'}), body);
  }

  function renderRiskTable(host, allRows, totalRows, truncated) {
    const search = el('input', {type: 'search', class: 'search-input', placeholder: 'Search risk preview by CVE, asset or rating…', 'aria-label': 'Search risk result preview'});
    const pageLabel = el('span');
    const previous = button('Previous', 'ghost');
    const next = button('Next', 'ghost');
    const tableHost = el('div');
    let page = 0;
    const paint = () => {
      const query = normalize(search.value);
      const filtered = query ? allRows.filter(row => [row.CVE_ID, row.Agent, row.Agent_ID, row.Affected_Product, row.Risk_Rating, row.Risk_Status].some(value => normalize(value).includes(query))) : allRows;
      const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
      if (page >= pages) page = pages - 1;
      const rows = filtered.slice(page * PAGE_SIZE, page * PAGE_SIZE + PAGE_SIZE);
      const table = el(
        'table',
        {class: 'data-table'},
        el('thead', {}, el('tr', {}, ...['Asset', 'CVE', 'Risk', 'Rating', 'Status', 'Why', 'Blockers'].map(label => el('th', {text: label})))),
        el('tbody', {}, ...rows.map(row => el(
          'tr',
          {},
          el('td', {text: row.Agent || row.Agent_ID || '—'}),
          el('td', {class: 'mono', text: row.CVE_ID || '—'}),
          el('td', {text: row.Risk_Score ? `${row.Risk_Score} / ${row.Risk_Scale || 'native'}` : '—'}),
          el('td', {text: row.Risk_Rating || '—'}),
          el('td', {text: row.Risk_Status || '—'}),
          el('td', {}, riskWhy(row)),
          el('td', {class: 'mono', text: row.Risk_Blockers || '—'})
        )))
      );
      tableHost.replaceChildren(table);
      const scope = truncated ? `previewing first ${allRows.length} of ${totalRows}` : `${allRows.length} of ${totalRows}`;
      pageLabel.textContent = `${scope} risk rows · page ${page + 1} of ${pages}`;
      previous.disabled = page <= 0;
      next.disabled = page + 1 >= pages;
    };
    search.addEventListener('input', () => { page = 0; paint(); });
    previous.addEventListener('click', () => { if (page > 0) { page--; paint(); } });
    next.addEventListener('click', () => { page++; paint(); });
    host.replaceChildren(el('div', {class: 'toolbar'}, search, el('div', {class: 'pagination'}, previous, pageLabel, next)), tableHost);
    paint();
  }

  function renderResult(host, runId, analysisId, execution, report, preview) {
    const result = report.result || {};
    const scope = report.scope || {};
    const ratingCounts = Object.entries(result.ratingCounts || {}).map(([name, count]) => `${name}: ${count}`).join(' · ') || 'No native ratings';
    const blockerCounts = blockersText(result.blockers);
    const headerActions = el('div', {class: 'inline-actions'},
      artifactButton('Download risk CSV', execution.riskCsv, `rbvm-risk-${execution.methodId}-${runId}-${analysisId}.csv`, 'primary'),
      artifactButton('Download risk report', execution.riskReport, `rbvm-risk-report-${execution.methodId}-${runId}-${analysisId}.json`),
      artifactButton('Download method definition', execution.methodDefinition, `${execution.methodId}.json`));
    host.replaceChildren(
      el('section', {class: 'panel'},
        el('div', {class: 'panel-header'}, el('div', {},
          el('h3', {class: 'panel-title', text: `${execution.provider} result`}),
          el('p', {class: 'panel-subtitle', text: `${execution.methodId} · native scale ${execution.nativeScale} · ${execution.replayed ? 'exact replay' : 'new immutable derivation'}`})
        ), headerActions),
        el('div', {class: 'panel-body'},
          callout('This is the selected method’s native output. RBVM does not normalize or average it with another risk method.'),
          el('div', {class: 'metrics'},
            metric('Computed', result.computedRows ?? '—', `of ${scope.findingRows ?? '—'} finding rows`),
            metric('Non-computable', result.nonComputableRows ?? '—', blockerCounts),
            metric('Mean score', result.meanScore ?? '—', execution.nativeScale),
            metric('Minimum', result.minimumScore ?? '—', execution.nativeScale),
            metric('Maximum', result.maximumScore ?? '—', execution.nativeScale),
            metric('Native ratings', ratingCounts)),
          el('p', {class: 'panel-subtitle', text: `Method SHA-256: ${execution.methodSha256}`})
        )),
      el('section', {class: 'panel'},
        el('div', {class: 'panel-header'}, el('div', {}, el('h3', {class: 'panel-title', text: 'Risk result preview'}), el('p', {class: 'panel-subtitle', text: 'Server-produced scores and explanations from the exact immutable analysis.'}))),
        el('div', {class: 'panel-body', 'data-risk-preview-table': 'true'}))
    );
    renderRiskTable(host.querySelector('[data-risk-preview-table]'), preview.rows, Number(scope.findingRows || preview.rows.length), preview.truncated);
  }

  async function loadSelector(root, runId, analysisId) {
    root.replaceChildren(el('div', {class: 'skeleton'}), el('div', {class: 'skeleton'}));
    try {
      const [catalogResponse, readinessResponse] = await Promise.all([
        api('/api/v1/csv-first-risk-methods'),
        api(`/api/v1/csv-first-risk-readiness/${encodeURIComponent(runId)}/${encodeURIComponent(analysisId)}`),
      ]);
      const catalog = catalogResponse.json || {};
      const readiness = readinessResponse.json || {};
      if (catalog.contractId !== API_CONTRACT || catalog.selectionSemantics !== 'EXPLICIT_PER_ANALYSIS_NO_IMPLICIT_DEFAULT') throw new Error('Unexpected risk-method catalog contract.');
      if (readiness.contractId !== READINESS_CONTRACT) throw new Error('Unexpected risk-readiness contract.');
      const readinessById = new Map((readiness.methods || []).map(value => [value.methodId, value]));
      const methods = catalog.methods || [];
      if (!methods.length) throw new Error('No CSV-first risk methods are available.');

      const name = `csv-risk-method-${analysisId}`;
      const cards = el('div', {class: 'grid-2'});
      const radios = [];
      for (const method of methods) {
        const card = methodCard(method, readinessById.get(method.methodId), name);
        radios.push(card.input);
        cards.append(card.body);
      }
      const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
      const selection = el('div', {class: 'stack'});
      const resultHost = el('div', {class: 'stack', 'data-risk-result-host': 'true'});
      const calculate = button('Calculate selected risk', 'primary');
      calculate.disabled = true;
      const updateSelection = () => {
        const selected = radios.find(value => value.checked);
        const method = methods.find(value => value.methodId === selected?.value);
        const ready = readinessById.get(method?.methodId);
        if (!method || !ready) {
          calculate.disabled = true;
          selection.replaceChildren(callout('Choose one method. No method is selected by default.'));
          return;
        }
        const total = Number(ready.computableRows || 0) + Number(ready.nonComputableRows || 0);
        calculate.disabled = Number(ready.computableRows || 0) < 1;
        selection.replaceChildren(
          callout(`${method.provider}: ${ready.computableRows}/${total} rows computable. ${blockersText(ready.blockers)}`, ready.nonComputableRows ? 'warning' : 'info'));
      };
      radios.forEach(radio => radio.addEventListener('change', updateSelection));
      updateSelection();

      calculate.addEventListener('click', async () => {
        const selected = radios.find(value => value.checked);
        const method = methods.find(value => value.methodId === selected?.value);
        if (!method) return;
        calculate.disabled = true;
        status.className = 'status-message';
        status.textContent = `Calculating ${method.provider} risk from immutable analysis ${analysisId}…`;
        try {
          const executionResponse = await api(`/api/v1/csv-first-risks/${encodeURIComponent(runId)}/${encodeURIComponent(analysisId)}/${encodeURIComponent(method.methodId)}`, {method: 'POST'});
          const execution = executionResponse.json || {};
          if (execution.contractId !== API_CONTRACT || execution.status !== 'COMPLETE' || execution.methodId !== method.methodId || execution.analysisId !== analysisId) throw new Error('Unexpected risk execution contract.');
          const [reportResponse, csvResponse] = await Promise.all([
            api(execution.riskReport),
            previousFetch(execution.riskCsv, {cache: 'no-store'}),
          ]);
          if (!csvResponse.ok) throw new Error(`Risk CSV could not be loaded (HTTP ${csvResponse.status}).`);
          const report = reportResponse.json || {};
          if (report.contractId !== REPORT_CONTRACT || report.methodId !== method.methodId || report.methodSha256 !== execution.methodSha256) throw new Error('Unexpected risk report contract.');
          const preview = await parseCsvPreview(csvResponse, PREVIEW_LIMIT);
          renderResult(resultHost, runId, analysisId, execution, report, preview);
          status.className = 'status-message success';
          status.textContent = `${method.provider} risk ready. ${report.result?.computedRows || 0} rows computed; ${report.result?.nonComputableRows || 0} remain non-computable.`;
          resultHost.scrollIntoView({block: 'start'});
        } catch (error) {
          status.className = 'status-message error';
          status.textContent = error.status === 403 ? 'Operator role is required to calculate risk.' : error.message;
        } finally {
          const current = radios.find(value => value.checked);
          const ready = readinessById.get(current?.value);
          calculate.disabled = !current || Number(ready?.computableRows || 0) < 1;
        }
      });

      root.replaceChildren(
        callout('Select exactly one risk method for this immutable CSV analysis. The browser never chooses a default, averages methods, or calculates scores client-side.'),
        cards,
        selection,
        status,
        el('div', {class: 'form-actions'}, calculate),
        resultHost
      );
    } catch (error) {
      root.replaceChildren(callout(error.status === 503 ? 'CSV-first risk runtime is unavailable in this deployment.' : `Risk methods could not be loaded: ${error.message}`, 'warning'));
    }
  }

  function patch() {
    const runId = new URLSearchParams(location.search).get('runId') || '';
    const analysis = analysisByRun.get(runId);
    const review = document.querySelector('[data-csv-run-review]');
    if (!runId || !analysis || !review || review.querySelector('[data-csv-risk-method-ui]')) return;
    const stack = review.querySelector('.panel-body > .stack') || review.querySelector('.panel-body');
    if (!stack) return;
    const section = el('section', {class: 'panel', 'data-csv-risk-method-ui': 'true'},
      el('div', {class: 'panel-header'}, el('div', {},
        el('h2', {class: 'panel-title', text: 'Organizational Risk Method'}),
        el('p', {class: 'panel-subtitle', text: `Choose one method for immutable analysis ${analysis.analysisId}. Each result keeps its native scale and method SHA.`}))),
      el('div', {class: 'panel-body', 'data-csv-risk-method-body': 'true'}));
    const anchor = stack.lastElementChild;
    if (anchor) stack.insertBefore(section, anchor);
    else stack.append(section);
    loadSelector(section.querySelector('[data-csv-risk-method-body]'), runId, String(analysis.analysisId));
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; patch(); });
  }

  const observerRoot = document.getElementById('rbvm-app') || document.documentElement;
  new MutationObserver(schedule).observe(observerRoot, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
