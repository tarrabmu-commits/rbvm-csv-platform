(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_RISK_BENCHMARK_UI_V1';
  const HTTP_CONTRACT = 'CSV_FIRST_RISK_BENCHMARK_HTTP_V1';
  const REPORT_CONTRACT = 'CSV_FIRST_RISK_METHOD_BENCHMARK_V1';
  const ANALYSIS_CONTRACT = 'CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1';
  const EXECUTION_SEMANTICS = 'DESCRIPTIVE_COMPARISON_ONLY_NO_METHOD_SELECTION';
  const analysisByRun = new Map();
  const previousFetch = window.fetch.bind(window);
  let queued = false;

  document.documentElement.dataset.csvFirstRiskBenchmarkUi = CONTRACT;

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

  window.fetch = async (input, options = {}) => {
    const response = await previousFetch(input, options);
    try {
      const url = new URL(typeof input === 'string' ? input : input.url, location.href);
      const method = String(options?.method || 'GET').toUpperCase();
      if (response.ok && method === 'POST' && /^\/api\/v1\/csv-first-customer-assets\/[0-9a-fA-F-]{36}\/analyses$/.test(url.pathname)) {
        const payload = await response.clone().json();
        if (payload?.contractId === ANALYSIS_CONTRACT && payload.immutable === true && payload.runId && payload.analysisId) {
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

  function formatNumber(value, digits = 3) {
    const number = Number(value);
    if (!Number.isFinite(number)) return '—';
    return number.toLocaleString(undefined, {maximumFractionDigits: digits});
  }

  function formatPercent(value) {
    const number = Number(value);
    if (!Number.isFinite(number)) return '—';
    return `${(number * 100).toFixed(1)}%`;
  }

  function methodLabel(methodId, methods) {
    const method = methods.find(item => item.methodId === methodId);
    return method ? `${method.provider} (${method.methodId})` : methodId;
  }

  function blockerText(blockers) {
    const entries = Object.entries(blockers || {});
    if (!entries.length) return 'No blockers';
    return entries.map(([name, count]) => `${name} (${count})`).join(' · ');
  }

  function renderMethods(report) {
    const total = Number(report.scope?.findingRows || 0);
    const cards = el('div', {class: 'grid-2'});
    for (const method of report.methods || []) {
      const computed = Number(method.computedRows || 0);
      const distribution = method.distribution || {};
      cards.append(el('section', {class: 'panel'},
        el('div', {class: 'panel-body'},
          el('div', {class: 'inline-actions'},
            el('strong', {text: method.provider || method.methodId}),
            el('span', {class: 'badge state-present', text: method.nativeScale ? `${method.nativeScale.minimum}..${method.nativeScale.maximum}` : 'native'})),
          el('p', {class: 'panel-subtitle mono', text: method.methodId}),
          el('div', {class: 'metrics'},
            metric('Coverage', formatPercent(method.coverage), `${computed}/${total} rows`),
            metric('Mean', formatNumber(distribution.mean), 'native score'),
            metric('Median', formatNumber(distribution.median), 'native score'),
            metric('P95', formatNumber(distribution.p95), 'native score')),
          el('p', {class: 'panel-subtitle', text: blockerText(method.blockers)}))));
    }
    return cards;
  }

  function renderPairwise(report) {
    const methods = report.methods || [];
    const rows = (report.pairwise || []).map(pair => {
      const top100 = pair.topOverlap?.['100'] || {};
      return el('tr', {},
        el('td', {text: methodLabel(pair.leftMethodId, methods)}),
        el('td', {text: methodLabel(pair.rightMethodId, methods)}),
        el('td', {text: Number(pair.commonComputedRows || 0).toLocaleString()}),
        el('td', {text: formatNumber(pair.spearmanRankCorrelation)}),
        el('td', {text: formatNumber(pair.kendallTauB)}),
        el('td', {text: `${top100.overlap ?? 0}/${top100.effectiveK ?? 0}`}),
        el('td', {text: formatPercent(top100.jaccard)}));
    });
    return el('div', {class: 'table-wrap'},
      el('table', {class: 'data-table'},
        el('thead', {}, el('tr', {}, ...['Method A', 'Method B', 'Common rows', 'Spearman', 'Kendall τ-b', 'Top-100 overlap', 'Top-100 Jaccard'].map(label => el('th', {text: label})))),
        el('tbody', {}, ...rows)));
  }

  function renderDisagreements(report) {
    const methods = report.methods || [];
    const sections = [];
    for (const pair of report.pairwise || []) {
      const disagreements = pair.largestRankDisagreements || [];
      if (!disagreements.length) continue;
      const body = el('div', {class: 'table-wrap'},
        el('table', {class: 'data-table'},
          el('thead', {}, el('tr', {}, ...['Row', 'Asset', 'CVE', 'Rank-percentile gap', 'Method A native score', 'Method B native score'].map(label => el('th', {text: label})))),
          el('tbody', {}, ...disagreements.slice(0, 10).map(row => {
            const left = row[pair.leftMethodId] || {};
            const right = row[pair.rightMethodId] || {};
            return el('tr', {},
              el('td', {text: row.analysisRow ?? '—'}),
              el('td', {text: row.asset || '—'}),
              el('td', {class: 'mono', text: row.cveId || '—'}),
              el('td', {text: formatPercent(row.rankPercentileGap)}),
              el('td', {text: formatNumber(left.nativeScore)}),
              el('td', {text: formatNumber(right.nativeScore)}));
          }))));
      sections.push(el('details', {class: 'priority-explanation'},
        el('summary', {text: `${methodLabel(pair.leftMethodId, methods)} vs ${methodLabel(pair.rightMethodId, methods)}`}),
        callout('These are the largest differences in within-method rank percentile. Native scores are shown only in their own method scales and are not subtracted from each other.'),
        body));
    }
    return el('div', {class: 'stack'}, ...sections);
  }

  function renderBenchmark(host, metadata, report) {
    const scope = report.scope || {};
    const download = button('Download benchmark report', 'secondary');
    download.addEventListener('click', () => {
      const link = el('a', {href: metadata.benchmarkReport, download: `rbvm-risk-benchmark-${metadata.runId}-${metadata.analysisId}.json`});
      document.body.append(link);
      link.click();
      link.remove();
    });

    host.replaceChildren(
      callout('Comparison is descriptive only. It does not select a risk method, average methods, normalize their native scales, or change the method you choose for calculation.'),
      el('div', {class: 'metrics'},
        metric('Finding rows', Number(scope.findingRows || 0).toLocaleString()),
        metric('Unique CVEs', Number(scope.uniqueCves || 0).toLocaleString()),
        metric('CSV assets', Number(scope.csvDistinctAssets || 0).toLocaleString()),
        metric('Benchmark', metadata.replayed ? 'Exact replay' : 'New derivation', `execution ${String(metadata.benchmarkExecutionSha256 || '').slice(0, 12)}…`)),
      el('div', {class: 'inline-actions'}, download),
      el('h3', {class: 'panel-title', text: 'Method coverage and native distributions'}),
      renderMethods(report),
      el('h3', {class: 'panel-title', text: 'Ranking agreement'}),
      callout('Spearman and Kendall compare ordering only on rows computable by both methods. Top-N overlap uses the same common population.'),
      renderPairwise(report),
      el('h3', {class: 'panel-title', text: 'Largest ranking disagreements'}),
      renderDisagreements(report),
      el('p', {class: 'panel-subtitle mono', text: `Source analysis SHA-256: ${report.sourceAnalysisSha256 || metadata.sourceAnalysisSha256 || '—'}`}));
  }

  async function runBenchmark(host, status, buttonNode, runId, analysisId) {
    buttonNode.disabled = true;
    status.className = 'status-message';
    status.textContent = 'Comparing all four pinned risk methods on the exact immutable analysis…';
    try {
      const execution = (await api(`/api/v1/csv-first-risk-benchmarks/${encodeURIComponent(runId)}/${encodeURIComponent(analysisId)}`, {method: 'POST'})).json || {};
      if (execution.contractId !== HTTP_CONTRACT || execution.analysisId !== analysisId || execution.semantics !== EXECUTION_SEMANTICS || !execution.benchmarkExecutionSha256 || !execution.benchmarkReport) {
        throw new Error('Unexpected risk benchmark execution contract.');
      }
      const report = (await api(execution.benchmarkReport)).json || {};
      if (report.contractId !== REPORT_CONTRACT || report.sourceAnalysisSha256 !== execution.sourceAnalysisSha256) {
        throw new Error('Unexpected risk benchmark report contract.');
      }
      renderBenchmark(host, execution, report);
      status.className = 'status-message success';
      status.textContent = `Risk method comparison ready for ${Number(report.scope?.findingRows || 0).toLocaleString()} findings.`;
      host.scrollIntoView({block: 'start'});
    } catch (error) {
      status.className = 'status-message error';
      status.textContent = error.status === 403 ? 'Operator role is required to materialize the risk benchmark.' : error.message;
    } finally {
      buttonNode.disabled = false;
    }
  }

  function patch() {
    const runId = new URLSearchParams(location.search).get('runId') || '';
    const analysis = analysisByRun.get(runId);
    const review = document.querySelector('[data-csv-run-review]');
    if (!runId || !analysis || !review || review.querySelector('[data-csv-risk-benchmark-ui]')) return;
    const stack = review.querySelector('.panel-body > .stack') || review.querySelector('.panel-body');
    if (!stack) return;

    const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
    const resultHost = el('div', {class: 'stack', 'data-risk-benchmark-result': 'true'});
    const compare = button('Compare risk methods', 'secondary');
    compare.addEventListener('click', () => runBenchmark(resultHost, status, compare, runId, String(analysis.analysisId)));
    const section = el('section', {class: 'panel', 'data-csv-risk-benchmark-ui': 'true'},
      el('div', {class: 'panel-header'}, el('div', {},
        el('h2', {class: 'panel-title', text: 'Risk Method Comparison'}),
        el('p', {class: 'panel-subtitle', text: `Compare all four pinned methods against immutable analysis ${analysis.analysisId} without changing the selected method.`}))),
      el('div', {class: 'panel-body'},
        callout('Use this after readiness to understand coverage and ranking differences. Comparison is server-side and preserves every method’s native semantics.'),
        el('div', {class: 'form-actions'}, compare),
        status,
        resultHost));

    const riskSection = review.querySelector('[data-csv-risk-method-ui]');
    if (riskSection?.parentNode === stack) riskSection.insertAdjacentElement('afterend', section);
    else stack.append(section);
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
