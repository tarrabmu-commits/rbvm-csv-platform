(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_CANONICAL_HANDOFF_UI_V2';
  const SOURCE_CONTRACT = 'CSV_FIRST_SOURCE_ARTIFACT_HTTP_V1';
  const MANIFEST_CONTRACT = 'CANONICAL_IMPORT_FINDING_MANIFEST_HTTP_V1';
  const EVIDENCE_CONTRACT = 'CSV_FIRST_CANONICAL_PUBLIC_EVIDENCE_HTTP_V1';
  const CSV_CONTRACTS = ['WAZUH_CSV_V1', 'WAZUH_CSV_V2'];
  let queued = false;
  let activeImport = null;

  document.documentElement.dataset.csvFirstCanonicalHandoffUi = CONTRACT;

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
  const field = (label, input) => el('div', {class: 'field'}, el('label', {}, el('span', {text: label}), input));

  function runId() {
    if (location.pathname.replace(/\/+$/, '') !== '/assets') return '';
    return new URLSearchParams(location.search).get('runId') || '';
  }

  function setStatus(node, message, kind = '') {
    node.textContent = message;
    node.className = `status-message${kind ? ` ${kind}` : ''}`;
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {...options, cache: 'no-store'});
    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const problem = await response.json();
        detail = problem.detail || problem.title || detail;
      } catch (_) { }
      throw new Error(detail);
    }
    return response;
  }

  function validProfile(value) {
    return /^[A-Za-z0-9._:-]{1,128}$/.test(value);
  }

  async function idempotencyKey(run, profile, contract) {
    const bytes = new TextEncoder().encode(`${run}|${profile}|${contract}`);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    const hex = [...new Uint8Array(digest)].map(value => value.toString(16).padStart(2, '0')).join('');
    return `csv-first-canonical-${run}-${hex.slice(0, 24)}`;
  }

  function metric(label, value) {
    return el('div', {class: 'metric'}, el('div', {class: 'metric-label', text: label}), el('div', {class: 'metric-value', text: value}));
  }

  function materializationView(data) {
    const materialization = data.materialization || {};
    return el('div', {class: 'metrics'},
      metric('Canonical status', data.status || '—'),
      metric('Inserted observations', materialization.insertedObservations ?? '—'),
      metric('New assets', materialization.newAssets ?? '—'),
      metric('New vulnerabilities', materialization.newVulnerabilities ?? '—'),
      metric('New findings/cases', materialization.newCases ?? '—')
    );
  }

  function previewView(data) {
    const ledger = data.analysis?.ledger || {};
    return el('div', {class: 'metrics'},
      metric('Preview status', data.status || '—'),
      metric('Accepted rows', ledger.acceptedRows ?? '—'),
      metric('Quarantined rows', ledger.quarantinedRows ?? '—'),
      metric('Contract', data.contractId || '—')
    );
  }

  function manifestUrl(importId) {
    return `/api/v1/canonical-imports/${encodeURIComponent(importId)}/findings.csv`;
  }

  function manifestLink(importId) {
    return el('a', {
      class: 'button button-secondary',
      href: manifestUrl(importId),
      download: `rbvm-findings-${importId}.csv`,
      text: 'Download exact Finding manifest',
      'data-finding-manifest-contract': MANIFEST_CONTRACT,
    });
  }

  function canonicalEvidenceAction(run) {
    const persist = button('Persist canonical EPSS + KEV', 'primary');
    const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
    const result = el('div');
    persist.addEventListener('click', async () => {
      persist.disabled = true;
      try {
        setStatus(status, 'Fetching validated FIRST daily EPSS and CISA KEV source snapshots for this CSV scope…');
        const response = await api(`/api/v1/csv-first-canonical-evidence/${encodeURIComponent(run)}`, {method: 'POST'});
        const data = await response.json();
        if (data.contractId !== EVIDENCE_CONTRACT) throw new Error('Unexpected canonical public-evidence contract.');
        result.replaceChildren(el('div', {class: 'metrics'},
          metric('EPSS accepted', data.epss?.acceptedRows ?? '—'),
          metric('EPSS inserted/replayed', `${data.epss?.insertedEvidence ?? 0}/${data.epss?.replayedEvidence ?? 0}`),
          metric('KEV accepted', data.cisaKev?.acceptedRows ?? '—'),
          metric('KEV inserted/replayed', `${data.cisaKev?.insertedEvidence ?? 0}/${data.cisaKev?.replayedEvidence ?? 0}`)
        ));
        setStatus(status, 'Canonical EPSS and KEV evidence persisted. CVSS v4 remains a contextual analysis artifact; no v4→v3.1 conversion or Risk score was created.', 'success');
      } catch (error) {
        setStatus(status, error.message, 'error');
      } finally {
        persist.disabled = false;
      }
    });
    return el('div', {class: 'stack', 'data-canonical-public-evidence': EVIDENCE_CONTRACT},
      callout('Canonical EPSS uses the pinned FIRST daily bulk feed with model version and exact source SHA. Canonical KEV uses the official CISA catalog snapshot. The CSV-first EPSS API response is not relabeled as bulk-feed evidence.'),
      el('div', {class: 'inline-actions'}, persist), status, result
    );
  }

  function readinessView() {
    return el('div', {class: 'stack', 'data-decision-readiness': 'FAIL_CLOSED'},
      el('h3', {text: 'Decision Input readiness'}),
      callout('Canonical scanner evidence and exact Finding_IDs are ready. Organizational Risk remains NON_COMPUTABLE until required customer evidence is explicitly assessed and associated.'),
      el('div', {class: 'metrics'},
        metric('Scanner evidence', 'READY'),
        metric('Public EPSS / KEV', 'PERSIST EXPLICITLY'),
        metric('Applicability', 'EXPLICIT ASSESSMENT REQUIRED'),
        metric('Exact reachability', 'CUSTOMER-CONFIRMED LINK REQUIRED'),
        metric('Business impact/service', 'CUSTOMER EVIDENCE/LINK REQUIRED'),
        metric('RBVM V2 primary method', 'NOT ADMITTED')
      ),
      callout('Internet Facing is not treated as exact reachability or MAV. Asset Criticality is not converted to CR/IR/AR. No applicability state is inferred.', 'warning')
    );
  }

  function completedView(data) {
    const run = runId();
    return el('div', {class: 'stack'},
      materializationView(data),
      callout('The Finding manifest is import-scoped through import_observation → observation → exposure. It does not match by hostname, CVE, product, or filename.'),
      el('div', {class: 'inline-actions'},
        manifestLink(data.importId),
        el('a', {class: 'button button-secondary', href: '/', text: 'Review canonical Findings'})
      ),
      canonicalEvidenceAction(run),
      readinessView()
    );
  }

  function announceCompleted(data) {
    document.documentElement.dataset.canonicalImportId = data.importId;
    window.dispatchEvent(new CustomEvent('rbvm:canonical-import-complete', {
      detail: {importId: data.importId, manifestUrl: manifestUrl(data.importId), contractId: MANIFEST_CONTRACT},
    }));
  }

  function patch() {
    const run = runId();
    if (!run) return;
    const root = document.getElementById('page-content');
    if (!root || root.querySelector('[data-csv-canonical-handoff]')) return;
    const anchor = root.querySelector('[data-customer-asset-setup]') || root.querySelector('.page-header');
    if (!anchor) return;

    const profile = el('input', {type: 'text', placeholder: 'e.g. wazuh-primary', autocomplete: 'off'});
    const contract = el('select');
    contract.append(el('option', {value: '', text: 'Select CSV contract…'}));
    for (const value of CSV_CONTRACTS) contract.append(el('option', {value, text: value}));
    const preview = button('Create canonical preview', 'primary');
    const confirm = button('Confirm canonical import', 'secondary');
    confirm.disabled = true;
    const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
    const result = el('div');

    preview.addEventListener('click', async () => {
      const sourceProfile = profile.value.trim();
      const csvContract = contract.value;
      if (!validProfile(sourceProfile)) {
        setStatus(status, 'Source Profile ID is required and may contain letters, numbers, dot, underscore, colon or hyphen.', 'error');
        return;
      }
      if (!CSV_CONTRACTS.includes(csvContract)) {
        setStatus(status, 'Select WAZUH_CSV_V1 or WAZUH_CSV_V2 before creating the preview.', 'error');
        return;
      }

      preview.disabled = true;
      confirm.disabled = true;
      activeImport = null;
      try {
        setStatus(status, 'Loading the exact original CSV-first source artifact…');
        const sourceResponse = await api(`/api/v1/csv-first-sources/${encodeURIComponent(run)}`);
        if (sourceResponse.headers.get('X-RBVM-Contract') !== SOURCE_CONTRACT) {
          throw new Error('The source artifact contract is missing or unexpected.');
        }
        const originalCsv = await sourceResponse.blob();
        const key = await idempotencyKey(run, sourceProfile, csvContract);
        setStatus(status, 'Creating canonical import preview from the original scanner CSV…');
        const response = await api('/api/v1/csv-imports', {
          method: 'POST',
          headers: {
            'Content-Type': 'text/csv; charset=utf-8',
            'X-Source-Profile-Id': sourceProfile,
            'X-CSV-Contract': csvContract,
            'Idempotency-Key': key,
          },
          body: originalCsv,
        });
        const data = await response.json();
        activeImport = data;
        if (data.status === 'COMPLETED') {
          result.replaceChildren(completedView(data));
          announceCompleted(data);
          setStatus(status, `Canonical import ${data.importId} is already complete. Exact Finding manifest is available.`, 'success');
          confirm.disabled = true;
        } else {
          result.replaceChildren(previewView(data));
          setStatus(status, `Preview ready for canonical import ${data.importId}. Review counts, then confirm explicitly.`, 'success');
          confirm.disabled = false;
        }
      } catch (error) {
        result.replaceChildren();
        setStatus(status, error.message, 'error');
      } finally {
        preview.disabled = false;
      }
    });

    confirm.addEventListener('click', async () => {
      if (!activeImport?.importId) {
        setStatus(status, 'Create a canonical preview first.', 'error');
        return;
      }
      confirm.disabled = true;
      preview.disabled = true;
      try {
        setStatus(status, `Confirming canonical import ${activeImport.importId}…`);
        const response = await api(`/api/v1/csv-imports/${encodeURIComponent(activeImport.importId)}/confirm`, {
          method: 'POST',
          headers: {'Idempotency-Key': `csv-first-confirm-${activeImport.importId}`},
        });
        const data = await response.json();
        activeImport = data;
        result.replaceChildren(completedView(data));
        announceCompleted(data);
        setStatus(status, 'Canonical import complete. Exact Finding_IDs are now available for Applicability and customer-confirmed context associations.', 'success');
      } catch (error) {
        setStatus(status, error.message, 'error');
        confirm.disabled = false;
      } finally {
        preview.disabled = false;
      }
    });

    const panel = el('section', {'data-csv-canonical-handoff': CONTRACT, class: 'panel'},
      el('div', {class: 'panel-header'},
        el('div', {},
          el('h2', {class: 'panel-title', text: 'Canonical Finding Handoff'}),
          el('p', {class: 'panel-subtitle', text: 'Convert this stateless CSV-first run into canonical scanner evidence only after an explicit preview and operator confirmation.'})
        )
      ),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('The canonical importer receives the exact original uploaded CSV, never the enriched CSV. Source Profile ID is integration identity, not risk context. Confirm is intentionally manual and auditable.'),
        el('div', {class: 'form-grid'}, field('Source Profile ID', profile), field('Scanner CSV Contract', contract)),
        el('div', {class: 'inline-actions'}, preview, confirm),
        status,
        result
      ))
    );
    anchor.insertAdjacentElement('afterend', panel);
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