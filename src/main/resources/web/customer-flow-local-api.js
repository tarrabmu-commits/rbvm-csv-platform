(() => {
  'use strict';

  const BUNDLE_CONTRACT = 'RBVM_CUSTOMER_ASSET_BUNDLE_V4';
  const API_ROOT = '/api/v1/csv-first-customer-assets';
  const CRITICALITY = ['UNKNOWN', 'MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW'];
  const INTERNET_FACING = ['UNKNOWN', 'YES', 'NO'];
  const PUBLICLY_EXPOSED = ['UNKNOWN', 'YES', 'NO'];
  const SECURITY_REQUIREMENT = ['X', 'L', 'M', 'H'];
  const SEMANTICS = 'CUSTOMER_DECLARED_ASSET_CONTEXT_PLUS_CISA_PUBLICLY_EXPOSED_PLUS_DIRECT_CVSS_V4_SECURITY_REQUIREMENTS';
  const NOTE = 'publiclyExposed is the explicit cisa:PE:1.0.0 BOD decision point. internetFacing remains legacy/coarse asset context and does not populate Publicly Exposed, NETWORK_REACHABILITY_CSV_V1, or MAV. CR/IR/AR are direct CVSS v4 X/L/M/H declarations and are not derived from Asset Criticality.';
  let queued = false;

  document.documentElement.dataset.csvFirstCustomerAssetLocalApi = 'CSV_FIRST_CUSTOMER_ASSET_LOCAL_API_UI_V2';

  function runIdFromLocation() { return new URLSearchParams(location.search).get('runId') || ''; }
  function statusNode(panel) { return panel.querySelector('.status-message'); }
  function setStatus(panel, message, kind = '') { const node = statusNode(panel); if (!node) return; node.textContent = message; node.className = `status-message${kind ? ` ${kind}` : ''}`; }
  function buttonByLabel(panel, label) { return [...panel.querySelectorAll('button')].find(button => button.textContent.trim() === label) || null; }
  function finishSetup(runId) { const params = new URLSearchParams({tab: 'managed', runId}); history.pushState({}, '', `/assets?${params}`); window.dispatchEvent(new PopStateEvent('popstate')); }
  async function responseError(response) { let detail = `HTTP ${response.status}`; try { const problem = await response.json(); detail = problem.detail || problem.title || detail; } catch (_) { } const error = new Error(detail); error.status = response.status; return error; }
  async function request(path, options = {}) { const response = await fetch(path, {...options, cache: 'no-store', credentials: 'same-origin'}); if (!response.ok) throw await responseError(response); return response; }

  function validateAsset(asset, index) {
    if (!asset || typeof asset !== 'object' || Array.isArray(asset)) throw new Error(`Asset ${index + 1} is invalid.`);
    const customerAssetKey = String(asset.customerAssetKey || '').trim();
    const displayName = String(asset.displayName || '').trim();
    const assetCriticality = String(asset.assetCriticality || 'UNKNOWN').trim().toUpperCase();
    const internetFacing = String(asset.internetFacing || 'UNKNOWN').trim().toUpperCase();
    const publiclyExposed = String(asset.publiclyExposed || 'UNKNOWN').trim().toUpperCase();
    const cr = String(asset.cvssConfidentialityRequirement || 'X').trim().toUpperCase();
    const ir = String(asset.cvssIntegrityRequirement || 'X').trim().toUpperCase();
    const ar = String(asset.cvssAvailabilityRequirement || 'X').trim().toUpperCase();
    if (!customerAssetKey && !displayName) throw new Error(`Asset ${index + 1} needs an Asset ID or Asset Name.`);
    if (!CRITICALITY.includes(assetCriticality)) throw new Error(`Asset ${index + 1} has invalid Asset Criticality.`);
    if (!INTERNET_FACING.includes(internetFacing)) throw new Error(`Asset ${index + 1} has invalid Internet Facing state.`);
    if (!PUBLICLY_EXPOSED.includes(publiclyExposed)) throw new Error(`Asset ${index + 1} has invalid CISA Publicly Exposed state.`);
    if (![cr, ir, ar].every(value => SECURITY_REQUIREMENT.includes(value))) throw new Error(`Asset ${index + 1} has invalid CVSS v4 CR/IR/AR values.`);
    if (assetCriticality === 'UNKNOWN' || internetFacing === 'UNKNOWN') throw new Error(`Asset ${index + 1} still needs Asset Criticality and Internet Facing for the existing customer-context workflow. Publicly Exposed may remain UNKNOWN; CR/IR/AR may remain X.`);
    return {customerAssetKey, displayName, assetCriticality, internetFacing, publiclyExposed, cvssConfidentialityRequirement: cr, cvssIntegrityRequirement: ir, cvssAvailabilityRequirement: ar};
  }

  function readRequiredField(editor, name, index) {
    const input = editor.querySelector(`[data-customer-field="${name}"]`);
    if (!input) throw new Error(`Asset ${index + 1} is missing the ${name} control.`);
    return String(input.value).trim();
  }

  function readAssets(panel) {
    if (typeof panel.rbvmReadCustomerAssets === 'function') {
      const values = panel.rbvmReadCustomerAssets();
      if (!Array.isArray(values) || !values.length) throw new Error('Load or add at least one asset first.');
      return values.map(validateAsset);
    }
    const editors = [...panel.querySelectorAll('[data-customer-asset-editor]')];
    if (!editors.length) throw new Error('Load or add at least one asset first.');
    return editors.map((editor, index) => validateAsset({
      customerAssetKey: readRequiredField(editor, 'customerAssetKey', index),
      displayName: readRequiredField(editor, 'displayName', index),
      assetCriticality: readRequiredField(editor, 'assetCriticality', index),
      internetFacing: readRequiredField(editor, 'internetFacing', index),
      publiclyExposed: readRequiredField(editor, 'publiclyExposed', index),
      cvssConfidentialityRequirement: readRequiredField(editor, 'CR', index),
      cvssIntegrityRequirement: readRequiredField(editor, 'IR', index),
      cvssAvailabilityRequirement: readRequiredField(editor, 'AR', index),
    }, index));
  }

  function buildBundle(panel) {
    return {contractId: BUNDLE_CONTRACT, schemaVersion: 4, exportedAt: new Date().toISOString(), semantics: SEMANTICS, note: NOTE, assets: readAssets(panel)};
  }

  function setPersisted(panel, persisted) {
    panel.dataset.customerBundlePersisted = persisted ? 'true' : 'false';
    const download = buttonByLabel(panel, 'Download customer data');
    const analyze = buttonByLabel(panel, 'Analyze saved data');
    if (download) download.disabled = !persisted;
    if (analyze) analyze.disabled = !persisted;
  }

  async function hydrateSavedBundle(panel, runId) {
    if (!runId || panel.dataset.customerBundleHydrated === 'true') return;
    panel.dataset.customerBundleHydrated = 'true';
    try {
      const response = await fetch(`${API_ROOT}/${encodeURIComponent(runId)}`, {cache: 'no-store', credentials: 'same-origin'});
      if (response.status === 404) { setPersisted(panel, false); return; }
      if (!response.ok) throw await responseError(response);
      const bundle = await response.json();
      if (bundle.contractId !== BUNDLE_CONTRACT || bundle.schemaVersion !== 4 || !Array.isArray(bundle.assets)) throw new Error(`Saved run data is not ${BUNDLE_CONTRACT} schema version 4.`);

      if (typeof panel.rbvmLoadCustomerBundle === 'function') {
        const count = panel.rbvmLoadCustomerBundle(bundle);
        if (count !== bundle.assets.length) throw new Error('Saved customer data did not restore the expected asset count.');
      } else {
        const upload = panel.querySelector('input[type="file"][accept*="json"]');
        if (!upload || typeof DataTransfer === 'undefined' || typeof File === 'undefined') throw new Error('This browser cannot restore saved customer data into the editor.');
        const transfer = new DataTransfer();
        transfer.items.add(new File([JSON.stringify(bundle)], 'rbvm-customer-assets-v4.json', {type: 'application/json'}));
        upload.files = transfer.files;
        upload.dispatchEvent(new Event('change', {bubbles: true}));
      }
      setPersisted(panel, true);
      setStatus(panel, `Restored saved customer data for ${bundle.assets.length} asset${bundle.assets.length === 1 ? '' : 's'} from this local run. Only a bounded editor page is rendered.`, 'success');
    } catch (error) {
      setPersisted(panel, false);
      setStatus(panel, error.message, 'error');
    }
  }

  async function persist(panel, runId, saveButton) {
    if (!runId) { setStatus(panel, 'Open Assets from a CSV-first run before saving customer data locally.', 'error'); return; }
    saveButton.disabled = true;
    try {
      const bundle = buildBundle(panel);
      setStatus(panel, `Saving ${bundle.assets.length} customer asset context record${bundle.assets.length === 1 ? '' : 's'} to this local run…`);
      await request(`${API_ROOT}/${encodeURIComponent(runId)}`, {method: 'PUT', headers: {'Content-Type': 'application/json; charset=utf-8'}, body: JSON.stringify(bundle)});
      setPersisted(panel, true);
      const bodIncomplete = bundle.assets.filter(asset => asset.publiclyExposed === 'UNKNOWN').length;
      const suffix = bodIncomplete ? ` ${bodIncomplete} asset${bodIncomplete === 1 ? '' : 's'} remain BOD-incomplete because Publicly Exposed is UNKNOWN.` : '';
      setStatus(panel, `Saved ${bundle.assets.length} customer asset context record${bundle.assets.length === 1 ? '' : 's'} to the Local API.${suffix}`, 'success');
    } catch (error) {
      setPersisted(panel, false);
      setStatus(panel, error.message, 'error');
    } finally {
      saveButton.disabled = false;
    }
  }

  async function downloadSaved(panel, runId, downloadButton) {
    if (!runId) { setStatus(panel, 'No CSV-first runId is available for local customer data.', 'error'); return; }
    downloadButton.disabled = true;
    try {
      const response = await request(`${API_ROOT}/${encodeURIComponent(runId)}`);
      const blob = await response.blob();
      const href = URL.createObjectURL(blob);
      const link = document.createElement('a'); link.href = href; link.download = 'rbvm-customer-assets-v4.json';
      document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(href);
      setStatus(panel, 'Downloaded the exact V4 customer data saved for this local run.', 'success');
    } catch (error) { setStatus(panel, error.message, 'error'); }
    finally { downloadButton.disabled = panel.dataset.customerBundlePersisted !== 'true'; }
  }

  function resultLink(label, href, filename) {
    const link = document.createElement('a'); link.className = 'button button-secondary'; link.textContent = label; link.href = href; if (filename) link.download = filename; return link;
  }

  function showAnalysisResult(panel, analysis, priority) {
    let host = panel.querySelector('[data-local-analysis-result]');
    if (!host) {
      host = document.createElement('div'); host.dataset.localAnalysisResult = 'true'; host.className = 'stack';
      const status = statusNode(panel); if (status) status.insertAdjacentElement('afterend', host); else panel.querySelector('.panel-body')?.append(host);
    }
    host.replaceChildren();
    const summary = document.createElement('div'); summary.className = 'callout callout-info';
    summary.textContent = `Analysis ${analysis.analysisId} is immutable. Pareto treatment priority is complete for rankable rows; Organizational Risk remains NON_COMPUTABLE.`;
    const actions = document.createElement('div'); actions.className = 'inline-actions';
    if (analysis.analysisCsv) actions.append(resultLink('Download analysis CSV', analysis.analysisCsv, 'rbvm-contextual-analysis.csv'));
    if (analysis.analysisSummary) actions.append(resultLink('Download analysis summary', analysis.analysisSummary, 'rbvm-contextual-analysis-summary.json'));
    if (priority.priorityCsv) actions.append(resultLink('Download priority CSV', priority.priorityCsv, 'rbvm-mvp-priority.csv'));
    if (priority.priorityReport) actions.append(resultLink('Download priority report', priority.priorityReport, 'rbvm-mvp-priority-report.json'));
    host.append(summary, actions);
  }

  async function analyzeSaved(panel, runId, analyzeButton) {
    if (!runId || panel.dataset.customerBundlePersisted !== 'true') { setStatus(panel, 'Save customer data to this local run before analyzing it.', 'error'); return; }
    analyzeButton.disabled = true;
    try {
      setStatus(panel, 'Creating immutable contextual analysis from the saved customer bundle…');
      const analysisResponse = await request(`${API_ROOT}/${encodeURIComponent(runId)}/analyses`, {method: 'POST'});
      const analysis = await analysisResponse.json();
      if (!analysis.priority) throw new Error('Contextual analysis did not return the Pareto priority endpoint.');
      setStatus(panel, `Analysis ${analysis.analysisId} complete. Materializing Pareto treatment priority…`);
      const priorityResponse = await request(analysis.priority, {method: 'POST'});
      const priority = await priorityResponse.json();
      showAnalysisResult(panel, analysis, priority);
      setStatus(panel, 'Saved customer context was analyzed and Pareto treatment priority was materialized. Organizational Risk remains NON_COMPUTABLE.', 'success');
    } catch (error) { setStatus(panel, error.message, 'error'); }
    finally { analyzeButton.disabled = panel.dataset.customerBundlePersisted !== 'true'; }
  }

  function enhance(panel) {
    if (panel.dataset.localApiEnhanced === 'true') return;
    const runId = runIdFromLocation();
    const saveButton = buttonByLabel(panel, 'Save customer data');
    const downloadButton = buttonByLabel(panel, 'Download customer data');
    const finishButton = buttonByLabel(panel, 'Finish setup');
    if (!saveButton || !downloadButton) return;
    panel.dataset.localApiEnhanced = 'true';

    const analyzeButton = document.createElement('button');
    analyzeButton.type = 'button'; analyzeButton.className = 'button button-secondary'; analyzeButton.textContent = 'Analyze saved data'; analyzeButton.disabled = true;
    saveButton.insertAdjacentElement('afterend', analyzeButton);
    if (runId) {
      saveButton.title = 'Persist the complete V4 customer bundle beside the CSV-first run; pagination does not limit persistence.';
      downloadButton.title = 'Download the exact V4 bundle persisted by the Local API.';
      analyzeButton.title = 'Create immutable contextual analysis from the saved run bundle, then materialize Pareto priority.';
      if (finishButton) finishButton.title = 'Finish setup without dropping the CSV-first run context.';
    }

    panel.addEventListener('click', event => {
      const target = event.target instanceof Element ? event.target.closest('button') : null;
      if (!target || !panel.contains(target)) return;
      const label = target.textContent.trim();
      if (label === 'Save customer data') {
        event.preventDefault(); event.stopImmediatePropagation(); void persist(panel, runId, target);
      } else if (label === 'Download customer data') {
        event.preventDefault(); event.stopImmediatePropagation(); void downloadSaved(panel, runId, target);
      } else if (label === 'Analyze saved data') {
        event.preventDefault(); event.stopImmediatePropagation(); void analyzeSaved(panel, runId, target);
      } else if (label === 'Finish setup' && runId) {
        event.preventDefault(); event.stopImmediatePropagation();
        if (panel.dataset.customerBundlePersisted !== 'true') { setStatus(panel, 'Save customer data to this local run before finishing setup.', 'error'); return; }
        finishSetup(runId);
      }
    }, true);

    const dirty = event => {
      const target = event.target;
      if (!(target instanceof Element) || !target.matches('[data-customer-field]')) return;
      setPersisted(panel, false);
    };
    panel.addEventListener('input', dirty, true);
    panel.addEventListener('change', dirty, true);

    if (!runId) {
      analyzeButton.disabled = true;
      saveButton.title = 'Start from a CSV-first import so this customer bundle has a runId.';
      return;
    }
    void hydrateSavedBundle(panel, runId);
  }

  function scan() { document.querySelectorAll('[data-customer-asset-setup]').forEach(enhance); }
  function schedule() { if (queued) return; queued = true; queueMicrotask(() => { queued = false; scan(); }); }
  const observerRoot = document.getElementById('rbvm-app') || document.documentElement;
  new MutationObserver(schedule).observe(observerRoot, {childList: true, subtree: true});
  window.addEventListener('popstate', schedule);
  window.addEventListener('DOMContentLoaded', schedule);
  schedule();
})();
