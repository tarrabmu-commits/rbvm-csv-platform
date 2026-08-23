(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V1';
  const BUNDLE_CONTRACT = 'RBVM_CUSTOMER_ASSET_BUNDLE_V1';
  const MAX_BUNDLE_ASSETS = 5000;
  let queued = false;
  let activeSetup = null;

  document.documentElement.dataset.csvFirstCustomerAssetUi = CONTRACT;

  const el = (tag, attrs = {}, ...children) => {
    const node = document.createElement(tag);
    Object.entries(attrs).forEach(([key, value]) => {
      if (value === null || value === undefined || value === false) return;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = String(value);
      else if (key === 'style') node.style.cssText = String(value);
      else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
      else if (key in node && !key.startsWith('aria') && !key.startsWith('data-')) node[key] = value;
      else node.setAttribute(key, String(value));
    });
    children.flat().forEach(child => {
      if (child === null || child === undefined || child === false) return;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
    return node;
  };

  const button = (label, kind = 'secondary') => el('button', {
    type: 'button', class: `button button-${kind}`, text: label,
  });
  const callout = (text, kind = 'info') => el('div', {class: `callout callout-${kind}`, text});
  const field = (label, input) => el('div', {class: 'field'}, el('label', {}, el('span', {text: label}), input));
  const setStatus = (node, message, kind = '') => {
    node.textContent = message;
    node.className = `status-message${kind ? ` ${kind}` : ''}`;
  };

  function currentView() {
    const params = new URLSearchParams(location.search);
    if (location.pathname === '/' && params.get('view') === 'imports') return 'imports';
    if (location.pathname.replace(/\/+$/, '') === '/assets' && params.get('tab') !== 'scanner-links') return 'assets';
    return null;
  }

  function schedule() {
    if (queued) return;
    queued = true;
    queueMicrotask(() => {
      queued = false;
      const root = document.getElementById('page-content');
      if (!root) return;
      const view = currentView();
      if (view === 'imports') injectCsvFirstImport(root);
      if (view === 'assets') injectCustomerAssetSetup(root);
    });
  }

  function spaGo(path) {
    history.pushState({}, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
    schedule();
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {...options, cache: 'no-store'});
    if (!response.ok) {
      let detail = `HTTP ${response.status}`;
      try {
        const problem = await response.json();
        detail = problem.detail || problem.title || detail;
      } catch (_) { }
      const error = new Error(detail);
      error.status = response.status;
      throw error;
    }
    return response;
  }

  const normalizeHeader = value => String(value || '').normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');

  function parseCsv(text) {
    const rows = [];
    let row = [];
    let cell = '';
    let quoted = false;
    for (let index = 0; index < text.length; index++) {
      const ch = text[index];
      if (quoted) {
        if (ch === '"') {
          if (text[index + 1] === '"') {
            cell += '"';
            index++;
          } else {
            quoted = false;
          }
        } else {
          cell += ch;
        }
      } else if (ch === '"') {
        quoted = true;
      } else if (ch === ',') {
        row.push(cell);
        cell = '';
      } else if (ch === '\n') {
        row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
        rows.push(row);
        row = [];
        cell = '';
      } else {
        cell += ch;
      }
    }
    if (quoted) throw new Error('CSV contains an unterminated quoted field.');
    if (cell.length || row.length) {
      row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
      rows.push(row);
    }
    return rows.filter(values => values.some(value => String(value).trim() !== ''));
  }

  function firstColumn(headers, candidates) {
    const normalized = headers.map(normalizeHeader);
    for (const candidate of candidates) {
      const index = normalized.indexOf(normalizeHeader(candidate));
      if (index >= 0) return index;
    }
    return -1;
  }

  function candidatesFromCsv(text) {
    const rows = parseCsv(text);
    if (rows.length < 2) throw new Error('CSV must contain a header and at least one data row.');
    const headers = rows[0].map(value => String(value).replace(/^\uFEFF/, '').trim());
    if (firstColumn(headers, ['CVE_ID', 'CVE ID', 'cve']) < 0) throw new Error('CSV must contain a CVE_ID column.');
    const keyIndex = firstColumn(headers, ['Agent_ID', 'Agent ID', 'Asset_ID', 'Asset ID', 'agent.id', 'agent_id']);
    const nameIndex = firstColumn(headers, ['Agent', 'Agent_Name', 'Agent Name', 'Asset', 'Asset_Name', 'Hostname', 'Host', 'agent.name', 'agent_name']);
    if (keyIndex < 0 && nameIndex < 0) {
      throw new Error('CSV needs an asset identity column such as Agent/Agent_ID, Asset/Asset_ID, or Hostname.');
    }

    const seen = new Map();
    rows.slice(1).forEach(values => {
      const key = keyIndex >= 0 ? String(values[keyIndex] || '').trim() : '';
      const name = nameIndex >= 0 ? String(values[nameIndex] || '').trim() : '';
      if (!key && !name) return;
      const identity = key ? `key:${key}` : `name:${name.normalize('NFKC').toLowerCase()}`;
      if (!seen.has(identity)) {
        seen.set(identity, {
          customerAssetKey: key,
          displayName: name || key,
          environment: 'UNKNOWN',
          businessService: '',
          businessOwner: '',
          businessCriticality: 'UNKNOWN',
          classificationMethod: 'CUSTOMER_DIRECT',
          guideContractId: 'ASSET_CLASSIFICATION_GUIDE_V1',
          guideRevision: 1,
        });
      }
    });
    if (!seen.size) throw new Error('No usable asset identities were found in the CSV.');
    return [...seen.values()];
  }

  function injectCsvFirstImport(root) {
    if (root.querySelector('[data-csv-first-import]')) return;
    const header = root.querySelector('.page-header');
    if (!header) return;

    const file = el('input', {type: 'file', accept: '.csv,text/csv'});
    const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
    const run = button('Enrich CSV & continue to Assets', 'primary');
    const panel = el('section', {'data-csv-first-import': 'true', class: 'panel'},
      el('div', {class: 'panel-header'}, el('div', {},
        el('h2', {class: 'panel-title', text: 'CSV-first customer run'}),
        el('p', {class: 'panel-subtitle', text: 'The uploaded CSV defines the complete run. Public vulnerability intelligence is collected first; customer-only context is completed on Assets next.'})
      )),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('Automatic: CVSS v4, EPSS, KEV, CISA SSVC, CWE/CPE and source provenance. Customer-specific business context is never guessed from public data.'),
        el('div', {class: 'form-grid'}, field('Customer vulnerability CSV', file)),
        el('div', {class: 'inline-actions'}, run),
        status
      ))
    );

    run.addEventListener('click', async () => {
      const selected = file.files && file.files[0];
      if (!selected) {
        setStatus(status, 'Choose the customer CSV first.', 'error');
        return;
      }
      run.disabled = true;
      try {
        setStatus(status, `Reading asset identities from ${selected.name}…`);
        const candidates = candidatesFromCsv(await selected.text());
        activeSetup = {
          contractId: CONTRACT,
          sourceFileName: selected.name,
          createdAt: new Date().toISOString(),
          candidates,
          run: null,
        };
        setStatus(status, `Collecting public intelligence for ${selected.name}…`);
        const response = await api('/api/v1/csv-first-enrichments', {
          method: 'POST',
          headers: {'Content-Type': 'text/csv; charset=utf-8'},
          body: selected,
        });
        activeSetup.run = await response.json();
        setStatus(status, `Public enrichment complete. Opening Assets for ${candidates.length} customer asset${candidates.length === 1 ? '' : 's'}…`, 'success');
        spaGo(activeSetup.run.next || `/assets?tab=managed&setup=1&runId=${encodeURIComponent(activeSetup.run.runId || '')}`);
      } catch (error) {
        setStatus(status, error.message, 'error');
        run.disabled = false;
      }
    });

    header.insertAdjacentElement('afterend', panel);
  }

  const textInput = (value = '', placeholder = '') => el('input', {type: 'text', value, placeholder});
  function selectInput(values, current) {
    const select = el('select');
    values.forEach(value => select.append(el('option', {value, text: value.replaceAll('_', ' '), selected: value === current})));
    return select;
  }

  function createAssetEditor(asset, index) {
    const key = textInput(asset.customerAssetKey || '', 'Stable customer key');
    const name = textInput(asset.displayName || '', 'Asset display name');
    const environment = selectInput(['PRODUCTION', 'PRE_PRODUCTION', 'DEVELOPMENT', 'TEST', 'SANDBOX', 'DISASTER_RECOVERY', 'UNKNOWN'], asset.environment || 'UNKNOWN');
    const criticality = selectInput(['MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'UNKNOWN'], asset.businessCriticality || 'UNKNOWN');
    const service = textInput(asset.businessService || '', 'Business service');
    const owner = textInput(asset.businessOwner || '', 'Business owner');
    const method = selectInput(['CUSTOMER_DIRECT', 'GUIDED'], asset.classificationMethod || 'CUSTOMER_DIRECT');
    const guideId = textInput(asset.guideContractId || 'ASSET_CLASSIFICATION_GUIDE_V1', 'Guide contract');
    const guideRevision = el('input', {type: 'number', min: '1', step: '1', value: asset.guideRevision || 1});
    const guideWrap = el('div', {class: 'wide'}, el('div', {class: 'form-grid'}, field('Guide contract ID', guideId), field('Guide revision', guideRevision)));
    const syncGuide = () => { guideWrap.hidden = method.value !== 'GUIDED'; };
    method.addEventListener('change', syncGuide);
    syncGuide();

    const details = el('details', {class: 'panel', open: index < 3},
      el('summary', {style: 'cursor:pointer;padding:16px 20px;font-weight:700;', text: asset.displayName || asset.customerAssetKey || `Asset ${index + 1}`}),
      el('div', {class: 'panel-body'}, el('div', {class: 'form-grid'},
        field('Customer asset key', key),
        field('Display name', name),
        field('Environment', environment),
        field('Business criticality', criticality),
        field('Business service', service),
        field('Business owner', owner),
        field('Classification method', method),
        guideWrap
      ))
    );

    return {
      node: details,
      read: () => {
        const output = {
          customerAssetKey: key.value.trim(),
          displayName: name.value.trim(),
          environment: environment.value,
          businessCriticality: criticality.value,
          businessService: service.value.trim(),
          businessOwner: owner.value.trim(),
          classificationMethod: method.value,
        };
        if (method.value === 'GUIDED') {
          output.guideContractId = guideId.value.trim();
          output.guideRevision = Number(guideRevision.value);
        }
        return output;
      },
    };
  }

  function validateBundle(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Customer data file must contain one JSON object.');
    if (value.contractId !== BUNDLE_CONTRACT || value.schemaVersion !== 1) throw new Error(`Expected ${BUNDLE_CONTRACT} schema version 1.`);
    if (!Array.isArray(value.assets) || value.assets.length > MAX_BUNDLE_ASSETS) throw new Error('Customer data bundle has an invalid asset list.');
    return value.assets.map((asset, index) => {
      if (!asset || typeof asset !== 'object' || Array.isArray(asset)) throw new Error(`Asset ${index + 1} is invalid.`);
      const customerAssetKey = String(asset.customerAssetKey || '').trim();
      const displayName = String(asset.displayName || '').trim();
      if (!customerAssetKey && !displayName) throw new Error(`Asset ${index + 1} needs customerAssetKey or displayName.`);
      return {
        customerAssetKey,
        displayName: displayName || customerAssetKey,
        environment: String(asset.environment || 'UNKNOWN'),
        businessService: String(asset.businessService || ''),
        businessOwner: String(asset.businessOwner || ''),
        businessCriticality: String(asset.businessCriticality || 'UNKNOWN'),
        classificationMethod: String(asset.classificationMethod || 'CUSTOMER_DIRECT'),
        guideContractId: String(asset.guideContractId || 'ASSET_CLASSIFICATION_GUIDE_V1'),
        guideRevision: Number(asset.guideRevision || 1),
      };
    });
  }

  async function fetchAllManagedAssets() {
    const output = [];
    let after = null;
    for (let page = 0; page < 100; page++) {
      const params = new URLSearchParams({limit: '100', lifecycle: 'ALL'});
      if (after) params.set('afterId', after);
      const data = await (await api(`/api/v1/managed-assets?${params}`)).json();
      output.push(...(data.assets || []));
      after = data.nextAfterId || null;
      if (!after) break;
    }
    return output;
  }

  function toBundleAsset(asset) {
    const revision = asset.currentRevision || {};
    const output = {
      customerAssetKey: asset.customerAssetKey || '',
      displayName: revision.displayName || '',
      environment: revision.environment || 'UNKNOWN',
      businessService: revision.businessService || '',
      businessOwner: revision.businessOwner || '',
      businessCriticality: revision.businessCriticality || 'UNKNOWN',
      classificationMethod: revision.classificationMethod || 'CUSTOMER_DIRECT',
    };
    if (revision.classificationMethod === 'GUIDED') {
      output.guideContractId = revision.guideContractId || 'ASSET_CLASSIFICATION_GUIDE_V1';
      output.guideRevision = revision.guideRevision || 1;
    }
    return output;
  }

  async function downloadCustomerBundle(status) {
    try {
      setStatus(status, 'Preparing customer data bundle…');
      const assets = (await fetchAllManagedAssets()).map(toBundleAsset);
      const bundle = {
        contractId: BUNDLE_CONTRACT,
        schemaVersion: 1,
        exportedAt: new Date().toISOString(),
        semantics: 'CUSTOMER_OWNED_ORGANIZATIONAL_ASSET_CONTEXT',
        assets,
      };
      const blob = new Blob([JSON.stringify(bundle, null, 2) + '\n'], {type: 'application/json'});
      const href = URL.createObjectURL(blob);
      const link = el('a', {href, download: 'rbvm-customer-assets.json'});
      document.body.append(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(href);
      setStatus(status, `Downloaded ${assets.length} managed asset record${assets.length === 1 ? '' : 's'}.`, 'success');
    } catch (error) {
      setStatus(status, error.message, 'error');
    }
  }

  function mergeBundleIntoSetup(current, imported) {
    if (!current || !Array.isArray(current.candidates) || !current.candidates.length) return imported;
    const byKey = new Map(imported.filter(asset => asset.customerAssetKey).map(asset => [asset.customerAssetKey, asset]));
    const byName = new Map();
    imported.forEach(asset => {
      const name = asset.displayName.normalize('NFKC').trim().toLowerCase();
      if (!name) return;
      if (byName.has(name)) byName.set(name, null);
      else byName.set(name, asset);
    });
    return current.candidates.map(candidate => {
      const matched = candidate.customerAssetKey
        ? byKey.get(candidate.customerAssetKey)
        : byName.get(candidate.displayName.normalize('NFKC').trim().toLowerCase());
      return matched ? {...candidate, ...matched, customerAssetKey: candidate.customerAssetKey || matched.customerAssetKey} : candidate;
    });
  }

  async function persistAssetContext(asset, existingAssets) {
    if (!asset.customerAssetKey && !asset.displayName) throw new Error('Each asset needs a customer key or display name.');
    let existing = null;
    if (asset.customerAssetKey) {
      existing = existingAssets.find(value => value.customerAssetKey === asset.customerAssetKey) || null;
    } else {
      const normalizedName = asset.displayName.normalize('NFKC').trim().toLowerCase();
      const matches = existingAssets.filter(value => String(value.currentRevision?.displayName || '').normalize('NFKC').trim().toLowerCase() === normalizedName);
      if (matches.length > 1) throw new Error(`Display name ${asset.displayName} matches multiple managed assets; add a customer asset key.`);
      existing = matches[0] || null;
    }

    const payload = {
      displayName: asset.displayName || asset.customerAssetKey,
      environment: asset.environment || 'UNKNOWN',
      businessService: asset.businessService || '',
      businessOwner: asset.businessOwner || '',
      businessCriticality: asset.businessCriticality || 'UNKNOWN',
      classificationMethod: asset.classificationMethod || 'CUSTOMER_DIRECT',
      changeNote: 'Customer context saved from CSV-first Customer Asset Setup V1',
    };
    if (payload.classificationMethod === 'GUIDED') {
      payload.guideContractId = asset.guideContractId || 'ASSET_CLASSIFICATION_GUIDE_V1';
      payload.guideRevision = Number(asset.guideRevision || 1);
    }

    if (!existing) {
      if (asset.customerAssetKey) payload.customerAssetKey = asset.customerAssetKey;
      return (await api('/api/v1/managed-assets', {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload),
      })).json();
    }

    const currentResponse = await api(`/api/v1/managed-assets/${encodeURIComponent(existing.id)}`);
    const current = await currentResponse.json();
    const etag = currentResponse.headers.get('ETag');
    if (!etag) throw new Error(`Managed asset ${existing.id} did not provide an ETag.`);
    payload.lifecycleStatus = current.currentRevision?.lifecycleStatus || 'ACTIVE';
    await api(`/api/v1/managed-assets/${encodeURIComponent(existing.id)}/revisions`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json', 'If-Match': etag},
      body: JSON.stringify(payload),
    });
    return current;
  }

  function injectCustomerAssetSetup(root) {
    if (root.querySelector('[data-customer-asset-setup]')) return;
    const header = root.querySelector('.page-header');
    if (!header) return;

    let setup = activeSetup;
    const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
    const editorsHost = el('div', {class: 'stack'});
    const upload = el('input', {type: 'file', accept: '.json,application/json', hidden: true});
    const uploadButton = button('Upload customer data');
    const downloadButton = button('Download customer data');
    const saveButton = button('Save customer data', 'primary');
    const runId = new URLSearchParams(location.search).get('runId') || setup?.run?.runId || '';
    const enrichedButton = runId ? button('Download enriched CSV') : null;
    let editors = [];

    const renderEditors = () => {
      editorsHost.replaceChildren();
      editors = [];
      const candidates = Array.isArray(setup?.candidates) ? setup.candidates : [];
      if (!candidates.length) {
        editorsHost.append(callout('No current CSV asset candidates. Upload a saved customer data bundle here, or use Create asset for one-by-one manual entry.', 'warning'));
        saveButton.disabled = true;
        return;
      }
      saveButton.disabled = false;
      editorsHost.append(callout(`${candidates.length} asset${candidates.length === 1 ? '' : 's'} need customer-owned context. Public vulnerability data does not fill these fields.`));
      candidates.forEach((candidate, index) => {
        const editor = createAssetEditor(candidate, index);
        editors.push(editor);
        editorsHost.append(editor.node);
      });
    };

    uploadButton.addEventListener('click', () => upload.click());
    upload.addEventListener('change', async () => {
      const file = upload.files && upload.files[0];
      if (!file) return;
      try {
        setStatus(status, `Loading ${file.name}…`);
        const imported = validateBundle(JSON.parse(await file.text()));
        setup = setup || {contractId: CONTRACT, sourceFileName: '', createdAt: new Date().toISOString(), run: null, candidates: []};
        setup.candidates = mergeBundleIntoSetup(setup, imported);
        activeSetup = setup;
        renderEditors();
        setStatus(status, `Loaded customer context for ${imported.length} asset${imported.length === 1 ? '' : 's'}. Review and save.`, 'success');
      } catch (error) {
        setStatus(status, error.message, 'error');
      } finally {
        upload.value = '';
      }
    });

    downloadButton.addEventListener('click', () => downloadCustomerBundle(status));
    if (enrichedButton) {
      enrichedButton.addEventListener('click', () => {
        const link = el('a', {href: `/api/v1/csv-first-enrichments/${encodeURIComponent(runId)}/csv`, download: 'rbvm-enriched.csv'});
        document.body.append(link);
        link.click();
        link.remove();
      });
    }

    saveButton.addEventListener('click', async () => {
      if (!editors.length) return;
      saveButton.disabled = true;
      uploadButton.disabled = true;
      downloadButton.disabled = true;
      try {
        const values = editors.map(editor => editor.read());
        setStatus(status, `Saving customer context for ${values.length} asset${values.length === 1 ? '' : 's'}…`);
        let existing = await fetchAllManagedAssets();
        let saved = 0;
        for (const value of values) {
          await persistAssetContext(value, existing);
          saved++;
          if (saved % 10 === 0 || saved === values.length) setStatus(status, `Saved ${saved} of ${values.length} assets…`);
          existing = await fetchAllManagedAssets();
        }
        setup.candidates = values;
        activeSetup = setup;
        setStatus(status, `Saved ${saved} customer asset record${saved === 1 ? '' : 's'}. Download customer data now to reuse it with the next CSV.`, 'success');
      } catch (error) {
        setStatus(status, error.status === 412 ? 'An asset changed while saving. Refresh Assets and retry after reviewing the latest revision.' : error.message, 'error');
      } finally {
        saveButton.disabled = false;
        uploadButton.disabled = false;
        downloadButton.disabled = false;
      }
    });

    const panel = el('section', {'data-customer-asset-setup': 'true', class: 'panel'},
      el('div', {class: 'panel-header'}, el('div', {},
        el('h2', {class: 'panel-title', text: 'Customer asset context'}),
        el('p', {class: 'panel-subtitle', text: 'Enter customer-only information manually, or upload the reusable file downloaded from a previous run.'})
      )),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('Reusable bundle contains organizational asset context only. It does not mix customer truth with CVSS, EPSS, KEV or other public evidence.'),
        upload,
        el('div', {class: 'inline-actions'}, uploadButton, downloadButton, saveButton, enrichedButton),
        status,
        editorsHost
      ))
    );

    renderEditors();
    header.insertAdjacentElement('afterend', panel);
  }

  new MutationObserver(schedule).observe(document.documentElement, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
