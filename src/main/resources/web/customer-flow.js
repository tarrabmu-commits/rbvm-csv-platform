(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V3';
  const BUNDLE_CONTRACT = 'RBVM_CUSTOMER_ASSET_BUNDLE_V3';
  const LEGACY_BUNDLE_CONTRACT_V2 = 'RBVM_CUSTOMER_ASSET_BUNDLE_V2';
  const LEGACY_BUNDLE_CONTRACT_V1 = 'RBVM_CUSTOMER_ASSET_BUNDLE_V1';
  const MAX_BUNDLE_ASSETS = 5000;
  const CRITICALITY = ['UNKNOWN', 'MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW'];
  const INTERNET_FACING = ['UNKNOWN', 'YES', 'NO'];
  const SECURITY_REQUIREMENT = ['X', 'L', 'M', 'H'];
  let queued = false;
  let activeSetup = null;

  document.documentElement.dataset.csvFirstCustomerAssetUi = CONTRACT;

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
  const field = (label, input) => el('div', {class: 'field'}, el('label', {}, el('span', {text: label}), input));

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
      patch();
    });
  }

  function patch() {
    const root = document.getElementById('page-content');
    if (!root) return;
    const view = currentView();
    if (view === 'imports') injectCsvFirstImport(root);
    if (view === 'assets') injectCustomerAssetSetup(root);
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

  function setStatus(node, message, kind = '') {
    node.textContent = message;
    node.className = `status-message${kind ? ` ${kind}` : ''}`;
  }

  function normalizeHeader(value) {
    return String(value || '').normalize('NFKC').toLowerCase().replace(/[^a-z0-9]/g, '');
  }

  function normalizeName(value) {
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
          if (text[index + 1] === '"') {
            cell += '"';
            index++;
          } else quoted = false;
        } else cell += ch;
        continue;
      }
      if (ch === '"') quoted = true;
      else if (ch === ',') {
        row.push(cell);
        cell = '';
      } else if (ch === '\n') {
        row.push(cell.endsWith('\r') ? cell.slice(0, -1) : cell);
        rows.push(row);
        row = [];
        cell = '';
      } else cell += ch;
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

  function blankAsset(key = '', name = '') {
    return {
      customerAssetKey: key,
      displayName: name || key,
      assetCriticality: 'UNKNOWN',
      internetFacing: 'UNKNOWN',
      cvssConfidentialityRequirement: 'X',
      cvssIntegrityRequirement: 'X',
      cvssAvailabilityRequirement: 'X',
    };
  }

  function candidatesFromCsv(text) {
    const rows = parseCsv(text);
    if (rows.length < 2) throw new Error('CSV must contain a header and at least one data row.');
    const headers = rows[0].map(value => String(value).replace(/^\uFEFF/, '').trim());
    const cveIndex = firstColumn(headers, ['CVE_ID', 'CVE ID', 'cve']);
    if (cveIndex < 0) throw new Error('CSV must contain a CVE_ID column.');
    const keyIndex = firstColumn(headers, ['Agent_ID', 'Agent ID', 'Asset_ID', 'Asset ID', 'agent.id', 'agent_id']);
    const nameIndex = firstColumn(headers, ['Agent', 'Agent_Name', 'Agent Name', 'Asset', 'Asset_Name', 'Hostname', 'Host', 'agent.name', 'agent_name']);
    if (keyIndex < 0 && nameIndex < 0) throw new Error('CSV needs an asset identity column such as Agent/Agent_ID, Asset/Asset_ID, or Hostname.');

    const seen = new Map();
    for (const values of rows.slice(1)) {
      const cve = String(values[cveIndex] || '').trim().toUpperCase();
      if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) continue;
      const key = keyIndex >= 0 ? String(values[keyIndex] || '').trim() : '';
      const name = nameIndex >= 0 ? String(values[nameIndex] || '').trim() : '';
      if (!key && !name) continue;
      const identity = key ? `key:${key}` : `name:${normalizeName(name)}`;
      if (!seen.has(identity)) seen.set(identity, blankAsset(key, name));
    }
    if (!seen.size) throw new Error('No usable asset identities were found in the CSV.');
    return [...seen.values()];
  }

  function spaGo(path) {
    history.pushState({}, '', path);
    window.dispatchEvent(new PopStateEvent('popstate'));
    schedule();
  }

  function injectCsvFirstImport(root) {
    if (root.querySelector('[data-csv-first-import]')) return;
    const header = root.querySelector('.page-header');
    if (!header) return;

    const file = el('input', {type: 'file', accept: '.csv,text/csv'});
    const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
    const run = button('Enrich CSV & continue to Assets', 'primary');
    const panel = el('section', {'data-csv-first-import': 'true', class: 'panel'},
      el('div', {class: 'panel-header'},
        el('div', {},
          el('h2', {class: 'panel-title', text: 'CSV-first customer run'}),
          el('p', {class: 'panel-subtitle', text: 'The uploaded CSV is the complete run scope. Public vulnerability intelligence is automatic; organization-specific asset and CVSS Environmental requirements remain customer-declared.'})
        )
      ),
      el('div', {class: 'panel-body'},
        el('div', {class: 'stack'},
          callout('Automatic: CVSS v4 Base, EPSS, KEV, CISA SSVC, CWE/CPE and provenance. Customer: Asset Criticality, Internet Facing, and optional direct CVSS CR/IR/AR requirements.'),
          el('div', {class: 'form-grid'}, field('Customer vulnerability CSV', file)),
          el('div', {class: 'inline-actions'}, run),
          status
        )
      )
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
        activeSetup = {contractId: CONTRACT, sourceFileName: selected.name, createdAt: new Date().toISOString(), candidates, run: null, savedAt: null};
        setStatus(status, `Collecting public intelligence for ${selected.name}…`);
        const response = await api('/api/v1/csv-first-enrichments', {
          method: 'POST',
          headers: {'Content-Type': 'text/csv; charset=utf-8'},
          body: selected,
        });
        const data = await response.json();
        activeSetup.run = data;
        setStatus(status, `Enrichment complete. Opening Assets for ${candidates.length} asset${candidates.length === 1 ? '' : 's'}…`, 'success');
        spaGo(data.next || `/assets?tab=managed&setup=1&runId=${encodeURIComponent(data.runId || '')}`);
      } catch (error) {
        setStatus(status, error.message, 'error');
        run.disabled = false;
      }
    });

    header.insertAdjacentElement('afterend', panel);
  }

  function textInput(value = '', placeholder = '', customerField = '') {
    return el('input', {type: 'text', value, placeholder, 'data-customer-field': customerField || null});
  }

  function selectInput(values, current, labels = {}, customerField = '') {
    const select = el('select', {'data-customer-field': customerField || null});
    for (const value of values) {
      select.append(el('option', {value, text: labels[value] || value.replaceAll('_', ' '), selected: value === current}));
    }
    return select;
  }

  function requirementInput(current, metric) {
    return selectInput(SECURITY_REQUIREMENT, current || 'X', {
      X: `Not Defined — ${metric}:X`,
      L: `Low — ${metric}:L`,
      M: `Medium — ${metric}:M`,
      H: `High — ${metric}:H`,
    }, metric);
  }

  function createAssetEditor(asset, index, onChange, onRemove) {
    const key = textInput(asset.customerAssetKey || '', 'Stable customer key', 'customerAssetKey');
    const name = textInput(asset.displayName || '', 'Asset name', 'displayName');
    const criticality = selectInput(CRITICALITY, asset.assetCriticality || 'UNKNOWN', {
      UNKNOWN: 'Select criticality…', MISSION_CRITICAL: 'Mission Critical', HIGH: 'High', MODERATE: 'Moderate', LOW: 'Low',
    }, 'assetCriticality');
    const internet = selectInput(INTERNET_FACING, asset.internetFacing || 'UNKNOWN', {
      UNKNOWN: 'Select Internet-facing state…', YES: 'Yes — Internet Facing', NO: 'No — Not Internet Facing',
    }, 'internetFacing');
    const cr = requirementInput(asset.cvssConfidentialityRequirement, 'CR');
    const ir = requirementInput(asset.cvssIntegrityRequirement, 'IR');
    const ar = requirementInput(asset.cvssAvailabilityRequirement, 'AR');
    for (const input of [key, name, criticality, internet, cr, ir, ar]) input.addEventListener('change', onChange);
    for (const input of [key, name]) input.addEventListener('input', onChange);

    const remove = button('Remove', 'ghost');
    remove.addEventListener('click', () => onRemove(index));
    const details = el('details', {class: 'panel', open: index < 4, 'data-customer-asset-editor': String(index)},
      el('summary', {style: 'cursor:pointer;padding:16px 20px;font-weight:700;', text: asset.displayName || asset.customerAssetKey || `Asset ${index + 1}`}),
      el('div', {class: 'panel-body'},
        el('div', {class: 'form-grid'},
          field('Asset ID', key),
          field('Asset Name', name),
          field('Asset Criticality', criticality),
          field('Internet Facing?', internet),
          field('Confidentiality Requirement (CVSS CR)', cr),
          field('Integrity Requirement (CVSS IR)', ir),
          field('Availability Requirement (CVSS AR)', ar)
        ),
        callout('CR/IR/AR are direct CVSS v4 Security Requirements. They are not derived from Asset Criticality. X means Not Defined.'),
        el('div', {class: 'inline-actions', style: 'margin-top:12px'}, remove)
      )
    );

    return {
      node: details,
      read: () => ({
        customerAssetKey: key.value.trim(),
        displayName: name.value.trim(),
        assetCriticality: criticality.value,
        internetFacing: internet.value,
        cvssConfidentialityRequirement: cr.value,
        cvssIntegrityRequirement: ir.value,
        cvssAvailabilityRequirement: ar.value,
      }),
    };
  }

  function validRequirement(value, index, label) {
    const normalized = String(value || 'X').toUpperCase();
    if (!SECURITY_REQUIREMENT.includes(normalized)) throw new Error(`Asset ${index + 1} has invalid ${label}; expected X/L/M/H.`);
    return normalized;
  }

  function normalizeBundleAsset(asset, index, version) {
    if (!asset || typeof asset !== 'object' || Array.isArray(asset)) throw new Error(`Asset ${index + 1} is invalid.`);
    const key = String(asset.customerAssetKey || '').trim();
    const name = String(asset.displayName || '').trim();
    if (!key && !name) throw new Error(`Asset ${index + 1} needs customerAssetKey or displayName.`);
    const criticality = String(version === 1 ? asset.businessCriticality || 'UNKNOWN' : asset.assetCriticality || 'UNKNOWN').toUpperCase();
    const internetFacing = String(version === 1 ? 'UNKNOWN' : asset.internetFacing || 'UNKNOWN').toUpperCase();
    if (!CRITICALITY.includes(criticality)) throw new Error(`Asset ${index + 1} has invalid Asset Criticality.`);
    if (!INTERNET_FACING.includes(internetFacing)) throw new Error(`Asset ${index + 1} has invalid Internet Facing state.`);
    return {
      customerAssetKey: key,
      displayName: name || key,
      assetCriticality: criticality,
      internetFacing,
      cvssConfidentialityRequirement: version === 3 ? validRequirement(asset.cvssConfidentialityRequirement, index, 'CVSS CR') : 'X',
      cvssIntegrityRequirement: version === 3 ? validRequirement(asset.cvssIntegrityRequirement, index, 'CVSS IR') : 'X',
      cvssAvailabilityRequirement: version === 3 ? validRequirement(asset.cvssAvailabilityRequirement, index, 'CVSS AR') : 'X',
    };
  }

  function validateBundle(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Customer data file must contain one JSON object.');
    if (!Array.isArray(value.assets) || value.assets.length > MAX_BUNDLE_ASSETS) throw new Error('Customer data bundle has an invalid asset list.');
    if (value.contractId === BUNDLE_CONTRACT && value.schemaVersion === 3) return value.assets.map((asset, index) => normalizeBundleAsset(asset, index, 3));
    if (value.contractId === LEGACY_BUNDLE_CONTRACT_V2 && value.schemaVersion === 2) return value.assets.map((asset, index) => normalizeBundleAsset(asset, index, 2));
    if (value.contractId === LEGACY_BUNDLE_CONTRACT_V1 && value.schemaVersion === 1) return value.assets.map((asset, index) => normalizeBundleAsset(asset, index, 1));
    throw new Error(`Expected ${BUNDLE_CONTRACT} schema version 3 (legacy V2/V1 are also accepted).`);
  }

  function mergeBundleIntoSetup(current, imported) {
    if (!current || !Array.isArray(current.candidates) || !current.candidates.length) return imported;
    const byKey = new Map(imported.filter(asset => asset.customerAssetKey).map(asset => [asset.customerAssetKey, asset]));
    const byName = new Map();
    for (const asset of imported) {
      const name = normalizeName(asset.displayName);
      if (!name) continue;
      if (byName.has(name)) byName.set(name, null);
      else byName.set(name, asset);
    }
    return current.candidates.map(candidate => {
      const matched = candidate.customerAssetKey ? byKey.get(candidate.customerAssetKey) : byName.get(normalizeName(candidate.displayName));
      return matched ? {...candidate, ...matched, customerAssetKey: candidate.customerAssetKey || matched.customerAssetKey} : candidate;
    });
  }

  function downloadJson(filename, value) {
    const blob = new Blob([JSON.stringify(value, null, 2) + '\n'], {type: 'application/json'});
    const href = URL.createObjectURL(blob);
    const link = el('a', {href, download: filename});
    document.body.append(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(href);
  }

  function focusSetupMode(root, panel) {
    if (new URLSearchParams(location.search).get('setup') !== '1') return;
    const header = root.querySelector('.page-header');
    for (const child of [...root.children]) if (child !== header && child !== panel) child.hidden = true;
  }

  function injectCustomerAssetSetup(root) {
    if (root.querySelector('[data-customer-asset-setup]')) return;
    const header = root.querySelector('.page-header');
    if (!header) return;

    let setup = activeSetup || {contractId: CONTRACT, sourceFileName: '', createdAt: new Date().toISOString(), candidates: [], run: null, savedAt: null};
    activeSetup = setup;

    const status = el('div', {class: 'status-message', role: 'status', 'aria-live': 'polite'});
    const editorsHost = el('div', {class: 'stack'});
    const upload = el('input', {type: 'file', accept: '.json,application/json', hidden: true});
    const uploadButton = button('Upload customer data');
    const addButton = button('Add asset manually', 'ghost');
    const saveButton = button('Save customer data', 'primary');
    const downloadButton = button('Download customer data');
    downloadButton.disabled = !setup.savedAt;
    const runId = new URLSearchParams(location.search).get('runId') || setup.run?.runId || '';
    const enrichedButton = runId ? button('Download enriched CSV') : null;
    const finishButton = new URLSearchParams(location.search).get('setup') === '1' ? button('Finish setup', 'ghost') : null;
    let editors = [];

    const markDirty = () => {
      setup.savedAt = null;
      downloadButton.disabled = true;
    };

    const renderEditors = () => {
      editorsHost.replaceChildren();
      editors = [];
      const candidates = Array.isArray(setup.candidates) ? setup.candidates : [];
      if (!candidates.length) {
        editorsHost.append(callout('No assets loaded yet. Upload a previously downloaded customer-data file or add an asset manually.', 'warning'));
        return;
      }
      editorsHost.append(callout(`${candidates.length} asset${candidates.length === 1 ? '' : 's'} loaded. Asset Criticality and Internet Facing remain customer context. CR/IR/AR are optional direct CVSS v4 requirements; leave X when not assessed.`));
      candidates.forEach((candidate, index) => {
        const editor = createAssetEditor(candidate, index, markDirty, removeIndex => {
          setup.candidates.splice(removeIndex, 1);
          markDirty();
          renderEditors();
        });
        editors.push(editor);
        editorsHost.append(editor.node);
      });
    };

    addButton.addEventListener('click', () => {
      setup.candidates.push(blankAsset());
      markDirty();
      renderEditors();
    });

    uploadButton.addEventListener('click', () => upload.click());
    upload.addEventListener('change', async () => {
      const file = upload.files && upload.files[0];
      if (!file) return;
      try {
        setStatus(status, `Loading ${file.name}…`);
        const imported = validateBundle(JSON.parse(await file.text()));
        setup.candidates = mergeBundleIntoSetup(setup, imported);
        setup.savedAt = null;
        renderEditors();
        setStatus(status, `Loaded customer data for ${imported.length} asset${imported.length === 1 ? '' : 's'}. Legacy bundles are upgraded with CR/IR/AR=X.`, 'success');
      } catch (error) {
        setStatus(status, error.message, 'error');
      } finally {
        upload.value = '';
      }
    });

    saveButton.addEventListener('click', () => {
      const values = editors.map(editor => editor.read());
      if (!values.length) {
        setStatus(status, 'Load or add at least one asset first.', 'error');
        return;
      }
      const invalidIdentity = values.filter(value => !value.customerAssetKey && !value.displayName).length;
      const incomplete = values.filter(value => value.assetCriticality === 'UNKNOWN' || value.internetFacing === 'UNKNOWN').length;
      if (invalidIdentity) {
        setStatus(status, `${invalidIdentity} asset${invalidIdentity === 1 ? '' : 's'} need an Asset ID or Asset Name.`, 'error');
        return;
      }
      if (incomplete) {
        setStatus(status, `${incomplete} asset${incomplete === 1 ? '' : 's'} still need Asset Criticality and/or Internet Facing. CR/IR/AR may remain X.`, 'error');
        return;
      }
      setup.candidates = values;
      setup.savedAt = new Date().toISOString();
      activeSetup = setup;
      downloadButton.disabled = false;
      setStatus(status, `Saved ${values.length} customer asset context record${values.length === 1 ? '' : 's'} for this run.`, 'success');
    });

    downloadButton.addEventListener('click', () => {
      if (!setup.savedAt) {
        setStatus(status, 'Save customer data before downloading it.', 'error');
        return;
      }
      downloadJson('rbvm-customer-assets-v3.json', {
        contractId: BUNDLE_CONTRACT,
        schemaVersion: 3,
        exportedAt: new Date().toISOString(),
        semantics: 'CUSTOMER_DECLARED_ASSET_CONTEXT_PLUS_DIRECT_CVSS_V4_SECURITY_REQUIREMENTS',
        note: 'CR/IR/AR are direct CVSS v4 X/L/M/H declarations. Asset Criticality does not derive CR/IR/AR. internetFacing is asset-level context and is not NETWORK_REACHABILITY_CSV_V1 evidence or MAV.',
        assets: setup.candidates,
      });
      setStatus(status, `Downloaded reusable V3 customer data for ${setup.candidates.length} asset${setup.candidates.length === 1 ? '' : 's'}.`, 'success');
    });

    if (enrichedButton) {
      enrichedButton.addEventListener('click', () => {
        const link = el('a', {href: `/api/v1/csv-first-enrichments/${encodeURIComponent(runId)}/csv`, download: 'rbvm-enriched.csv'});
        document.body.append(link);
        link.click();
        link.remove();
      });
    }
    if (finishButton) finishButton.addEventListener('click', () => spaGo('/assets?tab=managed'));

    const panel = el('section', {'data-customer-asset-setup': 'true', class: 'panel'},
      el('div', {class: 'panel-header'},
        el('div', {},
          el('h2', {class: 'panel-title', text: 'Customer Asset Context — CVSS v4'}),
          el('p', {class: 'panel-subtitle', text: 'Asset identity comes from the uploaded CSV. Organization-specific CVSS Confidentiality, Integrity, and Availability Requirements are declared directly when known.'})
        )
      ),
      el('div', {class: 'panel-body'},
        el('div', {class: 'stack'},
          callout('CR/IR/AR use FIRST CVSS v4 values X/L/M/H. They are not inferred from Asset Criticality. Internet Facing remains separate from endpoint-scoped reachability and does not set MAV.'),
          upload,
          el('div', {class: 'inline-actions'}, uploadButton, addButton, saveButton, downloadButton, enrichedButton, finishButton),
          status,
          editorsHost
        )
      )
    );

    renderEditors();
    header.insertAdjacentElement('afterend', panel);
    focusSetupMode(root, panel);
  }

  new MutationObserver(schedule).observe(document.documentElement, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
