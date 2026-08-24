(() => {
  'use strict';

  const CONTRACT = 'CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V4';
  const BUNDLE_CONTRACT = 'RBVM_CUSTOMER_ASSET_BUNDLE_V4';
  const LEGACY_BUNDLE_CONTRACT_V3 = 'RBVM_CUSTOMER_ASSET_BUNDLE_V3';
  const LEGACY_BUNDLE_CONTRACT_V2 = 'RBVM_CUSTOMER_ASSET_BUNDLE_V2';
  const LEGACY_BUNDLE_CONTRACT_V1 = 'RBVM_CUSTOMER_ASSET_BUNDLE_V1';
  const MAX_BUNDLE_ASSETS = 5000;
  const EDITOR_PAGE_SIZE = 50;
  const CRITICALITY = ['UNKNOWN', 'MISSION_CRITICAL', 'HIGH', 'MODERATE', 'LOW'];
  const INTERNET_FACING = ['UNKNOWN', 'YES', 'NO'];
  const PUBLICLY_EXPOSED = ['UNKNOWN', 'YES', 'NO'];
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
      publiclyExposed: 'UNKNOWN',
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
    if (seen.size > MAX_BUNDLE_ASSETS) throw new Error(`CSV contains more than ${MAX_BUNDLE_ASSETS} distinct assets.`);
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
      el('div', {class: 'panel-header'}, el('div', {},
        el('h2', {class: 'panel-title', text: 'CSV-first customer run'}),
        el('p', {class: 'panel-subtitle', text: 'The uploaded CSV is the complete run scope. Public vulnerability intelligence is automatic; organization-specific asset context remains customer-declared.'})
      )),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('Automatic: CVSS v4 Base, EPSS, KEV, CISA SSVC, CWE/CPE and provenance. Customer: Asset Criticality, legacy Internet Facing, explicit CISA Publicly Exposed, and optional direct CVSS CR/IR/AR requirements.'),
        el('div', {class: 'form-grid'}, field('Customer vulnerability CSV', file)),
        el('div', {class: 'inline-actions'}, run),
        status
      ))
    );

    run.addEventListener('click', async () => {
      const selected = file.files && file.files[0];
      if (!selected) { setStatus(status, 'Choose the customer CSV first.', 'error'); return; }
      run.disabled = true;
      try {
        setStatus(status, `Reading asset identities from ${selected.name}…`);
        const candidates = candidatesFromCsv(await selected.text());
        activeSetup = {contractId: CONTRACT, sourceFileName: selected.name, createdAt: new Date().toISOString(), candidates, run: null, savedAt: null};
        setStatus(status, `Collecting public intelligence for ${selected.name}…`);
        const response = await api('/api/v1/csv-first-enrichments', {
          method: 'POST', headers: {'Content-Type': 'text/csv; charset=utf-8'}, body: selected,
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
    for (const value of values) select.append(el('option', {value, text: labels[value] || value.replaceAll('_', ' '), selected: value === current}));
    return select;
  }

  function requirementInput(current, metric) {
    return selectInput(SECURITY_REQUIREMENT, current || 'X', {
      X: `Not Defined — ${metric}:X`, L: `Low — ${metric}:L`, M: `Medium — ${metric}:M`, H: `High — ${metric}:H`,
    }, metric);
  }

  function createAssetEditor(asset, index, onChange, onRemove, open = false) {
    const key = textInput(asset.customerAssetKey || '', 'Stable customer key', 'customerAssetKey');
    const name = textInput(asset.displayName || '', 'Asset name', 'displayName');
    const criticality = selectInput(CRITICALITY, asset.assetCriticality || 'UNKNOWN', {
      UNKNOWN: 'Select criticality…', MISSION_CRITICAL: 'Mission Critical', HIGH: 'High', MODERATE: 'Moderate', LOW: 'Low',
    }, 'assetCriticality');
    const internet = selectInput(INTERNET_FACING, asset.internetFacing || 'UNKNOWN', {
      UNKNOWN: 'Select Internet-facing state…', YES: 'Yes — Internet Facing', NO: 'No — Not Internet Facing',
    }, 'internetFacing');
    const publiclyExposed = selectInput(PUBLICLY_EXPOSED, asset.publiclyExposed || 'UNKNOWN', {
      UNKNOWN: 'Unknown / not assessed', YES: 'Yes — accessible to unauthenticated or untrusted entities via public networks', NO: 'No — not accessible that way',
    }, 'publiclyExposed');
    const cr = requirementInput(asset.cvssConfidentialityRequirement, 'CR');
    const ir = requirementInput(asset.cvssIntegrityRequirement, 'IR');
    const ar = requirementInput(asset.cvssAvailabilityRequirement, 'AR');
    const read = () => ({
      customerAssetKey: key.value.trim(), displayName: name.value.trim(), assetCriticality: criticality.value,
      internetFacing: internet.value, publiclyExposed: publiclyExposed.value,
      cvssConfidentialityRequirement: cr.value, cvssIntegrityRequirement: ir.value, cvssAvailabilityRequirement: ar.value,
    });
    const changed = () => onChange(index, read());
    for (const input of [key, name, criticality, internet, publiclyExposed, cr, ir, ar]) input.addEventListener('change', changed);
    for (const input of [key, name]) input.addEventListener('input', changed);

    const remove = button('Remove', 'ghost');
    remove.addEventListener('click', () => onRemove(index));
    const details = el('details', {class: 'panel', open, 'data-customer-asset-editor': String(index)},
      el('summary', {style: 'cursor:pointer;padding:16px 20px;font-weight:700;', text: asset.displayName || asset.customerAssetKey || `Asset ${index + 1}`}),
      el('div', {class: 'panel-body'},
        el('div', {class: 'form-grid'},
          field('Asset ID', key), field('Asset Name', name), field('Asset Criticality', criticality), field('Internet Facing?', internet),
          field('CISA Publicly Exposed?', publiclyExposed), field('Confidentiality Requirement (CVSS CR)', cr),
          field('Integrity Requirement (CVSS IR)', ir), field('Availability Requirement (CVSS AR)', ar)
        ),
        callout('CISA Publicly Exposed is an explicit BOD 26-04 customer decision point. Internet Facing is legacy/coarse context and never populates it. UNKNOWN is preserved when not assessed.'),
        callout('CR/IR/AR are direct CVSS v4 Security Requirements. They are not derived from Asset Criticality. X means Not Defined.'),
        el('div', {class: 'inline-actions', style: 'margin-top:12px'}, remove)
      )
    );
    return {node: details, read};
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
    const publiclyExposed = String(version === 4 ? asset.publiclyExposed || 'UNKNOWN' : 'UNKNOWN').toUpperCase();
    if (!CRITICALITY.includes(criticality)) throw new Error(`Asset ${index + 1} has invalid Asset Criticality.`);
    if (!INTERNET_FACING.includes(internetFacing)) throw new Error(`Asset ${index + 1} has invalid Internet Facing state.`);
    if (!PUBLICLY_EXPOSED.includes(publiclyExposed)) throw new Error(`Asset ${index + 1} has invalid CISA Publicly Exposed state.`);
    const supportsSecurityRequirements = version >= 3;
    return {
      customerAssetKey: key, displayName: name || key, assetCriticality: criticality, internetFacing, publiclyExposed,
      cvssConfidentialityRequirement: supportsSecurityRequirements ? validRequirement(asset.cvssConfidentialityRequirement, index, 'CVSS CR') : 'X',
      cvssIntegrityRequirement: supportsSecurityRequirements ? validRequirement(asset.cvssIntegrityRequirement, index, 'CVSS IR') : 'X',
      cvssAvailabilityRequirement: supportsSecurityRequirements ? validRequirement(asset.cvssAvailabilityRequirement, index, 'CVSS AR') : 'X',
    };
  }

  function validateBundle(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Customer data file must contain one JSON object.');
    if (!Array.isArray(value.assets) || value.assets.length > MAX_BUNDLE_ASSETS) throw new Error('Customer data bundle has an invalid asset list.');
    if (value.contractId === BUNDLE_CONTRACT && value.schemaVersion === 4) return value.assets.map((asset, index) => normalizeBundleAsset(asset, index, 4));
    if (value.contractId === LEGACY_BUNDLE_CONTRACT_V3 && value.schemaVersion === 3) return value.assets.map((asset, index) => normalizeBundleAsset(asset, index, 3));
    if (value.contractId === LEGACY_BUNDLE_CONTRACT_V2 && value.schemaVersion === 2) return value.assets.map((asset, index) => normalizeBundleAsset(asset, index, 2));
    if (value.contractId === LEGACY_BUNDLE_CONTRACT_V1 && value.schemaVersion === 1) return value.assets.map((asset, index) => normalizeBundleAsset(asset, index, 1));
    throw new Error(`Expected ${BUNDLE_CONTRACT} schema version 4 (legacy V3/V2/V1 are also accepted).`);
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
    document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(href);
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
    const search = el('input', {type: 'search', class: 'search-input', placeholder: 'Search asset ID or name…', 'aria-label': 'Search customer assets'});
    const previous = button('Previous', 'ghost');
    const next = button('Next', 'ghost');
    const pageLabel = el('span');
    let pageIndex = 0;

    const markDirty = () => { setup.savedAt = null; downloadButton.disabled = true; };
    const matchingIndexes = () => {
      const q = normalizeName(search.value);
      const candidates = Array.isArray(setup.candidates) ? setup.candidates : [];
      const result = [];
      for (let index = 0; index < candidates.length; index++) {
        const asset = candidates[index];
        if (!q || normalizeName(asset.customerAssetKey).includes(q) || normalizeName(asset.displayName).includes(q)) result.push(index);
      }
      return result;
    };

    const renderEditors = () => {
      editorsHost.replaceChildren();
      const candidates = Array.isArray(setup.candidates) ? setup.candidates : [];
      if (!candidates.length) {
        previous.disabled = true; next.disabled = true; pageLabel.textContent = '0 assets';
        editorsHost.append(callout('No assets loaded yet. Upload a previously downloaded customer-data file or add an asset manually.', 'warning'));
        return;
      }
      const indexes = matchingIndexes();
      const pages = Math.max(1, Math.ceil(indexes.length / EDITOR_PAGE_SIZE));
      pageIndex = Math.min(Math.max(0, pageIndex), pages - 1);
      const start = pageIndex * EDITOR_PAGE_SIZE;
      const visible = indexes.slice(start, start + EDITOR_PAGE_SIZE);
      previous.disabled = pageIndex === 0;
      next.disabled = pageIndex + 1 >= pages;
      pageLabel.textContent = `${indexes.length} matching / ${candidates.length} total · page ${pageIndex + 1} of ${pages} · max ${EDITOR_PAGE_SIZE} editors rendered`;
      editorsHost.append(callout(`${candidates.length} asset${candidates.length === 1 ? '' : 's'} loaded. Only the current page is rendered to keep browser memory bounded; Save and analysis still use the complete bundle. Publicly Exposed remains separate from Internet Facing, and CR/IR/AR remain direct customer CVSS v4 declarations.`));
      if (!visible.length) {
        editorsHost.append(callout('No customer assets match this search.', 'warning'));
        return;
      }
      visible.forEach((absoluteIndex, visibleIndex) => {
        const editor = createAssetEditor(candidates[absoluteIndex], absoluteIndex, (changedIndex, value) => {
          setup.candidates[changedIndex] = value;
          markDirty();
        }, removeIndex => {
          setup.candidates.splice(removeIndex, 1);
          markDirty();
          renderEditors();
        }, visibleIndex < 4);
        editorsHost.append(editor.node);
      });
    };

    search.addEventListener('input', () => { pageIndex = 0; renderEditors(); });
    previous.addEventListener('click', () => { if (pageIndex > 0) { pageIndex--; renderEditors(); } });
    next.addEventListener('click', () => { pageIndex++; renderEditors(); });

    addButton.addEventListener('click', () => {
      if (setup.candidates.length >= MAX_BUNDLE_ASSETS) { setStatus(status, `A customer bundle cannot exceed ${MAX_BUNDLE_ASSETS} assets.`, 'error'); return; }
      setup.candidates.push(blankAsset());
      search.value = '';
      pageIndex = Math.floor((setup.candidates.length - 1) / EDITOR_PAGE_SIZE);
      markDirty(); renderEditors();
    });

    const loadBundleIntoEditor = value => {
      const imported = validateBundle(value);
      setup.candidates = mergeBundleIntoSetup(setup, imported);
      setup.savedAt = null;
      pageIndex = 0;
      search.value = '';
      renderEditors();
      return setup.candidates.length;
    };

    uploadButton.addEventListener('click', () => upload.click());
    upload.addEventListener('change', async () => {
      const file = upload.files && upload.files[0];
      if (!file) return;
      try {
        setStatus(status, `Loading ${file.name}…`);
        const count = loadBundleIntoEditor(JSON.parse(await file.text()));
        setStatus(status, `Loaded customer data for ${count} asset${count === 1 ? '' : 's'}. Legacy V1–V3 bundles preserve missing semantics during upgrade.`, 'success');
      } catch (error) { setStatus(status, error.message, 'error'); }
      finally { upload.value = ''; }
    });

    const validateAll = () => {
      const values = setup.candidates.map((asset, index) => normalizeBundleAsset(asset, index, 4));
      if (!values.length) throw new Error('Load or add at least one asset first.');
      const incomplete = values.filter(value => value.assetCriticality === 'UNKNOWN' || value.internetFacing === 'UNKNOWN').length;
      if (incomplete) throw new Error(`${incomplete} asset${incomplete === 1 ? '' : 's'} still need Asset Criticality and/or Internet Facing for the existing customer-context workflow. CISA Publicly Exposed may remain UNKNOWN; CR/IR/AR may remain X.`);
      return values;
    };

    saveButton.addEventListener('click', () => {
      try {
        const values = validateAll();
        setup.candidates = values; setup.savedAt = new Date().toISOString(); activeSetup = setup; downloadButton.disabled = false;
        const bodIncomplete = values.filter(value => value.publiclyExposed === 'UNKNOWN').length;
        const suffix = bodIncomplete ? ` ${bodIncomplete} asset${bodIncomplete === 1 ? '' : 's'} remain BOD-incomplete because Publicly Exposed is UNKNOWN.` : '';
        setStatus(status, `Saved ${values.length} customer asset context record${values.length === 1 ? '' : 's'} for this run.${suffix}`, 'success');
      } catch (error) { setStatus(status, error.message, 'error'); }
    });

    downloadButton.addEventListener('click', () => {
      if (!setup.savedAt) { setStatus(status, 'Save customer data before downloading it.', 'error'); return; }
      downloadJson('rbvm-customer-assets-v4.json', {
        contractId: BUNDLE_CONTRACT, schemaVersion: 4, exportedAt: new Date().toISOString(),
        semantics: 'CUSTOMER_DECLARED_ASSET_CONTEXT_PLUS_CISA_PUBLICLY_EXPOSED_PLUS_DIRECT_CVSS_V4_SECURITY_REQUIREMENTS',
        note: 'publiclyExposed is the explicit cisa:PE:1.0.0 BOD decision point. internetFacing remains legacy/coarse asset context and does not populate Publicly Exposed, NETWORK_REACHABILITY_CSV_V1, or MAV. CR/IR/AR are direct CVSS v4 X/L/M/H declarations and are not derived from Asset Criticality.',
        assets: setup.candidates,
      });
      setStatus(status, `Downloaded reusable V4 customer data for ${setup.candidates.length} asset${setup.candidates.length === 1 ? '' : 's'}.`, 'success');
    });

    if (enrichedButton) enrichedButton.addEventListener('click', () => {
      const link = el('a', {href: `/api/v1/csv-first-enrichments/${encodeURIComponent(runId)}/csv`, download: 'rbvm-enriched.csv'});
      document.body.append(link); link.click(); link.remove();
    });
    if (finishButton) finishButton.addEventListener('click', () => spaGo('/assets?tab=managed'));

    const panel = el('section', {'data-customer-asset-setup': 'true', class: 'panel'},
      el('div', {class: 'panel-header'}, el('div', {},
        el('h2', {class: 'panel-title', text: 'Customer Asset Context — CISA BOD + CVSS v4'}),
        el('p', {class: 'panel-subtitle', text: 'Asset identity comes from the uploaded CSV. CISA Publicly Exposed and organization-specific CVSS Confidentiality, Integrity, and Availability Requirements are declared directly when known.'})
      )),
      el('div', {class: 'panel-body'}, el('div', {class: 'stack'},
        callout('Publicly Exposed follows cisa:PE:1.0.0 and remains UNKNOWN until the customer explicitly assesses it. Internet Facing remains separate legacy context and cannot set Publicly Exposed or MAV. CR/IR/AR use FIRST CVSS v4 values X/L/M/H and are not inferred from Asset Criticality.'),
        upload,
        el('div', {class: 'inline-actions'}, uploadButton, addButton, saveButton, downloadButton, enrichedButton, finishButton),
        status,
        el('div', {class: 'toolbar'}, el('div', {class: 'toolbar-main'}, search), el('div', {class: 'pagination'}, previous, pageLabel, next)),
        editorsHost
      ))
    );

    // Local-API extension consumes these in-memory hooks so persistence always covers the
    // complete bundle even though only one bounded editor page exists in the DOM.
    panel.rbvmReadCustomerAssets = () => setup.candidates.map(asset => ({...asset}));
    panel.rbvmLoadCustomerBundle = value => loadBundleIntoEditor(value);
    panel.rbvmCustomerAssetCount = () => setup.candidates.length;

    renderEditors();
    header.insertAdjacentElement('afterend', panel);
    focusSetupMode(root, panel);
  }

  const observerRoot = document.getElementById('rbvm-app') || document.documentElement;
  new MutationObserver(schedule).observe(observerRoot, {childList: true, subtree: true});
  window.addEventListener('DOMContentLoaded', schedule);
  window.addEventListener('popstate', schedule);
  schedule();
})();
