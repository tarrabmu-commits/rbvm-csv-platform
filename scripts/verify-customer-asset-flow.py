#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "src/main/resources/web/customer-flow.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
RUNTIME = ROOT / "build/manual/main/web/rbvm-ui.js"

required = [
    'CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V4',
    'RBVM_CUSTOMER_ASSET_BUNDLE_V4',
    'RBVM_CUSTOMER_ASSET_BUNDLE_V3',
    'RBVM_CUSTOMER_ASSET_BUNDLE_V2',
    'RBVM_CUSTOMER_ASSET_BUNDLE_V1',
    'Enrich CSV & continue to Assets',
    '/api/v1/csv-first-enrichments',
    'Upload customer data',
    'Download customer data',
    'Save customer data',
    'Download enriched CSV',
    'Add asset manually',
    'Asset Criticality',
    'Internet Facing?',
    'CISA Publicly Exposed?',
    'assetCriticality',
    'internetFacing',
    'publiclyExposed',
    "PUBLICLY_EXPOSED = ['UNKNOWN', 'YES', 'NO']",
    'Confidentiality Requirement (CVSS CR)',
    'Integrity Requirement (CVSS IR)',
    'Availability Requirement (CVSS AR)',
    'cvssConfidentialityRequirement',
    'cvssIntegrityRequirement',
    'cvssAvailabilityRequirement',
    "SECURITY_REQUIREMENT = ['X', 'L', 'M', 'H']",
    "X: `Not Defined — ${metric}:X`",
    'CISA Publicly Exposed may remain UNKNOWN',
    'CR/IR/AR may remain X',
    'activeSetup',
    'spaGo(',
    'CVE_ID',
]
for token in required:
    if token not in UI:
        raise AssertionError(f"customer asset flow missing {token}")

if 'customer-flow.js' not in COMPILE or 'cat "$ROOT_DIR/src/main/resources/web/customer-flow.js"' not in COMPILE:
    raise AssertionError('runtime frontend bundle does not include customer-flow.js')
if 'apply-current-risk-input-scope-ui.py' not in COMPILE:
    raise AssertionError('runtime frontend bundle does not apply the current risk-input scope transform')

for forbidden in [
    '/api/v1/managed-assets',
    'fetchAllManagedAssets',
    "field('Business service'",
    "field('Business owner'",
    "field('Environment'",
    "field('Classification method'",
    "businessCriticality: 'MISSION_CRITICAL'",
    "environment: 'PRODUCTION'",
    'EPSS_Probability *',
    'CVSS4_Base_Score *',
    'sessionStorage',
    'localStorage',
    'assetCriticality === \'HIGH\' ? \'H\'',
    'internetFacing === \'YES\' ? \'N\'',
    'publiclyExposed: internetFacing',
    'publiclyExposed = internetFacing',
]:
    if forbidden in UI:
        raise AssertionError(f"customer flow contains forbidden inference/persistence: {forbidden}")

if "candidate.customerAssetKey ? byKey.get(candidate.customerAssetKey)" not in UI:
    raise AssertionError('bundle reuse must match customer asset key before display name')
if "value.assetCriticality === 'UNKNOWN' || value.internetFacing === 'UNKNOWN'" not in UI:
    raise AssertionError('save must preserve existing required customer-context behavior')
if "version === 4 ? asset.publiclyExposed || 'UNKNOWN' : 'UNKNOWN'" not in UI:
    raise AssertionError('legacy bundles must upgrade Publicly Exposed to UNKNOWN without inference')
if "const supportsSecurityRequirements = version >= 3" not in UI:
    raise AssertionError('V3/V4 direct CR/IR/AR must be validated without inference')
if 'Internet Facing is legacy/coarse context and never populates it' not in UI:
    raise AssertionError('Internet Facing must remain separate from CISA Publicly Exposed')
if 'NETWORK_REACHABILITY_CSV_V1' not in UI or 'MAV' not in UI:
    raise AssertionError('Internet-facing boolean must remain separate from reachability/MAV')
if 'not derived from Asset Criticality' not in UI:
    raise AssertionError('customer flow must state CR/IR/AR are not derived from criticality')

# Source V4 retains historical/optional evidence fields for replay compatibility, but the
# compiled product surface must request only the two customer attributes in current scope.
if not RUNTIME.is_file():
    raise AssertionError('compiled frontend runtime is missing')
runtime = RUNTIME.read_text(encoding='utf-8')
for token in [
    'Customer: Asset Criticality and Internet Facing only.',
    'Customer Asset Context — Risk Inputs',
    'For the current risk workflow, provide only Asset Criticality and Internet Facing.',
    'Current customer inputs are Asset Criticality and Internet Facing only.',
    'before risk calculation.',
    'key.readOnly = true',
    'name.readOnly = true',
    "metric('Organizational Risk', 'SELECT METHOD', 'Calculated separately from MVP Priority')",
    'organizational risk is available through the selectable risk methods in Finding Review',
]:
    if token not in runtime:
        raise AssertionError(f'compiled current-scope UI missing {token}')

for retired_runtime_prompt in [
    "field('CISA Publicly Exposed?', publiclyExposed)",
    "field('Confidentiality Requirement (CVSS CR)', cr)",
    "field('Integrity Requirement (CVSS IR)', ir)",
    "field('Availability Requirement (CVSS AR)', ar)",
    'Organizational Risk remains NON_COMPUTABLE.',
]:
    if retired_runtime_prompt in runtime:
        raise AssertionError(f'compiled current-scope UI still exposes retired prompt/state: {retired_runtime_prompt}')

print('CSV-first customer asset V4 persistence + current two-field risk input UI: PASS')
