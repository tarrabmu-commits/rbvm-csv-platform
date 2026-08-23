#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "src/main/resources/web/customer-flow.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

required = [
    'CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V2',
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
    'assetCriticality',
    'internetFacing',
    "YES: 'Yes — Internet Facing'",
    "NO: 'No — Not Internet Facing'",
    'activeSetup',
    'spaGo(',
    'CVE_ID',
]
for token in required:
    if token not in UI:
        raise AssertionError(f"customer asset flow missing {token}")

if 'customer-flow.js' not in COMPILE or 'cat "$ROOT_DIR/src/main/resources/web/customer-flow.js"' not in COMPILE:
    raise AssertionError('runtime frontend bundle does not include customer-flow.js')

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
]:
    if forbidden in UI:
        raise AssertionError(f"MVP customer flow contains forbidden field/inference/persistence: {forbidden}")

if "candidate.customerAssetKey\n        ? byKey.get(candidate.customerAssetKey)" not in UI:
    raise AssertionError('bundle reuse must match customer asset key before display name')

if "value.assetCriticality === 'UNKNOWN' || value.internetFacing === 'UNKNOWN'" not in UI:
    raise AssertionError('save must reject incomplete MVP customer context')

if 'NETWORK_REACHABILITY_CSV_V1 evidence' not in UI:
    raise AssertionError('customer Internet-facing boolean must remain semantically separate from endpoint reachability evidence')

print('CSV-first MVP customer asset UI structural checks: PASS')
