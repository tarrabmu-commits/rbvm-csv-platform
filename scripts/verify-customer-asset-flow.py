#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "src/main/resources/web/customer-flow.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

required = [
    'CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V1',
    'RBVM_CUSTOMER_ASSET_BUNDLE_V1',
    'Enrich CSV & continue to Assets',
    '/api/v1/csv-first-enrichments',
    'Upload customer data',
    'Download customer data',
    'Save customer data',
    'Download enriched CSV',
    '/api/v1/managed-assets',
    'businessCriticality',
    'businessService',
    'businessOwner',
    'environment',
    'classificationMethod',
    'CUSTOMER_DIRECT',
    'GUIDED',
    'sessionStorage',
    'CVE_ID',
]
for token in required:
    if token not in UI:
        raise AssertionError(f"customer asset flow missing {token}")

if 'customer-flow.js' not in COMPILE or 'cat "$ROOT_DIR/src/main/resources/web/customer-flow.js"' not in COMPILE:
    raise AssertionError('runtime frontend bundle does not include customer-flow.js')

for forbidden in [
    "businessCriticality: 'MISSION_CRITICAL'",
    "environment: 'PRODUCTION'",
    'EPSS_Probability *',
    'CVSS4_Base_Score *',
]:
    if forbidden in UI:
        raise AssertionError(f"customer context must not be inferred from public vulnerability data: {forbidden}")

if "customerAssetKey\n        ? byKey.get" not in UI and "candidate.customerAssetKey\n        ? byKey.get" not in UI:
    raise AssertionError('bundle reuse must match customer asset key before display name')

print('CSV-first customer asset UI structural checks: PASS')
