#!/usr/bin/env python3
import importlib.util
import json
from pathlib import Path
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location("rbvm_csv_analysis", SCRIPTS / "analyze-csv-run-evidence.py")
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load CSV analysis module")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix="rbvm-customer-bundle-v4-") as tmp:
    tmp = Path(tmp)
    v4 = tmp / "v4.json"
    v3 = tmp / "v3.json"
    v2 = tmp / "v2.json"
    invalid = tmp / "invalid.json"

    v4.write_text(json.dumps({
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V4",
        "schemaVersion": 4,
        "assets": [{
            "customerAssetKey": "asset-1",
            "displayName": "Asset One",
            "assetCriticality": "HIGH",
            "internetFacing": "NO",
            "publiclyExposed": "YES",
            "cvssConfidentialityRequirement": "H",
            "cvssIntegrityRequirement": "M",
            "cvssAvailabilityRequirement": "L",
        }],
    }), encoding="utf-8")
    assets, sha, contract, schema = module.load_bundle(v4)
    if not sha or contract != "RBVM_CUSTOMER_ASSET_BUNDLE_V4" or schema != 4:
        raise AssertionError("V4 bundle provenance is incorrect")
    if assets[0]["publiclyExposed"] != "YES":
        raise AssertionError("V4 explicit publiclyExposed was not preserved")
    if assets[0]["internetFacing"] != "NO":
        raise AssertionError("V4 legacy internetFacing was not preserved separately")
    if (assets[0]["cvssConfidentialityRequirement"], assets[0]["cvssIntegrityRequirement"], assets[0]["cvssAvailabilityRequirement"]) != ("H", "M", "L"):
        raise AssertionError("V4 direct CVSS Security Requirements were not preserved")

    # V3 internetFacing=YES must not populate Publicly Exposed.
    v3.write_text(json.dumps({
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
        "schemaVersion": 3,
        "assets": [{
            "customerAssetKey": "asset-1",
            "displayName": "Asset One",
            "assetCriticality": "HIGH",
            "internetFacing": "YES",
            "cvssConfidentialityRequirement": "H",
            "cvssIntegrityRequirement": "M",
            "cvssAvailabilityRequirement": "L",
        }],
    }), encoding="utf-8")
    assets, _, contract, schema = module.load_bundle(v3)
    if contract != "RBVM_CUSTOMER_ASSET_BUNDLE_V3" or schema != 3:
        raise AssertionError("V3 bundle compatibility provenance is incorrect")
    if assets[0]["internetFacing"] != "YES" or assets[0]["publiclyExposed"] != "UNKNOWN":
        raise AssertionError("legacy V3 must upgrade Publicly Exposed to UNKNOWN without Internet Facing inference")

    v2.write_text(json.dumps({
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V2",
        "schemaVersion": 2,
        "assets": [{
            "customerAssetKey": "asset-1",
            "displayName": "Asset One",
            "assetCriticality": "HIGH",
            "internetFacing": "YES"
        }],
    }), encoding="utf-8")
    assets, _, contract, schema = module.load_bundle(v2)
    if contract != "RBVM_CUSTOMER_ASSET_BUNDLE_V2" or schema != 2:
        raise AssertionError("V2 bundle compatibility provenance is incorrect")
    if assets[0]["publiclyExposed"] != "UNKNOWN":
        raise AssertionError("legacy V2 must upgrade Publicly Exposed to UNKNOWN")
    if any(assets[0][field] != "X" for field in ("cvssConfidentialityRequirement", "cvssIntegrityRequirement", "cvssAvailabilityRequirement")):
        raise AssertionError("legacy V2 must still upgrade missing CR/IR/AR to X")

    invalid.write_text(json.dumps({
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V4",
        "schemaVersion": 4,
        "assets": [{
            "customerAssetKey": "asset-1", "displayName": "Asset One",
            "assetCriticality": "HIGH", "internetFacing": "YES", "publiclyExposed": "MAYBE",
            "cvssConfidentialityRequirement": "H", "cvssIntegrityRequirement": "M", "cvssAvailabilityRequirement": "L"
        }],
    }), encoding="utf-8")
    try:
        module.load_bundle(invalid)
    except RuntimeError:
        pass
    else:
        raise AssertionError("V4 must reject invalid publiclyExposed values")

ui = (ROOT / "src/main/resources/web/customer-flow.js").read_text(encoding="utf-8")
doc = (ROOT / "docs/RBVM_CUSTOMER_ASSET_BUNDLE_V4.md").read_text(encoding="utf-8")

for token in (
    "CSV_FIRST_CUSTOMER_ASSET_SETUP_UI_V4",
    "RBVM_CUSTOMER_ASSET_BUNDLE_V4",
    "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
    "PUBLICLY_EXPOSED = ['UNKNOWN', 'YES', 'NO']",
    "publiclyExposed: 'UNKNOWN'",
    "CISA Publicly Exposed?",
    "publiclyExposed: publiclyExposed.value",
    "version === 4 ? asset.publiclyExposed || 'UNKNOWN' : 'UNKNOWN'",
    "rbvm-customer-assets-v4.json",
    "cisa:PE:1.0.0",
):
    if token not in ui:
        raise AssertionError(f"customer-flow V4 missing required token: {token}")

# The actual V2/V3 conversion above is authoritative. UI wording may change, but the editor
# must continue to advertise bounded complete-bundle handling without inventing missing data.
for token in (
    "Legacy V1–V3 bundles preserve missing semantics during upgrade.",
    "EDITOR_PAGE_SIZE = 50",
    "panel.rbvmReadCustomerAssets",
    "panel.rbvmLoadCustomerBundle",
):
    if token not in ui:
        raise AssertionError(f"customer-flow V4 missing bounded/missing-evidence behavior: {token}")

for forbidden in (
    "publiclyExposed: internetFacing",
    "publiclyExposed = internetFacing",
    "internetFacing === 'YES' ? 'YES'",
    "internetFacing === 'NO' ? 'NO'",
):
    if forbidden in ui:
        raise AssertionError(f"customer-flow contains forbidden Internet Facing -> Publicly Exposed inference: {forbidden}")

for token in (
    "cisa:PE:1.0.0",
    "internetFacing=YES",
    "publiclyExposed=YES",
    "V1/V2/V3",
    "publiclyExposed = UNKNOWN",
    "UNKNOWN",
    "RBVM_MVP_PRIORITY_POLICY_V1",
):
    if token not in doc:
        raise AssertionError(f"V4 documentation missing boundary: {token}")

print("Customer Asset Bundle V4 explicit Publicly Exposed + legacy no-inference compatibility: PASS")
