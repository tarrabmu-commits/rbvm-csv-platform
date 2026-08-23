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
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

with tempfile.TemporaryDirectory(prefix="rbvm-customer-bundle-v3-") as tmp:
    tmp = Path(tmp)
    v3 = tmp / "v3.json"
    v2 = tmp / "v2.json"
    invalid = tmp / "invalid.json"

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
    assets, sha, contract, schema = module.load_bundle(v3)
    if not sha or contract != "RBVM_CUSTOMER_ASSET_BUNDLE_V3" or schema != 3:
        raise AssertionError("V3 bundle provenance is incorrect")
    if (assets[0]["cvssConfidentialityRequirement"], assets[0]["cvssIntegrityRequirement"], assets[0]["cvssAvailabilityRequirement"]) != ("H", "M", "L"):
        raise AssertionError("V3 direct CVSS Security Requirements were not preserved")

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
    if any(assets[0][field] != "X" for field in ("cvssConfidentialityRequirement", "cvssIntegrityRequirement", "cvssAvailabilityRequirement")):
        raise AssertionError("legacy V2 must upgrade missing CR/IR/AR to X, never infer values")

    invalid.write_text(json.dumps({
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
        "schemaVersion": 3,
        "assets": [{
            "customerAssetKey": "asset-1", "displayName": "Asset One",
            "assetCriticality": "HIGH", "internetFacing": "YES",
            "cvssConfidentialityRequirement": "CRITICAL",
            "cvssIntegrityRequirement": "M", "cvssAvailabilityRequirement": "L"
        }],
    }), encoding="utf-8")
    try:
        module.load_bundle(invalid)
    except RuntimeError:
        pass
    else:
        raise AssertionError("V3 must reject non-CVSS CR/IR/AR values")

print("Customer Asset Bundle V3 + legacy V2 compatibility: PASS")
