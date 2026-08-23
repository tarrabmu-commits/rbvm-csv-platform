#!/usr/bin/env python3
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "scripts/analyze-csv-run-evidence.py"
RESOLVER_DOC = (ROOT / "docs/CVSS_V4_CONTEXT_RESOLVER_V1.md").read_text(encoding="utf-8")
FORMULA_DOC = (ROOT / "docs/RBVM_FORMULA_V2_READINESS.md").read_text(encoding="utf-8")

for token in [
    "CVSS_V4_CONTEXT_RESOLVER_V1",
    "KEV=NOT_LISTED` never becomes `E:U`",
    "CR = X",
    "MAV = X",
]:
    if token not in RESOLVER_DOC:
        raise AssertionError(f"CVSS v4 resolver contract missing: {token}")

for token in [
    "RBVM_FORMULA_V2_READINESS_V1",
    "NON_COMPUTABLE",
    "No approved organizational-risk composition policy",
    "CVSS x EPSS",
]:
    if token not in FORMULA_DOC:
        raise AssertionError(f"Formula V2 readiness contract missing: {token}")

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    enriched = tmp / "enriched.csv"
    analysis = tmp / "analysis.csv"
    summary = tmp / "summary.json"
    bundle = tmp / "customer.json"

    headers = [
        "Agent", "CVE_ID", "Affected_Product", "Severity",
        "CVSS4_Status", "CVSS4_E", "CVSS4_Base_Score", "CVSS4_Base_Severity",
        "EPSS_Probability", "KEV_Listed", "CISA_Exploitation",
        "CISA_Automatable", "CISA_Technical_Impact",
    ]
    with enriched.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerow({
            "Agent": "asset-a", "CVE_ID": "CVE-2026-10001", "Affected_Product": "pkg-a", "Severity": "High",
            "CVSS4_Status": "PRESENT", "CVSS4_E": "", "CVSS4_Base_Score": "8.7", "CVSS4_Base_Severity": "HIGH",
            "EPSS_Probability": "0.42", "KEV_Listed": "true", "CISA_Exploitation": "active",
            "CISA_Automatable": "yes", "CISA_Technical_Impact": "total",
        })
        writer.writerow({
            "Agent": "asset-b", "CVE_ID": "CVE-2026-10002", "Affected_Product": "pkg-b", "Severity": "Medium",
            "CVSS4_Status": "MISSING", "CVSS4_E": "", "CVSS4_Base_Score": "", "CVSS4_Base_Severity": "",
            "EPSS_Probability": "", "KEV_Listed": "false", "CISA_Exploitation": "",
            "CISA_Automatable": "", "CISA_Technical_Impact": "",
        })

    bundle.write_text(json.dumps({
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V2",
        "schemaVersion": 2,
        "assets": [
            {"customerAssetKey": "", "displayName": "asset-a", "assetCriticality": "HIGH", "internetFacing": "YES"},
            {"customerAssetKey": "", "displayName": "asset-b", "assetCriticality": "LOW", "internetFacing": "NO"},
        ],
    }), encoding="utf-8")

    subprocess.run([
        sys.executable, str(ANALYZER), str(enriched), str(analysis), str(summary),
        "--customer-bundle", str(bundle),
    ], check=True, stdout=subprocess.DEVNULL)

    with analysis.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 2:
        raise AssertionError("analysis must preserve finding row count")
    first, second = rows
    if first["CVSS4_Threat_E_Resolved"] != "A" or first["CVSS4_Threat_E_Status"] != "PRESENT_KEV_ATTESTED":
        raise AssertionError("KEV listed must resolve E:A when published E is absent")
    if first["CVSS4_Context_Mode"] != "BT_INPUT_READY":
        raise AssertionError("resolved Threat E must make Base+Threat input ready")
    if first["CVSS4_CR_Resolved"] != "X" or first["CVSS4_MAV_Resolved"] != "X":
        raise AssertionError("MVP context must not fabricate environmental metrics")
    if first["Asset_Criticality"] != "HIGH" or first["Internet_Facing"] != "YES":
        raise AssertionError("customer bundle context must join by asset name")
    if first["RBVM_V2_Status"] != "NON_COMPUTABLE":
        raise AssertionError("Formula V2 must remain non-computable without approved composition policy")
    if second["CVSS4_Context_Mode"] != "UNAVAILABLE" or second["CVSS4_Threat_E_Status"] != "MISSING_BASE":
        raise AssertionError("missing CVSS v4 Base must remain unavailable")

    result = json.loads(summary.read_text(encoding="utf-8"))
    if result["scope"] != {"findingRows": 2, "uniqueAssets": 2, "uniqueCves": 2}:
        raise AssertionError("coverage scope is incorrect")
    if result["coverage"]["customerContextCompleteRows"] != 2:
        raise AssertionError("customer context coverage count is incorrect")
    if result["rbvmV2"]["riskComputedRows"] != 0 or result["rbvmV2"]["status"] != "NON_COMPUTABLE":
        raise AssertionError("analysis must not fabricate V2 risk")

print("CSV run evidence analysis + Formula V2 readiness checks: PASS")
