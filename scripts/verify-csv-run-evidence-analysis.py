#!/usr/bin/env python3
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
ANALYZER = ROOT / "scripts/analyze-csv-run-evidence.py"
RESOLVER_DOC = (ROOT / "docs/CVSS_V4_CONTEXT_RESOLVER_V2.md").read_text(encoding="utf-8")
FORMULA_DOC = (ROOT / "docs/RBVM_FORMULA_V2_READINESS.md").read_text(encoding="utf-8")

for token in [
    "CVSS_V4_CONTEXT_RESOLVER_V2",
    "KEV=NOT_LISTED` never becomes `E:U`",
    "CR = X | L | M | H",
    "Asset Criticality -> `CR/IR/AR` mapping",
    "Internet Facing -> `MAV` mapping",
    "CVSS-BTE",
]:
    if token not in RESOLVER_DOC:
        raise AssertionError(f"CVSS v4 resolver V2 contract missing: {token}")

for token in [
    "RBVM_FORMULA_V2_READINESS_V1",
    "NON_COMPUTABLE",
    "No approved organizational-risk composition policy",
    "EPSS probability must not be multiplied by ordinal CVSS severity",
]:
    if token not in FORMULA_DOC:
        raise AssertionError(f"Formula V2 readiness contract missing: {token}")

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    enriched = tmp / "enriched.csv"
    analysis = tmp / "analysis.csv"
    summary = tmp / "summary.json"
    bundle = tmp / "customer-v3.json"

    base_bt = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A"
    base_b = "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    headers = [
        "Agent", "CVE_ID", "Affected_Product", "Severity",
        "CVSS4_Status", "CVSS4_E", "CVSS4_Base_Score", "CVSS4_Base_Severity",
        "CVSS4_Calculated_Status", "CVSS4_Calculated_Nomenclature", "CVSS4_Calculated_Vector",
        "CVSS4_Calculated_Score", "CVSS4_Calculated_Severity",
        "EPSS_Probability", "KEV_Listed", "CISA_Exploitation",
        "CISA_Automatable", "CISA_Technical_Impact",
    ]
    with enriched.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerow({
            "Agent": "asset-a", "CVE_ID": "CVE-2026-10001", "Affected_Product": "pkg-a", "Severity": "Critical",
            "CVSS4_Status": "PRESENT", "CVSS4_E": "", "CVSS4_Base_Score": "9.3", "CVSS4_Base_Severity": "CRITICAL",
            "CVSS4_Calculated_Status": "CALCULATED", "CVSS4_Calculated_Nomenclature": "CVSS-BT",
            "CVSS4_Calculated_Vector": base_bt, "CVSS4_Calculated_Score": "9.3", "CVSS4_Calculated_Severity": "CRITICAL",
            "EPSS_Probability": "0.42", "KEV_Listed": "true", "CISA_Exploitation": "active",
            "CISA_Automatable": "yes", "CISA_Technical_Impact": "total",
        })
        writer.writerow({
            "Agent": "asset-b", "CVE_ID": "CVE-2026-10002", "Affected_Product": "pkg-b", "Severity": "High",
            "CVSS4_Status": "PRESENT", "CVSS4_E": "", "CVSS4_Base_Score": "7.3", "CVSS4_Base_Severity": "HIGH",
            "CVSS4_Calculated_Status": "CALCULATED", "CVSS4_Calculated_Nomenclature": "CVSS-B",
            "CVSS4_Calculated_Vector": base_b, "CVSS4_Calculated_Score": "7.3", "CVSS4_Calculated_Severity": "HIGH",
            "EPSS_Probability": "0.04", "KEV_Listed": "false", "CISA_Exploitation": "none",
            "CISA_Automatable": "no", "CISA_Technical_Impact": "partial",
        })
        writer.writerow({
            "Agent": "asset-c", "CVE_ID": "CVE-2026-10003", "Affected_Product": "pkg-c", "Severity": "Medium",
            "CVSS4_Status": "MISSING", "CVSS4_E": "", "CVSS4_Base_Score": "", "CVSS4_Base_Severity": "",
            "CVSS4_Calculated_Status": "MISSING", "CVSS4_Calculated_Nomenclature": "",
            "CVSS4_Calculated_Vector": "", "CVSS4_Calculated_Score": "", "CVSS4_Calculated_Severity": "",
            "EPSS_Probability": "0.01", "KEV_Listed": "true", "CISA_Exploitation": "active",
            "CISA_Automatable": "", "CISA_Technical_Impact": "",
        })

    bundle.write_text(json.dumps({
        "contractId": "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
        "schemaVersion": 3,
        "assets": [
            {
                "customerAssetKey": "", "displayName": "asset-a", "assetCriticality": "HIGH", "internetFacing": "YES",
                "cvssConfidentialityRequirement": "H", "cvssIntegrityRequirement": "M", "cvssAvailabilityRequirement": "L",
            },
            {
                "customerAssetKey": "", "displayName": "asset-b", "assetCriticality": "LOW", "internetFacing": "NO",
                "cvssConfidentialityRequirement": "H", "cvssIntegrityRequirement": "X", "cvssAvailabilityRequirement": "X",
            },
            {
                "customerAssetKey": "", "displayName": "asset-c", "assetCriticality": "MODERATE", "internetFacing": "YES",
                "cvssConfidentialityRequirement": "H", "cvssIntegrityRequirement": "H", "cvssAvailabilityRequirement": "H",
            },
        ],
    }), encoding="utf-8")

    subprocess.run([
        sys.executable, str(ANALYZER), str(enriched), str(analysis), str(summary),
        "--customer-bundle", str(bundle),
    ], check=True, stdout=subprocess.DEVNULL)

    with analysis.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if len(rows) != 3:
        raise AssertionError("analysis must preserve finding row count")

    first, second, third = rows
    if first["CVSS4_Threat_E_Resolved"] != "A" or first["CVSS4_Threat_E_Status"] != "PRESENT_KEV_ATTESTED":
        raise AssertionError("KEV listed must resolve E:A when published E is absent")
    if (first["CVSS4_CR_Resolved"], first["CVSS4_IR_Resolved"], first["CVSS4_AR_Resolved"]) != ("H", "M", "L"):
        raise AssertionError("direct customer CR/IR/AR values were not preserved")
    if first["CVSS4_Environmental_Requirement_Source"] != "CUSTOMER_DECLARED_CVSS_V4_SECURITY_REQUIREMENTS":
        raise AssertionError("direct Environmental provenance is missing")
    if first["CVSS4_Environmental_Requirement_Status"] != "COMPLETE" or first["CVSS4_Context_Nomenclature"] != "CVSS-BTE" or first["CVSS4_Context_Mode"] != "BTE":
        raise AssertionError("Base+Threat+Environmental context was not calculated as CVSS-BTE")
    if "/CR:H" not in first["CVSS4_Context_Vector"] or "/IR:M" not in first["CVSS4_Context_Vector"] or "/AR:L" not in first["CVSS4_Context_Vector"]:
        raise AssertionError("BTE vector does not contain direct customer Security Requirements")
    if first["CVSS4_MAV_Resolved"] != "X":
        raise AssertionError("Internet Facing must not fabricate MAV")

    if second["CVSS4_Environmental_Requirement_Status"] != "PARTIAL" or second["CVSS4_Context_Nomenclature"] != "CVSS-BE" or second["CVSS4_Context_Mode"] != "BE":
        raise AssertionError("partial direct Environmental assessment must produce CVSS-BE")
    if "/CR:H" not in second["CVSS4_Context_Vector"] or "/IR:" in second["CVSS4_Context_Vector"] or "/AR:" in second["CVSS4_Context_Vector"]:
        raise AssertionError("undefined Environmental requirements must remain X/omitted")

    if third["CVSS4_Context_Mode"] != "UNAVAILABLE" or third["CVSS4_Context_Score"]:
        raise AssertionError("missing CVSS v4 Base must remain unavailable even with customer CR/IR/AR")
    if any(row["RBVM_V2_Status"] != "NON_COMPUTABLE" for row in rows):
        raise AssertionError("contextual CVSS must not be relabeled Organizational Risk")

    result = json.loads(summary.read_text(encoding="utf-8"))
    if result["contractId"] != "CSV_RUN_EVIDENCE_ANALYSIS_V2":
        raise AssertionError("analysis contract version was not advanced")
    if result["source"]["customerBundleContractId"] != "RBVM_CUSTOMER_ASSET_BUNDLE_V3":
        raise AssertionError("customer bundle provenance is missing")
    if result["coverage"]["environmentalRequirementDefinedRows"] != 3:
        raise AssertionError("Environmental requirement coverage count is incorrect")
    if result["coverage"]["contextualNomenclature"].get("CVSS-BTE") != 1 or result["coverage"]["contextualNomenclature"].get("CVSS-BE") != 1:
        raise AssertionError("contextual nomenclature coverage is incorrect")
    if result["rbvmV2"]["riskComputedRows"] != 0 or result["rbvmV2"]["status"] != "NON_COMPUTABLE":
        raise AssertionError("analysis must not fabricate V2 risk")

print("CSV run evidence analysis V2 + direct CVSS Environmental requirements: PASS")
