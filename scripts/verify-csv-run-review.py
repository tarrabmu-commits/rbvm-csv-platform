#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "src/main/resources/web/csv-run-review.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

required = [
    "CSV_FIRST_FINDING_REVIEW_UI_V2",
    "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
    "Review Findings",
    "Finding Evidence Review — CSV Run",
    "/api/v1/csv-first-enrichments/",
    "/analysis",
    "CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1",
    "CVSS4_Context_Score_Status",
    "CVSS4_Context_Nomenclature",
    "CVSS4_Context_Score",
    "CVSS4_Context_Severity",
    "CVSS4_CR_Resolved",
    "CVSS4_IR_Resolved",
    "CVSS4_AR_Resolved",
    "CVSS4_Status",
    "CVSS4_Base_Score",
    "EPSS_Probability",
    "KEV_Listed",
    "CISA_Exploitation",
    "CISA_Automatable",
    "CISA_Technical_Impact",
    "Asset_Criticality",
    "Internet_Facing",
    "Customer_Context_Status",
    "cvssConfidentialityRequirement",
    "cvssIntegrityRequirement",
    "cvssAvailabilityRequirement",
    "methodAdmission",
    "NO_V2_PRIMARY_METHOD_ADMITTED",
    "Download contextual analysis CSV",
    "Download method admission",
    "Organizational Risk is not inferred",
    "Internet Facing is not mapped to MAV",
    "EPSS is not multiplied by CVSS",
]
for token in required:
    if token not in UI:
        raise AssertionError(f"CSV run review missing {token}")

for forbidden in [
    "CVSS4_Base_Score *",
    "EPSS_Probability *",
    "riskScore",
    "priorityScore",
    "remediationSla",
    "localStorage",
    "sessionStorage",
    "contextResolver(",
    "joinRows(",
]:
    if forbidden in UI:
        raise AssertionError(f"CSV run review contains forbidden client-side decision/join/persistence logic: {forbidden}")

if "method: 'POST'" not in UI or "'Content-Type': 'application/json; charset=utf-8'" not in UI:
    raise AssertionError('finding review must submit the V3 customer bundle to server-side contextual analysis')
if "fetch(run.analysisCsv" not in UI or "fetch(run.methodAdmission" not in UI:
    raise AssertionError('finding review must consume server-generated analysis and admission artifacts')
if 'csv-run-review.js' not in COMPILE or 'cat "$ROOT_DIR/src/main/resources/web/csv-run-review.js"' not in COMPILE:
    raise AssertionError("runtime frontend bundle does not include csv-run-review.js")

print("CSV-first contextual finding review UI structural checks: PASS")
