#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "src/main/resources/web/csv-run-review.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

required = [
    "CSV_FIRST_FINDING_REVIEW_UI_V1",
    "Review Findings",
    "Finding Evidence Review — CSV Run",
    "/api/v1/csv-first-enrichments/",
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
    "MATCHED_ID",
    "MATCHED_NAME",
    "Download review CSV",
    "no risk score, priority or SLA is calculated",
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
]:
    if forbidden in UI:
        raise AssertionError(f"CSV run review contains forbidden decision/persistence logic: {forbidden}")

if 'csv-run-review.js' not in COMPILE or 'cat "$ROOT_DIR/src/main/resources/web/csv-run-review.js"' not in COMPILE:
    raise AssertionError("runtime frontend bundle does not include csv-run-review.js")

print("CSV-first finding review UI structural checks: PASS")
