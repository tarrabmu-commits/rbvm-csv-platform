#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "src/main/resources/web/csv-run-review.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

required = [
    "CSV_FIRST_FINDING_REVIEW_UI_V4",
    "CSV_FIRST_MVP_PRIORITY_HTTP_V1",
    "RBVM_MVP_PRIORITY_POLICY_V1",
    "RBVM_MVP_PRIORITY_EXPLAINABILITY_V1",
    "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388",
    "Review Findings",
    "Finding Evidence Review — CSV Run",
    "/api/v1/csv-first-customer-assets/",
    "/analyses",
    "CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1",
    "customerBundleSource !== 'SAVED_RUN_BUNDLE'",
    "customerBundlePersisted !== 'true'",
    "run.immutable !== true",
    "run.analysisId",
    "priority.organizationalRisk !== 'NON_COMPUTABLE'",
    "priorityReport.organizationalRiskComputed !== false",
    "priorityReport.riskStatus !== 'NON_COMPUTABLE'",
    "priorityReport.explainability?.contractId !== PRIORITY_EXPLAINABILITY",
    "RBVM_MVP_Priority_Status",
    "RBVM_MVP_Priority_Front",
    "RBVM_MVP_Priority_Blockers",
    "RBVM_MVP_Priority_Explanation",
    "RANKED_RELATIVE_ONLY",
    "UNRANKABLE_MISSING_EVIDENCE",
    "MVP Priority",
    "Why?",
    "Download priority-ranked CSV",
    "Download priority report",
    "Download contextual analysis CSV",
    "Download method admission",
    "Immutable contextual analysis",
    "Organizational Risk remains NON_COMPUTABLE",
    "PREVIEW_ROW_LIMIT = 500",
    "PAGE_SIZE = 100",
    "parseCsvPreview",
    "response.body.getReader()",
    "reader.cancel()",
    "browser preview is deliberately bounded",
    "complete artifacts remain downloadable",
    "panel.rbvmPriorityPreviewRows = rows",
    "panel.rbvmPriorityPreviewRows = null",
    "CVSS4_Context_Score_Status",
    "CVSS4_Context_Nomenclature",
    "CVSS4_Context_Score",
    "CVSS4_Context_Severity",
    "EPSS_Probability",
    "KEV_Listed",
    "Asset_Criticality",
    "Internet_Facing",
    "Customer_Context_Status",
]
for token in required:
    if token not in UI:
        raise AssertionError(f"CSV run review missing {token}")

for forbidden in [
    "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
    "function customerBundle(",
    "querySelectorAll('details.panel')",
    "CVSS4_Base_Score *",
    "EPSS_Probability *",
    "riskScore",
    "priorityScore",
    "remediationSla",
    "localStorage",
    "sessionStorage",
    "contextResolver(",
    "joinRows(",
    "let loaded =",
]:
    if forbidden in UI:
        raise AssertionError(f"CSV run review contains retired/client-side decision or retention logic: {forbidden}")

if UI.count("method: 'POST'") < 2:
    raise AssertionError('finding review must create saved-bundle analysis and explicitly request server-side derived priority')
if "fetch(priority.priorityCsv" not in UI or "fetch(priority.priorityReport" not in UI or "fetch(run.methodAdmission" not in UI:
    raise AssertionError('finding review must consume server-generated priority and admission artifacts')
if "artifactButton('Download contextual analysis CSV', run.analysisCsv" not in UI:
    raise AssertionError('finding review must preserve access to the immutable contextual-analysis source artifact')
if "function priorityWhy(row)" not in UI or "el('details', {class: 'priority-explanation'}" not in UI:
    raise AssertionError('finding review must expose server-generated row explainability without client-side scoring')
if 'csv-run-review.js' not in COMPILE or 'cat "$ROOT_DIR/src/main/resources/web/csv-run-review.js"' not in COMPILE:
    raise AssertionError("runtime frontend bundle does not include csv-run-review.js")

print("CSV-first saved V4 immutable finding review + bounded preview checks: PASS")
