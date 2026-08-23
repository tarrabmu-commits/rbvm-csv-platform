#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
UI = (ROOT / "src/main/resources/web/csv-run-review.js").read_text(encoding="utf-8")
COMPILE = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")

required = [
    "CSV_FIRST_FINDING_REVIEW_UI_V3",
    "RBVM_CUSTOMER_ASSET_BUNDLE_V3",
    "CSV_FIRST_MVP_PRIORITY_HTTP_V1",
    "RBVM_MVP_PRIORITY_POLICY_V1",
    "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388",
    "Review Findings",
    "Finding Evidence Review — CSV Run",
    "/api/v1/csv-first-enrichments/",
    "/analyses",
    "/api/v1/csv-first-priorities/",
    "CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1",
    "run.immutable !== true",
    "run.analysisId",
    "priority.sourceAnalysisImmutable !== true",
    "priority.derivedArtifactsImmutable !== true",
    "priority.organizationalRisk !== 'NON_COMPUTABLE'",
    "priorityReport.organizationalRiskComputed !== false",
    "priorityReport.riskStatus !== 'NON_COMPUTABLE'",
    "RBVM_MVP_Priority_Status",
    "RBVM_MVP_Priority_Front",
    "RBVM_MVP_Priority_Blockers",
    "RANKED_RELATIVE_ONLY",
    "UNRANKABLE_MISSING_EVIDENCE",
    "MVP Priority",
    "Front 1 means nondominated treatment priority",
    "not Critical/High risk",
    "Download priority-ranked CSV",
    "Download priority report",
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
    "Download exact customer bundle",
    "Immutable contextual analysis",
    "Organizational Risk remains NON_COMPUTABLE",
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
    "text: 'Critical'",
    "text: 'High'",
]:
    if forbidden in UI:
        raise AssertionError(f"CSV run review contains forbidden client-side decision/join/persistence logic: {forbidden}")

if UI.count("method: 'POST'") < 2 or "'Content-Type': 'application/json; charset=utf-8'" not in UI:
    raise AssertionError('finding review must submit customer context and explicitly request server-side derived priority')
if "fetch(priority.priorityCsv" not in UI or "fetch(priority.priorityReport" not in UI or "fetch(run.methodAdmission" not in UI:
    raise AssertionError('finding review must consume server-generated priority and admission artifacts')
if "artifactButton('Download exact customer bundle', run.customerBundle" not in UI:
    raise AssertionError('finding review must expose the exact immutable customer bundle used by the analysis')
if "artifactButton('Download contextual analysis CSV', run.analysisCsv" not in UI:
    raise AssertionError('finding review must preserve access to the immutable contextual-analysis source artifact')
if 'csv-run-review.js' not in COMPILE or 'cat "$ROOT_DIR/src/main/resources/web/csv-run-review.js"' not in COMPILE:
    raise AssertionError("runtime frontend bundle does not include csv-run-review.js")

print("CSV-first immutable contextual finding review + MVP priority UI structural checks: PASS")
