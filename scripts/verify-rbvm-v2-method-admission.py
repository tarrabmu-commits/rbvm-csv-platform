#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/evaluate-rbvm-v2-method-candidates.py"
DOC = (ROOT / "docs/RBVM_V2_METHOD_ADMISSION_V1.md").read_text(encoding="utf-8")

for token in (
    "RBVM_V2_METHOD_ADMISSION_V1",
    "NO_V2_PRIMARY_METHOD_ADMITTED",
    "CVSS_V4_CONTEXTUAL_SEVERITY",
    "LEGACY_REFERENCE_ONLY",
    "BLOCKED_INPUT_CONTRACT",
    "Internet Facing` must not substitute for exact Finding/endpoint Reachability",
    "CR/IR/AR must not substitute for Business/Mission Impact evidence",
):
    if token not in DOC:
        raise AssertionError(f"V2 method admission document missing {token}")

with tempfile.TemporaryDirectory(prefix="rbvm-v2-admission-") as temp:
    temp = Path(temp)
    analysis = temp / "analysis.csv"
    report = temp / "report.json"
    headers = [
        "Agent", "CVE_ID",
        "CVSS4_Context_Score_Status", "CVSS4_Context_Nomenclature", "CVSS4_Context_Score",
        "EPSS_Probability", "KEV_Listed", "Customer_Context_Status",
        "Asset_Criticality", "Internet_Facing", "CVSS4_Environmental_Requirement_Status",
        "RBVM_V2_Status",
    ]
    with analysis.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerow({
            "Agent": "asset-a", "CVE_ID": "CVE-2026-10001",
            "CVSS4_Context_Score_Status": "CALCULATED_FIRST_REFERENCE_COMPATIBLE",
            "CVSS4_Context_Nomenclature": "CVSS-BTE", "CVSS4_Context_Score": "9.1",
            "EPSS_Probability": "0.42", "KEV_Listed": "true",
            "Customer_Context_Status": "MATCHED_KEY", "Asset_Criticality": "HIGH",
            "Internet_Facing": "YES", "CVSS4_Environmental_Requirement_Status": "COMPLETE",
            "RBVM_V2_Status": "NON_COMPUTABLE",
        })
        writer.writerow({
            "Agent": "asset-b", "CVE_ID": "CVE-2026-10002",
            "CVSS4_Context_Score_Status": "MISSING", "CVSS4_Context_Nomenclature": "",
            "CVSS4_Context_Score": "", "EPSS_Probability": "0.01", "KEV_Listed": "false",
            "Customer_Context_Status": "MATCHED_NAME", "Asset_Criticality": "LOW",
            "Internet_Facing": "NO", "CVSS4_Environmental_Requirement_Status": "NOT_DEFINED",
            "RBVM_V2_Status": "NON_COMPUTABLE",
        })

    subprocess.run(
        [sys.executable, str(SCRIPT), str(analysis), str(report)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    value = json.loads(report.read_text(encoding="utf-8"))

    if value["contractId"] != "RBVM_V2_METHOD_ADMISSION_REPORT_V1":
        raise AssertionError("admission report contract drift")
    if value["selection"] != {
        "reason": "No approved V2 Organizational Risk method identity is executable from the current CSV-first evidence contract.",
        "riskComputedRows": 0,
        "selectedMethodId": None,
        "selectedMethodSha256": None,
        "state": "NO_V2_PRIMARY_METHOD_ADMITTED",
    }:
        raise AssertionError("V2 method admission must not auto-select a risk method")

    candidates = {candidate.get("methodId") or "UNDEFINED_V2": candidate for candidate in value["candidates"]}
    if candidates["CVSS_V4_CONTEXTUAL_SEVERITY"]["admissionState"] != "NOT_A_RISK_METHOD":
        raise AssertionError("contextual CVSS must remain technical severity")
    if candidates["RBVM_FORMULA_V1"]["admissionState"] != "LEGACY_REFERENCE_ONLY":
        raise AssertionError("Formula V1 must remain immutable legacy reference for CSV-first V2")
    if candidates["OWASP_DERIVED_RBVM_V1"]["admissionState"] != "BLOCKED_INPUT_CONTRACT":
        raise AssertionError("OWASP-derived V1 must require exact Decision Input V3")
    if candidates["MICROSOFT_PD_DERIVED_RBVM_V1"]["admissionState"] != "BLOCKED_INPUT_CONTRACT":
        raise AssertionError("Microsoft-derived V1 must require exact Decision Input V3")
    if candidates["UNDEFINED_V2"]["admissionState"] != "METHOD_NOT_APPROVED":
        raise AssertionError("undefined Formula V2 must not become executable")

    capability = value["csvFirstCapability"]
    if capability["exactFindingReachability"] or capability["businessMissionImpact"] or capability["applicabilityEvidence"]:
        raise AssertionError("CSV-first capability must not fabricate missing evidence families")
    if not capability["contextualCvssV4TechnicalSeverity"]:
        raise AssertionError("CSV-first capability must recognize contextual CVSS v4")

    if value["evidenceCoverage"]["contextualCvssCalculatedRows"] != 1:
        raise AssertionError("contextual CVSS coverage count drift")
    if value["evidenceCoverage"]["kevObservedRows"] != 2:
        raise AssertionError("KEV observed state coverage drift")
    if value["evidenceCoverage"]["rbvmV2NonComputableRows"] != 2:
        raise AssertionError("V2 non-computable coverage drift")
    if not value.get("reportSha256") or len(value["reportSha256"]) != 64:
        raise AssertionError("admission report must be SHA-bound")

print("RBVM V2 risk-method admission verification: PASS")
