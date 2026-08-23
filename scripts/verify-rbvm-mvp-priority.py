#!/usr/bin/env python3
from __future__ import annotations

import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/rank-rbvm-mvp-priority.py"
DOC = (ROOT / "docs/RBVM_MVP_PRIORITY_POLICY_V1.md").read_text(encoding="utf-8")
EXPECTED_SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"

for token in (
    "RBVM_MVP_PRIORITY_POLICY_V1",
    EXPECTED_SHA,
    "relative treatment priority",
    "weights = []",
    "thresholds = []",
    "Organizational Risk = NON_COMPUTABLE",
    "UNRANKABLE_MISSING_EVIDENCE",
    "Internet Facing = exact Reachability",
):
    if token not in DOC:
        raise AssertionError(f"MVP priority policy document missing {token}")

with tempfile.TemporaryDirectory(prefix="rbvm-mvp-priority-") as temp:
    temp = Path(temp)
    source = temp / "analysis.csv"
    ranked = temp / "ranked.csv"
    report = temp / "report.json"
    headers = [
        "Agent", "CVE_ID", "KEV_Listed", "Internet_Facing",
        "Asset_Criticality", "EPSS_Probability", "CVSS4_Context_Score",
        "RBVM_V2_Status",
    ]
    rows = [
        {
            "Agent": "asset-a", "CVE_ID": "CVE-2026-10001",
            "KEV_Listed": "true", "Internet_Facing": "YES",
            "Asset_Criticality": "HIGH", "EPSS_Probability": "0.40",
            "CVSS4_Context_Score": "8.0", "RBVM_V2_Status": "NON_COMPUTABLE",
        },
        {
            "Agent": "asset-b", "CVE_ID": "CVE-2026-10002",
            "KEV_Listed": "false", "Internet_Facing": "NO",
            "Asset_Criticality": "MODERATE", "EPSS_Probability": "0.20",
            "CVSS4_Context_Score": "7.0", "RBVM_V2_Status": "NON_COMPUTABLE",
        },
        {
            "Agent": "asset-c", "CVE_ID": "CVE-2026-10003",
            "KEV_Listed": "false", "Internet_Facing": "YES",
            "Asset_Criticality": "MISSION_CRITICAL", "EPSS_Probability": "0.90",
            "CVSS4_Context_Score": "9.5", "RBVM_V2_Status": "NON_COMPUTABLE",
        },
        {
            "Agent": "asset-d", "CVE_ID": "CVE-2026-10004",
            "KEV_Listed": "false", "Internet_Facing": "UNKNOWN",
            "Asset_Criticality": "LOW", "EPSS_Probability": "0.01",
            "CVSS4_Context_Score": "4.0", "RBVM_V2_Status": "NON_COMPUTABLE",
        },
    ]
    with source.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(rows)

    subprocess.run(
        [sys.executable, str(SCRIPT), str(source), str(ranked), str(report)],
        check=True,
        stdout=subprocess.DEVNULL,
    )

    with ranked.open("r", encoding="utf-8", newline="") as handle:
        output = list(csv.DictReader(handle))
    by_agent = {row["Agent"]: row for row in output}

    if by_agent["asset-a"]["RBVM_MVP_Priority_Front"] != "1":
        raise AssertionError("asset-a must be nondominated front 1")
    if by_agent["asset-c"]["RBVM_MVP_Priority_Front"] != "1":
        raise AssertionError("asset-c must be nondominated front 1 due to tradeoff with KEV")
    if by_agent["asset-b"]["RBVM_MVP_Priority_Front"] != "2":
        raise AssertionError("asset-b must be dominated and placed in front 2")
    if by_agent["asset-a"]["RBVM_MVP_Priority_Dominates"] != "1":
        raise AssertionError("asset-a must dominate asset-b only")
    if by_agent["asset-d"]["RBVM_MVP_Priority_Status"] != "UNRANKABLE_MISSING_EVIDENCE":
        raise AssertionError("missing customer exposure must remain unrankable")
    if "INTERNET_FACING_MISSING_OR_INVALID" not in by_agent["asset-d"]["RBVM_MVP_Priority_Blockers"]:
        raise AssertionError("missing Internet Facing blocker must be explicit")
    if any(row["RBVM_MVP_Priority_Method_SHA256"] != EXPECTED_SHA for row in output):
        raise AssertionError("every ranked output row must bind the exact method SHA")
    if any(row["RBVM_V2_Status"] != "NON_COMPUTABLE" for row in output):
        raise AssertionError("priority policy must not mutate Organizational Risk status")

    value = json.loads(report.read_text(encoding="utf-8"))
    if value["contractId"] != "RBVM_MVP_PRIORITY_REPORT_V1":
        raise AssertionError("priority report contract drift")
    if value["methodId"] != "RBVM_MVP_PRIORITY_POLICY_V1" or value["methodSha256"] != EXPECTED_SHA:
        raise AssertionError("priority policy identity drift")
    if value["organizationalRiskComputed"] is not False or value["riskStatus"] != "NON_COMPUTABLE":
        raise AssertionError("priority report must not claim Organizational Risk")
    if value["rankedRows"] != 3 or value["unrankableRows"] != 1:
        raise AssertionError("priority coverage counts drift")
    if value["frontCounts"] != {"1": 2, "2": 1}:
        raise AssertionError("Pareto front counts drift")
    canonical = value["canonicalRepresentation"]
    if canonical["weights"] != [] or canonical["thresholds"] != []:
        raise AssertionError("MVP priority policy must remain weight-free and threshold-free")
    if not value.get("reportSha256") or len(value["reportSha256"]) != 64:
        raise AssertionError("priority report must be SHA-bound")

print("RBVM MVP priority policy verification: PASS")
