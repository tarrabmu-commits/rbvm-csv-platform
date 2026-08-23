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
FIXTURE = ROOT / "testdata/rbvm-mvp-priority-golden.csv"
EXPECTED_SHA = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"

EXPECTED = {
    "A_KNOWN_EXPLOITED_STRONG_CONTEXT": ("RANKED_RELATIVE_ONLY", "1"),
    "B_HIGHER_PROBABILITY_NO_KEV": ("RANKED_RELATIVE_ONLY", "1"),
    "C_KEV_BUT_LOWER_CONTEXT": ("RANKED_RELATIVE_ONLY", "2"),
    "D_DOMINATED_BASELINE": ("RANKED_RELATIVE_ONLY", "3"),
    "E_MISSING_CUSTOMER_EXPOSURE": ("UNRANKABLE_MISSING_EVIDENCE", ""),
    "F_MAX_TECHNICAL_TRADEOFF": ("RANKED_RELATIVE_ONLY", "1"),
}


def run(source: Path, directory: Path, stem: str):
    ranked = directory / f"{stem}.csv"
    report = directory / f"{stem}.json"
    subprocess.run(
        [sys.executable, str(SCRIPT), str(source), str(ranked), str(report)],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    with ranked.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    return rows, json.loads(report.read_text(encoding="utf-8"))


def keyed(rows):
    return {row["Golden_Case_ID"]: row for row in rows}


if not FIXTURE.is_file():
    raise AssertionError("MVP priority golden fixture is missing")

with tempfile.TemporaryDirectory(prefix="rbvm-mvp-golden-") as temp_value:
    temp = Path(temp_value)
    normal_rows, normal_report = run(FIXTURE, temp, "normal")
    normal = keyed(normal_rows)

    if set(normal) != set(EXPECTED):
        raise AssertionError("golden case identity set drift")

    for case_id, (expected_status, expected_front) in EXPECTED.items():
        row = normal[case_id]
        if row["RBVM_MVP_Priority_Status"] != expected_status:
            raise AssertionError(f"{case_id} status drift: {row['RBVM_MVP_Priority_Status']}")
        if row["RBVM_MVP_Priority_Front"] != expected_front:
            raise AssertionError(f"{case_id} front drift: {row['RBVM_MVP_Priority_Front']}")
        if row["RBVM_MVP_Priority_Method_SHA256"] != EXPECTED_SHA:
            raise AssertionError(f"{case_id} method SHA drift")
        explanation = row.get("RBVM_MVP_Priority_Explanation", "")
        if expected_status == "RANKED_RELATIVE_ONLY":
            if f"Front {expected_front}:" not in explanation:
                raise AssertionError(f"{case_id} ranked explanation drift")
            if "not Organizational Risk or an SLA" not in explanation:
                raise AssertionError(f"{case_id} explanation lost risk boundary")
        else:
            if "customer Internet Facing" not in explanation:
                raise AssertionError(f"{case_id} missing-evidence explanation drift")
            if "INTERNET_FACING_MISSING_OR_INVALID" not in row["RBVM_MVP_Priority_Blockers"]:
                raise AssertionError(f"{case_id} blocker drift")

    if normal_report.get("frontCounts") != {"1": 3, "2": 1, "3": 1}:
        raise AssertionError(f"golden front counts drift: {normal_report.get('frontCounts')}")
    if normal_report.get("rankedRows") != 5 or normal_report.get("unrankableRows") != 1:
        raise AssertionError("golden rankability counts drift")
    if normal_report.get("riskStatus") != "NON_COMPUTABLE" or normal_report.get("organizationalRiskComputed") is not False:
        raise AssertionError("golden benchmark must not compute Organizational Risk")
    if normal_report.get("explainability", {}).get("contractId") != "RBVM_MVP_PRIORITY_EXPLAINABILITY_V1":
        raise AssertionError("golden explainability contract drift")

    with FIXTURE.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
        reversed_rows = list(reversed(list(reader)))
    reversed_source = temp / "reversed-input.csv"
    with reversed_source.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers)
        writer.writeheader()
        writer.writerows(reversed_rows)

    reversed_output, _ = run(reversed_source, temp, "reversed")
    reversed_by_id = keyed(reversed_output)
    for case_id in EXPECTED:
        left = normal[case_id]
        right = reversed_by_id[case_id]
        for column in (
            "RBVM_MVP_Priority_Status",
            "RBVM_MVP_Priority_Front",
            "RBVM_MVP_Priority_Dominated_By",
            "RBVM_MVP_Priority_Dominates",
            "RBVM_MVP_Priority_Blockers",
            "RBVM_MVP_Priority_Explanation",
            "RBVM_MVP_Priority_Method_SHA256",
        ):
            if left[column] != right[column]:
                raise AssertionError(f"row-order dependence detected for {case_id} / {column}")

print("RBVM MVP priority golden benchmark: PASS")
