#!/usr/bin/env python3
"""Golden verification for the CSV-first risk-method layer."""

from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "scripts/evaluate-csv-first-risk.py"
METHODS = ROOT / "docs/fixtures/csv-first-risk-methods"

EXPECTED_SHA = {
    "RBVM_CSV_BOUNDED_RISK_V1.json":
        "f4c3b8c3aed6c68b2767caefa7a70e49f968ad00e6fa91f3a4ed397fadc1b0e1",
    "JUPITERONE_STYLE_CSV_V1.json":
        "27521ffbabb17e3b7c74f212e5bc7e6781e8b8d1c58c30ec4194386b6af02fd6",
    "SERVICENOW_STYLE_CSV_V1.json":
        "ad73605f0f24d7303cf6fa2eafb0724460ca98c2edd766db07efe134a9e5be7d",
    "BRINQA_STYLE_CSV_V1.json":
        "d3e2385226e8d9c65a9e4c33b2ca541822563e0795f49c4a971e5af00520deb3",
}


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(*args: str) -> None:
    subprocess.run(
        [sys.executable, str(EVALUATOR), *args],
        check=True,
        capture_output=True,
        text=True,
    )


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def row_for(rows: list[dict[str, str]], cve: str) -> dict[str, str]:
    return next(row for row in rows if row["CVE_ID"] == cve)


def assert_close(actual: str, expected: float, tolerance: float = 1e-6) -> None:
    value = float(actual)
    if abs(value - expected) > tolerance:
        raise AssertionError(f"expected {expected}, got {value}")


def main() -> None:
    if not EVALUATOR.is_file():
        raise AssertionError("CSV-first risk evaluator is missing")

    for name, expected in EXPECTED_SHA.items():
        path = METHODS / name
        if not path.is_file():
            raise AssertionError(f"missing risk method fixture: {name}")
        actual = file_sha(path)
        if actual != expected:
            raise AssertionError(f"fixture SHA drift for {name}: {actual}")
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("contractId") != "CSV_FIRST_RISK_METHOD_DEFINITION_V1":
            raise AssertionError(f"unexpected method contract for {name}")

    rows = [
        {
            "CVE_ID": "CVE-2026-0001", "Agent": "a1",
            "CVSS4_Base_Score_Calculated": "8.8", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.005", "EPSS_Percentile": "0.4075",
            "KEV_Listed": "false", "Asset_Criticality": "MISSION_CRITICAL",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            # Duplicate observation for the same asset+CVE must not inflate Jupiter occurrence.
            "CVE_ID": "CVE-2026-0001", "Agent": "a1",
            "CVSS4_Base_Score_Calculated": "8.8", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.005", "EPSS_Percentile": "0.4075",
            "KEV_Listed": "false", "Asset_Criticality": "MISSION_CRITICAL",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            "CVE_ID": "CVE-2026-0001", "Agent": "a2",
            "CVSS4_Base_Score_Calculated": "8.8", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.005", "EPSS_Percentile": "0.4075",
            "KEV_Listed": "false", "Asset_Criticality": "MISSION_CRITICAL",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            "CVE_ID": "CVE-2026-0002", "Agent": "a3",
            "CVSS4_Base_Score_Calculated": "8.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.40", "EPSS_Percentile": "0.80",
            "KEV_Listed": "false", "Asset_Criticality": "HIGH",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            "CVE_ID": "CVE-2026-0003", "Agent": "a4",
            "CVSS4_Base_Score_Calculated": "6.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.20", "EPSS_Percentile": "0.70",
            "KEV_Listed": "true", "Asset_Criticality": "HIGH",
            "Internet_Facing": "YES", "Publicly_Exposed": "",
        },
        {
            "CVE_ID": "CVE-2026-0004", "Agent": "a5",
            "CVSS4_Base_Score_Calculated": "5.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.03", "EPSS_Percentile": "0.50",
            "KEV_Listed": "false", "Asset_Criticality": "MODERATE",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
    ]

    with tempfile.TemporaryDirectory(prefix="rbvm-risk-verify-") as temporary:
        directory = Path(temporary)
        analysis = directory / "analysis.csv"
        with analysis.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)

        readiness = directory / "readiness.json"
        run("readiness", str(analysis), str(METHODS), str(readiness))
        readiness_value = json.loads(readiness.read_text(encoding="utf-8"))
        if readiness_value["scope"]["distinctAssets"] != 5:
            raise AssertionError("CSV population must be five distinct assets")

        outputs = {}
        for fixture in EXPECTED_SHA:
            method = METHODS / fixture
            method_id = json.loads(method.read_text(encoding="utf-8"))["methodId"]
            risk_csv = directory / f"{method_id}.csv"
            report = directory / f"{method_id}.json"
            run("evaluate", str(analysis), str(method), str(risk_csv), str(report))
            outputs[method_id] = read_csv(risk_csv)

        jupiter = row_for(outputs["JUPITERONE_STYLE_CSV_V1"], "CVE-2026-0001")
        assert_close(jupiter["Risk_Score"], 0.69532)
        explanation = json.loads(jupiter["Risk_Explanation_JSON"])
        if explanation["affectedAssets"] != 2 or explanation["csvDistinctAssets"] != 5:
            raise AssertionError("Jupiter occurrence must use distinct CSV assets")

        brinqa = row_for(outputs["BRINQA_STYLE_CSV_V1"], "CVE-2026-0001")
        assert_close(brinqa["Risk_Score"], 7.8)

        servicenow = row_for(outputs["SERVICENOW_STYLE_CSV_V1"], "CVE-2026-0002")
        assert_close(servicenow["Risk_Score"], 62.0)

        rbvm_missing = row_for(outputs["RBVM_CSV_BOUNDED_RISK_V1"], "CVE-2026-0003")
        if rbvm_missing["Risk_Status"] != "NON_COMPUTABLE":
            raise AssertionError("RBVM must not impute missing Publicly Exposed evidence")
        if "PUBLICLY_EXPOSED_MISSING_OR_INVALID" not in rbvm_missing["Risk_Blockers"]:
            raise AssertionError("RBVM missing-evidence blocker is absent")

        rbvm_baseline = row_for(outputs["RBVM_CSV_BOUNDED_RISK_V1"], "CVE-2026-0004")
        if rbvm_baseline["Risk_Status"] != "COMPUTED":
            raise AssertionError("RBVM baseline row should compute")
        explanation = json.loads(rbvm_baseline["Risk_Explanation_JSON"])
        assert_close(str(explanation["z"]), 0.0)

    print("CSV-first risk methods verification: PASS")


if __name__ == "__main__":
    main()
