#!/usr/bin/env python3
"""Golden verification for active and legacy CSV-first risk methods."""
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
ACTIVE_METHODS = ROOT / "docs/fixtures/csv-first-risk-methods-active"
LEGACY_METHODS = ROOT / "docs/fixtures/csv-first-risk-methods"

ACTIVE_SHA = {
    "RBVM_CSV_BOUNDED_RISK_V2.json":
        "fb0ccafd51df21baebf709fcee137d1db212a36d7cfe90242f71c4e3f0385947",
    "JUPITERONE_STYLE_CSV_V2.json":
        "26d132aee325b80985746ba7bd9c4acb554bb59cd6daf8a36c5926c489add5ec",
    "SERVICENOW_STYLE_CSV_V1.json":
        "ad73605f0f24d7303cf6fa2eafb0724460ca98c2edd766db07efe134a9e5be7d",
    "BRINQA_STYLE_CSV_V1.json":
        "d3e2385226e8d9c65a9e4c33b2ca541822563e0795f49c4a971e5af00520deb3",
}
LEGACY_SHA = {
    "RBVM_CSV_BOUNDED_RISK_V1.json":
        "f4c3b8c3aed6c68b2767caefa7a70e49f968ad00e6fa91f3a4ed397fadc1b0e1",
    "JUPITERONE_STYLE_CSV_V1.json":
        "27521ffbabb17e3b7c74f212e5bc7e6781e8b8d1c58c30ec4194386b6af02fd6",
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


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def row_for(rows: list[dict[str, str]], cve: str) -> dict[str, str]:
    return next(row for row in rows if row["CVE_ID"] == cve)


def assert_close(actual: str, expected: float, tolerance: float = 1e-6) -> None:
    value = float(actual)
    if abs(value - expected) > tolerance:
        raise AssertionError(f"expected {expected}, got {value}")


def verify_fixture_set(directory: Path, expected: dict[str, str], exact: bool) -> None:
    if not directory.is_dir():
        raise AssertionError(f"missing risk method directory: {directory}")
    actual_files = sorted(path.name for path in directory.glob("*.json") if path.is_file() and not path.is_symlink())
    if exact and actual_files != sorted(expected):
        raise AssertionError(f"active method catalog drift: {actual_files}")
    for name, expected_sha in expected.items():
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise AssertionError(f"missing risk method fixture: {name}")
        actual_sha = file_sha(path)
        if actual_sha != expected_sha:
            raise AssertionError(f"fixture SHA drift for {name}: {actual_sha}")
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("contractId") != "CSV_FIRST_RISK_METHOD_DEFINITION_V1":
            raise AssertionError(f"unexpected method contract for {name}")


def evaluate_fixture(directory: Path, fixture: str, analysis: Path, output_dir: Path) -> tuple[list[dict[str, str]], dict]:
    method = directory / fixture
    method_id = json.loads(method.read_text(encoding="utf-8"))["methodId"]
    risk_csv = output_dir / f"{method_id}.csv"
    report = output_dir / f"{method_id}.json"
    run("evaluate", str(analysis), str(method), str(risk_csv), str(report))
    return read_csv(risk_csv), json.loads(report.read_text(encoding="utf-8"))


def main() -> None:
    if not EVALUATOR.is_file():
        raise AssertionError("CSV-first risk evaluator is missing")

    verify_fixture_set(ACTIVE_METHODS, ACTIVE_SHA, exact=True)
    verify_fixture_set(LEGACY_METHODS, LEGACY_SHA, exact=False)

    base_rows = [
        {
            "CVE_ID": "CVE-2026-0001", "Agent": "a1",
            "CVSS4_Base_Score_Calculated": "8.8", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.005", "EPSS_Percentile": "0.4075",
            "KEV_Listed": "false", "Asset_Criticality": "MISSION_CRITICAL",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            # Duplicate observation for the same asset+CVE must not inflate occurrence.
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
            # V2 RBVM must compute without Publicly_Exposed when Internet_Facing is present.
            "CVE_ID": "CVE-2026-0003", "Agent": "a4",
            "CVSS4_Base_Score_Calculated": "6.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.20", "EPSS_Percentile": "0.70",
            "KEV_Listed": "true", "Asset_Criticality": "HIGH",
            "Internet_Facing": "YES", "Publicly_Exposed": "",
        },
        {
            # Neutral EPSS baseline.
            "CVE_ID": "CVE-2026-0004", "Agent": "a5",
            "CVSS4_Base_Score_Calculated": "5.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.03", "EPSS_Percentile": "0.50",
            "KEV_Listed": "false", "Asset_Criticality": "MODERATE",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            # Missing Internet_Facing must block V2 RBVM rather than impute NO.
            "CVE_ID": "CVE-2026-0005", "Agent": "a6",
            "CVSS4_Base_Score_Calculated": "7.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.03", "EPSS_Percentile": "0.60",
            "KEV_Listed": "false", "Asset_Criticality": "HIGH",
            "Internet_Facing": "", "Publicly_Exposed": "NO",
        },
    ]

    with tempfile.TemporaryDirectory(prefix="rbvm-risk-verify-") as temporary:
        directory = Path(temporary)
        analysis = directory / "analysis.csv"
        write_csv(analysis, base_rows)

        readiness = directory / "readiness.json"
        run("readiness", str(analysis), str(ACTIVE_METHODS), str(readiness))
        readiness_value = json.loads(readiness.read_text(encoding="utf-8"))
        method_ids = [value["methodId"] for value in readiness_value["methods"]]
        expected_ids = [
            "BRINQA_STYLE_CSV_V1",
            "JUPITERONE_STYLE_CSV_V2",
            "RBVM_CSV_BOUNDED_RISK_V2",
            "SERVICENOW_STYLE_CSV_V1",
        ]
        if method_ids != expected_ids:
            raise AssertionError(f"active readiness catalog must contain exactly four methods: {method_ids}")
        if readiness_value["scope"]["distinctAssets"] != 6:
            raise AssertionError("CSV population must be six distinct assets")

        rbvm_rows, _ = evaluate_fixture(ACTIVE_METHODS, "RBVM_CSV_BOUNDED_RISK_V2.json", analysis, directory)
        rbvm_public_missing = row_for(rbvm_rows, "CVE-2026-0003")
        if rbvm_public_missing["Risk_Status"] != "COMPUTED":
            raise AssertionError("RBVM V2 must use Internet Facing and must not require Publicly Exposed")
        rbvm_baseline = row_for(rbvm_rows, "CVE-2026-0004")
        if rbvm_baseline["Risk_Status"] != "COMPUTED":
            raise AssertionError("RBVM V2 baseline row should compute")
        baseline_explanation = json.loads(rbvm_baseline["Risk_Explanation_JSON"])
        assert_close(str(baseline_explanation["z"]), 0.0)
        rbvm_missing_internet = row_for(rbvm_rows, "CVE-2026-0005")
        if rbvm_missing_internet["Risk_Status"] != "NON_COMPUTABLE":
            raise AssertionError("RBVM V2 must block missing Internet Facing")
        if "INTERNET_FACING_MISSING_OR_INVALID" not in rbvm_missing_internet["Risk_Blockers"]:
            raise AssertionError("RBVM V2 missing Internet Facing blocker is absent")

        brinqa_rows, _ = evaluate_fixture(ACTIVE_METHODS, "BRINQA_STYLE_CSV_V1.json", analysis, directory)
        assert_close(row_for(brinqa_rows, "CVE-2026-0001")["Risk_Score"], 7.8)
        service_rows, _ = evaluate_fixture(ACTIVE_METHODS, "SERVICENOW_STYLE_CSV_V1.json", analysis, directory)
        assert_close(row_for(service_rows, "CVE-2026-0002")["Risk_Score"], 62.0)

        # Separate 100-asset corpus makes the requested JupiterOne-style x10 prevalence observable.
        prevalence_rows = []
        for index in range(1, 101):
            prevalence_rows.append({
                "CVE_ID": "CVE-2026-0100" if index == 1 else f"CVE-2026-{1000 + index}",
                "Agent": f"asset-{index:03d}",
                "CVSS4_Base_Score_Calculated": "8.8",
                "CVSS4_Base_Score": "",
                "EPSS_Probability": "0.005",
                "EPSS_Percentile": "0.4075",
                "KEV_Listed": "false",
                "Asset_Criticality": "MODERATE",
                "Internet_Facing": "NO",
                "Publicly_Exposed": "NO",
            })
        prevalence = directory / "prevalence.csv"
        write_csv(prevalence, prevalence_rows)
        jupiter_rows, jupiter_report = evaluate_fixture(
            ACTIVE_METHODS, "JUPITERONE_STYLE_CSV_V2.json", prevalence, directory)
        jupiter = row_for(jupiter_rows, "CVE-2026-0100")
        assert_close(jupiter["Risk_Score"], 0.49532)
        explanation = json.loads(jupiter["Risk_Explanation_JSON"])
        if explanation["affectedAssets"] != 1 or explanation["csvDistinctAssets"] != 100:
            raise AssertionError("JupiterOne V2 prevalence must use one of one hundred distinct CSV assets")
        assert_close(str(explanation["occurrenceRatio"]), 0.01)
        assert_close(str(explanation["occurrenceMultiplier"]), 10.0)
        assert_close(str(explanation["occurrenceComponent"]), 0.1)
        if jupiter_report["scope"]["distinctAssets"] != 100:
            raise AssertionError("JupiterOne V2 report must preserve the exact CSV population scope")

        # Legacy fixtures remain executable by explicit immutable identity for historical replay.
        legacy_rbvm_rows, _ = evaluate_fixture(
            LEGACY_METHODS, "RBVM_CSV_BOUNDED_RISK_V1.json", analysis, directory)
        legacy_missing = row_for(legacy_rbvm_rows, "CVE-2026-0003")
        if legacy_missing["Risk_Status"] != "NON_COMPUTABLE":
            raise AssertionError("legacy RBVM V1 semantics must remain unchanged")
        if "PUBLICLY_EXPOSED_MISSING_OR_INVALID" not in legacy_missing["Risk_Blockers"]:
            raise AssertionError("legacy RBVM V1 Publicly Exposed blocker must remain unchanged")

    print("CSV-first active V2 risk methods + legacy replay verification: PASS")


if __name__ == "__main__":
    main()
