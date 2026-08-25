#!/usr/bin/env python3
"""Verify deterministic descriptive comparison of the four active CSV-first risk methods."""
from __future__ import annotations

import csv
import importlib.util
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "scripts" / "benchmark-csv-first-risk-methods.py"
METHODS = ROOT / "docs" / "fixtures" / "csv-first-risk-methods-active"
EXPECTED = {
    "RBVM_CSV_BOUNDED_RISK_V3",
    "JUPITERONE_STYLE_CSV_V2",
    "SERVICENOW_STYLE_CSV_V1",
    "BRINQA_STYLE_CSV_V1",
}


def load_benchmark_module():
    spec = importlib.util.spec_from_file_location("csv_first_risk_benchmark", BENCHMARK)
    if spec is None or spec.loader is None:
        raise AssertionError("benchmark module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_rows():
    return [
        ["a1", "CVE-2026-0001", "pkg-a", "9.5", "0.80", "0.99", "LISTED", "MISSION_CRITICAL", "YES"],
        ["a2", "CVE-2026-0001", "pkg-a", "9.5", "0.80", "0.99", "LISTED", "HIGH", "NO"],
        ["a3", "CVE-2026-0002", "pkg-b", "7.5", "0.20", "0.80", "NOT_LISTED", "HIGH", "YES"],
        ["a4", "CVE-2026-0003", "pkg-c", "6.0", "0.05", "0.60", "NOT_LISTED", "MODERATE", "NO"],
        ["a5", "CVE-2026-0004", "pkg-d", "4.0", "0.01", "0.30", "NOT_LISTED", "LOW", "NO"],
        ["a1", "CVE-2026-0005", "pkg-e", "8.0", "0.02", "0.50", "NOT_LISTED", "MISSION_CRITICAL", "YES"],
        ["a2", "CVE-2026-0006", "pkg-f", "5.0", "0.03", "0.40", "NOT_LISTED", "MODERATE", "YES"],
        ["a3", "CVE-2026-0007", "pkg-g", "9.0", "0.50", "0.95", "LISTED", "", "YES"],
        ["a4", "CVE-2026-0008", "pkg-h", "3.0", "", "0.20", "NOT_LISTED", "LOW", "NO"],
    ]


def write_analysis(path):
    headers = [
        "Agent",
        "CVE_ID",
        "Affected_Product",
        "CVSS4_Base_Score_Calculated",
        "EPSS_Probability",
        "EPSS_Percentile",
        "KEV_Listed",
        "Asset_Criticality",
        "Internet_Facing",
    ]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(synthetic_rows())


def assert_no_decision_semantics(value):
    forbidden_keys = {"winner", "recommendedMethod", "selectedMethod", "primaryMethod", "normalizedScore", "averageScore"}
    if isinstance(value, dict):
        assert not (set(value) & forbidden_keys), f"benchmark leaked decision semantics: {set(value) & forbidden_keys}"
        for child in value.values():
            assert_no_decision_semantics(child)
    elif isinstance(value, list):
        for child in value:
            assert_no_decision_semantics(child)


def main():
    module = load_benchmark_module()
    assert math.isclose(module.kendall_tau_b([1, 2, 3], [1, 2, 3]), 1.0)
    assert math.isclose(module.kendall_tau_b([1, 2, 3], [3, 2, 1]), -1.0)
    assert math.isclose(module.kendall_tau_b([1, 1, 2], [1, 2, 2]), 0.5)
    assert math.isclose(module.spearman([1, 2, 3], [1, 2, 3]), 1.0)
    assert math.isclose(module.spearman([1, 2, 3], [3, 2, 1]), -1.0)

    with tempfile.TemporaryDirectory(prefix="rbvm-risk-benchmark-") as directory:
        base = Path(directory)
        analysis = base / "analysis.csv"
        first = base / "benchmark-a.json"
        second = base / "benchmark-b.json"
        write_analysis(analysis)

        command = [sys.executable, str(BENCHMARK), str(analysis), str(METHODS)]
        subprocess.run(command + [str(first)], cwd=ROOT, check=True, capture_output=True, text=True)
        subprocess.run(command + [str(second)], cwd=ROOT, check=True, capture_output=True, text=True)
        assert first.read_bytes() == second.read_bytes(), "benchmark output must be byte-for-byte deterministic"

        report = json.loads(first.read_text(encoding="utf-8"))
        assert report["contractId"] == "CSV_FIRST_RISK_METHOD_BENCHMARK_V1"
        assert report["semantics"] == "DESCRIPTIVE_COMPARISON_ONLY_NO_METHOD_SELECTION_NO_SCORE_NORMALIZATION_NO_AVERAGING"
        assert report["scope"]["findingRows"] == 9
        assert report["scope"]["uniqueCves"] == 8
        assert report["scope"]["csvDistinctAssets"] == 5
        assert report["scope"]["missingAssetIdentityRows"] == 0
        assert len(report["sourceAnalysisSha256"]) == 64

        methods = {entry["methodId"]: entry for entry in report["methods"]}
        assert set(methods) == EXPECTED
        assert methods["JUPITERONE_STYLE_CSV_V2"]["computedRows"] == 9
        assert methods["JUPITERONE_STYLE_CSV_V2"]["nonComputableRows"] == 0
        for method_id in EXPECTED - {"JUPITERONE_STYLE_CSV_V2"}:
            assert methods[method_id]["computedRows"] == 7, method_id
            assert methods[method_id]["nonComputableRows"] == 2, method_id
            blockers = methods[method_id]["blockers"]
            assert blockers.get("ASSET_CRITICALITY_MISSING_OR_INVALID") == 1, (method_id, blockers)
            assert blockers.get("EPSS_PROBABILITY_MISSING_OR_INVALID") == 1, (method_id, blockers)

        assert len(report["pairwise"]) == 6
        for pair in report["pairwise"]:
            assert pair["commonComputedRows"] == 7
            assert pair["spearmanRankCorrelation"] is None or -1.0 <= pair["spearmanRankCorrelation"] <= 1.0
            assert pair["kendallTauB"] is None or -1.0 <= pair["kendallTauB"] <= 1.0
            assert set(pair["topOverlap"]) == {"10", "50", "100"}
            assert pair["topOverlap"]["10"]["effectiveK"] == 7
            assert len(pair["largestRankDisagreements"]) <= 7
            for disagreement in pair["largestRankDisagreements"]:
                assert 1 <= disagreement["analysisRow"] <= 9
                assert 0.0 <= disagreement["rankPercentileGap"] <= 1.0

        rbvm_slices = methods["RBVM_CSV_BOUNDED_RISK_V3"]["evidenceSlices"]
        assert rbvm_slices["kev"]["LISTED"]["rows"] == 3
        assert rbvm_slices["internetFacing"]["YES"]["rows"] == 5
        assert rbvm_slices["assetCriticality"]["UNKNOWN"]["rows"] == 1
        assert rbvm_slices["epssBand"]["UNKNOWN"]["rows"] == 1

        semantics = report["comparisonSemantics"]
        assert semantics["pairwisePopulation"] == "INTERSECTION_OF_ROWS_COMPUTABLE_BY_BOTH_METHODS"
        assert semantics["nativeScores"] == "PRESERVED_NOT_NORMALIZED_ACROSS_METHODS"
        assert_no_decision_semantics(report)

    print("CSV-first risk benchmark verification: PASS")


if __name__ == "__main__":
    main()
