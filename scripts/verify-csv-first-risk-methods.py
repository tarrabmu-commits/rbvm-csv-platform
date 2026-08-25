#!/usr/bin/env python3
"""Golden verification for active and legacy CSV-first risk methods."""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVALUATOR = ROOT / "scripts/evaluate-csv-first-risk.py"
ACTIVE_METHODS = ROOT / "docs/fixtures/csv-first-risk-methods-active"
LEGACY_METHODS = ROOT / "docs/fixtures/csv-first-risk-methods"

ACTIVE_SHA = {
    "RBVM_CSV_BOUNDED_RISK_V3.json":
        "190d1da1d8703057f594fd2419bc00c0601d71e2b3f9320781feda21b828bb5b",
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
    "RBVM_CSV_BOUNDED_RISK_V2.json":
        "fb0ccafd51df21baebf709fcee137d1db212a36d7cfe90242f71c4e3f0385947",
    "JUPITERONE_STYLE_CSV_V1.json":
        "27521ffbabb17e3b7c74f212e5bc7e6781e8b8d1c58c30ec4194386b6af02fd6",
}
RATING_SEMANTICS = "PRESENTATION_ONLY_NOT_PRIORITY_SLA_OR_TREATMENT"


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


def assert_non_decreasing(values: list[float], label: str) -> None:
    for left, right in zip(values, values[1:]):
        if right + 1e-6 < left:
            raise AssertionError(f"{label} is not monotonic: {values}")


def verify_fixture_set(directory: Path, expected: dict[str, str], exact: bool) -> None:
    if not directory.is_dir():
        raise AssertionError(f"missing risk method directory: {directory}")
    actual_files = sorted(
        path.name
        for path in directory.glob("*.json")
        if path.is_file() and not path.is_symlink()
    )
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


def evaluate_fixture(
    directory: Path,
    fixture: str,
    analysis: Path,
    output_dir: Path,
    suffix: str = "",
) -> tuple[list[dict[str, str]], dict]:
    method = directory / fixture
    method_id = json.loads(method.read_text(encoding="utf-8"))["methodId"]
    risk_csv = output_dir / f"{method_id}{suffix}.csv"
    report = output_dir / f"{method_id}{suffix}.json"
    run("evaluate", str(analysis), str(method), str(risk_csv), str(report))
    return read_csv(risk_csv), json.loads(report.read_text(encoding="utf-8"))


def base_rows() -> list[dict[str, str]]:
    return [
        {
            "CVE_ID": "CVE-2026-0001", "Agent": "a1",
            "CVSS4_Base_Score_Calculated": "8.8", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.005", "EPSS_Percentile": "0.4075",
            "KEV_Listed": "false", "Asset_Criticality": "MISSION_CRITICAL",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
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
        {
            "CVE_ID": "CVE-2026-0005", "Agent": "a6",
            "CVSS4_Base_Score_Calculated": "7.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.03", "EPSS_Percentile": "0.60",
            "KEV_Listed": "false", "Asset_Criticality": "HIGH",
            "Internet_Facing": "", "Publicly_Exposed": "NO",
        },
        {
            "CVE_ID": "CVE-2026-0006", "Agent": "a7",
            "CVSS4_Base_Score_Calculated": "9.5", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.03", "EPSS_Percentile": "0.50",
            "KEV_Listed": "false", "Asset_Criticality": "LOW",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            "CVE_ID": "CVE-2026-0007", "Agent": "a8",
            "CVSS4_Base_Score_Calculated": "5.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0", "EPSS_Percentile": "0.01",
            "KEV_Listed": "false", "Asset_Criticality": "MODERATE",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            "CVE_ID": "CVE-2026-0008", "Agent": "a9",
            "CVSS4_Base_Score_Calculated": "5.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.001", "EPSS_Percentile": "0.10",
            "KEV_Listed": "true", "Asset_Criticality": "MODERATE",
            "Internet_Facing": "NO", "Publicly_Exposed": "NO",
        },
        {
            "CVE_ID": "CVE-2026-0009", "Agent": "a10",
            "CVSS4_Base_Score_Calculated": "5.0", "CVSS4_Base_Score": "",
            "EPSS_Probability": "0.03", "EPSS_Percentile": "0.50",
            "KEV_Listed": "false", "Asset_Criticality": "MODERATE",
            "Internet_Facing": "YES", "Publicly_Exposed": "NO",
        },
    ]


def verify_rbvm_v3_anchors(rows: list[dict[str, str]], report: dict) -> None:
    baseline = row_for(rows, "CVE-2026-0004")
    assert_close(baseline["Risk_Score"], 5.0)
    baseline_explanation = json.loads(baseline["Risk_Explanation_JSON"])
    assert_close(str(baseline_explanation["impact"]), 5.0)
    assert_close(str(baseline_explanation["z"]), 0.0)

    low_asset = row_for(rows, "CVE-2026-0006")
    assert_close(low_asset["Risk_Score"], 8.55)

    negative = row_for(rows, "CVE-2026-0007")
    assert_close(negative["Risk_Score"], 4.75)
    negative_explanation = json.loads(negative["Risk_Explanation_JSON"])
    assert_close(str(negative_explanation["negativeThreatDiscountAuthority"]), 0.05)

    kev = row_for(rows, "CVE-2026-0008")
    assert_close(kev["Risk_Score"], 7.0)
    if json.loads(kev["Risk_Explanation_JSON"])["threatResolution"] != "KEV_OVERRIDE":
        raise AssertionError("KEV must explicitly override the predictive EPSS threat signal")

    internet = row_for(rows, "CVE-2026-0009")
    assert_close(internet["Risk_Score"], 5.5)

    missing = row_for(rows, "CVE-2026-0005")
    if missing["Risk_Status"] != "NON_COMPUTABLE":
        raise AssertionError("RBVM V3 must block missing Internet Facing")
    if "INTERNET_FACING_MISSING_OR_INVALID" not in missing["Risk_Blockers"]:
        raise AssertionError("RBVM V3 missing Internet Facing blocker is absent")

    public_missing = row_for(rows, "CVE-2026-0003")
    if public_missing["Risk_Status"] != "COMPUTED":
        raise AssertionError("RBVM V3 must not require Publicly Exposed")

    if report.get("ratingSemantics") != RATING_SEMANTICS:
        raise AssertionError("RBVM V3 bands must be explicitly presentation-only")


def monotonicity_rows() -> list[dict[str, str]]:
    cvss_values = [0.5, 2.5, 5.0, 7.5, 9.5, 10.0]
    asset_values = ["LOW", "MODERATE", "HIGH", "MISSION_CRITICAL"]
    epss_values = [0.0, 0.003, 0.01, 0.03, 0.05, 0.15, 0.30, 1.0]
    rows = []
    index = 100000
    for cvss in cvss_values:
        for asset in asset_values:
            for epss in epss_values:
                for kev in (False, True):
                    for internet in (False, True):
                        index += 1
                        rows.append({
                            "CVE_ID": f"CVE-2099-{index}",
                            "Agent": f"golden-{index}",
                            "CVSS4_Base_Score_Calculated": str(cvss),
                            "CVSS4_Base_Score": "",
                            "EPSS_Probability": str(epss),
                            "EPSS_Percentile": "0.5",
                            "KEV_Listed": "true" if kev else "false",
                            "Asset_Criticality": asset,
                            "Internet_Facing": "YES" if internet else "NO",
                            "Publicly_Exposed": "",
                            "Golden_CVSS": str(cvss),
                            "Golden_Asset": asset,
                            "Golden_EPSS": str(epss),
                            "Golden_KEV": "1" if kev else "0",
                            "Golden_Internet": "1" if internet else "0",
                        })
    return rows


def verify_monotonicity(rows: list[dict[str, str]]) -> None:
    if any(row["Risk_Status"] != "COMPUTED" for row in rows):
        raise AssertionError("RBVM V3 monotonicity corpus must be fully computable")

    by_other = defaultdict(list)
    for row in rows:
        key = (row["Golden_Asset"], row["Golden_EPSS"], row["Golden_KEV"], row["Golden_Internet"])
        by_other[key].append((float(row["Golden_CVSS"]), float(row["Risk_Score"])))
    for key, values in by_other.items():
        values.sort()
        assert_non_decreasing([score for _, score in values], f"CVSS monotonicity {key}")

    asset_order = {"LOW": 0, "MODERATE": 1, "HIGH": 2, "MISSION_CRITICAL": 3}
    by_other.clear()
    for row in rows:
        key = (row["Golden_CVSS"], row["Golden_EPSS"], row["Golden_KEV"], row["Golden_Internet"])
        by_other[key].append((asset_order[row["Golden_Asset"]], float(row["Risk_Score"])))
    for key, values in by_other.items():
        values.sort()
        assert_non_decreasing([score for _, score in values], f"asset monotonicity {key}")

    by_other.clear()
    for row in rows:
        key = (row["Golden_CVSS"], row["Golden_Asset"], row["Golden_KEV"], row["Golden_Internet"])
        by_other[key].append((float(row["Golden_EPSS"]), float(row["Risk_Score"])))
    for key, values in by_other.items():
        values.sort()
        assert_non_decreasing([score for _, score in values], f"EPSS monotonicity {key}")

    pairs = defaultdict(dict)
    for row in rows:
        key = (row["Golden_CVSS"], row["Golden_Asset"], row["Golden_EPSS"], row["Golden_KEV"])
        pairs[key][row["Golden_Internet"]] = float(row["Risk_Score"])
    for key, pair in pairs.items():
        if pair["1"] + 1e-6 < pair["0"]:
            raise AssertionError(f"Internet Facing decreased RBVM V3 score: {key}")

    pairs.clear()
    for row in rows:
        key = (row["Golden_CVSS"], row["Golden_Asset"], row["Golden_EPSS"], row["Golden_Internet"])
        pairs[key][row["Golden_KEV"]] = float(row["Risk_Score"])
    for key, pair in pairs.items():
        if pair["1"] + 1e-6 < pair["0"]:
            raise AssertionError(f"KEV decreased RBVM V3 score: {key}")


def main() -> None:
    if not EVALUATOR.is_file():
        raise AssertionError("CSV-first risk evaluator is missing")

    verify_fixture_set(ACTIVE_METHODS, ACTIVE_SHA, exact=True)
    verify_fixture_set(LEGACY_METHODS, LEGACY_SHA, exact=False)

    with tempfile.TemporaryDirectory(prefix="rbvm-risk-verify-") as temporary:
        directory = Path(temporary)
        analysis = directory / "analysis.csv"
        rows = base_rows()
        write_csv(analysis, rows)

        readiness = directory / "readiness.json"
        run("readiness", str(analysis), str(ACTIVE_METHODS), str(readiness))
        readiness_value = json.loads(readiness.read_text(encoding="utf-8"))
        method_ids = [value["methodId"] for value in readiness_value["methods"]]
        expected_ids = [
            "BRINQA_STYLE_CSV_V1",
            "JUPITERONE_STYLE_CSV_V2",
            "RBVM_CSV_BOUNDED_RISK_V3",
            "SERVICENOW_STYLE_CSV_V1",
        ]
        if method_ids != expected_ids:
            raise AssertionError(f"active readiness catalog must contain exactly four methods: {method_ids}")

        rbvm_rows, rbvm_report = evaluate_fixture(
            ACTIVE_METHODS, "RBVM_CSV_BOUNDED_RISK_V3.json", analysis, directory
        )
        verify_rbvm_v3_anchors(rbvm_rows, rbvm_report)

        brinqa_rows, _ = evaluate_fixture(ACTIVE_METHODS, "BRINQA_STYLE_CSV_V1.json", analysis, directory)
        assert_close(row_for(brinqa_rows, "CVE-2026-0001")["Risk_Score"], 7.8)
        service_rows, _ = evaluate_fixture(ACTIVE_METHODS, "SERVICENOW_STYLE_CSV_V1.json", analysis, directory)
        assert_close(row_for(service_rows, "CVE-2026-0002")["Risk_Score"], 62.0)

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
            ACTIVE_METHODS, "JUPITERONE_STYLE_CSV_V2.json", prevalence, directory
        )
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

        monotonic = directory / "rbvm-v3-monotonicity.csv"
        write_csv(monotonic, monotonicity_rows())
        monotonic_rows_out, _ = evaluate_fixture(
            ACTIVE_METHODS,
            "RBVM_CSV_BOUNDED_RISK_V3.json",
            monotonic,
            directory,
            "-monotonicity",
        )
        verify_monotonicity(monotonic_rows_out)

        legacy_rbvm_v1_rows, _ = evaluate_fixture(
            LEGACY_METHODS, "RBVM_CSV_BOUNDED_RISK_V1.json", analysis, directory
        )
        legacy_v1_missing = row_for(legacy_rbvm_v1_rows, "CVE-2026-0003")
        if legacy_v1_missing["Risk_Status"] != "NON_COMPUTABLE":
            raise AssertionError("legacy RBVM V1 semantics must remain unchanged")
        if "PUBLICLY_EXPOSED_MISSING_OR_INVALID" not in legacy_v1_missing["Risk_Blockers"]:
            raise AssertionError("legacy RBVM V1 Publicly Exposed blocker must remain unchanged")

        legacy_rbvm_v2_rows, _ = evaluate_fixture(
            LEGACY_METHODS, "RBVM_CSV_BOUNDED_RISK_V2.json", analysis, directory
        )
        legacy_v2_baseline = row_for(legacy_rbvm_v2_rows, "CVE-2026-0004")
        assert_close(legacy_v2_baseline["Risk_Score"], 5.0)
        if json.loads(legacy_v2_baseline["Risk_Explanation_JSON"])["impact"] != 5.0:
            raise AssertionError("legacy RBVM V2 geometric-mean identity must remain replayable")

    print(
        "CSV-first active RBVM V3 + vendor benchmarks + V1/V2 replay verification: PASS "
        "monotonicity_cases=768"
    )


if __name__ == "__main__":
    main()
