#!/usr/bin/env python3
"""Evaluate current CSV-first evidence against RBVM risk-method admission rules.

This command does not calculate Organizational Risk. It reports which existing
method identities are admissible, reference-only, or blocked by incompatible or
missing evidence contracts.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

CONTRACT_ID = "RBVM_V2_METHOD_ADMISSION_REPORT_V1"
ADMISSION_CONTRACT_ID = "RBVM_V2_METHOD_ADMISSION_V1"
CONTEXT_RESOLVER_ID = "CVSS_V4_CONTEXT_RESOLVER_V2"

FORMULA_V1 = {
    "methodFamily": "RBVM_FORMULA",
    "methodId": "RBVM_FORMULA_V1",
    "methodVersion": 1,
    "methodSha256": "88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e",
    "classification": "RBVM_POLICY",
    "inputContractId": "RBVM_DECISION_INPUT_SNAPSHOT_V3",
}
OWASP_V1 = {
    "methodFamily": "STANDARD_DERIVED",
    "methodId": "OWASP_DERIVED_RBVM_V1",
    "methodVersion": 1,
    "methodSha256": "03a72c8479e834174dc6985580d2543ad61b01628a79da5d59c5b5785e80c9c3",
    "classification": "STANDARD_DERIVED",
    "provider": "OWASP",
    "sourceEquation": "Risk = Likelihood * Impact",
    "inputContractId": "RBVM_DECISION_INPUT_SNAPSHOT_V3",
}
MICROSOFT_V1 = {
    "methodFamily": "STANDARD_DERIVED",
    "methodId": "MICROSOFT_PD_DERIVED_RBVM_V1",
    "methodVersion": 1,
    "methodSha256": "b22520b7b5a7d5f06782270feaf6729089ebafef79f20aea43dddf18396dcce6",
    "classification": "STANDARD_DERIVED",
    "provider": "Microsoft",
    "sourceEquation": "Risk = Probability * Damage Potential",
    "inputContractId": "RBVM_DECISION_INPUT_SNAPSHOT_V3",
}

REQUIRED_HEADERS = {
    "CVE_ID",
    "CVSS4_Context_Score_Status",
    "CVSS4_Context_Nomenclature",
    "CVSS4_Context_Score",
    "EPSS_Probability",
    "KEV_Listed",
    "Customer_Context_Status",
    "Asset_Criticality",
    "Internet_Facing",
    "CVSS4_Environmental_Requirement_Status",
    "RBVM_V2_Status",
}


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis_csv", type=Path)
    parser.add_argument("output_json", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_sha(value: object) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def read_rows(path: Path) -> list[dict[str, str]]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("analysis CSV must be a regular non-symlink file")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = set(reader.fieldnames or [])
        missing = sorted(REQUIRED_HEADERS - headers)
        if missing:
            raise RuntimeError("analysis CSV missing required columns: " + ", ".join(missing))
        rows = list(reader)
    if not rows:
        raise RuntimeError("analysis CSV must contain at least one finding row")
    return rows


def nonempty(value: object) -> bool:
    return bool(str(value or "").strip())


def kev_observed(value: object) -> bool:
    return str(value or "").strip().lower() in {
        "true", "false", "listed", "not_listed", "1", "0", "yes", "no"
    }


def contextual_cvss_ready(row: dict[str, str]) -> bool:
    return (
        row.get("CVSS4_Context_Score_Status") == "CALCULATED_FIRST_REFERENCE_COMPATIBLE"
        and nonempty(row.get("CVSS4_Context_Nomenclature"))
        and nonempty(row.get("CVSS4_Context_Score"))
    )


def customer_context_ready(row: dict[str, str]) -> bool:
    return (
        row.get("Customer_Context_Status") in {"MATCHED_KEY", "MATCHED_NAME"}
        and row.get("Asset_Criticality") not in {"", "UNKNOWN", None}
        and row.get("Internet_Facing") not in {"", "UNKNOWN", None}
    )


def verify_method_fixture(path: Path, expected_sha: str, expected_contract: str) -> None:
    raw = path.read_bytes()
    actual_sha = hashlib.sha256(raw).hexdigest()
    if actual_sha != expected_sha:
        raise RuntimeError(f"method fixture SHA drift for {expected_contract}: {actual_sha}")
    value = json.loads(raw.decode("utf-8"))
    if value.get("contractId") != expected_contract:
        raise RuntimeError(f"method fixture contract drift for {expected_contract}")


def method_candidate(base: dict[str, object], state: str, blockers: list[str], note: str) -> dict[str, object]:
    value = dict(base)
    value.update({
        "admissionState": state,
        "blockers": blockers,
        "note": note,
        "riskComputedRows": 0,
    })
    return value


def main() -> None:
    args = arguments()
    rows = read_rows(args.analysis_csv)

    verify_method_fixture(
        ROOT / "docs/fixtures/OWASP_DERIVED_RBVM_V1.json",
        str(OWASP_V1["methodSha256"]),
        str(OWASP_V1["methodId"]),
    )
    verify_method_fixture(
        ROOT / "docs/fixtures/MICROSOFT_PD_DERIVED_RBVM_V1.json",
        str(MICROSOFT_V1["methodSha256"]),
        str(MICROSOFT_V1["methodId"]),
    )

    contextual_rows = sum(contextual_cvss_ready(row) for row in rows)
    epss_rows = sum(nonempty(row.get("EPSS_Probability")) for row in rows)
    kev_rows = sum(kev_observed(row.get("KEV_Listed")) for row in rows)
    customer_rows = sum(customer_context_ready(row) for row in rows)
    environmental_rows = sum(
        row.get("CVSS4_Environmental_Requirement_Status") in {"PARTIAL", "COMPLETE"}
        for row in rows
    )
    rbvm_non_computable_rows = sum(row.get("RBVM_V2_Status") == "NON_COMPUTABLE" for row in rows)
    nomenclature = Counter(
        row.get("CVSS4_Context_Nomenclature") or "NONE"
        for row in rows
    )

    # These three families are deliberately not part of the current CSV-first contract.
    # A boolean customer Internet-facing declaration is not exact Reachability, and
    # CR/IR/AR are not Business/Mission Impact evidence.
    csv_first_capability = {
        "applicabilityEvidence": False,
        "contextualCvssV4TechnicalSeverity": True,
        "knownExploitation": True,
        "exploitationProbability": True,
        "assetContext": True,
        "exactFindingReachability": False,
        "businessMissionImpact": False,
        "decisionInputV3Snapshot": False,
    }

    shared_v3_blockers = [
        "CSV_FIRST_INPUT_IS_NOT_RBVM_DECISION_INPUT_SNAPSHOT_V3",
        "APPLICABILITY_EVIDENCE_NOT_IN_CSV_FIRST_CONTRACT",
        "EXACT_FINDING_REACHABILITY_NOT_IN_CSV_FIRST_CONTRACT",
        "BUSINESS_MISSION_IMPACT_NOT_IN_CSV_FIRST_CONTRACT",
    ]

    candidates = [
        {
            "methodFamily": "EVIDENCE_ENGINE",
            "methodId": "CVSS_V4_CONTEXTUAL_SEVERITY",
            "methodVersion": 1,
            "methodSha256": None,
            "classification": "EVIDENCE_ENGINE",
            "inputContractId": "CSV_RUN_EVIDENCE_ANALYSIS_V2",
            "admissionState": "NOT_A_RISK_METHOD",
            "calculatedRows": contextual_rows,
            "riskComputedRows": 0,
            "blockers": ["OUTPUT_SEMANTICS_ARE_TECHNICAL_SEVERITY_NOT_ORGANIZATIONAL_RISK"],
            "note": "May be consumed as contextual technical-severity evidence only.",
        },
        method_candidate(
            FORMULA_V1,
            "LEGACY_REFERENCE_ONLY",
            shared_v3_blockers + ["FORMULA_V1_USES_CVSS_V31_BASE_NOT_CONTEXTUAL_CVSS_V4"],
            "Accepted immutable historical RBVM policy; current CSV-first V2 evidence must not be coerced into its input contract.",
        ),
        method_candidate(
            OWASP_V1,
            "BLOCKED_INPUT_CONTRACT",
            shared_v3_blockers + ["DERIVED_V1_NORMALIZATION_USES_CVSS_V31_BASE"],
            "Published OWASP outer equation is preserved, but RBVM evidence mapping is local policy and exact Decision Input V3 evidence is required.",
        ),
        method_candidate(
            MICROSOFT_V1,
            "BLOCKED_INPUT_CONTRACT",
            shared_v3_blockers + ["DERIVED_V1_NORMALIZATION_USES_CVSS_V31_BASE"],
            "Published Microsoft outer equation is preserved, but RBVM evidence mapping is local policy and exact Decision Input V3 evidence is required.",
        ),
        {
            "methodFamily": "RBVM_FORMULA",
            "methodId": None,
            "methodVersion": None,
            "methodSha256": None,
            "classification": "UNDEFINED",
            "inputContractId": None,
            "admissionState": "METHOD_NOT_APPROVED",
            "riskComputedRows": 0,
            "blockers": [
                "NO_RBVM_FORMULA_V2_IDENTITY",
                "NO_APPROVED_V2_CANONICAL_REPRESENTATION",
                "NO_APPROVED_V2_OUTPUT_SCALE_OR_THRESHOLDS",
                "NO_APPROVED_V2_MISSING_STALE_AMBIGUOUS_POLICY",
                "NO_EMPIRICAL_CALIBRATION_ACCEPTANCE",
            ],
            "note": "There is no approved RBVM Formula V2. Absence of a method identity must not be replaced by an implicit default.",
        },
    ]

    report = {
        "contractId": CONTRACT_ID,
        "admissionContractId": ADMISSION_CONTRACT_ID,
        "contextResolverContractId": CONTEXT_RESOLVER_ID,
        "analysisCsv": args.analysis_csv.name,
        "analysisCsvSha256": sha256_file(args.analysis_csv),
        "scope": {
            "findingRows": len(rows),
            "uniqueCves": len({row.get("CVE_ID") for row in rows if row.get("CVE_ID")}),
        },
        "evidenceCoverage": {
            "contextualCvssCalculatedRows": contextual_rows,
            "contextualCvssNomenclature": dict(sorted(nomenclature.items())),
            "epssPresentRows": epss_rows,
            "kevObservedRows": kev_rows,
            "customerContextReadyRows": customer_rows,
            "directEnvironmentalRequirementRows": environmental_rows,
            "rbvmV2NonComputableRows": rbvm_non_computable_rows,
        },
        "csvFirstCapability": csv_first_capability,
        "candidates": candidates,
        "selection": {
            "state": "NO_V2_PRIMARY_METHOD_ADMITTED",
            "selectedMethodId": None,
            "selectedMethodSha256": None,
            "riskComputedRows": 0,
            "reason": "No approved V2 Organizational Risk method identity is executable from the current CSV-first evidence contract.",
        },
        "forbiddenSubstitutions": [
            "INTERNET_FACING_AS_EXACT_REACHABILITY",
            "CR_IR_AR_AS_BUSINESS_MISSION_IMPACT",
            "CONTEXTUAL_CVSS_AS_ORGANIZATIONAL_RISK",
            "CATALOG_ORDER_AS_METHOD_SELECTION",
            "FIELD_NAME_SIMILARITY_AS_INPUT_CONTRACT_COMPATIBILITY",
        ],
    }
    report["reportSha256"] = canonical_sha(report)

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
