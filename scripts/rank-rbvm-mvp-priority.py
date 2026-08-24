#!/usr/bin/env python3
"""Rank CSV-first findings by a weight-free Pareto treatment-priority policy.

This is RBVM local policy, not Organizational Risk. It preserves CVSS, EPSS,
KEV, customer Asset Criticality, and customer Internet Facing as distinct
signals and computes relative nondominated fronts only when all five inputs
are present. Missing evidence is never imputed.
"""

from __future__ import annotations

import argparse
import csv
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path

METHOD_ID = "RBVM_MVP_PRIORITY_POLICY_V1"
REPORT_CONTRACT = "RBVM_MVP_PRIORITY_REPORT_V1"
EXPLAINABILITY_CONTRACT = "RBVM_MVP_PRIORITY_EXPLAINABILITY_V1"
CRITICALITY = {"LOW": 1, "MODERATE": 2, "HIGH": 3, "MISSION_CRITICAL": 4}
INTERNET = {"NO": 0, "YES": 1}
BLOCKER_LABELS = {
    "KEV_STATE_MISSING_OR_INVALID": "CISA KEV state",
    "INTERNET_FACING_MISSING_OR_INVALID": "customer Internet Facing",
    "ASSET_CRITICALITY_MISSING_OR_INVALID": "customer Asset Criticality",
    "EPSS_MISSING_OR_INVALID": "FIRST EPSS probability",
    "CVSS4_CONTEXT_SCORE_MISSING_OR_INVALID": "contextual CVSS v4 score",
}

CANONICAL = {
    "methodId": METHOD_ID,
    "methodVersion": 1,
    "classification": "RBVM_POLICY",
    "outputSemantics": "RELATIVE_TREATMENT_PRIORITY_PARETO_FRONT_WITHIN_INPUT_SET",
    "organizationalRisk": False,
    "dimensions": [
        {
            "name": "CISA_KEV",
            "source": "KEV_Listed",
            "orientation": "HIGHER_IS_MORE_URGENT",
            "mapping": {"false": 0, "true": 1},
        },
        {
            "name": "CUSTOMER_INTERNET_FACING",
            "source": "Internet_Facing",
            "orientation": "HIGHER_IS_MORE_URGENT",
            "mapping": {"NO": 0, "YES": 1},
        },
        {
            "name": "CUSTOMER_ASSET_CRITICALITY",
            "source": "Asset_Criticality",
            "orientation": "HIGHER_IS_MORE_URGENT",
            "mapping": {"LOW": 1, "MODERATE": 2, "HIGH": 3, "MISSION_CRITICAL": 4},
        },
        {
            "name": "FIRST_EPSS_30_DAY_PROBABILITY",
            "source": "EPSS_Probability",
            "orientation": "HIGHER_IS_MORE_URGENT",
            "range": [0, 1],
        },
        {
            "name": "CVSS_V4_CONTEXTUAL_TECHNICAL_SEVERITY",
            "source": "CVSS4_Context_Score",
            "orientation": "HIGHER_IS_MORE_URGENT",
            "range": [0, 10],
        },
    ],
    "dominance": "A_DOMINATES_B_IFF_ALL_DIMENSIONS_A_GTE_B_AND_AT_LEAST_ONE_GT",
    "fronting": "ITERATIVE_NONDOMINATED_SORT; FRONT_1_HIGHEST_RELATIVE_TREATMENT_PRIORITY",
    "missingEvidencePolicy": "UNRANKABLE; DO_NOT_IMPUTE",
    "thresholds": [],
    "weights": [],
}

CANONICAL_JSON = json.dumps(CANONICAL, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
METHOD_SHA256 = hashlib.sha256(CANONICAL_JSON.encode("utf-8")).hexdigest()
EXPECTED_METHOD_SHA256 = "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388"
if METHOD_SHA256 != EXPECTED_METHOD_SHA256:
    raise RuntimeError("RBVM_MVP_PRIORITY_POLICY_V1 canonical representation drift")

OUTPUT_COLUMNS = [
    "RBVM_MVP_Priority_Status",
    "RBVM_MVP_Priority_Front",
    "RBVM_MVP_Priority_Dominated_By",
    "RBVM_MVP_Priority_Dominates",
    "RBVM_MVP_Priority_Blockers",
    "RBVM_MVP_Priority_Explanation",
    "RBVM_MVP_Priority_Method_SHA256",
]


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis_csv", type=Path)
    parser.add_argument("ranked_csv", type=Path)
    parser.add_argument("report_json", type=Path)
    return parser.parse_args()


def parse_bool(value):
    text = str(value or "").strip().lower()
    if text in {"true", "1", "yes", "listed"}:
        return 1
    if text in {"false", "0", "no", "not_listed", "not listed"}:
        return 0
    raise ValueError("KEV_STATE_MISSING_OR_INVALID")


def parse_decimal(value, minimum, maximum, blocker):
    text = str(value or "").strip()
    if not text:
        raise ValueError(blocker)
    try:
        parsed = Decimal(text)
    except InvalidOperation as error:
        raise ValueError(blocker) from error
    if not parsed.is_finite() or parsed < minimum or parsed > maximum:
        raise ValueError(blocker)
    return parsed


def vector(row):
    blockers = []

    try:
        kev = parse_bool(row.get("KEV_Listed"))
    except ValueError as error:
        blockers.append(str(error))
        kev = None

    internet_text = str(row.get("Internet_Facing") or "").strip().upper()
    internet = INTERNET.get(internet_text)
    if internet is None:
        blockers.append("INTERNET_FACING_MISSING_OR_INVALID")

    criticality_text = str(row.get("Asset_Criticality") or "").strip().upper()
    criticality = CRITICALITY.get(criticality_text)
    if criticality is None:
        blockers.append("ASSET_CRITICALITY_MISSING_OR_INVALID")

    try:
        epss = parse_decimal(row.get("EPSS_Probability"), Decimal("0"), Decimal("1"), "EPSS_MISSING_OR_INVALID")
    except ValueError as error:
        blockers.append(str(error))
        epss = None

    try:
        cvss = parse_decimal(row.get("CVSS4_Context_Score"), Decimal("0"), Decimal("10"), "CVSS4_CONTEXT_SCORE_MISSING_OR_INVALID")
    except ValueError as error:
        blockers.append(str(error))
        cvss = None

    if blockers:
        return None, blockers
    return (Decimal(kev), Decimal(internet), Decimal(criticality), epss, cvss), []


def dominates(left, right):
    return all(a >= b for a, b in zip(left, right)) and any(a > b for a, b in zip(left, right))


def dominance_relation(left, right):
    """Return 1 if left dominates, -1 if right dominates, otherwise 0.

    A single pass is materially cheaper than asking ``dominates`` twice for
    every pair and is exactly equivalent to the frozen dominance definition.
    """
    left_better = False
    right_better = False
    for left_value, right_value in zip(left, right):
        if left_value > right_value:
            left_better = True
        elif right_value > left_value:
            right_better = True
        if left_better and right_better:
            return 0
    if left_better:
        return 1
    if right_better:
        return -1
    return 0


def pareto_relations(vectors):
    """Compute fronts and row-weighted dominance counts in one pairwise pass.

    Identical five-dimensional vectors cannot dominate one another because the
    frozen policy requires at least one strictly greater dimension. Grouping
    identical vectors therefore preserves every row result while avoiding
    repeated work. Unique vector pairs are compared exactly once, after which a
    deterministic topological peel produces the same iterative nondominated
    fronts as the original reference implementation.
    """
    if not vectors:
        return {}, {}, {}

    groups = {}
    for row_index, value in vectors.items():
        groups.setdefault(value, []).append(row_index)

    unique_vectors = sorted(groups)
    outgoing = {value: [] for value in unique_vectors}
    incoming_group_count = {value: 0 for value in unique_vectors}
    dominates_rows_by_group = {value: 0 for value in unique_vectors}
    dominated_by_rows_by_group = {value: 0 for value in unique_vectors}

    for left_index, left in enumerate(unique_vectors):
        left_rows = len(groups[left])
        for right in unique_vectors[left_index + 1:]:
            relation = dominance_relation(left, right)
            if relation == 1:
                outgoing[left].append(right)
                incoming_group_count[right] += 1
                dominates_rows_by_group[left] += len(groups[right])
                dominated_by_rows_by_group[right] += left_rows
            elif relation == -1:
                outgoing[right].append(left)
                incoming_group_count[left] += 1
                dominates_rows_by_group[right] += left_rows
                dominated_by_rows_by_group[left] += len(groups[right])

    pending = dict(incoming_group_count)
    current = [value for value in unique_vectors if pending[value] == 0]
    group_fronts = {}
    front_number = 1
    assigned = 0
    while current:
        next_front = []
        for value in current:
            group_fronts[value] = front_number
            assigned += 1
            for dominated in outgoing[value]:
                pending[dominated] -= 1
                if pending[dominated] == 0:
                    next_front.append(dominated)
        current = sorted(next_front)
        front_number += 1

    if assigned != len(unique_vectors):
        raise RuntimeError("Pareto front calculation made no progress")

    fronts = {}
    dominates_count = {}
    dominated_by_count = {}
    for value, row_indexes in groups.items():
        for row_index in row_indexes:
            fronts[row_index] = group_fronts[value]
            dominates_count[row_index] = dominates_rows_by_group[value]
            dominated_by_count[row_index] = dominated_by_rows_by_group[value]
    return fronts, dominates_count, dominated_by_count


def nondominated_fronts(vectors):
    """Compatibility helper retaining the historical function contract."""
    fronts, _, _ = pareto_relations(vectors)
    return fronts


def canonical_file_sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def ranked_explanation(row, front, dominated_by, dominates_rows):
    kev = "LISTED" if parse_bool(row.get("KEV_Listed")) == 1 else "NOT_LISTED"
    internet = str(row.get("Internet_Facing") or "").strip().upper()
    criticality = str(row.get("Asset_Criticality") or "").strip().upper()
    epss = str(row.get("EPSS_Probability") or "").strip()
    cvss = str(row.get("CVSS4_Context_Score") or "").strip()
    return (
        f"Front {front}: complete admitted evidence; KEV={kev}, Internet Facing={internet}, "
        f"Asset Criticality={criticality}, EPSS={epss}, Contextual CVSS v4={cvss}; "
        f"dominated by {dominated_by} row(s), dominates {dominates_rows} row(s). "
        "Relative Pareto treatment priority only; not Organizational Risk or an SLA."
    )


def unrankable_explanation(blockers):
    labels = [BLOCKER_LABELS.get(blocker, blocker) for blocker in blockers]
    return (
        "Unrankable because required evidence is missing or invalid: "
        + ", ".join(labels)
        + ". Missing evidence is not imputed."
    )


def main():
    args = arguments()
    with args.analysis_csv.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
        required = {"KEV_Listed", "Internet_Facing", "Asset_Criticality", "EPSS_Probability", "CVSS4_Context_Score"}
        missing = sorted(required - set(headers))
        if missing:
            raise RuntimeError("analysis CSV missing required columns: " + ", ".join(missing))
        collisions = sorted(set(headers) & set(OUTPUT_COLUMNS))
        if collisions:
            raise RuntimeError("priority output columns already exist: " + ", ".join(collisions))
        rows = list(reader)

    vectors = {}
    blockers_by_row = {}
    for index, row in enumerate(rows):
        value, blockers = vector(row)
        if value is not None:
            vectors[index] = value
        blockers_by_row[index] = blockers

    if vectors:
        fronts, dominates_count, dominated_by_count = pareto_relations(vectors)
    else:
        fronts, dominates_count, dominated_by_count = {}, {}, {}

    output = []
    front_counts = {}
    unrankable_reasons = {}
    for index, row in enumerate(rows):
        joined = dict(row)
        if index in vectors:
            front = fronts[index]
            explanation = ranked_explanation(
                row,
                front,
                dominated_by_count[index],
                dominates_count[index],
            )
            joined.update({
                "RBVM_MVP_Priority_Status": "RANKED_RELATIVE_ONLY",
                "RBVM_MVP_Priority_Front": str(front),
                "RBVM_MVP_Priority_Dominated_By": str(dominated_by_count[index]),
                "RBVM_MVP_Priority_Dominates": str(dominates_count[index]),
                "RBVM_MVP_Priority_Blockers": "",
                "RBVM_MVP_Priority_Explanation": explanation,
                "RBVM_MVP_Priority_Method_SHA256": METHOD_SHA256,
            })
            front_counts[str(front)] = front_counts.get(str(front), 0) + 1
        else:
            blockers = blockers_by_row[index]
            joined.update({
                "RBVM_MVP_Priority_Status": "UNRANKABLE_MISSING_EVIDENCE",
                "RBVM_MVP_Priority_Front": "",
                "RBVM_MVP_Priority_Dominated_By": "",
                "RBVM_MVP_Priority_Dominates": "",
                "RBVM_MVP_Priority_Blockers": "|".join(blockers),
                "RBVM_MVP_Priority_Explanation": unrankable_explanation(blockers),
                "RBVM_MVP_Priority_Method_SHA256": METHOD_SHA256,
            })
            for blocker in blockers:
                unrankable_reasons[blocker] = unrankable_reasons.get(blocker, 0) + 1
        output.append(joined)

    args.ranked_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.ranked_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers + OUTPUT_COLUMNS)
        writer.writeheader()
        writer.writerows(output)

    report = {
        "contractId": REPORT_CONTRACT,
        "methodId": METHOD_ID,
        "methodSha256": METHOD_SHA256,
        "canonicalRepresentation": CANONICAL,
        "inputSha256": canonical_file_sha(args.analysis_csv),
        "outputSha256": canonical_file_sha(args.ranked_csv),
        "organizationalRiskComputed": False,
        "riskStatus": "NON_COMPUTABLE",
        "prioritySemantics": CANONICAL["outputSemantics"],
        "explainability": {
            "contractId": EXPLAINABILITY_CONTRACT,
            "rowColumn": "RBVM_MVP_Priority_Explanation",
            "derivation": "DETERMINISTIC_RENDERING_OF_ADMITTED_INPUTS_FRONT_AND_DOMINANCE_COUNTS",
            "changesPriority": False,
        },
        "rows": len(rows),
        "rankedRows": len(vectors),
        "unrankableRows": len(rows) - len(vectors),
        "frontCounts": dict(sorted(front_counts.items(), key=lambda item: int(item[0]))),
        "unrankableReasons": dict(sorted(unrankable_reasons.items())),
        "notes": [
            "Front 1 means nondominated within this exact input set; it is not a Critical/High risk rating.",
            "Adding or removing rows can change Pareto front numbers because this policy is relative.",
            "Internet Facing is customer-declared asset-level context and is not exact Finding/endpoint reachability.",
            "KEV NOT_LISTED is not interpreted as no exploitation risk.",
            "No EPSS threshold, CVSS threshold, weighted sum, or EPSS×CVSS multiplication is used.",
            "The explanation column renders already-admitted evidence and Pareto relationships; it does not add scoring logic.",
        ],
    }
    report_payload = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    report["reportSha256"] = hashlib.sha256(report_payload).hexdigest()
    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
