#!/usr/bin/env python3
"""Benchmark active CSV-first risk methods on one immutable contextual analysis.

The benchmark is descriptive only. It preserves each method's native scale and compares
methods through coverage and rank behavior; it never averages, normalizes, or selects a
winning risk method.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

CONTRACT = "CSV_FIRST_RISK_METHOD_BENCHMARK_V1"
EXPECTED_ACTIVE_METHODS = {
    "RBVM_CSV_BOUNDED_RISK_V3",
    "JUPITERONE_STYLE_CSV_V2",
    "SERVICENOW_STYLE_CSV_V1",
    "BRINQA_STYLE_CSV_V1",
}
TOP_KS = (10, 50, 100)
DISAGREEMENT_LIMIT = 25


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("analysis_csv", type=Path)
    parser.add_argument("methods_directory", type=Path)
    parser.add_argument("output_json", type=Path)
    return parser.parse_args()


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_evaluator():
    path = Path(__file__).with_name("evaluate-csv-first-risk.py")
    spec = importlib.util.spec_from_file_location("csv_first_risk_evaluator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load CSV-first risk evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_methods(evaluator, directory):
    if not directory.is_dir() or directory.is_symlink():
        raise RuntimeError("active risk-method directory must be a regular directory")
    entries = sorted(path for path in directory.glob("*.json") if path.is_file() and not path.is_symlink())
    methods = []
    for path in entries:
        method = evaluator.load_method(path)
        methods.append((method, path, sha256_file(path)))
    ids = {method["methodId"] for method, _, _ in methods}
    if ids != EXPECTED_ACTIVE_METHODS or len(methods) != len(EXPECTED_ACTIVE_METHODS):
        raise RuntimeError(
            "active benchmark requires exactly the four pinned CSV-first risk methods; got "
            + ", ".join(sorted(ids))
        )
    return sorted(methods, key=lambda item: item[0]["methodId"])


def percentile(sorted_values, probability):
    if not sorted_values:
        return None
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (len(sorted_values) - 1) * probability
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return sorted_values[lower]
    fraction = position - lower
    return sorted_values[lower] + (sorted_values[upper] - sorted_values[lower]) * fraction


def rounded(value, digits=9):
    if value is None:
        return None
    return round(float(value), digits)


def score_distribution(scores):
    ordered = sorted(scores)
    if not ordered:
        return {
            "minimum": None,
            "maximum": None,
            "mean": None,
            "median": None,
            "p75": None,
            "p90": None,
            "p95": None,
            "p99": None,
        }
    return {
        "minimum": rounded(ordered[0]),
        "maximum": rounded(ordered[-1]),
        "mean": rounded(sum(ordered) / len(ordered)),
        "median": rounded(percentile(ordered, 0.50)),
        "p75": rounded(percentile(ordered, 0.75)),
        "p90": rounded(percentile(ordered, 0.90)),
        "p95": rounded(percentile(ordered, 0.95)),
        "p99": rounded(percentile(ordered, 0.99)),
    }


def average_ranks(values):
    """Return 1-based average ranks where the highest score receives the best rank."""
    indexed = sorted(enumerate(values), key=lambda item: (-item[1], item[0]))
    ranks = [0.0] * len(values)
    position = 0
    while position < len(indexed):
        end = position + 1
        value = indexed[position][1]
        while end < len(indexed) and indexed[end][1] == value:
            end += 1
        average = ((position + 1) + end) / 2.0
        for offset in range(position, end):
            ranks[indexed[offset][0]] = average
        position = end
    return ranks


def pearson(left, right):
    if len(left) != len(right) or len(left) < 2:
        return None
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum((x - left_mean) * (y - right_mean) for x, y in zip(left, right))
    left_sq = sum((x - left_mean) ** 2 for x in left)
    right_sq = sum((y - right_mean) ** 2 for y in right)
    denominator = math.sqrt(left_sq * right_sq)
    if denominator == 0:
        return None
    return numerator / denominator


def spearman(left, right):
    return pearson(average_ranks(left), average_ranks(right))


class Fenwick:
    def __init__(self, size):
        self.tree = [0] * (size + 1)

    def add(self, index, value):
        while index < len(self.tree):
            self.tree[index] += value
            index += index & -index

    def prefix(self, index):
        result = 0
        while index > 0:
            result += self.tree[index]
            index -= index & -index
        return result


def choose2(count):
    return count * (count - 1) // 2


def kendall_tau_b(left, right):
    """Dependency-free Kendall tau-b with exact tie handling in O(n log n)."""
    if len(left) != len(right) or len(left) < 2:
        return None
    pairs = list(zip(left, right))
    n = len(pairs)
    n0 = choose2(n)
    x_counts = Counter(x for x, _ in pairs)
    y_counts = Counter(y for _, y in pairs)
    joint_counts = Counter(pairs)
    n1 = sum(choose2(count) for count in x_counts.values())
    n2 = sum(choose2(count) for count in y_counts.values())
    n3 = sum(choose2(count) for count in joint_counts.values())
    denominator = math.sqrt((n0 - n1) * (n0 - n2))
    if denominator == 0:
        return None

    y_values = sorted(set(right))
    y_index = {value: index + 1 for index, value in enumerate(y_values)}
    ordered = sorted(pairs, key=lambda pair: (pair[0], pair[1]))
    fenwick = Fenwick(len(y_values))
    inserted = 0
    discordant = 0
    start = 0
    while start < n:
        end = start + 1
        x_value = ordered[start][0]
        while end < n and ordered[end][0] == x_value:
            end += 1
        for _, y_value in ordered[start:end]:
            index = y_index[y_value]
            less_or_equal = fenwick.prefix(index)
            discordant += inserted - less_or_equal
        for _, y_value in ordered[start:end]:
            fenwick.add(y_index[y_value], 1)
            inserted += 1
        start = end

    untied_pairs = n0 - n1 - n2 + n3
    concordance_minus_discordance = untied_pairs - 2 * discordant
    return concordance_minus_discordance / denominator


def rank_percentile(rank, count):
    if count <= 1:
        return 1.0
    return 1.0 - ((rank - 1.0) / (count - 1.0))


def row_identity(row, analysis_row):
    asset = str(row.get("Agent_ID") or row.get("Agent") or "").strip()
    return {
        "analysisRow": analysis_row,
        "asset": asset,
        "cveId": str(row.get("CVE_ID") or "").strip().upper(),
        "affectedProduct": str(row.get("Affected_Product") or "").strip(),
    }


def evidence_slice(row, evaluator):
    criticality = str(row.get("Asset_Criticality") or "").strip().upper()
    if criticality not in {"LOW", "MODERATE", "HIGH", "MISSION_CRITICAL"}:
        criticality = "UNKNOWN"
    kev = evaluator.resolve_bool(row.get("KEV_Listed"))
    internet = evaluator.resolve_bool(row.get("Internet_Facing"))
    epss = evaluator.parse_float(row.get("EPSS_Probability"), 0.0, 1.0)
    if epss is None:
        epss_band = "UNKNOWN"
    elif epss < 0.01:
        epss_band = "LT_1_PERCENT"
    elif epss < 0.05:
        epss_band = "1_TO_5_PERCENT"
    elif epss < 0.20:
        epss_band = "5_TO_20_PERCENT"
    elif epss < 0.50:
        epss_band = "20_TO_50_PERCENT"
    else:
        epss_band = "GTE_50_PERCENT"
    return {
        "kev": "LISTED" if kev is True else "NOT_LISTED" if kev is False else "UNKNOWN",
        "internetFacing": "YES" if internet is True else "NO" if internet is False else "UNKNOWN",
        "assetCriticality": criticality,
        "epssBand": epss_band,
    }


def summarize_slices(rows, method_scores, evaluator):
    dimensions = {
        "kev": defaultdict(lambda: {"rows": 0, "computedRows": 0, "scores": []}),
        "internetFacing": defaultdict(lambda: {"rows": 0, "computedRows": 0, "scores": []}),
        "assetCriticality": defaultdict(lambda: {"rows": 0, "computedRows": 0, "scores": []}),
        "epssBand": defaultdict(lambda: {"rows": 0, "computedRows": 0, "scores": []}),
    }
    for index, row in enumerate(rows):
        labels = evidence_slice(row, evaluator)
        score = method_scores.get(index)
        for dimension, label in labels.items():
            bucket = dimensions[dimension][label]
            bucket["rows"] += 1
            if score is not None:
                bucket["computedRows"] += 1
                bucket["scores"].append(score)
    output = {}
    for dimension, groups in dimensions.items():
        output[dimension] = {}
        for label in sorted(groups):
            bucket = groups[label]
            output[dimension][label] = {
                "rows": bucket["rows"],
                "computedRows": bucket["computedRows"],
                "meanNativeScore": rounded(sum(bucket["scores"]) / len(bucket["scores"])) if bucket["scores"] else None,
            }
    return output


def method_results(rows, method, evaluator, context):
    scores_by_row = {}
    blockers = Counter()
    ratings = Counter()
    for index, row in enumerate(rows):
        score, row_blockers, _ = evaluator.evaluate_row(row, method, context)
        if score is None or row_blockers:
            blockers.update(row_blockers)
            continue
        score = float(score)
        scores_by_row[index] = score
        native_rating = evaluator.rating(score, method.get("ratingBands", []))
        if native_rating:
            ratings[native_rating] += 1
    scores = list(scores_by_row.values())
    return {
        "scoresByRow": scores_by_row,
        "summary": {
            "computedRows": len(scores_by_row),
            "nonComputableRows": len(rows) - len(scores_by_row),
            "coverage": rounded(len(scores_by_row) / len(rows)),
            "blockers": dict(sorted(blockers.items())),
            "ratingCounts": dict(sorted(ratings.items())),
            "distribution": score_distribution(scores),
            "quantileMethod": "LINEAR_INTERPOLATION_TYPE7",
        },
    }


def ordered_common_rows(common_rows, scores):
    return sorted(common_rows, key=lambda index: (-scores[index], index))


def top_overlap(common_rows, left_scores, right_scores):
    left_order = ordered_common_rows(common_rows, left_scores)
    right_order = ordered_common_rows(common_rows, right_scores)
    result = {}
    for requested in TOP_KS:
        size = min(requested, len(common_rows))
        if size == 0:
            result[str(requested)] = {"effectiveK": 0, "overlap": 0, "jaccard": None}
            continue
        left = set(left_order[:size])
        right = set(right_order[:size])
        intersection = len(left & right)
        union = len(left | right)
        result[str(requested)] = {
            "effectiveK": size,
            "overlap": intersection,
            "jaccard": rounded(intersection / union) if union else None,
        }
    return result


def disagreement_rows(rows, common_rows, left_id, right_id, left_scores, right_scores):
    ordered_indices = sorted(common_rows)
    left_values = [left_scores[index] for index in ordered_indices]
    right_values = [right_scores[index] for index in ordered_indices]
    left_ranks = average_ranks(left_values)
    right_ranks = average_ranks(right_values)
    count = len(ordered_indices)
    disagreements = []
    for offset, row_index in enumerate(ordered_indices):
        left_percentile = rank_percentile(left_ranks[offset], count)
        right_percentile = rank_percentile(right_ranks[offset], count)
        identity = row_identity(rows[row_index], row_index + 1)
        identity.update({
            "rankPercentileGap": rounded(abs(left_percentile - right_percentile)),
            left_id: {
                "nativeScore": rounded(left_scores[row_index]),
                "averageRank": rounded(left_ranks[offset], 6),
                "rankPercentile": rounded(left_percentile),
            },
            right_id: {
                "nativeScore": rounded(right_scores[row_index]),
                "averageRank": rounded(right_ranks[offset], 6),
                "rankPercentile": rounded(right_percentile),
            },
        })
        disagreements.append(identity)
    disagreements.sort(key=lambda item: (-item["rankPercentileGap"], item["analysisRow"]))
    return disagreements[:DISAGREEMENT_LIMIT]


def pairwise_report(rows, method_data):
    method_ids = sorted(method_data)
    pairs = []
    for left_position, left_id in enumerate(method_ids):
        for right_id in method_ids[left_position + 1:]:
            left_scores = method_data[left_id]["scoresByRow"]
            right_scores = method_data[right_id]["scoresByRow"]
            common = sorted(set(left_scores) & set(right_scores))
            left_values = [left_scores[index] for index in common]
            right_values = [right_scores[index] for index in common]
            pairs.append({
                "leftMethodId": left_id,
                "rightMethodId": right_id,
                "commonComputedRows": len(common),
                "spearmanRankCorrelation": rounded(spearman(left_values, right_values)),
                "kendallTauB": rounded(kendall_tau_b(left_values, right_values)),
                "topOverlap": top_overlap(common, left_scores, right_scores),
                "largestRankDisagreements": disagreement_rows(
                    rows, common, left_id, right_id, left_scores, right_scores
                ),
            })
    return pairs


def main():
    args = arguments()
    evaluator = load_evaluator()
    _, rows = evaluator.read_rows(args.analysis_csv)
    context = evaluator.common_context(rows)
    methods = load_methods(evaluator, args.methods_directory)

    method_data = {}
    method_output = []
    for method, path, method_sha in methods:
        result = method_results(rows, method, evaluator, context)
        result["summary"]["evidenceSlices"] = summarize_slices(
            rows, result["scoresByRow"], evaluator
        )
        method_data[method["methodId"]] = result
        method_output.append({
            "methodId": method["methodId"],
            "methodVersion": method["methodVersion"],
            "methodSha256": method_sha,
            "classification": method["classification"],
            "provider": method.get("provider"),
            "nativeScale": method["nativeScale"],
            **result["summary"],
        })

    report = {
        "contractId": CONTRACT,
        "semantics": "DESCRIPTIVE_COMPARISON_ONLY_NO_METHOD_SELECTION_NO_SCORE_NORMALIZATION_NO_AVERAGING",
        "sourceAnalysisCsv": args.analysis_csv.name,
        "sourceAnalysisSha256": sha256_file(args.analysis_csv),
        "scope": {
            "findingRows": len(rows),
            "uniqueCves": len({str(row.get("CVE_ID") or "").strip().upper() for row in rows if str(row.get("CVE_ID") or "").strip()}),
            "csvDistinctAssets": int(context["distinctAssets"]),
            "missingAssetIdentityRows": int(context["missingAssetIdentityRows"]),
        },
        "methods": method_output,
        "pairwise": pairwise_report(rows, method_data),
        "comparisonSemantics": {
            "rankDirection": "HIGHER_NATIVE_SCORE_RANKS_FIRST_WITHIN_EACH_METHOD",
            "ties": "AVERAGE_RANK_FOR_CORRELATION",
            "topNTieBreak": "SOURCE_ANALYSIS_ROW_ORDER_ONLY_FOR_EXACT_K_DETERMINISM",
            "pairwisePopulation": "INTERSECTION_OF_ROWS_COMPUTABLE_BY_BOTH_METHODS",
            "rankDisagreementBasis": "ABSOLUTE_DIFFERENCE_IN_WITHIN_METHOD_RANK_PERCENTILES",
            "nativeScores": "PRESERVED_NOT_NORMALIZED_ACROSS_METHODS",
        },
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(canonical_json(report) + "\n", encoding="utf-8")
    print(canonical_json({
        "contractId": CONTRACT,
        "findingRows": len(rows),
        "methods": [method["methodId"] for method, _, _ in methods],
        "output": str(args.output_json),
    }))


if __name__ == "__main__":
    main()
