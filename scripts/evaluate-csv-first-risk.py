#!/usr/bin/env python3
"""Evaluate versioned CSV-first risk methods against one immutable analysis CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path

METHOD_CONTRACT = "CSV_FIRST_RISK_METHOD_DEFINITION_V1"
REPORT_CONTRACT = "CSV_FIRST_RISK_REPORT_V1"
READINESS_CONTRACT = "CSV_FIRST_RISK_READINESS_V1"

OUTPUT_COLUMNS = [
    "Risk_Method_ID",
    "Risk_Method_Version",
    "Risk_Method_SHA256",
    "Risk_Status",
    "Risk_Score",
    "Risk_Scale",
    "Risk_Rating",
    "Risk_Blockers",
    "Risk_Explanation_JSON",
]

TRUE_VALUES = {"true", "1", "yes", "listed"}
FALSE_VALUES = {"false", "0", "no", "not_listed", "not-listed"}


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("analysis_csv", type=Path)
    evaluate.add_argument("method_definition", type=Path)
    evaluate.add_argument("risk_csv", type=Path)
    evaluate.add_argument("report_json", type=Path)

    readiness = sub.add_parser("readiness")
    readiness.add_argument("analysis_csv", type=Path)
    readiness.add_argument("methods_directory", type=Path)
    readiness.add_argument("output_json", type=Path)
    return parser.parse_args()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def canonical_json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def load_method(path: Path) -> dict:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("method definition must be a regular file")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or value.get("contractId") != METHOD_CONTRACT:
        raise RuntimeError(f"expected {METHOD_CONTRACT}")
    if not value.get("methodId") or int(value.get("methodVersion", 0)) < 1:
        raise RuntimeError("method definition identity is invalid")
    return value


def read_rows(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("analysis CSV must be a regular non-symlink file")
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        headers = list(reader.fieldnames or [])
        if "CVE_ID" not in headers:
            raise RuntimeError("analysis CSV must contain CVE_ID")
        collisions = sorted(set(headers) & set(OUTPUT_COLUMNS))
        if collisions:
            raise RuntimeError("analysis CSV already contains risk output columns: " + ", ".join(collisions))
        rows = list(reader)
    if not rows:
        raise RuntimeError("analysis CSV must contain at least one finding row")
    return headers, rows


def text(value) -> str:
    return str(value or "").strip()


def parse_float(value, minimum=None, maximum=None):
    raw = text(value)
    if not raw:
        return None
    try:
        number = float(raw)
    except ValueError:
        return None
    if not math.isfinite(number):
        return None
    if minimum is not None and number < minimum:
        return None
    if maximum is not None and number > maximum:
        return None
    return number


def resolve_first_numeric(row: dict[str, str], columns: list[str], minimum, maximum):
    for column in columns:
        number = parse_float(row.get(column), minimum, maximum)
        if number is not None:
            return number, column
    return None, None


def resolve_bool(value):
    raw = text(value).lower()
    if raw in TRUE_VALUES:
        return True
    if raw in FALSE_VALUES:
        return False
    return None


def asset_identity(row: dict[str, str]):
    for field in ("Agent_ID", "Asset_ID"):
        value = text(row.get(field))
        if value:
            return "KEY:" + value, field
    for field in ("Agent", "Asset_Name", "Hostname"):
        value = text(row.get(field))
        if value:
            return "NAME:" + value.casefold(), field
    return None, None


def common_context(rows: list[dict[str, str]]):
    identities = []
    cve_assets = defaultdict(set)
    missing_identity_rows = 0
    for row in rows:
        identity, _ = asset_identity(row)
        if identity is None:
            missing_identity_rows += 1
            continue
        identities.append(identity)
        cve = text(row.get("CVE_ID")).upper()
        if cve:
            cve_assets[cve].add(identity)
    return {
        "distinctAssets": len(set(identities)),
        "missingAssetIdentityRows": missing_identity_rows,
        "affectedAssetsByCve": {key: len(value) for key, value in cve_assets.items()},
    }


def rating(score: float, bands: list[dict]) -> str:
    for band in sorted(bands, key=lambda value: float(value["minimum"]), reverse=True):
        if score >= float(band["minimum"]):
            return str(band["rating"])
    return ""


def scale_text(method: dict) -> str:
    scale = method["nativeScale"]
    return f'{scale["minimum"]}..{scale["maximum"]}'


def criticality_value(row, method, blockers):
    value = text(row.get("Asset_Criticality")).upper()
    mapping = method.get("policy", {}).get("assetCriticalityMap", {})
    if value not in mapping:
        blockers.append("ASSET_CRITICALITY_MISSING_OR_INVALID")
        return None
    return float(mapping[value])


def require_binary(row, column, blocker, blockers):
    value = resolve_bool(row.get(column))
    if value is None:
        blockers.append(blocker)
    return value


def cvss_value(row, method, blockers):
    columns = method.get("inputs", {}).get(
        "cvssColumns", ["CVSS4_Base_Score_Calculated", "CVSS4_Base_Score"]
    )
    value, source = resolve_first_numeric(row, columns, 0.0, 10.0)
    if value is None:
        blockers.append("CVSS_BASE_MISSING_OR_INVALID")
    return value, source


def epss_probability(row, blockers):
    value = parse_float(row.get("EPSS_Probability"), 0.0, 1.0)
    if value is None:
        blockers.append("EPSS_PROBABILITY_MISSING_OR_INVALID")
    return value


def epss_percentile(row, blockers):
    value = parse_float(row.get("EPSS_Percentile"), 0.0, 1.0)
    if value is None:
        blockers.append("EPSS_PERCENTILE_MISSING_OR_INVALID")
    return value


def kev_value(row, blockers):
    value = resolve_bool(row.get("KEV_Listed"))
    if value is None:
        blockers.append("KEV_STATE_MISSING_OR_INVALID")
    return value


def evaluate_rbvm(row, method, _context):
    blockers = []
    cvss, cvss_source = cvss_value(row, method, blockers)
    epss = epss_probability(row, blockers)
    kev = kev_value(row, blockers)
    asset = criticality_value(row, method, blockers)
    public = require_binary(
        row, "Publicly_Exposed", "PUBLICLY_EXPOSED_MISSING_OR_INVALID", blockers
    )
    if blockers:
        return None, blockers, {"requiredEvidence": "INCOMPLETE"}

    policy = method["policy"]
    impact = math.sqrt(cvss * asset)
    p0 = float(policy["epssBaselineProbability"])
    odds = (epss / (1.0 - epss)) if epss < 1.0 else math.inf
    baseline_odds = p0 / (1.0 - p0)
    if kev:
        z = 1.0
        threat_resolution = "KEV_OVERRIDE"
    elif math.isinf(odds):
        z = 1.0
        threat_resolution = "EPSS"
    else:
        odds_ratio = odds / baseline_odds
        z = (odds_ratio - 1.0) / (odds_ratio + 1.0)
        threat_resolution = "EPSS"
    q = int(policy["threatPower"])
    positive = max(z, 0.0) ** q
    negative = max(-z, 0.0) ** q
    core = (
        impact
        + float(policy["positiveThreatHeadroomAuthority"]) * positive * (10.0 - impact)
        - float(policy["negativeThreatDiscountAuthority"]) * negative * impact
    )
    exposure = float(policy["publicExposureModifier"]) if public else 0.0
    score = min(10.0, max(0.0, core + exposure))
    explanation = {
        "cvssBase": round(cvss, 6),
        "cvssSourceColumn": cvss_source,
        "assetCriticality": text(row.get("Asset_Criticality")).upper(),
        "assetCriticalityValue": asset,
        "impact": round(impact, 6),
        "epssProbability": epss,
        "epssBaselineProbability": p0,
        "kevListed": kev,
        "threatResolution": threat_resolution,
        "z": round(z, 9),
        "core": round(core, 6),
        "publiclyExposed": public,
        "publicExposureModifier": exposure,
    }
    return score, [], explanation


def evaluate_jupiter(row, method, context):
    blockers = []
    cvss, cvss_source = cvss_value(row, method, blockers)
    percentile = epss_percentile(row, blockers)
    identity, identity_source = asset_identity(row)
    if identity is None:
        blockers.append("CSV_ASSET_IDENTITY_MISSING")
    if context["missingAssetIdentityRows"] > 0:
        blockers.append("CSV_ASSET_POPULATION_INCOMPLETE")
    population = int(context["distinctAssets"])
    if population < 1:
        blockers.append("CSV_ASSET_POPULATION_EMPTY")
    cve = text(row.get("CVE_ID")).upper()
    affected = int(context["affectedAssetsByCve"].get(cve, 0))
    if affected < 1:
        blockers.append("CVE_AFFECTED_ASSET_COUNT_EMPTY")
    if blockers:
        return None, sorted(set(blockers)), {"requiredEvidence": "INCOMPLETE"}

    policy = method["policy"]
    cvss_component = float(policy["cvssWeight"]) * (cvss / 10.0) ** float(policy["cvssExponent"])
    epss_component = float(policy["epssPercentileWeight"]) * percentile
    occurrence_ratio = affected / population
    occurrence_component = min(float(policy["occurrenceCap"]), occurrence_ratio)
    score = min(1.0, max(0.0, cvss_component + epss_component + occurrence_component))
    explanation = {
        "cvssBase": round(cvss, 6),
        "cvssSourceColumn": cvss_source,
        "cvssComponent": round(cvss_component, 9),
        "epssPercentile": percentile,
        "epssPercentileComponent": round(epss_component, 9),
        "assetIdentitySourceColumn": identity_source,
        "affectedAssets": affected,
        "csvDistinctAssets": population,
        "populationScope": "DISTINCT_ASSETS_IN_THIS_INPUT_CSV",
        "occurrenceRatio": round(occurrence_ratio, 9),
        "occurrenceCap": float(policy["occurrenceCap"]),
        "occurrenceComponent": round(occurrence_component, 9),
    }
    return score, [], explanation


def evaluate_servicenow(row, method, _context):
    blockers = []
    cvss, cvss_source = cvss_value(row, method, blockers)
    epss = epss_probability(row, blockers)
    asset = criticality_value(row, method, blockers)
    internet = require_binary(row, "Internet_Facing", "INTERNET_FACING_MISSING_OR_INVALID", blockers)
    if blockers:
        return None, blockers, {"requiredEvidence": "INCOMPLETE"}

    policy = method["policy"]
    weights = policy["weights"]
    severity_factor = 10.0 * cvss
    epss_factor = 100.0 * epss
    exposure_factor = 100.0 if internet else 0.0
    score = (
        float(weights["severity"]) * severity_factor
        + float(weights["epss"]) * epss_factor
        + float(weights["criticality"]) * asset
        + float(weights["exposure"]) * exposure_factor
    ) / 100.0
    score = min(100.0, max(0.0, score))
    explanation = {
        "configurationSemantics": "SERVICENOW_CALCULATOR_STYLE_LOCAL_DEMO_CONFIGURATION",
        "cvssBase": round(cvss, 6),
        "cvssSourceColumn": cvss_source,
        "severityFactor": round(severity_factor, 6),
        "epssProbability": epss,
        "epssFactor": round(epss_factor, 6),
        "assetCriticality": text(row.get("Asset_Criticality")).upper(),
        "criticalityFactor": asset,
        "internetFacing": internet,
        "exposureFactor": exposure_factor,
        "weights": weights,
    }
    return score, [], explanation


def threshold_factor(value: float, rules: list[dict]) -> tuple[float, str]:
    for rule in rules:
        minimum = rule.get("minimum")
        maximum = rule.get("maximum")
        if minimum is not None and value < float(minimum):
            continue
        if maximum is not None and value >= float(maximum):
            continue
        return float(rule["offset"]), str(rule["label"])
    raise RuntimeError("no factor rule matched")


def evaluate_brinqa(row, method, _context):
    blockers = []
    cvss, cvss_source = cvss_value(row, method, blockers)
    epss = epss_probability(row, blockers)
    kev = kev_value(row, blockers)
    criticality = text(row.get("Asset_Criticality")).upper()
    criticality_offsets = method["policy"]["assetCriticalityOffsets"]
    if criticality not in criticality_offsets:
        blockers.append("ASSET_CRITICALITY_MISSING_OR_INVALID")
    internet = require_binary(row, "Internet_Facing", "INTERNET_FACING_MISSING_OR_INVALID", blockers)
    if blockers:
        return None, blockers, {"requiredEvidence": "INCOMPLETE"}

    policy = method["policy"]
    epss_offset, epss_band = threshold_factor(epss, policy["epssOffsets"])
    kev_offset = float(policy["kevListedOffset"]) if kev else 0.0
    criticality_offset = float(criticality_offsets[criticality])
    exposure_offset = float(policy["internetFacingOffset"]) if internet else 0.0
    raw = cvss + epss_offset + kev_offset + criticality_offset + exposure_offset
    score = min(10.0, max(0.0, raw))
    explanation = {
        "configurationSemantics": "BRINQA_RISK_FACTOR_STYLE_LOCAL_BENCHMARK",
        "baseFromCvss": round(cvss, 6),
        "cvssSourceColumn": cvss_source,
        "epssProbability": epss,
        "epssBand": epss_band,
        "epssOffset": epss_offset,
        "kevListed": kev,
        "kevOffset": kev_offset,
        "assetCriticality": criticality,
        "assetCriticalityOffset": criticality_offset,
        "internetFacing": internet,
        "internetFacingOffset": exposure_offset,
        "rawBeforeClamp": round(raw, 6),
    }
    return score, [], explanation


EVALUATORS = {
    "RBVM_BOUNDED": evaluate_rbvm,
    "JUPITERONE_STYLE": evaluate_jupiter,
    "SERVICENOW_STYLE": evaluate_servicenow,
    "BRINQA_STYLE": evaluate_brinqa,
}


def evaluate_row(row, method, context):
    implementation = str(method.get("implementation") or "")
    evaluator = EVALUATORS.get(implementation)
    if evaluator is None:
        raise RuntimeError(f"unsupported method implementation: {implementation}")
    return evaluator(row, method, context)


def readiness_for(rows, method, context):
    blockers = Counter()
    computable = 0
    for row in rows:
        score, row_blockers, _ = evaluate_row(row, method, context)
        if score is not None and not row_blockers:
            computable += 1
        else:
            blockers.update(row_blockers)
    return {
        "methodId": method["methodId"],
        "methodVersion": method["methodVersion"],
        "computableRows": computable,
        "nonComputableRows": len(rows) - computable,
        "blockers": dict(sorted(blockers.items())),
    }


def run_evaluate(args):
    method = load_method(args.method_definition)
    headers, rows = read_rows(args.analysis_csv)
    context = common_context(rows)
    method_sha = sha256_file(args.method_definition)
    source_sha = sha256_file(args.analysis_csv)
    computed = 0
    non_computable = 0
    blocker_counts = Counter()
    scores = []
    rating_counts = Counter()

    args.risk_csv.parent.mkdir(parents=True, exist_ok=True)
    with args.risk_csv.open("w", encoding="utf-8", newline="") as target:
        writer = csv.DictWriter(target, fieldnames=headers + OUTPUT_COLUMNS)
        writer.writeheader()
        for row in rows:
            score, blockers, explanation = evaluate_row(row, method, context)
            joined = dict(row)
            if score is None or blockers:
                non_computable += 1
                blocker_counts.update(blockers)
                joined.update({
                    "Risk_Method_ID": method["methodId"],
                    "Risk_Method_Version": str(method["methodVersion"]),
                    "Risk_Method_SHA256": method_sha,
                    "Risk_Status": "NON_COMPUTABLE",
                    "Risk_Score": "",
                    "Risk_Scale": scale_text(method),
                    "Risk_Rating": "",
                    "Risk_Blockers": "|".join(sorted(set(blockers))),
                    "Risk_Explanation_JSON": canonical_json(explanation),
                })
            else:
                computed += 1
                scores.append(score)
                native_rating = rating(score, method.get("ratingBands", []))
                if native_rating:
                    rating_counts[native_rating] += 1
                joined.update({
                    "Risk_Method_ID": method["methodId"],
                    "Risk_Method_Version": str(method["methodVersion"]),
                    "Risk_Method_SHA256": method_sha,
                    "Risk_Status": "COMPUTED",
                    "Risk_Score": f"{score:.6f}".rstrip("0").rstrip("."),
                    "Risk_Scale": scale_text(method),
                    "Risk_Rating": native_rating,
                    "Risk_Blockers": "",
                    "Risk_Explanation_JSON": canonical_json(explanation),
                })
            writer.writerow(joined)

    report = {
        "contractId": REPORT_CONTRACT,
        "methodId": method["methodId"],
        "methodVersion": method["methodVersion"],
        "methodSha256": method_sha,
        "classification": method["classification"],
        "provider": method.get("provider"),
        "nativeScale": method["nativeScale"],
        "sourceAnalysisCsv": args.analysis_csv.name,
        "sourceAnalysisSha256": source_sha,
        "riskCsv": args.risk_csv.name,
        "riskCsvSha256": sha256_file(args.risk_csv),
        "scope": {
            "findingRows": len(rows),
            "uniqueCves": len({text(row.get("CVE_ID")).upper() for row in rows if text(row.get("CVE_ID"))}),
            "distinctAssets": context["distinctAssets"],
            "missingAssetIdentityRows": context["missingAssetIdentityRows"],
        },
        "result": {
            "computedRows": computed,
            "nonComputableRows": non_computable,
            "blockers": dict(sorted(blocker_counts.items())),
            "ratingCounts": dict(sorted(rating_counts.items())),
            "minimumScore": round(min(scores), 9) if scores else None,
            "maximumScore": round(max(scores), 9) if scores else None,
            "meanScore": round(sum(scores) / len(scores), 9) if scores else None,
        },
        "methodSemantics": method.get("semantics"),
        "immutableInput": True,
        "networkIoUsed": False,
        "databaseStateUsed": False,
    }
    args.report_json.parent.mkdir(parents=True, exist_ok=True)
    args.report_json.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


def run_readiness(args):
    headers, rows = read_rows(args.analysis_csv)
    del headers
    context = common_context(rows)
    methods = []
    for path in sorted(args.methods_directory.glob("*.json")):
        if path.is_symlink() or not path.is_file():
            continue
        method = load_method(path)
        value = readiness_for(rows, method, context)
        value["methodSha256"] = sha256_file(path)
        value["classification"] = method["classification"]
        value["provider"] = method.get("provider")
        value["nativeScale"] = method["nativeScale"]
        methods.append(value)
    report = {
        "contractId": READINESS_CONTRACT,
        "sourceAnalysisSha256": sha256_file(args.analysis_csv),
        "scope": {
            "findingRows": len(rows),
            "distinctAssets": context["distinctAssets"],
            "missingAssetIdentityRows": context["missingAssetIdentityRows"],
        },
        "methods": methods,
    }
    args.output_json.write_text(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, sort_keys=True))


def main():
    args = arguments()
    if args.command == "evaluate":
        run_evaluate(args)
    else:
        run_readiness(args)


if __name__ == "__main__":
    main()
