#!/usr/bin/env python3
import copy
import json
import re
from decimal import Decimal, InvalidOperation
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/fixtures/RBVM_FORMULA_GOLDEN_CASES_V1.json"
DOC = ROOT / "docs/RBVM_FORMULA_GOLDEN_CASES_V1.md"
DECISIONS = ROOT / "docs/RBVM_FORMULA_READINESS_DECISIONS_V1.md"
CANONICAL = ROOT / "docs/RBVM_FORMULA_CANONICALIZATION_V1.md"
ASSET = ROOT / "src/main/java/io/rbvm/csv/AssetContextCsvEvidence.java"
REACH = ROOT / "src/main/java/io/rbvm/csv/NetworkReachabilityCsvEvidence.java"
IMPACT = ROOT / "src/main/java/io/rbvm/csv/BusinessImpactCsvEvidence.java"

DIMENSIONS = {
    "APPLICABILITY": ("applicability", "APPLICABILITY"),
    "TECHNICAL_SEVERITY": ("technicalSeverity", "TECHNICAL_SEVERITY"),
    "KNOWN_EXPLOITATION": ("knownExploitation", "KNOWN_EXPLOITATION"),
    "EXPLOITATION_PROBABILITY": ("exploitProbability", "EXPLOITATION_PROBABILITY"),
    "ASSET_CONTEXT": ("assetContext", "ASSET_CONTEXT"),
    "NETWORK_REACHABILITY": ("reachability", "NETWORK_REACHABILITY"),
    "BUSINESS_MISSION_IMPACT": ("businessImpact", "BUSINESS_MISSION_IMPACT"),
}
STATE_BLOCKERS = ("MISSING", "STALE", "AMBIGUOUS")
CANONICAL_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def set_path(profile: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    cursor = profile
    for part in parts[:-1]:
        require(part in cursor and isinstance(cursor[part], dict), f"invalid fixture path {dotted!r}")
        cursor = cursor[part]
    require(parts[-1] in cursor, f"invalid fixture path {dotted!r}")
    cursor[parts[-1]] = copy.deepcopy(value)


def apply_changes(base: dict, changes: dict) -> dict:
    profile = copy.deepcopy(base)
    for path, value in changes.items():
        set_path(profile, path, value)
    return profile


def evaluate_eligibility(profile: dict) -> tuple[str, str | None]:
    app = profile["applicability"]
    if app["state"] in STATE_BLOCKERS:
        return "NON_COMPUTABLE", f"APPLICABILITY_{app['state']}"
    require(app["state"] == "PRESENT", "unexpected Applicability state")
    if app["status"] == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", "NOT_APPLICABLE"
    if app["status"] == "UNKNOWN":
        return "NON_COMPUTABLE", "APPLICABILITY_UNKNOWN"
    require(app["status"] == "APPLICABLE", "unexpected Applicability value")

    for dimension in (
        "TECHNICAL_SEVERITY",
        "KNOWN_EXPLOITATION",
        "EXPLOITATION_PROBABILITY",
        "ASSET_CONTEXT",
        "NETWORK_REACHABILITY",
        "BUSINESS_MISSION_IMPACT",
    ):
        key, prefix = DIMENSIONS[dimension]
        state = profile[key]["state"]
        if state in STATE_BLOCKERS:
            return "NON_COMPUTABLE", f"{prefix}_{state}"
        require(state == "PRESENT", f"unexpected {dimension} state")

    if profile["knownExploitation"]["status"] == "UNKNOWN":
        return "NON_COMPUTABLE", "KEV_VALUE_UNKNOWN"
    require(profile["knownExploitation"]["status"] in ("LISTED", "NOT_LISTED"),
            "unexpected KEV value")

    if profile["assetContext"]["businessCriticality"] == "UNKNOWN":
        return "NON_COMPUTABLE", "BUSINESS_CRITICALITY_UNKNOWN"

    reach = profile["reachability"]["subgrains"]
    if len(reach) != 1:
        return "NON_COMPUTABLE", "REACHABILITY_MULTI_SUBGRAIN"
    if reach[0]["status"] == "UNKNOWN":
        return "NON_COMPUTABLE", "REACHABILITY_VALUE_UNKNOWN"

    impacts = profile["businessImpact"]["impacts"]
    services = {item["businessService"].strip().lower() for item in impacts}
    if len(services) != 1:
        return "NON_COMPUTABLE", "BUSINESS_IMPACT_MULTI_SERVICE"
    if any(item["impactLevel"] == "UNKNOWN" for item in impacts):
        return "NON_COMPUTABLE", "BUSINESS_IMPACT_VALUE_UNKNOWN"

    return "COMPUTED", None


def flatten(value, prefix="") -> dict[str, object]:
    if isinstance(value, dict):
        result = {}
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else key
            result.update(flatten(value[key], child))
        return result
    if isinstance(value, list):
        return {prefix: value}
    return {prefix: value}


def diff_paths(left: dict, right: dict) -> set[str]:
    a = flatten(left)
    b = flatten(right)
    return {key for key in set(a) | set(b) if a.get(key) != b.get(key)}


def all_objects(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from all_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from all_objects(child)


def verify_decimal(value: str, path: str, minimum: Decimal, maximum: Decimal) -> None:
    require(isinstance(value, str), f"{path} must be a decimal string")
    require(CANONICAL_DECIMAL.fullmatch(value) is not None,
            f"{path} must use canonical non-negative decimal spelling: {value!r}")
    try:
        parsed = Decimal(value)
    except InvalidOperation as exc:
        raise AssertionError(f"invalid decimal at {path}: {value!r}") from exc
    require(minimum <= parsed <= maximum, f"{path} is outside [{minimum},{maximum}]")


def main() -> None:
    data = json.loads(FIXTURE.read_text(encoding="utf-8"))
    doc = DOC.read_text(encoding="utf-8")
    decisions = DECISIONS.read_text(encoding="utf-8")
    canonical = CANONICAL.read_text(encoding="utf-8")

    require(data["contractId"] == "RBVM_FORMULA_GOLDEN_CASES_V1", "wrong golden-case contract ID")
    require(data["inputContractId"] == "RBVM_DECISION_INPUT_SNAPSHOT_V3", "golden cases must target Decision Input V3")
    require(data["readinessDecisionContractId"] == "RBVM_FORMULA_READINESS_DECISIONS_V1", "wrong readiness contract")
    require(data["formulaCanonicalizationContractId"] == "RBVM_FORMULA_CANONICALIZATION_V1", "wrong canonicalization contract")
    require(data["fixtureKind"] == "FORMULA_CONSUMED_SEMANTIC_PROFILE_GENERATOR", "fixture must be semantic, not native evidence")
    require(data["nativeEvidenceImportable"] is False, "golden fixture must never masquerade as importable native evidence")
    require(data["numericOutputsFrozen"] is False, "Stage 8 must not freeze Formula numbers")
    require(data["decimalRepresentation"] == "CANONICAL_DECIMAL_STRING", "fixture decimal representation must be explicit")

    base = data["baseProfile"]
    require(set(base) == {item[0] for item in DIMENSIONS.values()}, "base profile must contain exactly seven dimensions")
    require(all(base[key]["state"] == "PRESENT" for key, _ in DIMENSIONS.values()), "base profile must be complete")
    require(evaluate_eligibility(base) == ("COMPUTED", None), "base profile must be Formula-computable")

    # The semantic generator contains consumed values, not native-source provenance or CVSS vectors.
    serialized = json.dumps(data, sort_keys=True)
    for forbidden in ('"vector"', '"evidenceId"', '"evidenceSha256"', '"bindingId"', '"formulaEquation"', '"weight"', '"coefficient"', '"threshold"'):
        require(forbidden not in serialized, f"Stage 8 fixture leaked forbidden/native field {forbidden}")

    # Validate all numeric semantic inputs without binary floating point.
    for obj in all_objects(data):
        if "cvssBase" in obj:
            verify_decimal(obj["cvssBase"], "cvssBase", Decimal("0"), Decimal("10"))
        if "probability" in obj:
            verify_decimal(obj["probability"], "probability", Decimal("0"), Decimal("1"))
        if "percentile" in obj:
            verify_decimal(obj["percentile"], "percentile", Decimal("0"), Decimal("1"))

    # Validate fixture vocabularies against the evidence-domain source enums.
    asset_source = ASSET.read_text(encoding="utf-8")
    reach_source = REACH.read_text(encoding="utf-8")
    impact_source = IMPACT.read_text(encoding="utf-8")
    for obj in all_objects(data):
        if "businessCriticality" in obj and obj["businessCriticality"] is not None:
            require(obj["businessCriticality"] in asset_source, f"unknown BusinessCriticality {obj['businessCriticality']}")
        if "status" in obj and "originScope" in obj:
            require(obj["status"] in reach_source, f"unknown ReachabilityStatus {obj['status']}")
            require(obj["originScope"] in reach_source, f"unknown OriginScope {obj['originScope']}")
            require(obj["transportProtocol"] in reach_source, f"unknown TransportProtocol {obj['transportProtocol']}")
        if "impactLevel" in obj:
            require(obj["impactLevel"] in impact_source, f"unknown ImpactLevel {obj['impactLevel']}")
            require(obj["impactDimension"] in impact_source, f"unknown ImpactDimension {obj['impactDimension']}")

    matrix = data["parameterizedStateMatrix"]
    require(matrix["dimensions"] == list(DIMENSIONS), "state matrix must cover the seven dimensions in canonical order")
    require(matrix["states"] == list(STATE_BLOCKERS), "state matrix must cover MISSING/STALE/AMBIGUOUS")
    require(matrix["expectedResultState"] == "NON_COMPUTABLE", "state matrix must fail closed")
    require(matrix["numericOutput"] is None, "state matrix must have no numeric result")
    generated = 0
    for dimension in matrix["dimensions"]:
        key, prefix = DIMENSIONS[dimension]
        for state in matrix["states"]:
            profile = copy.deepcopy(base)
            profile[key]["state"] = state
            actual = evaluate_eligibility(profile)
            expected = ("NON_COMPUTABLE", f"{prefix}_{state}")
            require(actual == expected, f"generated matrix case {dimension}/{state} expected {expected}, got {actual}")
            generated += 1
    require(generated == 21, "state matrix must generate exactly 21 terminal cases")

    all_case_ids = set()
    for section in ("terminalValueCases", "structuralCases", "namedComputedProfiles"):
        for case in data[section]:
            require(case["id"] not in all_case_ids, f"duplicate case id {case['id']}")
            all_case_ids.add(case["id"])
            profile = apply_changes(base, case["changes"])
            actual_state, actual_reason = evaluate_eligibility(profile)
            require(actual_state == case["resultState"], f"{case['id']} state mismatch: {actual_state}")
            if "reasonCode" in case:
                require(actual_reason == case["reasonCode"], f"{case['id']} reason mismatch: {actual_reason}")
            else:
                require(actual_reason is None, f"{case['id']} unexpectedly terminal: {actual_reason}")

    required_terminal = {
        "GC-NOT-APPLICABLE", "GC-APPLICABILITY-UNKNOWN", "GC-KEV-UNKNOWN",
        "GC-BUSINESS-CRITICALITY-UNKNOWN", "GC-REACHABILITY-VALUE-UNKNOWN",
        "GC-BUSINESS-IMPACT-VALUE-UNKNOWN",
    }
    require(required_terminal <= all_case_ids, "explicit terminal-value coverage is incomplete")
    required_structural = {
        "GC-REACHABILITY-MULTI-SUBGRAIN", "GC-BUSINESS-IMPACT-MULTI-SERVICE",
        "GC-BUSINESS-IMPACT-MULTI-DIMENSION-SAME-SERVICE",
        "GC-UNLINKED-NO-INDEPENDENT-ASSET-CONTEXT",
    }
    require(required_structural <= all_case_ids, "structural golden coverage is incomplete")

    sensitivity_ids = set()
    expected_sensitivity = {"GS-CVSS", "GS-KEV", "GS-EPSS", "GS-CRITICALITY", "GS-REACHABILITY", "GS-IMPACT"}
    for pair in data["materialSensitivityPairs"]:
        require(pair["id"] not in sensitivity_ids, f"duplicate sensitivity id {pair['id']}")
        sensitivity_ids.add(pair["id"])
        require(pair["expectedRelation"] == "GREATER_THAN", f"{pair['id']} must require material sensitivity")
        low = apply_changes(base, pair["lowChanges"])
        high = apply_changes(base, pair["highChanges"])
        require(evaluate_eligibility(low)[0] == "COMPUTED", f"{pair['id']} low profile must compute")
        require(evaluate_eligibility(high)[0] == "COMPUTED", f"{pair['id']} high profile must compute")
        relevant_diffs = diff_paths(low, high) - {
            "exploitProbability.percentile",
            "assetContext.environment",
            "assetContext.businessService",
            "assetContext.businessOwner",
        }
        require(len(relevant_diffs) == 1, f"{pair['id']} must isolate exactly one Formula-relevant semantic difference: {relevant_diffs}")
    require(sensitivity_ids == expected_sensitivity, "material-sensitivity coverage must include all six Formula dimensions after Applicability")

    exclusion_expected = {
        "GI-EPSS-PERCENTILE": {"exploitProbability.percentile"},
        "GI-ENVIRONMENT": {"assetContext.environment"},
        "GI-OWNER": {"assetContext.businessOwner"},
    }
    exclusion_ids = set()
    for pair in data["arithmeticExclusionPairs"]:
        exclusion_ids.add(pair["id"])
        require(pair["expectedRelation"] == "EQUAL_TO", f"{pair['id']} must be an equality invariant")
        left = apply_changes(base, pair["leftChanges"])
        right = apply_changes(base, pair["rightChanges"])
        require(evaluate_eligibility(left)[0] == "COMPUTED", f"{pair['id']} left profile must compute")
        require(evaluate_eligibility(right)[0] == "COMPUTED", f"{pair['id']} right profile must compute")
        require(diff_paths(left, right) == exclusion_expected[pair["id"]],
                f"{pair['id']} changes more than its approved excluded field")
    require(exclusion_ids == set(exclusion_expected), "arithmetic-exclusion coverage drifted")

    named_ids = {case["id"] for case in data["namedComputedProfiles"]}
    relations = data["partialOrderRelations"]
    require(any(item["left"] == "GC-ALL-ADVERSE" and item["relation"] == "GREATER_THAN" and item["right"] == "BASE_PROFILE" for item in relations),
            "dominance relation is required")
    required_unordered = {
        frozenset(("GC-CRITICAL-NOT-LISTED-LOW-EPSS", "GC-MEDIUM-KEV-HIGH-EPSS")),
        frozenset(("GC-HIGH-TECH-LOW-IMPACT-ISOLATED", "GC-LOWER-TECH-MISSION-REACHABLE")),
    }
    actual_unordered = {
        frozenset((item["left"], item["right"]))
        for item in relations if item["relation"] == "UNORDERED_BY_READINESS"
    }
    require(actual_unordered == required_unordered, "trade-off cases must remain explicitly unordered before Formula V1")
    for item in relations:
        require(item["left"] == "GC-ALL-ADVERSE" or item["left"] in named_ids, f"unknown relation left {item['left']}")
        require(item["right"] == "BASE_PROFILE" or item["right"] in named_ids, f"unknown relation right {item['right']}")
        require(item["relation"] in ("GREATER_THAN", "UNORDERED_BY_READINESS"), "unexpected partial-order relation")

    replay_ids = {item["id"] for item in data["historicalReplayInvariants"]}
    require(replay_ids == {
        "GR-HISTORICAL-ASOF-LINK", "GR-HISTORICAL-EVIDENCE", "GR-FORMULA-IDENTITY",
        "GR-PRIORITY-INDEPENDENCE", "GR-EXACT-REPLAY",
    }, "historical/replay invariant set drifted")

    for marker in (
        "partial order, not total ranking",
        "numericOutputsFrozen = false",
        "GREATER_THAN",
        "UNORDERED_BY_READINESS",
        "exact Decision Input + exact Formula identity",
        "contains no",
    ):
        require(marker.lower() in doc.lower(), f"golden-case documentation missing {marker!r}")
    for marker in ("strict complete-evidence policy", "EPSS probability only", "RBVM Relative Risk Index"):
        require(marker.lower() in decisions.lower(), f"readiness decisions missing {marker!r}")
    for marker in ("RBVM_FORMULA_CANONICAL_BINARY_V1", "RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1"):
        require(marker in canonical, f"canonicalization contract missing {marker}")

    print(f"Formula golden-case checks: PASS generated_state_cases={generated} explicit_cases={len(all_case_ids)}")


if __name__ == "__main__":
    main()
