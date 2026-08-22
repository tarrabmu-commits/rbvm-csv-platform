#!/usr/bin/env python3
import copy
import hashlib
import json
import re
import struct
from decimal import Decimal, InvalidOperation, localcontext, ROUND_HALF_EVEN
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMULA_PATH = ROOT / "docs/fixtures/RBVM_FORMULA_V1.json"
EXPECTED_PATH = ROOT / "docs/fixtures/RBVM_FORMULA_V1_EXPECTED_RESULTS.json"
GOLDEN_PATH = ROOT / "docs/fixtures/RBVM_FORMULA_GOLDEN_CASES_V1.json"
DOC_PATH = ROOT / "docs/RBVM_FORMULA_V1.md"

CANONICAL_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$")
STATE_BLOCKERS = {"MISSING", "STALE", "AMBIGUOUS"}
EXPECTED_FACTOR_IDS = [
    "CVSS_V31_BASE",
    "EPSS_PROBABILITY",
    "CISA_KEV_MEMBERSHIP",
    "REACHABILITY_STATUS",
    "BUSINESS_CRITICALITY",
    "BUSINESS_IMPACT_LEVEL",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def decimal(value: str, path: str) -> Decimal:
    require(isinstance(value, str), f"{path} must be a canonical decimal string")
    require(CANONICAL_DECIMAL.fullmatch(value) is not None,
            f"{path} is not canonical decimal text: {value!r}")
    try:
        return Decimal(value)
    except InvalidOperation as exc:
        raise AssertionError(f"invalid decimal {path}: {value!r}") from exc


def enc_string(value: str) -> bytes:
    raw = value.encode("utf-8")
    return struct.pack(">I", len(raw)) + raw


def enc_i32(value: int) -> bytes:
    return struct.pack(">i", value)


def enc_map(values: dict[str, str]) -> bytes:
    out = [struct.pack(">I", len(values))]
    for key, value in sorted(values.items()):
        decimal(value, f"canonical map {key}")
        out.extend((enc_string(key), enc_string(value)))
    return b"".join(out)


def enc_nullable_string(value: str | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + enc_string(value)


def enc_factor(factor: dict) -> bytes:
    return b"".join((
        enc_i32(factor["ordinal"]),
        enc_string(factor["factorId"]),
        enc_string(factor["dimension"]),
        enc_string(factor["weight"]),
        enc_string(factor["transformId"]),
        enc_map(factor["parameters"]),
        enc_map(factor["mapping"]),
        enc_nullable_string(factor["reducerId"]),
    ))


def enc_rule(rule: dict) -> bytes:
    return b"".join((
        enc_i32(rule["ordinal"]),
        enc_string(rule["ruleId"]),
        enc_string(rule["ruleType"]),
        enc_map(rule["parameters"]),
    ))


def enc_list(values: list, encoder) -> bytes:
    return struct.pack(">I", len(values)) + b"".join(encoder(value) for value in values)


def canonical_formula_bytes(formula: dict) -> bytes:
    factors = sorted(formula["factors"], key=lambda item: item["ordinal"])
    rules = sorted(formula["rules"], key=lambda item: item["ordinal"])
    extensions = formula["reservedExtensions"]
    return b"".join((
        enc_string(formula["canonicalPayloadFormatId"]),
        enc_string(formula["formulaId"]),
        enc_i32(formula["formulaVersion"]),
        enc_string(formula["formulaSemantics"]),
        enc_string(formula["inputContractId"]),
        enc_string(formula["outputName"]),
        enc_string(formula["outputMinimum"]),
        enc_string(formula["outputMaximum"]),
        enc_i32(formula["outputDisplayScale"]),
        enc_string(formula["arithmeticPolicy"]),
        enc_string(formula["roundingMode"]),
        enc_string(formula["applicabilityGatePolicy"]),
        enc_string(formula["evidenceStatePolicy"]),
        enc_string(formula["multiSubgrainPolicy"]),
        enc_list(factors, enc_factor),
        enc_list(rules, enc_rule),
        enc_string(formula["explanationSchemaId"]),
        enc_list(extensions, enc_string),
    ))


def set_path(profile: dict, dotted: str, value) -> None:
    parts = dotted.split(".")
    cursor = profile
    for part in parts[:-1]:
        require(part in cursor and isinstance(cursor[part], dict), f"invalid golden path {dotted!r}")
        cursor = cursor[part]
    require(parts[-1] in cursor, f"invalid golden path {dotted!r}")
    cursor[parts[-1]] = copy.deepcopy(value)


def apply_changes(base: dict, changes: dict) -> dict:
    profile = copy.deepcopy(base)
    for path, value in changes.items():
        set_path(profile, path, value)
    return profile


def eligibility(profile: dict) -> tuple[str, str | None]:
    app = profile["applicability"]
    state = app["state"]
    if state in STATE_BLOCKERS:
        return "NON_COMPUTABLE", f"APPLICABILITY_{state}"
    require(state == "PRESENT", "unexpected Applicability state")
    if app["status"] == "NOT_APPLICABLE":
        return "NOT_APPLICABLE", "NOT_APPLICABLE"
    if app["status"] == "UNKNOWN":
        return "NON_COMPUTABLE", "APPLICABILITY_UNKNOWN"
    require(app["status"] == "APPLICABLE", "unexpected Applicability value")

    dimensions = (
        ("technicalSeverity", "TECHNICAL_SEVERITY"),
        ("knownExploitation", "KNOWN_EXPLOITATION"),
        ("exploitProbability", "EXPLOITATION_PROBABILITY"),
        ("assetContext", "ASSET_CONTEXT"),
        ("reachability", "NETWORK_REACHABILITY"),
        ("businessImpact", "BUSINESS_MISSION_IMPACT"),
    )
    for key, prefix in dimensions:
        state = profile[key]["state"]
        if state in STATE_BLOCKERS:
            return "NON_COMPUTABLE", f"{prefix}_{state}"
        require(state == "PRESENT", f"unexpected state for {key}")

    if profile["knownExploitation"]["status"] == "UNKNOWN":
        return "NON_COMPUTABLE", "KEV_VALUE_UNKNOWN"
    if profile["assetContext"]["businessCriticality"] == "UNKNOWN":
        return "NON_COMPUTABLE", "BUSINESS_CRITICALITY_UNKNOWN"

    subgrains = profile["reachability"]["subgrains"]
    if len(subgrains) != 1:
        return "NON_COMPUTABLE", "REACHABILITY_MULTI_SUBGRAIN"
    if subgrains[0]["status"] == "UNKNOWN":
        return "NON_COMPUTABLE", "REACHABILITY_VALUE_UNKNOWN"

    impacts = profile["businessImpact"]["impacts"]
    services = {item["businessService"].strip().lower() for item in impacts}
    if len(services) != 1:
        return "NON_COMPUTABLE", "BUSINESS_IMPACT_MULTI_SERVICE"
    if any(item["impactLevel"] == "UNKNOWN" for item in impacts):
        return "NON_COMPUTABLE", "BUSINESS_IMPACT_VALUE_UNKNOWN"

    return "COMPUTED", None


def factor_by_id(formula: dict, factor_id: str) -> dict:
    matches = [item for item in formula["factors"] if item["factorId"] == factor_id]
    require(len(matches) == 1, f"Formula must contain exactly one factor {factor_id}")
    return matches[0]


def map_value(factor: dict, key: str) -> Decimal:
    require(key in factor["mapping"], f"{factor['factorId']} missing mapping for {key}")
    return decimal(factor["mapping"][key], f"{factor['factorId']}.{key}")


def evaluate_computed(formula: dict, profile: dict) -> Decimal:
    state, reason = eligibility(profile)
    require(state == "COMPUTED" and reason is None, f"profile is not computable: {state}/{reason}")

    cvss = factor_by_id(formula, "CVSS_V31_BASE")
    epss = factor_by_id(formula, "EPSS_PROBABILITY")
    kev = factor_by_id(formula, "CISA_KEV_MEMBERSHIP")
    reach = factor_by_id(formula, "REACHABILITY_STATUS")
    criticality = factor_by_id(formula, "BUSINESS_CRITICALITY")
    impact = factor_by_id(formula, "BUSINESS_IMPACT_LEVEL")

    divisor = decimal(cvss["parameters"]["divisor"], "CVSS divisor")
    normalized = {
        "CVSS_V31_BASE": decimal(profile["technicalSeverity"]["cvssBase"], "cvssBase") / divisor,
        "EPSS_PROBABILITY": decimal(profile["exploitProbability"]["probability"], "EPSS probability"),
        "CISA_KEV_MEMBERSHIP": map_value(kev, profile["knownExploitation"]["status"]),
        "REACHABILITY_STATUS": map_value(reach, profile["reachability"]["subgrains"][0]["status"]),
        "BUSINESS_CRITICALITY": map_value(criticality, profile["assetContext"]["businessCriticality"]),
    }
    impact_values = [map_value(impact, item["impactLevel"]) for item in profile["businessImpact"]["impacts"]]
    require(impact["reducerId"] == "MAX_MAPPED_IMPACT_LEVEL_PER_SERVICE_V1",
            "Business Impact reducer must be explicit MAX policy")
    normalized["BUSINESS_IMPACT_LEVEL"] = max(impact_values)

    with localcontext() as ctx:
        ctx.prec = 34
        ctx.rounding = ROUND_HALF_EVEN
        raw = Decimal("0")
        for factor in formula["factors"]:
            value = normalized[factor["factorId"]]
            require(Decimal("0") <= value <= Decimal("1"),
                    f"{factor['factorId']} normalized value outside [0,1]")
            raw += decimal(factor["weight"], f"{factor['factorId']}.weight") * value
        require(Decimal("0") <= raw <= Decimal("1"), "Formula raw result outside [0,1]")
        scaled = raw * decimal(formula["rules"][0]["parameters"]["scale"], "output scale")
        return scaled.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)


def main() -> None:
    formula = json.loads(FORMULA_PATH.read_text(encoding="utf-8"))
    expected = json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))
    golden = json.loads(GOLDEN_PATH.read_text(encoding="utf-8"))
    doc = DOC_PATH.read_text(encoding="utf-8")

    require(formula["formulaId"] == "RBVM_FORMULA_V1", "wrong Formula ID")
    require(formula["formulaVersion"] == 1, "wrong Formula version")
    require(formula["formulaSemantics"] == "WEIGHTED_ADDITIVE_RELATIVE_RISK_INDEX_V1",
            "unexpected Formula semantics")
    require(formula["inputContractId"] == "RBVM_DECISION_INPUT_SNAPSHOT_V3",
            "Formula V1 must consume Decision Input V3")
    require(formula["outputName"] == "RBVM Relative Risk Index", "wrong output name")
    require(formula["outputMinimum"] == "0" and formula["outputMaximum"] == "100",
            "Formula bounds must be 0..100")
    require(formula["outputDisplayScale"] == 2, "Formula output scale must be 2")
    require(formula["arithmeticPolicy"] == "DECIMAL_PRECISION_34", "wrong precision policy")
    require(formula["roundingMode"] == "HALF_EVEN", "wrong rounding mode")
    require(formula["reservedExtensions"] == [], "Formula V1 reserved extensions must be empty")

    factors = sorted(formula["factors"], key=lambda item: item["ordinal"])
    require([item["ordinal"] for item in factors] == list(range(1, 7)),
            "Formula factors must use contiguous ordinals 1..6")
    require([item["factorId"] for item in factors] == EXPECTED_FACTOR_IDS,
            "Formula factor order/identity drifted")
    require(sum(decimal(item["weight"], f"weight {item['factorId']}") for item in factors) == Decimal("1"),
            "Formula factor weights must sum exactly to 1")

    serialized_formula = json.dumps(formula, sort_keys=True)
    for forbidden in ("percentile", "environment", "businessOwner", "priority", "sla", "treatment"):
        require(forbidden.lower() not in serialized_formula.lower(),
                f"Formula arithmetic artifact leaked excluded concept {forbidden!r}")

    payload = canonical_formula_bytes(formula)
    actual_sha = hashlib.sha256(payload).hexdigest()
    require(len(payload) == formula["canonicalPayloadByteLength"],
            f"canonical Formula payload length mismatch: {len(payload)}")
    require(actual_sha == formula["formulaSha256"],
            f"Formula SHA mismatch: expected {formula['formulaSha256']}, got {actual_sha}")
    require(expected["formulaSha256"] == actual_sha, "expected-result fixture Formula SHA drifted")

    require("RBVM_POLICY" in doc, "Formula contract must classify numeric policy explicitly")
    require("not claimed to be statistically fitted or standards-mandated" in doc,
            "Formula contract must not overclaim weight authority")
    require("NOT_LISTED -> 0" in doc and "zero contribution from this categorical Formula factor only" in doc,
            "KEV zero-contribution semantics must be explicit")
    require("NOT_REACHABLE -> 0" in doc and "does not zero the Finding Risk Result" in doc,
            "Reachability zero-contribution semantics must be explicit")

    base = golden["baseProfile"]
    require(evaluate_computed(formula, base) == Decimal(expected["computedOutputs"]["BASE_PROFILE"]),
            "base profile numeric result drifted")

    profiles = {"BASE_PROFILE": base}
    for section in ("terminalValueCases", "structuralCases", "namedComputedProfiles"):
        for case in golden[section]:
            profiles[case["id"]] = apply_changes(base, case["changes"])

    # Preserve every Stage 8 terminal/state gate.
    matrix = golden["parameterizedStateMatrix"]
    dim_keys = {
        "APPLICABILITY": "applicability",
        "TECHNICAL_SEVERITY": "technicalSeverity",
        "KNOWN_EXPLOITATION": "knownExploitation",
        "EXPLOITATION_PROBABILITY": "exploitProbability",
        "ASSET_CONTEXT": "assetContext",
        "NETWORK_REACHABILITY": "reachability",
        "BUSINESS_MISSION_IMPACT": "businessImpact",
    }
    for dimension in matrix["dimensions"]:
        for state in matrix["states"]:
            profile = copy.deepcopy(base)
            profile[dim_keys[dimension]]["state"] = state
            actual_state, _ = eligibility(profile)
            require(actual_state == "NON_COMPUTABLE", f"{dimension}/{state} must remain NON_COMPUTABLE")

    for case in golden["terminalValueCases"] + golden["structuralCases"]:
        profile = profiles[case["id"]]
        state, reason = eligibility(profile)
        require(state == case["resultState"], f"{case['id']} result state drifted")
        if "reasonCode" in case:
            require(reason == case["reasonCode"], f"{case['id']} reason code drifted: {reason}")

    # Freeze exact outputs selected by this Formula identity.
    for case_id, value in expected["computedOutputs"].items():
        actual = evaluate_computed(formula, profiles[case_id])
        require(actual == Decimal(value), f"{case_id} expected {value}, got {actual}")

    # Stage 8 requires every Formula-relevant controlled pair to increase materially.
    for pair in golden["materialSensitivityPairs"]:
        low = evaluate_computed(formula, apply_changes(base, pair["lowChanges"]))
        high = evaluate_computed(formula, apply_changes(base, pair["highChanges"]))
        require(high > low, f"{pair['id']} must be strictly risk-increasing: {low} -> {high}")

    # Fields explicitly excluded from Formula V1 arithmetic must be exactly score-neutral.
    for pair in golden["arithmeticExclusionPairs"]:
        left = evaluate_computed(formula, apply_changes(base, pair["leftChanges"]))
        right = evaluate_computed(formula, apply_changes(base, pair["rightChanges"]))
        require(left == right, f"{pair['id']} excluded field changed Formula result: {left} != {right}")

    all_adverse = evaluate_computed(formula, profiles["GC-ALL-ADVERSE"])
    require(all_adverse > evaluate_computed(formula, base), "all-adverse profile must dominate base")

    for tradeoff in expected["resolvedTradeoffs"]:
        higher = evaluate_computed(formula, profiles[tradeoff["higher"]])
        lower = evaluate_computed(formula, profiles[tradeoff["lower"]])
        require(tradeoff["relation"] == "GREATER_THAN" and higher > lower,
                f"resolved tradeoff {tradeoff['higher']} > {tradeoff['lower']} failed")

    # Exact replay with decimal arithmetic must be deterministic.
    first = evaluate_computed(formula, profiles["GC-ALL-ADVERSE"])
    second = evaluate_computed(formula, copy.deepcopy(profiles["GC-ALL-ADVERSE"]))
    require(first == second, "Formula replay is not deterministic")

    print(
        "RBVM Formula V1 proposal checks: PASS "
        f"sha256={actual_sha} base={evaluate_computed(formula, base):.2f} "
        f"all_adverse={all_adverse:.2f}"
    )


if __name__ == "__main__":
    main()
