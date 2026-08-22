#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
decisions = (ROOT / "docs/RBVM_FORMULA_READINESS_DECISIONS_V1.md").read_text(encoding="utf-8")
readiness = (ROOT / "docs/RBVM_FORMULA_READINESS_V1.md").read_text(encoding="utf-8")
v3 = (ROOT / "docs/DECISION_INPUT_V3.md").read_text(encoding="utf-8")

required_decisions = (
    "RBVM_FORMULA_READINESS_DECISIONS_V1",
    "APPROVED_FOR_GOLDEN_CASE_DESIGN",
    "COMPUTED",
    "NOT_APPLICABLE",
    "NON_COMPUTABLE",
    "APPLICABILITY_UNKNOWN",
    "APPLICABILITY_MISSING",
    "strict complete-evidence policy",
    "EPSS probability only",
    "EPSS_Percentile` is excluded",
    "must not directly multiply CVSS Base by EPSS probability",
    "Business_Criticality",
    "BUSINESS_CRITICALITY_UNKNOWN",
    "REACHABILITY_MULTI_SUBGRAIN",
    "BUSINESS_IMPACT_MULTI_SERVICE",
    "multiple distinct impact dimensions are allowed",
    "compensating-control effectiveness is **outside Formula V1**",
    "RBVM Relative Risk Index",
    "0.00 .. 100.00",
    "RBVM_DECISION_INPUT_SNAPSHOT_V3",
    "deterministic machine-readable explanation",
    "The only remaining pre-Formula gate is **Stage 8",
)
for marker in required_decisions:
    if marker.lower() not in decisions.lower():
        raise AssertionError(f"Formula readiness decision missing {marker!r}")

for state in ("MISSING", "STALE", "AMBIGUOUS"):
    if f"`{state}` -> `NON_COMPUTABLE" not in decisions:
        raise AssertionError(f"strict evidence-quality gate missing {state}")

for forbidden in (
    "MISSING => 0",
    "STALE => latest current row",
    "AMBIGUOUS => highest numeric value",
):
    if forbidden not in readiness:
        raise AssertionError(f"baseline readiness invariant disappeared: {forbidden}")

for marker in (
    "Finding↔Reachability Scope",
    "Finding↔Business Service",
    "same scanner asset",
):
    if marker not in v3:
        raise AssertionError(f"Decision Input V3 association invariant missing {marker!r}")

# Stage 7 must remain policy-only. Numeric Formula constants beyond the approved output
# scale, weights and thresholds belong to the later Formula artifact, not this contract.
for forbidden in (
    "priority tier mapping",
    "SLA_30_DAYS",
    "PATCH_IN_3_DAYS",
    "formula equation =",
):
    if forbidden.lower() in decisions.lower():
        raise AssertionError(f"Stage 7 leaked later policy/scoring construct {forbidden!r}")

print("Formula readiness final decision checks: PASS")
