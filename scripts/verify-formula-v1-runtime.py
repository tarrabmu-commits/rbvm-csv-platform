#!/usr/bin/env python3
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FORMULA = json.loads((ROOT / "docs/fixtures/RBVM_FORMULA_V1.json").read_text(encoding="utf-8"))
RUNTIME = (ROOT / "src/main/java/io/rbvm/decision/RbvmFormulaV1.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/decision/RbvmFormulaV1SelfTest.java").read_text(encoding="utf-8")
PLATFORM_TEST = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
DOC = (ROOT / "docs/RBVM_FORMULA_V1.md").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


require(FORMULA["formulaId"] == "RBVM_FORMULA_V1", "wrong Formula artifact")
require(FORMULA["inputContractId"] == "RBVM_DECISION_INPUT_SNAPSHOT_V3",
        "Formula artifact must target Decision Input V3")
require(FORMULA["formulaSha256"] in RUNTIME,
        "runtime Formula SHA must match canonical Formula artifact")
require('FORMULA_ID = "RBVM_FORMULA_V1"' in RUNTIME,
        "runtime Formula ID is not fixed")
require("FORMULA_VERSION = 1" in RUNTIME,
        "runtime Formula version is not fixed")
require('OUTPUT_NAME = "RBVM Relative Risk Index"' in RUNTIME,
        "runtime output name drifted")
require("snapshot.isV3()" in RUNTIME and "accepts only RBVM_DECISION_INPUT_SNAPSHOT_V3" in RUNTIME,
        "runtime must reject non-V3 Decision Inputs")
require(re.search(r"new\s+MathContext\(34\s*,\s*RoundingMode\.HALF_EVEN\)", RUNTIME) is not None,
        "runtime decimal precision/rounding drifted")
require("setScale(2, RoundingMode.HALF_EVEN)" in RUNTIME,
        "runtime output rounding/scale drifted")

for factor in FORMULA["factors"]:
    require(f'"{factor["factorId"]}"' in RUNTIME,
            f"runtime missing Formula factor {factor['factorId']}")

for accessor in (".percentile()", ".environment()", ".businessOwner()", ".businessService()"):
    require(accessor not in RUNTIME,
            f"Formula runtime arithmetic leaked excluded accessor {accessor}")

for required_test in (
    'assertComputed(base, "45.00")',
    '"95.60"',
    '"49.80"',
    '"70.00"',
    '"27.50"',
    '"60.00"',
    '"48.75"',
    "DimensionState.MISSING",
    "DimensionState.STALE",
    "DimensionState.AMBIGUOUS",
    "REACHABILITY_MULTI_SUBGRAIN",
    "BUSINESS_IMPACT_MULTI_SERVICE",
    "APPLICABILITY_UNKNOWN",
    "BUSINESS_CRITICALITY_UNKNOWN",
    "REACHABILITY_VALUE_UNKNOWN",
    "BUSINESS_IMPACT_VALUE_UNKNOWN",
):
    require(required_test in SELF_TEST,
            f"Formula runtime self-test missing {required_test!r}")

require("RbvmFormulaV1SelfTest.main(args);" in PLATFORM_TEST,
        "Formula evaluator self-test must run in PlatformSelfTest")
require("Status: `ACCEPTED`" in DOC,
        "Formula contract status must reflect accepted identity")
require("io.rbvm.decision.RbvmFormulaV1" in DOC,
        "Formula contract must identify the accepted runtime evaluator")
require("RBVM_FORMULA_V1 Pure Evaluator" in README,
        "README must expose the current Formula runtime boundary")
require("Formula result               = Priority / SLA / Treatment" in README,
        "README must preserve explicit Formula/priority separation")
require("Risk Formula, priority, treatment, SLA" not in README,
        "README contains the stale pre-Formula roadmap boundary")
require("Formula result               = Priority / SLA / Treatment" not in RUNTIME,
        "runtime must not emit downstream policy")

print(
    "RBVM Formula V1 runtime structural checks: PASS "
    f"sha256={FORMULA['formulaSha256']}"
)
