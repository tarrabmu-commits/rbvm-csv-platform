#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = (ROOT / "docs/RBVM_FORMULA_CANONICALIZATION_V1.md").read_text(encoding="utf-8")
RUNTIME = (ROOT / "src/main/java/io/rbvm/decision/RbvmFormulaV1Explanation.java").read_text(encoding="utf-8")
SELF_TEST = (ROOT / "src/test/java/io/rbvm/decision/RbvmFormulaV1ExplanationSelfTest.java").read_text(encoding="utf-8")
PLATFORM_TEST = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


require("RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1" in CANONICAL,
        "canonicalization contract no longer defines Formula explanation V1")
require('PAYLOAD_FORMAT =\n            "RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1"' in RUNTIME,
        "runtime explanation payload format drifted")
require("RbvmFormulaV1.evaluate(input)" in RUNTIME,
        "explanation must bind to the deterministic Formula evaluation for the exact input")
require("if (!expected.equals(result))" in RUNTIME,
        "explanation must reject a result that does not match the exact input")
require("if (!input.snapshot().isV3())" in RUNTIME,
        "explanation must accept Decision Input V3 only")
require("for (EvidenceDimension dimension : EvidenceDimension.values())" in RUNTIME,
        "explanation dimensions must use the fixed EvidenceDimension order")

for provenance_field in (
    "reference.nativeEvidenceKind().name()",
    "reference.evidenceId().toString()",
    "reference.evidenceSha256()",
    "reference.evidenceSource()",
    "reference.observedAt().toString()",
    "binding.bindingKind().name()",
    "binding.bindingId().toString()",
    "binding.bindingSha256()",
    "binding.bindingSource()",
    "binding.recordedAt().toString()",
):
    require(provenance_field in RUNTIME,
            f"canonical explanation missing provenance field {provenance_field}")

for top_level_field in (
    "formulaId",
    "formulaVersion",
    "formulaSha256",
    "inputContractId",
    "inputSnapshotSha256",
    "findingId",
    "evaluatedAt",
    "methodologyRevision",
    "methodologyPolicySha256",
    "reasonCodes",
    "finalRiskResult",
):
    require(top_level_field in RUNTIME,
            f"canonical explanation missing top-level semantic {top_level_field}")

require("finalRiskResult == null ? null : canonicalDecimalText(finalRiskResult)" in RUNTIME,
        "final Formula result must use canonical decimal text in explanation bytes")
require("return canonicalPayload.clone();" in RUNTIME,
        "canonical explanation bytes must not expose mutable internal state")
require("MessageDigest.getInstance(\"SHA-256\")" in RUNTIME,
        "canonical explanation identity must have SHA-256")

for forbidden in (
    "PriorityTier",
    "Sla",
    "Treatment",
    "Remediation",
    "current_",
    "SELECT ",
    "INSERT ",
    "UPDATE ",
):
    require(forbidden not in RUNTIME,
            f"canonical explanation crossed its pure provenance boundary: {forbidden!r}")

for required_test in (
    "canonicalizesComputedExplanationDeterministically",
    "preservesTerminalExplanationWithoutNumericSubstitutes",
    "bindsExplanationIdentityToExactEvidenceProvenance",
    "rejectsAResultNotProducedByTheExactInput",
    '"45.00"',
    '"NOT_APPLICABLE"',
    '"EXPLOITATION_PROBABILITY_MISSING"',
    "FINDING_REACHABILITY_SCOPE_LINK_EVENT",
    "!left.canonicalSha256().equals(right.canonicalSha256())",
):
    require(required_test in SELF_TEST,
            f"Formula explanation self-test missing {required_test!r}")

require("RbvmFormulaV1ExplanationSelfTest.main(args);" in PLATFORM_TEST,
        "Formula explanation self-test must run in PlatformSelfTest")

print("RBVM Formula V1 canonical explanation structural checks: PASS")
