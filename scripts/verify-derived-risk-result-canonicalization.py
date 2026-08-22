#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/main/java/io/rbvm/decision/RbvmDerivedRiskCanonicalResult.java"
TEST = ROOT / "src/test/java/io/rbvm/decision/RbvmDerivedRiskCanonicalResultSelfTest.java"
DOC = ROOT / "docs/DERIVED_RISK_RESULT_CANONICALIZATION_V1.md"

source = SOURCE.read_text(encoding="utf-8")
test = TEST.read_text(encoding="utf-8")
doc = DOC.read_text(encoding="utf-8")

required_source = [
    'RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1',
    'RbvmDecisionInputSnapshot.V3_ID',
    'definition.methodologyId()',
    'definition.methodologySha256()',
    'definition.sourceEquation()',
    'value.inputSnapshotSha256()',
    'value.findingId()',
    'value.state().name()',
    'value.numericScore()',
    'value.numericScale()',
    'value.rating()',
    'Comparator',
    'duplicate measureId',
    'MessageDigest.getInstance("SHA-256")',
]
for token in required_source:
    assert token in source, f"missing canonicalization source invariant: {token}"

for forbidden in [
    'FormulaResultStore',
    'Postgres',
    'current_',
    'latest',
    'Priority',
    'SLA',
]:
    assert forbidden not in source, f"forbidden canonicalization coupling: {forbidden}"

required_test = [
    '1260c23be5c03990440af13650797d382d640f77f0cc358fd1fd92dc4cdea13d',
    'canonicalPayload().length == 981',
    'normalizesMeasureOrderWithoutChangingSemantics',
    'preservesTerminalNonNumericSemantics',
    'expected duplicate measure rejection',
    'expected V3 input requirement',
]
for token in required_test:
    assert token in test, f"missing canonicalization acceptance check: {token}"

required_doc = [
    'RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1',
    'IMPLEMENTED_DOMAIN_ONLY',
    'inputSnapshotSha256',
    'methodologyId',
    'methodologySha256',
    'canonicalResultSha256',
    'byte-identical',
    'Existing `RBVM_FORMULA_V1` rows',
]
for token in required_doc:
    assert token in doc, f"missing canonicalization documentation invariant: {token}"

print("Derived risk result canonicalization structural checks: PASS")
