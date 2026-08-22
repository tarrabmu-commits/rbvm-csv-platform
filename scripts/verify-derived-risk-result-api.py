#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
api = (ROOT / "src/main/java/io/rbvm/csv/DerivedRiskResultApi.java").read_text()
factory = (ROOT / "src/main/java/io/rbvm/postgres/DerivedRiskResultRuntimeFactory.java").read_text()
test = (ROOT / "src/test/java/io/rbvm/csv/DerivedRiskResultApiSelfTest.java").read_text()
doc = (ROOT / "docs/DERIVED_RISK_RESULT_API_V1.md").read_text()

for marker in [
    "RBVM_DERIVED_RISK_RESULT_API_V1",
    "RBVM_DERIVED_RISK_METHODOLOGY_CATALOG_API_V1",
    "RBVM_DERIVED_RISK_RESULT_MATERIALIZATION_API_V1",
    "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT",
    "getByResultSha256",
    "getByInputSnapshotAndMethodology",
    "materialize(",
    "resultSha256",
    "inputSnapshotSha256",
    "methodologyId",
    "methodologySha256",
    "replayVerifier.replay",
    "canonicalPayloadBase64",
    "strongEtag",
]:
    assert marker in api, f"derived risk API invariant missing {marker!r}"

for forbidden in [
    "latest",
    "current_",
    "preferredMethodology",
    "defaultMethodology",
    "definitions().get(0)",
    "Priority",
    "SLA",
    "Treatment",
]:
    assert forbidden not in api, f"derived risk API contains forbidden construct {forbidden!r}"

assert "REQUIRED_SCHEMA_VERSION = 24" in factory
for marker in [
    "PostgresDerivedRiskResultStore",
    "PostgresDecisionInputSnapshotStore",
    "PostgresDecisionInputEvidenceResolver",
    "DerivedRiskResultReplayVerifier",
    "DefaultDerivedRiskResultMaterializer",
]:
    assert marker in factory, f"derived risk runtime factory missing {marker!r}"

for marker in [
    "exposesCatalogWithoutDefaultSemantics",
    "materializesAndReadsExactMethodologyIdentities",
    "rejectsInvalidMissingAndNonCanonicalMethodologyIdentities",
    "fixture.store().size() == 2",
    "owasp_derived_rbvm_v1",
    "canonicalPayloadBase64",
]:
    assert marker in test, f"derived risk API self-test missing {marker!r}"

for marker in [
    "EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT",
    "There is no `latest`, `current`, or preferred-result selector",
    "does not define HTTP transport",
    "primary/preferred methodology",
    "cross-methodology averaging or normalization",
    "Priority",
    "Treatment",
    "SLA",
]:
    assert marker in doc, f"derived risk API documentation missing {marker!r}"

print("Derived risk result API structural checks: PASS")
