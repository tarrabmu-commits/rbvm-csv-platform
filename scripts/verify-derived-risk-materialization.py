#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

materializer = (ROOT / "src/main/java/io/rbvm/postgres/DefaultDerivedRiskResultMaterializer.java").read_text()
contract = (ROOT / "src/main/java/io/rbvm/postgres/DerivedRiskResultMaterializer.java").read_text()
result = (ROOT / "src/main/java/io/rbvm/postgres/DerivedRiskResultMaterializationResult.java").read_text()
self_test = (ROOT / "src/test/java/io/rbvm/postgres/DefaultDerivedRiskResultMaterializerSelfTest.java").read_text()
live = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV24DerivedRiskLiveSelfTest.java").read_text()
doc = (ROOT / "docs/DERIVED_RISK_RESULT_MATERIALIZATION_V1.md").read_text()

for marker in [
    "inputSnapshotSha256",
    "methodologyId",
    "methodologySha256",
]:
    assert marker in contract, f"derived materializer contract missing explicit selector {marker}"

for marker in [
    "snapshots.findBySha256",
    "snapshot.isV3()",
    "RbvmDerivedRiskMethodologyCatalog",
    "definition.methodologyId().equals(requestedMethodologyId)",
    "definition.methodologySha256().equals(methodologySha)",
    "evidenceResolver.resolve(snapshot)",
    "methodology.evaluate(resolved)",
    "RbvmDerivedRiskCanonicalResult.from",
    "results.install(canonicalResult)",
    "RESULT_CONFLICT",
    "findByResultSha256",
    "replayVerifier.replay",
]:
    assert marker in materializer, f"derived materializer invariant missing {marker!r}"

for forbidden in [
    "DecisionInputSnapshotBuilder",
    "current_",
    "findLatest",
    "latest(",
    "METHODOLOGIES.get(0)",
    "definitions().get(0)",
    "Priority",
    "SLA",
    "Treatment",
]:
    assert forbidden not in materializer, f"derived materializer contains forbidden construct {forbidden!r}"

assert "installedOrReplayed" in result
assert "methodologyId" in result
assert "methodologySha256" in result

for marker in [
    "materializesTwoExplicitMethodologiesWithoutDefault",
    "MethodologyNotFoundException",
    "MethodologyIdentityMismatchException",
    "resultStore.size() == 2",
]:
    assert marker in self_test, f"derived materializer self-test missing {marker!r}"

for marker in [
    "DefaultDerivedRiskResultMaterializer",
    "materializer.materialize",
    "Status.INSERTED",
    "Status.REPLAYED",
    "methodologies=2",
]:
    assert marker in live, f"live derived materializer proof missing {marker!r}"

for marker in [
    "Catalog order is never used as a default",
    "does not expose HTTP transport",
    "preferred/default methodology",
    "cross-methodology normalized score",
    "Priority",
    "Treatment",
    "SLA",
]:
    assert marker in doc, f"derived materialization documentation missing {marker!r}"

print("Derived risk result materialization structural checks: PASS")
