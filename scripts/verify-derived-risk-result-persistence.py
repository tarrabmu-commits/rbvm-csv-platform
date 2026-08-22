#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

migration = (ROOT / "db/migration/V24__derived_risk_result_persistence.sql").read_text()
security = (ROOT / "db/security/runtime-role.sql").read_text()
migrator = (ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text()
store = (ROOT / "src/main/java/io/rbvm/postgres/PostgresDerivedRiskResultStore.java").read_text()
replay = (ROOT / "src/main/java/io/rbvm/postgres/DerivedRiskResultReplayVerifier.java").read_text()
stored = (ROOT / "src/main/java/io/rbvm/postgres/StoredDerivedRiskResult.java").read_text()
live = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV24DerivedRiskLiveSelfTest.java").read_text()
doc = (ROOT / "docs/DERIVED_RISK_RESULT_PERSISTENCE_V1.md").read_text()

required_migration = [
    "CREATE TABLE rbvm.derived_risk_result",
    "RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1",
    "UNIQUE (tenant_id, result_sha256)",
    "FOREIGN KEY (tenant_id, input_snapshot_sha256, finding_id)",
    "REFERENCES rbvm.decision_input_snapshot(tenant_id, snapshot_sha256, finding_id)",
    "methodology_id",
    "methodology_version",
    "methodology_sha256",
    "result_state",
    "numeric_score",
    "numeric_scale",
    "rating",
]
for marker in required_migration:
    assert marker in migration, f"missing V24 migration marker: {marker}"

assert "new Migration(24, \"V24__derived_risk_result_persistence.sql\")" in migrator
assert "rbvm.derived_risk_result" in security
assert "REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.derived_risk_result" in security

assert "REQUIRED_SCHEMA_VERSION = 24" in store
assert "RbvmDerivedRiskCanonicalResult" in store
assert "RbvmDerivedRiskMethodologyCatalog" in store
assert "RESULT_CONFLICT" in store
assert "decision_input_snapshot" in store
assert "RBVM_DECISION_INPUT_SNAPSHOT_V3" in store or "V3_ID" in store
assert "implemented.equals(supplied)" in store
assert "definition does not match the implemented identity" in store
assert "formula_result" not in store, "derived persistence must not reuse Formula V1 table"

assert "DecisionInputEvidenceResolver" in replay
assert "findBySha256" in replay
assert "RbvmDerivedRiskMethodologyCatalog" in replay
assert "canonicalPayload" in replay
assert "current_" not in replay
assert "latest" not in replay.lower()
assert "current_" not in store
assert "latest" not in store.lower()

assert "RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1" in stored
assert "resultSha256 does not match canonical payload bytes" in stored

for marker in [
    "PostgresV24DerivedRiskLiveSelfTest",
    "DerivedRiskResultInstallResult.Status.INSERTED",
    "DerivedRiskResultInstallResult.Status.REPLAYED",
    "verifyBySnapshotAndMethodology",
    "UPDATE rbvm.derived_risk_result",
    "DELETE FROM rbvm.derived_risk_result",
    "TRUNCATE rbvm.derived_risk_result",
]:
    assert marker in live, f"missing live V24 proof marker: {marker}"

for marker in [
    "does not introduce HTTP transport",
    "methodology preference",
    "cross-methodology averaging",
    "Priority",
    "Treatment",
    "SLA",
]:
    assert marker in doc, f"derived persistence boundary missing documentation marker: {marker}"

print("Derived risk result persistence structural checks: PASS")
