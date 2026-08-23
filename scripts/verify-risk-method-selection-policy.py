#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

contract = (ROOT / "src/main/java/io/rbvm/decision/RbvmRiskMethodSelectionPolicy.java").read_text()
self_test = (ROOT / "src/test/java/io/rbvm/decision/RbvmRiskMethodSelectionPolicySelfTest.java").read_text()
migration = (ROOT / "db/migration/V25__risk_method_selection_policy.sql").read_text()
store = (ROOT / "src/main/java/io/rbvm/postgres/PostgresRiskMethodSelectionPolicyStore.java").read_text()
store_api = (ROOT / "src/main/java/io/rbvm/postgres/RiskMethodSelectionPolicyStore.java").read_text()
security = (ROOT / "db/security/runtime-role.sql").read_text()
migrator = (ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text()
live = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV25RiskMethodSelectionPolicyLiveSelfTest.java").read_text()
workflow = (ROOT / ".github/workflows/postgres-integration.yml").read_text()
doc = (ROOT / "docs/RISK_METHOD_SELECTION_POLICY_V1.md").read_text()
normalized_doc = " ".join(doc.split())

for marker in [
    'ID = "RBVM_RISK_METHOD_SELECTION_POLICY_V1"',
    'SEMANTICS =',
    'TENANT_SCOPED_EXPLICIT_PRIMARY_RISK_METHOD_EXACT_IDENTITY',
    'RBVM_RISK_METHOD_SELECTION_POLICY_CANONICAL_BINARY_V1',
    'PRIMARY',
    'RBVM_FORMULA',
    'STANDARD_DERIVED',
    'RbvmFormulaV1.FORMULA_ID',
    'RbvmFormulaV1.FORMULA_VERSION',
    'RbvmFormulaV1.FORMULA_SHA256',
    'RbvmDerivedRiskMethodologyCatalog.find(methodId)',
    'requireCatalogBound()',
    'rehydrate(',
]:
    assert marker in contract, f"risk method selection contract missing {marker!r}"

for marker in [
    '92303a4df7e0381f379a929359349158aba2f5dbe8dd7e51fc211abc8f2238cf',
    'canonicalPayload().length == 223',
    'RbvmRiskMethodSelectionPolicy.formulaV1(1)',
    'RbvmRiskMethodSelectionPolicy.derived',
    'revisionChangesCanonicalIdentityWithoutChangingMethodIdentity',
    'rehydrateRejectsCanonicalTampering',
]:
    assert marker in self_test, f"risk method selection self-test missing {marker!r}"

for marker in [
    'CREATE TABLE rbvm.risk_method_selection_policy',
    "contract_id = 'RBVM_RISK_METHOD_SELECTION_POLICY_V1'",
    "selection_role = 'PRIMARY'",
    "method_family IN ('RBVM_FORMULA', 'STANDARD_DERIVED')",
    'method_id text NOT NULL',
    'method_version integer NOT NULL',
    'method_sha256 char(64) NOT NULL',
    'UNIQUE (tenant_id, contract_id, revision)',
    'UNIQUE (tenant_id, policy_sha256)',
]:
    assert marker in migration, f"V25 risk method selection migration missing {marker!r}"

migration_lower = migration.lower()
for forbidden in [
    'create view rbvm.current_risk_method',
    'create view rbvm.active_risk_method',
    'create view rbvm.default_risk_method',
    'priority_tier',
    'sla_days',
    'treatment_decision',
]:
    assert forbidden not in migration_lower, f"V25 migration must not contain {forbidden!r}"

assert 'new Migration(25, "V25__risk_method_selection_policy.sql")' in migrator
assert 'rbvm.risk_method_selection_policy' in security
assert 'REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.risk_method_selection_policy' in security

for marker in [
    'REQUIRED_SCHEMA_VERSION = 25',
    'policy.requireCatalogBound();',
    'findByRevision',
    'findByPolicySha256',
    'Status.REPLAYED',
    'Status.REVISION_CONFLICT',
    'canonicalPayload()',
    'RbvmRiskMethodSelectionPolicy.CANONICAL_PAYLOAD_FORMAT',
]:
    assert marker in store or marker in store_api, f"risk method store missing {marker!r}"

store_lower = store.lower()
assert 'findlatest' not in store_lower
assert 'findcurrent' not in store_lower
assert 'defaultmethod' not in store_lower
assert 'average' not in store_lower

for marker in [
    'PostgresV25RiskMethodSelectionPolicyLiveSelfTest',
    'Status.INSERTED',
    'Status.REPLAYED',
    'Status.REVISION_CONFLICT',
    'findByRevision(1)',
    'findByPolicySha256',
    'UPDATE rbvm.risk_method_selection_policy',
    'DELETE FROM rbvm.risk_method_selection_policy',
    'TRUNCATE rbvm.risk_method_selection_policy',
    'policyRowCount(runtimeConnections) == 3',
]:
    assert marker in live, f"V25 live proof missing {marker!r}"

assert 'V18-V26' in workflow
assert 'PostgresV25RiskMethodSelectionPolicyLiveSelfTest' in workflow

for marker in [
    'No implicit selection',
    'default methodology',
    'score averaging',
    'exact policy revision and SHA',
    'No Priority / Treatment / SLA semantics',
    'no current/latest/default view',
    'HTTP/API activation or browser controls are intentionally not part',
]:
    assert marker in normalized_doc, f"risk method selection documentation missing {marker!r}"

print("Risk method selection policy V1 structural checks: PASS")
