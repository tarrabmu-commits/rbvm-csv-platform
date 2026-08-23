#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
contract = (ROOT / "src/main/java/io/rbvm/decision/RbvmActiveRiskMethodExecutionBinding.java").read_text()
contract_test = (ROOT / "src/test/java/io/rbvm/decision/RbvmActiveRiskMethodExecutionBindingSelfTest.java").read_text()
migration = (ROOT / "db/migration/V27__active_risk_method_execution_binding.sql").read_text()
store_api = (ROOT / "src/main/java/io/rbvm/postgres/ActiveRiskMethodExecutionBindingStore.java").read_text()
store = (ROOT / "src/main/java/io/rbvm/postgres/PostgresActiveRiskMethodExecutionBindingStore.java").read_text()
outcome = (ROOT / "src/main/java/io/rbvm/postgres/ActiveRiskMethodExecutionBindingInstallResult.java").read_text()
materializer = (ROOT / "src/main/java/io/rbvm/postgres/DefaultActiveRiskMethodExecutionBindingMaterializer.java").read_text()
dispatcher = (ROOT / "src/main/java/io/rbvm/postgres/DefaultActiveRiskMethodResultMaterializer.java").read_text()
materializer_test = (ROOT / "src/test/java/io/rbvm/postgres/DefaultActiveRiskMethodExecutionBindingMaterializerSelfTest.java").read_text()
live = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV27ActiveRiskMethodExecutionBindingLiveSelfTest.java").read_text()
migrator = (ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text()
security = (ROOT / "db/security/runtime-role.sql").read_text()
workflow = (ROOT / ".github/workflows/postgres-integration.yml").read_text()
platform = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text()
doc = (ROOT / "docs/ACTIVE_RISK_METHOD_EXECUTION_BINDING_V1.md").read_text()

for marker in [
    'RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_V1',
    'EXACT_ACTIVATION_EVENT_EXACT_POLICY_EXACT_PRIMARY_METHOD_EXACT_DECISION_INPUT_EXACT_RESULT',
    'RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_CANONICAL_BINARY_V1',
    'activationRevision',
    'activationEventSha256',
    'policyRevision',
    'policySha256',
    'SelectionRole.PRIMARY',
    'MethodFamily',
    'methodId',
    'methodVersion',
    'methodSha256',
    'inputSnapshotSha256',
    'RBVM_FORMULA_RESULT',
    'DERIVED_RISK_RESULT',
    'bindingSha256',
    'execution binding requires an explicit ACTIVE event',
    'activation event does not reference the supplied exact policy identity',
]:
    assert marker in contract, f"execution binding contract missing {marker!r}"

for marker in [
    '72cb38f987d28316565dca9794fcd3f9b22b4f1e4b4c57272ebad22cb35a5760',
    'binding.canonicalPayload().length == 541',
    'derivedPoliciesBindOnlyDerivedResults',
    'clearedAndMismatchedPoliciesAreRejected',
    'rehydrationDetectsIdentityTampering',
]:
    assert marker in contract_test, f"execution binding self-test missing {marker!r}"

for marker in [
    'CREATE TABLE rbvm.active_risk_method_execution_binding',
    'UNIQUE (tenant_id, activation_event_sha256, input_snapshot_sha256)',
    'UNIQUE (tenant_id, binding_sha256)',
    "result_family IN ('RBVM_FORMULA_RESULT', 'DERIVED_RISK_RESULT')",
    "method_family IN ('RBVM_FORMULA', 'STANDARD_DERIVED')",
    'risk_method_selection_activation_execution_identity',
    'formula_result_execution_binding_identity',
    'derived_risk_result_execution_binding_identity',
    'REFERENCES rbvm.risk_method_selection_policy_activation_event',
    'REFERENCES rbvm.risk_method_selection_policy(tenant_id, revision, policy_sha256)',
    'REFERENCES rbvm.decision_input_snapshot(tenant_id, snapshot_sha256)',
    'REFERENCES rbvm.formula_result',
    'REFERENCES rbvm.derived_risk_result',
    'formula_explanation_sha256 = result_sha256',
    'derived_result_sha256 = result_sha256',
]:
    assert marker in migration, f"V27 migration missing {marker!r}"

migration_lower = migration.lower()
for forbidden in [
    'create view rbvm.current_active_risk_method_execution',
    'max(activation_revision)',
    'order by activation_revision desc',
    'priority_tier',
    'sla_days',
    'treatment_decision',
    'normalized_score',
]:
    assert forbidden not in migration_lower, f"V27 migration contains forbidden semantic {forbidden!r}"

for marker in [
    'REQUIRED_SCHEMA_VERSION = 27',
    'TRANSACTION_SERIALIZABLE',
    'pg_advisory_xact_lock',
    'findByBindingSha256',
    'findByActivationAndInput',
    'EXECUTION_CONFLICT',
    'REPLAYED',
    'binding.activationEventSha256()',
    'binding.inputSnapshotSha256()',
    'binding.canonicalPayload()',
]:
    assert marker in store or marker in store_api or marker in outcome, f"execution binding store missing {marker!r}"

for marker in [
    'RiskMethodSelectionPolicyActivationStore activations',
    'findByActivationRevision(activationRevision)',
    'candidate.eventSha256().equals(activationEventSha256)',
    'ExplicitlyClearedActivationException',
    'PolicyIntegrityFailureException',
    'policy.requireCatalogBound()',
    'findByActivationAndInput',
    'existing binding replay must not re-execute the risk method',
]:
    source = materializer + materializer_test
    assert marker in source, f"execution binding materializer missing {marker!r}"

assert '.current()' not in materializer, 'execution materializer must never resolve current activation'
assert 'current_risk_method_selection_policy_activation' not in materializer

for marker in [
    'case RBVM_FORMULA -> materializeFormula',
    'case STANDARD_DERIVED -> materializeDerived',
    'stored.formulaId().equals(policy.methodId())',
    'stored.formulaSha256().equals(policy.methodSha256())',
    'stored.methodologyId().equals(policy.methodId())',
    'stored.methodologySha256().equals(policy.methodSha256())',
]:
    assert marker in dispatcher, f"exact result dispatcher missing {marker!r}"

assert 'new Migration(27, "V27__active_risk_method_execution_binding.sql")' in migrator
assert 'rbvm.active_risk_method_execution_binding' in security
assert 'REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.active_risk_method_execution_binding' in security

for marker in [
    'PostgresV27ActiveRiskMethodExecutionBindingLiveSelfTest',
    'schemaVersion == 27',
    'Status.INSERTED',
    'formulaReplay.replayed()',
    'MethodFamily.RBVM_FORMULA',
    'MethodFamily.STANDARD_DERIVED',
    'ResultFamily.RBVM_FORMULA_RESULT',
    'ResultFamily.DERIVED_RISK_RESULT',
    '[SQLState=23503]',
    'UPDATE rbvm.active_risk_method_execution_binding',
    'DELETE FROM rbvm.active_risk_method_execution_binding',
    'TRUNCATE rbvm.active_risk_method_execution_binding',
]:
    assert marker in live, f"V27 live proof missing {marker!r}"

assert 'RbvmActiveRiskMethodExecutionBindingSelfTest.main(args);' in platform
assert 'DefaultActiveRiskMethodExecutionBindingMaterializerSelfTest.main(args);' in platform
assert 'PostgresV27ActiveRiskMethodExecutionBindingLiveSelfTest' in workflow
assert 'V18-V27' in workflow

for marker in [
    'never stores or means `current`',
    'activation revision and activation event SHA',
    'policy revision and policy SHA',
    'Decision Input snapshot SHA',
    'EXECUTION_CONFLICT',
    'valid result SHA belonging to a different methodology is rejected',
    'No Priority, Treatment, SLA',
    'operational `current` discovery is not a reproducibility key',
]:
    assert marker.lower() in doc.lower(), f"execution binding documentation missing {marker!r}"

print('Active Risk Method Execution Binding V1 structural checks: PASS')
