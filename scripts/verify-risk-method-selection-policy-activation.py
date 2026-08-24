#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
contract = (ROOT / 'src/main/java/io/rbvm/decision/RbvmRiskMethodSelectionPolicyActivationEvent.java').read_text()
self_test = (ROOT / 'src/test/java/io/rbvm/decision/RbvmRiskMethodSelectionPolicyActivationEventSelfTest.java').read_text()
migration = (ROOT / 'db/migration/V26__risk_method_selection_policy_activation.sql').read_text()
store_api = (ROOT / 'src/main/java/io/rbvm/postgres/RiskMethodSelectionPolicyActivationStore.java').read_text()
store = (ROOT / 'src/main/java/io/rbvm/postgres/PostgresRiskMethodSelectionPolicyActivationStore.java').read_text()
outcome = (ROOT / 'src/main/java/io/rbvm/postgres/RiskMethodSelectionPolicyActivationInstallResult.java').read_text()
migrator = (ROOT / 'src/main/java/io/rbvm/postgres/PostgresMigrator.java').read_text()
security = (ROOT / 'db/security/runtime-role.sql').read_text()
live = (ROOT / 'src/test/java/io/rbvm/postgres/PostgresV26RiskMethodSelectionActivationLiveSelfTest.java').read_text()
workflow = (ROOT / '.github/workflows/postgres-integration.yml').read_text()
platform = (ROOT / 'src/test/java/io/rbvm/csv/PlatformSelfTest.java').read_text()
doc = (ROOT / 'docs/RISK_METHOD_SELECTION_POLICY_ACTIVATION_V1.md').read_text()

for marker in [
    'RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_V1',
    'TENANT_SCOPED_EXPLICIT_ACTIVE_POLICY_POINTER_APPEND_ONLY',
    'RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_CANONICAL_BINARY_V1',
    'ActivationState.ACTIVE',
    'ActivationState.CLEARED',
    'policy.revision()',
    'policy.policySha256()',
    'changedBy',
    'changeNote',
    'recordedAt',
    'eventSha256',
    'CLEARED activation must not carry a policy identity',
]:
    assert marker in contract, f'activation contract missing {marker!r}'

for marker in [
    'e7e1a60b1139e4ae98050516fce253998ca2ad1cc2a4c1113caf11a0f40b482b',
    'event.canonicalPayload().length == 241',
    'distinguishesActivationRevisionFromPolicyRevision',
    'supportsExplicitClearedState',
    'rejectsInvalidStateShapeAndTampering',
]:
    assert marker in self_test, f'activation self-test missing {marker!r}'

for marker in [
    'CREATE TABLE rbvm.risk_method_selection_policy_activation_event',
    'activation_revision integer NOT NULL CHECK (activation_revision > 0)',
    "activation_state text NOT NULL CHECK (activation_state IN ('ACTIVE', 'CLEARED'))",
    'UNIQUE (tenant_id, activation_revision)',
    'UNIQUE (tenant_id, event_sha256)',
    'FOREIGN KEY (tenant_id, policy_revision, policy_sha256)',
    'REFERENCES rbvm.risk_method_selection_policy(tenant_id, revision, policy_sha256)',
    'CREATE VIEW rbvm.current_risk_method_selection_policy_activation',
    'ORDER BY tenant_id, activation_revision DESC',
    'CREATE VIEW rbvm.active_risk_method_selection_policy',
    "WHERE a.activation_state = 'ACTIVE'",
    'policy revision order has no activation semantics',
]:
    assert marker in migration, f'V26 migration missing {marker!r}'

migration_lower = migration.lower()
for forbidden in [
    'order by tenant_id, policy_revision desc',
    'max(policy_revision)',
    'priority_tier',
    'sla_days',
    'treatment_decision',
    'risk_score',
]:
    assert forbidden not in migration_lower, f'V26 migration contains forbidden semantic {forbidden!r}'

assert 'new Migration(26, "V26__risk_method_selection_policy_activation.sql")' in migrator
assert 'rbvm.risk_method_selection_policy_activation_event' in security
assert 'rbvm.current_risk_method_selection_policy_activation' in security
assert 'rbvm.active_risk_method_selection_policy' in security
assert 'REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.risk_method_selection_policy_activation_event' in security

for marker in [
    'REQUIRED_SCHEMA_VERSION = 26',
    'TRANSACTION_SERIALIZABLE',
    'pg_advisory_xact_lock',
    'existingByRevision',
    'currentStored',
    'event.activationRevision() < current.activationRevision()',
    'STALE_ACTIVATION_REVISION',
    'requireExactPolicy',
    'event.policyRevision()',
    'event.policySha256()',
    'findByActivationRevision',
    'findByEventSha256',
    'current()',
    'current_risk_method_selection_policy_activation',
]:
    assert marker in store or marker in store_api or marker in outcome, f'activation store missing {marker!r}'

for forbidden in [
    'max(policy_revision)',
    'order by policy_revision',
    'defaultmethod',
    'preferredmethod',
    'averagescore',
    'prioritytier',
    'sladays',
]:
    assert forbidden not in store.lower(), f'activation store contains forbidden semantic {forbidden!r}'

for marker in [
    'PostgresV26RiskMethodSelectionActivationLiveSelfTest',
    'schema version >=26',
    'Status.INSERTED',
    'Status.REPLAYED',
    'Status.REVISION_CONFLICT',
    'Status.STALE_ACTIVATION_REVISION',
    'missingPolicy',
    'activePolicyRevision(runtimeConnections) == 1',
    'activePolicyRevision(runtimeConnections) == 2',
    'ActivationState.CLEARED',
    'activePolicyRowCount(runtimeConnections) == 0',
    'UPDATE rbvm.risk_method_selection_policy_activation_event',
    'DELETE FROM rbvm.risk_method_selection_policy_activation_event',
    'TRUNCATE rbvm.risk_method_selection_policy_activation_event',
]:
    assert marker in live, f'V26 live proof missing {marker!r}'

for marker in [
    'Activation revision is not policy revision',
    'STALE_ACTIVATION_REVISION',
    '`CLEARED` carries no policy identity',
    'greatest accepted explicit activation revision',
    'never the greatest policy revision',
    'exact policy revision + SHA',
    'does not calculate or alter any risk score',
    'HTTP/API mutation and browser activation controls are intentionally deferred',
]:
    assert marker.lower() in doc.lower(), f'activation documentation missing {marker!r}'

assert 'RbvmRiskMethodSelectionPolicyActivationEventSelfTest.main(args);' in platform
for live_test in [
    'PostgresV23FormulaResultLiveSelfTest',
    'PostgresV24DerivedRiskLiveSelfTest',
    'PostgresV25RiskMethodSelectionPolicyLiveSelfTest',
    'PostgresV26RiskMethodSelectionActivationLiveSelfTest',
    'PostgresV27ActiveRiskMethodExecutionBindingLiveSelfTest',
]:
    assert live_test in workflow, f'postgres workflow missing required live proof {live_test!r}'

print('Risk Method Selection Policy Activation V1 structural checks: PASS')
