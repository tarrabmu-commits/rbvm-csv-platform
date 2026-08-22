#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
snapshot = (ROOT / "src/main/java/io/rbvm/decision/RbvmDecisionInputSnapshot.java").read_text(encoding="utf-8")
selection = (ROOT / "src/main/java/io/rbvm/decision/DecisionInputEvidenceSelection.java").read_text(encoding="utf-8")
builder = (ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputSnapshotBuilder.java").read_text(encoding="utf-8")
resolver = (ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputEvidenceResolver.java").read_text(encoding="utf-8")
migration = (ROOT / "db/migration/V22__decision_input_v3_context_bindings.sql").read_text(encoding="utf-8")
live = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV22LiveSelfTest.java").read_text(encoding="utf-8")
v23_live = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV23FormulaResultLiveSelfTest.java").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/postgres-integration.yml").read_text(encoding="utf-8")
doc = (ROOT / "docs/DECISION_INPUT_V3.md").read_text(encoding="utf-8")

for needle in (
    'RBVM_DECISION_INPUT_SNAPSHOT_V3',
    'FINDING_SCOPED_POLICY_BOUND_TYPED_ASSOCIATION_PROVENANCE_SNAPSHOT',
    'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V3',
    'FINDING_REACHABILITY_SCOPE_LINK_EVENT',
    'FINDING_BUSINESS_SERVICE_LINK_EVENT',
    'V3 network reachability evidence requires exact Finding reachability-scope binding',
    'V3 business impact evidence requires exact Finding business-service binding',
):
    if needle not in snapshot:
        raise AssertionError(f"snapshot V3 contract missing {needle!r}")

for needle in (
    'BindingReference bindingReference',
    'NativeEvidenceKind nativeEvidenceKind',
    'FINDING_REACHABILITY_SCOPE_LINK_EVENT',
    'FINDING_BUSINESS_SERVICE_LINK_EVENT',
):
    if needle not in selection:
        raise AssertionError(f"selection V3 support missing {needle!r}")

for needle in (
    'schemaVersion >= V3_SCHEMA_VERSION',
    'RbvmDecisionInputSnapshot.createV3',
    'FROM rbvm.finding_reachability_scope_link_event',
    'FROM rbvm.finding_business_service_link_event',
    "WHERE l.link_status = 'LINKED'",
    'e.asset_id = ?',
    'e.origin_label = l.origin_label_normalized',
    'e.business_service_normalized = l.business_service_normalized',
    'AND recorded_at <= ?',
    'DecisionInputEvidenceSelection.select',
):
    if needle not in builder:
        raise AssertionError(f"builder V3 ordering/invariant missing {needle!r}")

for needle in (
    'snapshot.isV3()',
    'Decision Input Snapshot V3 requires PostgreSQL schema version 22',
    'verifyReachabilityBinding',
    'verifyBusinessServiceBinding',
    'snapshot.findingId()',
    'requireFindingAsset',
    "!\"LINKED\".equals",
    'FINDING_REACHABILITY_SCOPE_LINK_EVENT',
    'FINDING_BUSINESS_SERVICE_LINK_EVENT',
):
    if needle not in resolver:
        raise AssertionError(f"resolver V3 verification missing {needle!r}")

for needle in (
    'RBVM_DECISION_INPUT_SNAPSHOT_V3',
    'FINDING_REACHABILITY_SCOPE_LINK_EVENT',
    'FINDING_BUSINESS_SERVICE_LINK_EVENT',
    'decision_input_binding_shape_check',
):
    if needle not in migration:
        raise AssertionError(f"V22 migration missing {needle!r}")

for needle in (
    'schemaVersion == 22',
    'cross-asset duplicate target must not add another reachability reference',
    'cross-asset duplicate service must not add another impact reference',
    'later unlink must not change an as-of T8 V3 snapshot',
    'does not belong to snapshot Finding asset',
    'REPLAYED',
):
    if needle not in live:
        raise AssertionError(f"live V22 replay/isolation proof missing {needle!r}")

for needle in (
    'PostgresV22LiveSelfTest.class',
    '"exerciseV3"',
    'schemaVersion',
):
    if needle not in v23_live:
        raise AssertionError(
            f"V23 live integration must retain V22 Decision Input V3 coverage: missing {needle!r}"
        )

for needle in (
    'v22-live-integration',
    'PostgresV23FormulaResultLiveSelfTest',
    'Run live V18-V23 persistence, Decision Input V3, and Formula replay integration',
):
    if needle not in workflow:
        raise AssertionError(f"PostgreSQL workflow is stale for Decision Input V3: missing {needle!r}")

for needle in (
    'Association filtering is therefore candidate construction',
    'same scanner asset',
    'resolver never re-runs source selection',
    'no Formula',
):
    if needle.lower() not in doc.lower():
        raise AssertionError(f"V3 documentation missing {needle!r}")

for forbidden in (
    'riskScore',
    'priorityScore',
    'MISSING_TO_ZERO',
    'AUTO_LINK',
    'INFERRED_LINK',
):
    if forbidden in builder or forbidden in resolver:
        raise AssertionError(f"Decision Input V3 contains forbidden policy/scoring construct {forbidden!r}")

print('Decision Input V3 structural checks: PASS')
