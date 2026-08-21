#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

snapshot = (ROOT / "src/main/java/io/rbvm/decision/RbvmDecisionInputSnapshot.java").read_text()
selection = (ROOT / "src/main/java/io/rbvm/decision/DecisionInputEvidenceSelection.java").read_text()
builder = (ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputSnapshotBuilder.java").read_text()
resolver = (ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputEvidenceResolver.java").read_text()
store = (ROOT / "src/main/java/io/rbvm/postgres/PostgresDecisionInputSnapshotStore.java").read_text()
migrator = (ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text()
migration = (ROOT / "db/migration/V20__decision_input_v2_managed_asset_context.sql").read_text()

required_snapshot = [
    'RBVM_DECISION_INPUT_SNAPSHOT_V2',
    'RBVM_DECISION_INPUT_SNAPSHOT_CANONICAL_BINARY_V2',
    'NativeEvidenceKind',
    'MANAGED_ASSET_REVISION',
    'SCANNER_MANAGED_ASSET_LINK_EVENT',
    'createV2(',
]
for marker in required_snapshot:
    assert marker in snapshot, f"missing V22 snapshot marker: {marker}"

assert 'SourceIdentity(' in selection
assert 'candidate.nativeEvidenceKind()' in selection
assert 'sourceAllowed(policy, candidate.evidenceSource())' in selection

for marker in [
    'FROM rbvm.scanner_managed_asset_link_event',
    'FROM rbvm.managed_asset_revision',
    'recorded_at <= ?',
    'ORDER BY revision DESC',
    'NativeEvidenceKind.MANAGED_ASSET_REVISION',
    'RbvmDecisionInputSnapshot.createV2(',
]:
    assert marker in builder, f"missing V22 builder marker: {marker}"

assert 'current_scanner_managed_asset_link' not in builder
assert 'current_managed_asset' not in builder
assert 'active_scanner_managed_asset_link' not in builder

for marker in [
    'switch (reference.nativeEvidenceKind())',
    'resolveManagedAssetContext(',
    'verifyManagedAssetBinding(',
    'FROM rbvm.managed_asset_revision',
    'FROM rbvm.scanner_managed_asset_link_event',
    'FROM rbvm.exposure',
]:
    assert marker in resolver, f"missing V22 resolver marker: {marker}"

for marker in [
    'snapshot.canonicalPayloadFormat()',
    'native_evidence_kind',
    'binding_kind',
    'binding_id',
]:
    assert marker in store, f"missing V22 store marker: {marker}"

assert 'new Migration(20, "V20__decision_input_v2_managed_asset_context.sql")' in migrator
for marker in [
    'native_evidence_kind',
    'binding_kind',
    'binding_id',
    'MANAGED_ASSET_REVISION',
    'SCANNER_MANAGED_ASSET_LINK_EVENT',
    'RBVM_DECISION_INPUT_SNAPSHOT_V2',
]:
    assert marker in migration, f"missing V22 migration marker: {marker}"

print("Decision Input V2 structural checks: PASS")
