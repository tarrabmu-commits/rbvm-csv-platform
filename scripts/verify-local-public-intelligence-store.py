#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
migration = (ROOT / 'db/migration/V30__local_public_intelligence_store.sql').read_text(encoding='utf-8')
store = (ROOT / 'src/main/java/io/rbvm/postgres/PostgresPublicIntelligenceStore.java').read_text(encoding='utf-8')
live = (ROOT / 'src/test/java/io/rbvm/postgres/PostgresV30PublicIntelligenceStoreLiveSelfTest.java').read_text(encoding='utf-8')
migrator = (ROOT / 'src/main/java/io/rbvm/postgres/PostgresMigrator.java').read_text(encoding='utf-8')
security = (ROOT / 'db/security/runtime-role.sql').read_text(encoding='utf-8')
workflow = (ROOT / '.github/workflows/postgres-integration.yml').read_text(encoding='utf-8')
doc = (ROOT / 'docs/LOCAL_PUBLIC_INTELLIGENCE_STORE_V1.md').read_text(encoding='utf-8')

for token in [
    'CREATE TABLE rbvm.public_intelligence_sync_run',
    "provider IN ('NVD', 'FIRST_EPSS', 'CISA_KEV', 'CVE_PROGRAM')",
    "sync_mode IN ('BOOTSTRAP', 'INCREMENTAL')",
    "status IN ('STAGING', 'COMPLETE', 'FAILED')",
    'public_intelligence_nonfailed_source_idx',
    "WHERE status IN ('STAGING', 'COMPLETE')",
    'CREATE TABLE rbvm.public_intelligence_record',
    "record_state IN ('ACTIVE', 'TOMBSTONE')",
    'public_intelligence_record_append_only',
    'public intelligence records may only be appended to a STAGING run',
    'CREATE VIEW rbvm.latest_public_intelligence_record',
    "WHERE r.status = 'COMPLETE'",
    'DISTINCT ON (r.provider, e.cve_id)',
    'CREATE VIEW rbvm.current_public_intelligence_record',
    "WHERE record_state = 'ACTIVE'",
    'CREATE VIEW rbvm.public_intelligence_source_status',
]:
    assert token in migration, f'V30 local public-intelligence migration missing {token!r}'

assert 'tenant_id' not in migration.lower(), 'global public-intelligence mirror must not be tenant-duplicated'
latest_pos = migration.index('CREATE VIEW rbvm.latest_public_intelligence_record')
current_pos = migration.index('CREATE VIEW rbvm.current_public_intelligence_record')
assert latest_pos < current_pos, 'latest provider state must resolve before current ACTIVE filtering'
latest_body = migration[latest_pos:current_pos]
assert "record_state = 'ACTIVE'" not in latest_body, 'filtering ACTIVE before latest resolution would resurrect tombstones'

for forbidden in [
    'priority_tier',
    'risk_score',
    'sla_days',
    'organizational_risk_score',
]:
    assert forbidden not in migration.lower(), f'V30 mirror contains forbidden decision semantic {forbidden!r}'

for token in [
    'REQUIRED_SCHEMA_VERSION = 30',
    'public final class PostgresPublicIntelligenceStore',
    'enum Provider',
    'NVD', 'FIRST_EPSS', 'CISA_KEV', 'CVE_PROGRAM',
    'beginOrReplay(',
    'appendRecords(',
    'completeRun(',
    'failRun(',
    'lookupCurrent(',
    'rbvm.current_public_intelligence_record',
    'pg_advisory_xact_lock',
    'createArrayOf("text"',
    'array.free()',
    'RecordState.TOMBSTONE',
]:
    assert token in store, f'local public-intelligence store missing {token!r}'

assert 'new Migration(30, "V30__local_public_intelligence_store.sql")' in migrator

for token in [
    'rbvm.public_intelligence_sync_run',
    'rbvm.public_intelligence_record',
    'rbvm.latest_public_intelligence_record',
    'rbvm.current_public_intelligence_record',
    'rbvm.public_intelligence_source_status',
    'REVOKE UPDATE, DELETE, TRUNCATE ON rbvm.public_intelligence_record',
]:
    assert token in security, f'runtime role missing V30 permission boundary {token!r}'

for token in [
    'PostgresV30PublicIntelligenceStoreLiveSelfTest',
    'STAGING source records must never be current',
    'TOMBSTONE must suppress',
    'FAILED source SHA must remain retryable',
    'record history must be append-only',
    'COMPLETE sync runs must reject late record insertion',
]:
    assert token in live, f'V30 live proof missing {token!r}'
assert 'PostgresV30PublicIntelligenceStoreLiveSelfTest' in workflow

for token in [
    'LOCAL_PUBLIC_INTELLIGENCE_STORE_V1',
    'global',
    'non-tenant',
    'only complete',
    'last successful',
    'tombstone',
    'customer context',
    'does not change historical decision artifacts',
    'csv enrichment is not switched to the local store by v30',
]:
    assert token.lower() in doc.lower(), f'local public-intelligence documentation missing {token!r}'

print('Local Public Intelligence Store V1 structural checks: PASS')
