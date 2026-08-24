#!/usr/bin/env python3
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
migration = (ROOT / "db/migration/V31__public_intelligence_sync_job.sql").read_text(encoding="utf-8")
migrator = (ROOT / "src/main/java/io/rbvm/postgres/PostgresMigrator.java").read_text(encoding="utf-8")
store = (ROOT / "src/main/java/io/rbvm/postgres/PostgresPublicIntelligenceSyncJobStore.java").read_text(encoding="utf-8")
reader = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceStatusReader.java").read_text(encoding="utf-8")
factory = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceSyncRuntimeFactory.java").read_text(encoding="utf-8")
handler = (ROOT / "src/main/java/io/rbvm/csv/PublicIntelligenceStatusHttpHandler.java").read_text(encoding="utf-8")
main = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
live = (ROOT / "src/test/java/io/rbvm/postgres/PostgresV31PublicIntelligenceSyncJobLiveSelfTest.java").read_text(encoding="utf-8")
http_test = (ROOT / "src/test/java/io/rbvm/csv/PublicIntelligenceStatusHttpSelfTest.java").read_text(encoding="utf-8")
security = (ROOT / "db/security/runtime-role.sql").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/postgres-integration.yml").read_text(encoding="utf-8")
doc = (ROOT / "docs/PUBLIC_INTELLIGENCE_SYNC_JOB_V1.md").read_text(encoding="utf-8")
openapi_path = ROOT / "api/public-intelligence-status-v1.openapi.yaml"
openapi = yaml.safe_load(openapi_path.read_text(encoding="utf-8"))

for token in [
    "CREATE TABLE rbvm.public_intelligence_sync_job",
    "trigger_source IN ('MANUAL', 'SCHEDULED', 'STARTUP', 'SYSTEM')",
    "status IN ('RUNNING', 'COMPLETE', 'FAILED')",
    "stage IN ('ACQUIRING', 'BUILDING', 'ADMITTING', 'COMPLETE', 'FAILED')",
    "public_intelligence_one_running_job_per_provider_idx",
    "WHERE status = 'RUNNING'",
    "public_intelligence_sync_job_guard",
    "terminal public_intelligence_sync_job is immutable",
    "ACQUIRING may only advance to BUILDING",
    "BUILDING may only advance to ADMITTING",
    "ADMITTING may only link a run or complete",
    "FOREIGN KEY (provider, sync_run_id)",
    "CREATE VIEW rbvm.public_intelligence_provider_status_v1",
    "LEFT JOIN rbvm.public_intelligence_source_status",
]:
    assert token in migration, f"V31 migration missing {token!r}"

for forbidden in [
    "tenant_id",
    "priority_tier",
    "risk_score",
    "sla_days",
    "organizational_risk_score",
]:
    assert forbidden not in migration.lower(), f"V31 lifecycle contains forbidden semantic {forbidden!r}"

assert 'new Migration(31, "V31__public_intelligence_sync_job.sql")' in migrator

for token in [
    "REQUIRED_SCHEMA_VERSION = 31",
    "class PostgresPublicIntelligenceSyncJobStore",
    "implements PublicIntelligenceStatusReader",
    "TriggerSource",
    "ACQUIRING",
    "BUILDING",
    "ADMITTING",
    "start(",
    "acquired(",
    "bundleBuilt(",
    "linkSyncRun(",
    "complete(",
    "fail(",
    "public_intelligence_provider_status_v1",
    "r.status = 'COMPLETE'",
]:
    assert token in store, f"V31 store missing {token!r}"

assert "interface PublicIntelligenceStatusReader" in reader
assert "ProviderStatus" in reader
assert "PostgresPublicIntelligenceSyncJobStore(connections, false)" in factory

for token in [
    "PUBLIC_INTELLIGENCE_STATUS_HTTP_V1",
    'ROOT = "/api/v1/intelligence/status"',
    "ApiRole.VIEWER",
    "neverAttempted",
    "neverSucceeded",
    "latestJob",
    "lastSuccess",
    "Cache-Control",
    "no-store",
    "INTELLIGENCE_STATUS_UNAVAILABLE",
]:
    assert token in handler, f"status HTTP handler missing {token!r}"

assert "PublicIntelligenceSyncRuntimeFactory.fromEnvironment" in main
assert "PublicIntelligenceStatusHttpHandler.ROOT" in main
assert "/api/v1/intelligence/status" in main

for token in [
    "pre-admission acquisition failure must persist as FAILED",
    "only one RUNNING job per provider may exist",
    "linked STAGING V30 run must not permit job completion",
    "terminal sync-job history must be immutable",
    "database guard must reject skipped lifecycle stages",
]:
    assert token in live, f"V31 live proof missing {token!r}"
assert "PostgresV31PublicIntelligenceSyncJobLiveSelfTest" in workflow

for token in [
    "PublicIntelligenceStatusHttpSelfTest",
    "status GET must return 200",
    "status endpoint must be read-only",
    "missing PostgreSQL status capability must return 503",
]:
    assert token in http_test, f"status HTTP self-test missing {token!r}"

for token in [
    "rbvm.public_intelligence_sync_job",
    "rbvm.public_intelligence_provider_status_v1",
    "REVOKE DELETE, TRUNCATE ON rbvm.public_intelligence_sync_job",
]:
    assert token in security, f"runtime role missing V31 boundary {token!r}"

assert openapi.get("openapi") == "3.1.2"
assert "/api/v1/intelligence/status" in openapi.get("paths", {})
operation = openapi["paths"]["/api/v1/intelligence/status"]["get"]
assert operation.get("operationId") == "getPublicIntelligenceStatus"
providers = openapi["components"]["schemas"]["ProviderStatus"]["properties"]["provider"]["enum"]
assert set(providers) == {"NVD", "FIRST_EPSS", "CISA_KEV", "CVE_PROGRAM"}
provider_array = openapi["components"]["schemas"]["PublicIntelligenceStatusResponse"]["properties"]["providers"]
assert provider_array.get("minItems") == 4 and provider_array.get("maxItems") == 4

for token in [
    "PUBLIC_INTELLIGENCE_SYNC_JOB_V1",
    "ACQUIRING",
    "BUILDING",
    "ADMITTING",
    "end-to-end operational job",
    "last successful V30 source",
    "GET /api/v1/intelligence/status",
    "10K remains a regression checkpoint",
]:
    assert token.lower() in doc.lower(), f"V31 documentation missing {token!r}"

print("Public Intelligence Sync Job V1 checks: PASS")
