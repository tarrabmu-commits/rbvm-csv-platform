#!/usr/bin/env python3
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[1]
coordinator = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceSyncCoordinator.java").read_text(encoding="utf-8")
pipeline = (ROOT / "src/main/java/io/rbvm/postgres/SubprocessPublicIntelligenceSourcePipeline.java").read_text(encoding="utf-8")
reader = (ROOT / "src/main/java/io/rbvm/postgres/PostgresPublicIntelligenceCurrentCveReader.java").read_text(encoding="utf-8")
factory = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceOrchestrationRuntimeFactory.java").read_text(encoding="utf-8")
handler = (ROOT / "src/main/java/io/rbvm/csv/PublicIntelligenceSyncHttpHandler.java").read_text(encoding="utf-8")
main = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
compile_script = (ROOT / "scripts/compile.sh").read_text(encoding="utf-8")
platform_test = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
http_test = (ROOT / "src/test/java/io/rbvm/csv/PublicIntelligenceSyncHttpSelfTest.java").read_text(encoding="utf-8")
live_test = (ROOT / "src/test/java/io/rbvm/postgres/PostgresPublicIntelligenceSyncOrchestratorLiveSelfTest.java").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/postgres-integration.yml").read_text(encoding="utf-8")
v30 = (ROOT / "db/migration/V30__local_public_intelligence_store.sql").read_text(encoding="utf-8")
doc = (ROOT / "docs/PUBLIC_INTELLIGENCE_SYNC_ORCHESTRATOR_V1.md").read_text(encoding="utf-8")
openapi = yaml.safe_load((ROOT / "api/public-intelligence-sync-v1.openapi.yaml").read_text(encoding="utf-8"))

for token in [
    "implements PublicIntelligenceSyncTrigger",
    "jobs.start(",
    "pipeline.acquire(",
    "jobs.acquired(",
    "pipeline.buildBundle(",
    "PublicIntelligenceSyncBundleImporter.validateBundle",
    "PublicIntelligenceSyncBundleImporter.importBundle",
    "jobs.linkSyncRun(",
    "jobs.complete(",
    "SOURCE_ACQUISITION_FAILED",
    "SOURCE_BUNDLE_BUILD_FAILED",
    "SOURCE_ADMISSION_FAILED",
    "completeSnapshotProvider",
    "Provider.FIRST_EPSS",
    "Provider.CISA_KEV",
    "Provider.CVE_PROGRAM",
    "Set.of()",
    "AlreadyRunningException",
]:
    assert token in coordinator, f"orchestrator missing {token!r}"

for forbidden in [
    "risk_score",
    "organizational_risk",
    "priority_tier",
    "sla_days",
    "tenant_id",
]:
    assert forbidden not in coordinator.lower(), f"orchestrator contains forbidden semantic {forbidden!r}"
    assert forbidden not in handler.lower(), f"sync HTTP contains forbidden semantic {forbidden!r}"

for token in [
    "new ProcessBuilder(List.copyOf(command))",
    "redirectErrorStream(true)",
    "MAX_TOOL_OUTPUT_BYTES",
    "DEFAULT_TIMEOUT_SECONDS",
    "destroyForcibly",
    "requireSafeAcquisition",
    "requireSafeTools",
    "NVD partial/year feeds must never infer tombstones from absence",
    "fetch-local-public-intelligence-source.py",
    "build-public-intelligence-bundle-from-acquisition.py",
    "build-public-intelligence-sync-bundle.py",
]:
    assert token in pipeline, f"subprocess pipeline missing {token!r}"
assert "bash -c" not in pipeline and "sh -c" not in pipeline

for token in [
    "rbvm.current_public_intelligence_record",
    "ORDER BY cve_id",
]:
    assert token in reader, f"current-CVE reader missing {token!r}"
for token in [
    "CREATE VIEW rbvm.current_public_intelligence_record AS",
    "WHERE record_state = 'ACTIVE'",
]:
    assert token in v30, f"V30 current-public-intelligence semantics missing {token!r}"

for token in [
    "PostgresPublicIntelligenceSyncJobStore(connections, false)",
    "PostgresPublicIntelligenceStore(connections, false)",
    "PostgresPublicIntelligenceCurrentCveReader(connections)",
    "SubprocessPublicIntelligenceSourcePipeline(environment)",
    "public-intelligence-sync-work",
    "RBVM_INTELLIGENCE_SYNC_WORKERS",
]:
    assert token in factory, f"runtime factory missing {token!r}"

for token in [
    "PUBLIC_INTELLIGENCE_SYNC_HTTP_V1",
    'ROOT = "/api/v1/intelligence/sync"',
    "ApiRole.OPERATOR",
    '"POST"',
    "INTELLIGENCE_SYNC_ALREADY_RUNNING",
    "INTELLIGENCE_SYNC_UNAVAILABLE",
    "feed is valid only for provider NVD",
    "Location",
    "no-store",
]:
    assert token in handler, f"sync HTTP handler missing {token!r}"

for token in [
    "PublicIntelligenceOrchestrationRuntimeFactory.fromEnvironment",
    "PublicIntelligenceSyncHttpHandler.ROOT",
    "new PublicIntelligenceSyncHttpHandler(publicIntelligenceSync, authenticator)",
]:
    assert token in main, f"product runtime wiring missing {token!r}"

for resource in [
    "fetch-local-public-intelligence-source.py",
    "build-public-intelligence-bundle-from-acquisition.py",
    "build-public-intelligence-sync-bundle.py",
    "intelligence-tools/scripts",
]:
    assert resource in compile_script, f"compile packaging missing {resource!r}"

assert "PublicIntelligenceSyncHttpSelfTest.main(args)" in platform_test
for token in [
    "CISA sync POST must return 202",
    "NVD exact year sync POST must return 202",
    "sync endpoint must be POST-only",
    "non-NVD provider must reject NVD feed query parameter",
    "missing synchronization runtime must return 503",
    "overlapping provider synchronization must return 409",
]:
    assert token in http_test, f"HTTP self-test missing {token!r}"

for token in [
    "complete-snapshot provider must receive its previous current test CVE",
    "explicit tombstone must suppress the removed CISA test CVE",
    "NVD partial/year feeds must never receive previous CVEs for tombstone inference",
    "NVD modified absence must not tombstone an older current CVE",
    "pre-admission source failure must not invent a V30 run identity",
    "SOURCE_ACQUISITION_FAILED",
]:
    assert token in live_test, f"live orchestrator proof missing {token!r}"
assert "PostgresPublicIntelligenceSyncOrchestratorLiveSelfTest" in workflow

assert openapi.get("openapi") == "3.1.2"
path = openapi["paths"]["/api/v1/intelligence/sync/{provider}"]
assert set(path.keys()) == {"post"}
operation = path["post"]
assert operation.get("operationId") == "triggerPublicIntelligenceSync"
responses = operation["responses"]
for status in ["202", "400", "403", "405", "409", "503"]:
    assert status in responses, f"OpenAPI missing response {status}"
provider = next(p for p in operation["parameters"] if p["name"] == "provider")
assert set(provider["schema"]["enum"]) == {"NVD", "FIRST_EPSS", "CISA_KEV", "CVE_PROGRAM"}
feed = next(p for p in operation["parameters"] if p["name"] == "feed")
assert feed["required"] is False
accepted = openapi["components"]["schemas"]["SyncAccepted"]
assert accepted["properties"]["contractId"]["enum"] == ["PUBLIC_INTELLIGENCE_SYNC_HTTP_V1"]

for token in [
    "PUBLIC_INTELLIGENCE_SYNC_ORCHESTRATOR_V1",
    "ACQUIRING",
    "BUILDING",
    "ADMITTING",
    "one exact acquired source payload",
    "OPERATOR",
    "NVD annual and modified feeds",
    "never become tombstones",
    "ProcessBuilder",
    "failed refresh does not erase",
    "1K/5K/10K/25K/50K/100K+",
]:
    assert token.lower() in doc.lower(), f"orchestrator documentation missing {token!r}"

print("Public Intelligence Sync Orchestrator V1 checks: PASS")
