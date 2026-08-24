#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
settings = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceAutomationSettings.java").read_text(encoding="utf-8")
plan = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceAutomationPlanExecutor.java").read_text(encoding="utf-8")
controller = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceAutomationController.java").read_text(encoding="utf-8")
factory = (ROOT / "src/main/java/io/rbvm/postgres/PublicIntelligenceAutomationRuntimeFactory.java").read_text(encoding="utf-8")
state_reader = (ROOT / "src/main/java/io/rbvm/postgres/PostgresPublicIntelligenceNvdBootstrapStateReader.java").read_text(encoding="utf-8")
self_test = (ROOT / "src/test/java/io/rbvm/postgres/PublicIntelligenceAutomationSelfTest.java").read_text(encoding="utf-8")
live_test = (ROOT / "src/test/java/io/rbvm/postgres/PostgresPublicIntelligenceNvdBootstrapStateLiveSelfTest.java").read_text(encoding="utf-8")
platform_test = (ROOT / "src/test/java/io/rbvm/csv/PlatformSelfTest.java").read_text(encoding="utf-8")
main = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
workflow = (ROOT / ".github/workflows/postgres-integration.yml").read_text(encoding="utf-8")
doc = (ROOT / "docs/PUBLIC_INTELLIGENCE_AUTOMATION_V1.md").read_text(encoding="utf-8")

for token in [
    "RBVM_INTELLIGENCE_NVD_BOOTSTRAP_ON_STARTUP",
    "RBVM_INTELLIGENCE_STARTUP_REFRESH_PROVIDERS",
    "RBVM_INTELLIGENCE_SCHEDULE_NVD_SECONDS",
    "RBVM_INTELLIGENCE_SCHEDULE_FIRST_EPSS_SECONDS",
    "RBVM_INTELLIGENCE_SCHEDULE_CISA_KEV_SECONDS",
    "RBVM_INTELLIGENCE_SCHEDULE_CVE_PROGRAM_SECONDS",
    "MIN_SCHEDULE_SECONDS = 3_600L",
    "MAX_SCHEDULE_SECONDS = 31L * 24L * 60L * 60L",
    '"0".equals(raw.trim())',
    "return nvdBootstrapOnStartup",
]:
    assert token in settings, f"automation settings missing {token!r}"

for token in [
    "NVD_FIRST_ANNUAL_YEAR = 2002",
    "completedAnnualYears()",
    "!complete.contains(year)",
    "Integer.toString(year)",
    "TriggerSource.STARTUP",
    '"modified"',
    "awaitComplete",
    "Status.COMPLETE",
    "Status.FAILED",
    "errorCode",
    "Provider.NVD ? \"modified\" : null",
]:
    assert token in plan, f"automation plan missing {token!r}"

for token in [
    "scheduleWithFixedDelay",
    "settings.nvdBootstrapOnStartup()",
    "settings.startupRefreshProviders()",
    "settings.scheduledRefreshIntervals()",
    "provider == PostgresPublicIntelligenceStore.Provider.NVD",
    "PublicIntelligenceSyncCoordinator.AlreadyRunningException",
    "scheduler.shutdownNow()",
    "awaitTermination(5, TimeUnit.SECONDS)",
]:
    assert token in controller, f"automation controller missing {token!r}"
assert "scheduleAtFixedRate" not in controller

for token in [
    "if (!automation.enabled()) return Optional.empty()",
    "Public intelligence automation requires RBVM_PROJECTION_BACKEND=POSTGRESQL",
    "Public intelligence automation requires the V31 synchronization runtime",
    "PostgresPublicIntelligenceSyncCompletionReader",
    "PostgresPublicIntelligenceNvdBootstrapStateReader",
]:
    assert token in factory, f"automation runtime factory missing {token!r}"

for token in [
    "ANNUAL_URI = Pattern.compile",
    "nvd\\.nist\\.gov/feeds/json/cve/2\\.0/",
    "(20[0-9]{2})",
    "provider = 'NVD'",
    "sync_mode = 'BOOTSTRAP'",
    "status = 'COMPLETE'",
    "matcher.matches()",
    "completedAnnualYears",
]:
    assert token in state_reader, f"NVD bootstrap state reader missing {token!r}"
assert "modified" not in state_reader.lower(), "bootstrap coverage reader must not special-case modified as annual coverage"

for token in [
    "automation must be disabled by default",
    "sub-hour automatic refresh cadence must be rejected",
    "NVD:2003:STARTUP",
    "NVD:2005:STARTUP",
    "NVD:modified:STARTUP",
    "bootstrap must not skip past a failed year or run modified tail",
    "NVD:modified:SCHEDULED",
]:
    assert token in self_test, f"automation self-test missing {token!r}"

for token in [
    "completed exact annual NVD run must count toward bootstrap",
    "failed annual NVD run must not count toward bootstrap",
    "incremental annual-looking NVD run must not count toward bootstrap",
    "modified NVD source must never masquerade as annual coverage",
]:
    assert token in live_test, f"automation live test missing {token!r}"
assert "PostgresPublicIntelligenceNvdBootstrapStateLiveSelfTest" in workflow
assert "PublicIntelligenceAutomationSelfTest.main(args)" in platform_test

for token in [
    "PublicIntelligenceAutomationRuntimeFactory.fromEnvironment",
    "publicIntelligenceAutomation.ifPresent(PublicIntelligenceAutomationController::start)",
    "publicIntelligenceAutomation.ifPresent(PublicIntelligenceAutomationController::close)",
    "publicIntelligenceOrchestration.ifPresent(PublicIntelligenceSyncCoordinator::close)",
]:
    assert token in main, f"product automation wiring missing {token!r}"
assert main.index("application.start();") < main.index(
    "publicIntelligenceAutomation.ifPresent(PublicIntelligenceAutomationController::start)"
), "automation must start only after HTTP server start"
assert main.index(
    "publicIntelligenceAutomation.ifPresent(PublicIntelligenceAutomationController::close)"
) < main.index(
    "publicIntelligenceOrchestration.ifPresent(PublicIntelligenceSyncCoordinator::close)"
), "automation must stop before source orchestrator"

for source in [settings, plan, controller, factory, state_reader]:
    lowered = source.lower()
    for forbidden in [
        "risk_score",
        "organizational_risk",
        "priority_tier",
        "sla_days",
        "tenant_id",
    ]:
        assert forbidden not in lowered, f"automation contains forbidden semantic {forbidden!r}"

for token in [
    "disabled by default",
    "2002 -> 2003 -> ... -> current UTC year -> modified",
    "fixed delay",
    "first missing annual source",
    "does not skip the failed year",
    "one application node",
    "not leader election",
    "ownership/lease contract",
    "1K/5K/10K/25K/50K/100K+",
]:
    assert token.lower() in doc.lower(), f"automation documentation missing {token!r}"

print("Public Intelligence Automation V1 checks: PASS")
