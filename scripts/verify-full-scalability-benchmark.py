#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
runner_path = ROOT / "scripts/run-full-scalability-benchmark.py"
isolated_runner_path = ROOT / "scripts/run-full-scalability-benchmark-isolated.py"
runner = runner_path.read_text(encoding="utf-8")
isolated_runner = isolated_runner_path.read_text(encoding="utf-8")
bridge = (ROOT / "src/test/java/io/rbvm/postgres/PostgresFullScalabilityBenchmarkBridge.java").read_text(encoding="utf-8")
probe = (ROOT / "src/test/java/io/rbvm/postgres/PostgresFullScalabilityLocalExportProbe.java").read_text(encoding="utf-8")
projection = (ROOT / "src/main/java/io/rbvm/postgres/PostgresCanonicalProjection.java").read_text(encoding="utf-8")
doc = (ROOT / "docs/FULL_SCALABILITY_BENCHMARK_V1.md").read_text(encoding="utf-8")
full_workflow = (ROOT / ".github/workflows/full-scalability-benchmark.yml").read_text(encoding="utf-8")
postgres_workflow = (ROOT / ".github/workflows/postgres-integration.yml").read_text(encoding="utf-8")

# Structural token checks are not a substitute for Python syntax validation. Compile both
# benchmark entry points without executing them so malformed promotion edits fail immediately.
compile(runner, str(runner_path), "exec")
compile(isolated_runner, str(isolated_runner_path), "exec")

for token in [
    "RBVM_FULL_SCALABILITY_BENCHMARK_V1",
    "DEFAULT_SIZES = (1_000, 5_000, 10_000, 25_000, 50_000, 100_000)",
    '"tenThousandIsPlatformLimit": False',
    '"CAPACITY_NOT_REACHED_AT_RUN_SAFETY_CEILING"',
    '"MEASURED_BOTTLENECK_OR_FAILURE"',
    '"RESOURCE_EXHAUSTION"',
    'marker = "SQLState="',
    'sqlstate.startswith("53")',
    'completed.returncode in {137, -9}',
    '"--stress"',
    '"--stress-max-rows"',
    '"--unique-cve-ratio"',
    'default=0.05',
    'default=1_600_000',
    '"localLookupExportSeconds"',
    '"setupSeedSeconds"',
    '"canonicalProjectionManifest"',
    '"canonicalPriorityPersistenceRead"',
    '"postgres"',
    '"peakRssMiB"',
    '"rowsPerSecond"',
]:
    if token not in runner:
        raise AssertionError(f"full scalability runner missing {token!r}")

for token in [
    "LOCAL_EXPORT_CLASS",
    'name != "public-intelligence-seed-export"',
    '"synthetic-public-intelligence-setup"',
    '"isolated-local-lookup-export"',
    '"ISOLATED_LOCAL_LOOKUP_EXPORT_PROCESS"',
    'seed_metrics["localLookupExportSeconds"] = probe_metrics["localLookupExportSeconds"]',
    'seed_metrics["dbLookupExportDelta"] = probe_metrics["dbLookupExportDelta"]',
    'lookup_process["setupPeakRssMiB"] = setup_process.get("peakRssMiB")',
]:
    if token not in isolated_runner:
        raise AssertionError(f"isolated scalability runner missing {token!r}")

for token in [
    'RBVM_SCALABILITY_BENCHMARK_MODE',
    'jdbc.startsWith("jdbc:postgresql://127.0.0.1:")',
    'jdbc.startsWith("jdbc:postgresql://localhost:")',
    'DROP SCHEMA IF EXISTS rbvm CASCADE',
    'PostgresPublicIntelligenceStore',
    'PostgresPublicIntelligenceSyncJobStore',
    'PostgresCisaKevCatalogValidationReader',
    'PostgresCsvFirstLocalIntelligenceSnapshotExporter',
    'PostgresCanonicalProjection',
    'PostgresCanonicalImportFindingExporter',
    'PostgresCanonicalMvpPriorityAccess',
    'RBVM_FULL_SCALABILITY_POSTGRES_BRIDGE_V1',
    'APPEND_BATCH = 1_000',
    'READ_SAMPLE_LIMIT = 100',
]:
    if token not in bridge:
        raise AssertionError(f"PostgreSQL scalability bridge missing {token!r}")

for token in [
    'RBVM_SCALABILITY_BENCHMARK_MODE',
    'benchmark probe refuses non-local PostgreSQL targets',
    'PostgresCsvFirstLocalIntelligenceSnapshotExporter',
    'RBVM_FULL_SCALABILITY_LOCAL_EXPORT_PROBE_V1',
    '"localLookupExportSeconds"',
    '"localLookupCvesPerSecond"',
    '"dbLookupExportDelta"',
]:
    if token not in probe:
        raise AssertionError(f"isolated local-export probe missing {token!r}")

for forbidden in [
    "urlopen(",
    "HttpClient.newHttpClient",
    "collect-public-vulnerability-intel.py",
    "NVD_API_KEY",
]:
    if forbidden in bridge or forbidden in probe:
        raise AssertionError(f"benchmark path must remain local-only: {forbidden}")

# Synthetic seed generation is intentionally excluded from upload hot-path time.
if 'hot_path_seconds = seed["localLookupExportSeconds"]' not in runner:
    raise AssertionError("benchmark hot path must start at local PostgreSQL lookup/export")
if '"syntheticPublicIntelligenceSeedSeconds": seed["setupSeedSeconds"]' not in runner:
    raise AssertionError("synthetic provider seeding must be reported separately as setup")

# Large canonical imports force custom PostgreSQL plans only inside the import transaction.
# This prevents cached RI-trigger plans chosen against nearly-empty growing relations from
# becoming quadratic, without changing FK enforcement or the case-event transaction path.
plan_token = 'SET LOCAL plan_cache_mode = force_custom_plan'
if projection.count(plan_token) != 1:
    raise AssertionError("canonical import projection must set force_custom_plan exactly once")
import_start = projection.index("public void synchronizeImport")
case_event_start = projection.index("public void synchronizeCaseEvent")
plan_position = projection.index(plan_token)
if not import_start < plan_position < case_event_start:
    raise AssertionError("force_custom_plan must remain scoped to synchronizeImport only")

# Product decisions must not drift inside a performance harness.
for token in [
    "88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388",
    'report.get("organizationalRiskComputed") is not False',
    'report.get("riskStatus") != "NON_COMPUTABLE"',
]:
    if token not in runner:
        raise AssertionError(f"benchmark correctness guard missing {token!r}")

# Full capacity work is manual; pull-request PostgreSQL integration proves only a bounded smoke tier.
for token in [
    "workflow_dispatch:",
    'default: "1000,5000,10000,25000,50000,100000"',
    'default: "1600000"',
    "--stress-max-rows",
    "RBVM_SCALABILITY_BENCHMARK_MODE: 'true'",
    "scripts/run-full-scalability-benchmark-isolated.py",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
]:
    if token not in full_workflow:
        raise AssertionError(f"manual full scalability workflow missing {token!r}")
if "pull_request:" in full_workflow or "push:" in full_workflow:
    raise AssertionError("full 100K+ scalability workflow must remain manual, not PR/push triggered")
for token in [
    "Run 1K full-scalability correctness smoke",
    "scripts/run-full-scalability-benchmark-isolated.py",
    "--sizes 1000",
    "--stress-max-rows 1000",
    "priorityMappedSourceRows'] == 1000",
    "ISOLATED_LOCAL_LOOKUP_EXPORT_PROCESS",
    "Upload 1K scalability smoke evidence",
]:
    if token not in postgres_workflow:
        raise AssertionError(f"PostgreSQL integration smoke gate missing {token!r}")
if "--sizes 100000" in postgres_workflow:
    raise AssertionError("normal PostgreSQL integration must not run the 100K capacity tier")

for token in [
    "1K -> 5K -> 10K -> 25K -> 50K -> 100K Findings",
    "10K is a regression checkpoint, not a platform limit",
    "CAPACITY_NOT_REACHED_AT_RUN_SAFETY_CEILING",
    "unique-CVE ratio",
    "--unique-cve-ratio 1.0",
    "setupSeedSeconds",
    "localLookupExportSeconds",
    "isolated process",
    "manual workflow",
    "Never run this harness against an operational RBVM database",
]:
    if token.lower() not in doc.lower():
        raise AssertionError(f"full scalability benchmark documentation missing {token!r}")

print("Full scalability benchmark structural checks: PASS")
