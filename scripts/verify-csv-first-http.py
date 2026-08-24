#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstEnrichmentHttpHandler.java").read_text(encoding="utf-8")
LOCAL_HANDLER = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstLocalEnrichmentHttpHandler.java").read_text(encoding="utf-8")
LAUNCHER = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
RUN = (ROOT / "scripts/run-server.sh").read_text(encoding="utf-8")
BUILD = (ROOT / "scripts/build-distribution.sh").read_text(encoding="utf-8")

required_handler = [
    'CSV_FIRST_PUBLIC_INTELLIGENCE_HTTP_V1',
    'CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1',
    '/api/v1/csv-first-enrichments',
    'INPUT_CSV_ONLY',
    'INPUT_CSV_PLUS_CUSTOMER_DECLARED_CONTEXT',
    'databaseStateUsed',
    'new ProcessBuilder(',
    'scripts/enrich-uploaded-csv.py',
    'scripts/analyze-csv-run-evidence.py',
    'scripts/evaluate-rbvm-v2-method-candidates.py',
    'ANALYSIS_CREATE_PATH',
    'ANALYSIS_ARTIFACT_PATH',
    '/analyses$',
    'method-admission',
    'customer-bundle',
    'analysisId',
    'immutable',
    'organizationalRisk',
    'NON_COMPUTABLE',
    'ApiRole.OPERATOR',
    'ApiRole.VIEWER',
    'application/json',
    'PROCESS_TIMEOUT',
    'copyBounded(',
    'RBVM_REPOSITORY_ROOT',
]
for token in required_handler:
    if token not in HANDLER:
        raise AssertionError(f"CSV-first compatibility handler missing {token}")

for forbidden in [
    'bash -c', 'sh -c', 'Runtime.getRuntime().exec',
    'CVSS4_Base_Score *', 'EPSS_Probability *', 'riskScore', 'priorityScore',
    'customer-bundle.json.tmp', 'StandardCopyOption.REPLACE_EXISTING',
]:
    if forbidden in HANDLER:
        raise AssertionError(f"CSV-first compatibility handler contains forbidden execution/decision/overwrite logic: {forbidden}")

if 'UUID analysisId = UUID.randomUUID();' not in HANDLER:
    raise AssertionError('each contextual analysis must receive a distinct immutable analysisId')
if 'Path analysisDirectory = analysisDirectory(runId, analysisId);' not in HANDLER:
    raise AssertionError('contextual analysis must use a run-scoped immutable analysis directory')
if 'deleteTree(analysisDirectory);' not in HANDLER:
    raise AssertionError('failed contextual analyses must remove partial revision artifacts')
if 'Files.isRegularFile(enriched)' not in HANDLER or 'RUN_NOT_FOUND' not in HANDLER:
    raise AssertionError('contextual analysis must require an existing completed enrichment run')
if 'response.put("immutable", true);' not in HANDLER:
    raise AssertionError('successful contextual analysis response must state immutable=true')
if 'response.put("customerBundle"' not in HANDLER:
    raise AssertionError('successful analysis must expose the exact submitted customer bundle artifact')

for token in [
    'new CsvFirstEnrichmentHttpHandler(',
    'CsvFirstLocalEnrichmentExecutor',
    'CSV_FIRST_LOCAL_INTELLIGENCE_UNAVAILABLE',
    'GLOBAL_PUBLIC_INTELLIGENCE_ONLY',
    'tenantDatabaseStateUsed',
]:
    if token not in LOCAL_HANDLER:
        raise AssertionError(f'local CSV-first product wrapper missing {token!r}')

if 'server.createContext(' not in LAUNCHER or 'new CsvFirstLocalEnrichmentHttpHandler' not in LAUNCHER:
    raise AssertionError('local CSV-first product handler is not registered before platform start')
if 'new CsvFirstEnrichmentHttpHandler(dataDirectory, maximumUploadBytes, authenticator)' in LAUNCHER:
    raise AssertionError('product launcher must not register live legacy CSV enrichment POST transport')
if 'io.rbvm.csv.RbvmPlatformMain' not in RUN:
    raise AssertionError('local launcher does not use CSV-first enabled main')
if 'Main-Class: io.rbvm.csv.RbvmPlatformMain' not in BUILD:
    raise AssertionError('distribution manifest does not use CSV-first enabled main')

print('CSV-first local public enrichment + immutable contextual-analysis HTTP structural checks: PASS')
