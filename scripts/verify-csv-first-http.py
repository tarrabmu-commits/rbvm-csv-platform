#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstEnrichmentHttpHandler.java").read_text(encoding="utf-8")
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
    'analysis-summary',
    'method-admission',
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
        raise AssertionError(f"CSV-first handler missing {token}")

for forbidden in [
    'bash -c', 'sh -c', 'Runtime.getRuntime().exec',
    'CVSS4_Base_Score *', 'EPSS_Probability *', 'riskScore', 'priorityScore',
]:
    if forbidden in HANDLER:
        raise AssertionError(f"CSV-first handler contains forbidden execution/decision logic: {forbidden}")

if '"analysis".equals(type) && "POST".equals(method)' not in HANDLER:
    raise AssertionError('contextual analysis must be an explicit POST on the run-scoped analysis resource')
if 'Files.isRegularFile(enriched)' not in HANDLER or 'RUN_NOT_FOUND' not in HANDLER:
    raise AssertionError('contextual analysis must require an existing completed enrichment run')
if 'customer-bundle.json' not in HANDLER:
    raise AssertionError('contextual analysis must preserve the submitted customer bundle as a run artifact')
if 'cleanupContextArtifacts(' not in HANDLER:
    raise AssertionError('failed contextual analysis must not leave partial result artifacts')

if 'server.createContext(' not in LAUNCHER or 'new CsvFirstEnrichmentHttpHandler' not in LAUNCHER:
    raise AssertionError('CSV-first handler is not registered before platform start')
if 'io.rbvm.csv.RbvmPlatformMain' not in RUN:
    raise AssertionError('local launcher does not use CSV-first enabled main')
if 'Main-Class: io.rbvm.csv.RbvmPlatformMain' not in BUILD:
    raise AssertionError('distribution manifest does not use CSV-first enabled main')

print('CSV-first public enrichment + contextual-analysis HTTP structural checks: PASS')
