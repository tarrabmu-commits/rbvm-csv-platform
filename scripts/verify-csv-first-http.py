#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HANDLER = (ROOT / "src/main/java/io/rbvm/csv/CsvFirstEnrichmentHttpHandler.java").read_text(encoding="utf-8")
LAUNCHER = (ROOT / "src/main/java/io/rbvm/csv/RbvmPlatformMain.java").read_text(encoding="utf-8")
RUN = (ROOT / "scripts/run-server.sh").read_text(encoding="utf-8")
BUILD = (ROOT / "scripts/build-distribution.sh").read_text(encoding="utf-8")

required_handler = [
    'CSV_FIRST_PUBLIC_INTELLIGENCE_HTTP_V1',
    '/api/v1/csv-first-enrichments',
    'INPUT_CSV_ONLY',
    'databaseStateUsed',
    'new ProcessBuilder(',
    'scripts/enrich-uploaded-csv.py',
    'PROCESS_TIMEOUT',
    'copyBounded(',
    'RBVM_REPOSITORY_ROOT',
]
for token in required_handler:
    if token not in HANDLER:
        raise AssertionError(f"CSV-first handler missing {token}")

for forbidden in ['bash -c', 'sh -c', 'Runtime.getRuntime().exec']:
    if forbidden in HANDLER:
        raise AssertionError(f"CSV-first handler must not invoke shell execution: {forbidden}")

if 'server.createContext(' not in LAUNCHER or 'new CsvFirstEnrichmentHttpHandler' not in LAUNCHER:
    raise AssertionError('CSV-first handler is not registered before platform start')
if 'io.rbvm.csv.RbvmPlatformMain' not in RUN:
    raise AssertionError('local launcher does not use CSV-first enabled main')
if 'Main-Class: io.rbvm.csv.RbvmPlatformMain' not in BUILD:
    raise AssertionError('distribution manifest does not use CSV-first enabled main')

print('CSV-first HTTP transport structural checks: PASS')
