#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
handler = (ROOT / 'src/main/java/io/rbvm/csv/CsvFirstEnrichmentJobHttpHandler.java').read_text(encoding='utf-8')
local_handler = (ROOT / 'src/main/java/io/rbvm/csv/CsvFirstLocalEnrichmentJobHttpHandler.java').read_text(encoding='utf-8')
executor = (ROOT / 'src/main/java/io/rbvm/csv/CsvFirstLocalEnrichmentExecutor.java').read_text(encoding='utf-8')
launcher = (ROOT / 'src/main/java/io/rbvm/csv/RbvmPlatformMain.java').read_text(encoding='utf-8')
compile_sh = (ROOT / 'scripts/compile.sh').read_text(encoding='utf-8')
transform = (ROOT / 'scripts/stabilize-csv-first-async-runtime.py').read_text(encoding='utf-8')
source_flow = (ROOT / 'src/main/resources/web/customer-flow.js').read_text(encoding='utf-8')
status_ui = (ROOT / 'src/main/resources/web/csv-first-job-status.js').read_text(encoding='utf-8')
status_css = (ROOT / 'src/main/resources/web/csv-first-job-status.css').read_text(encoding='utf-8')

for token in [
    'CSV_FIRST_ENRICHMENT_JOB_HTTP_V1',
    '/api/v1/csv-first-enrichment-jobs',
    'sendJson(exchange, 202, response)',
    'job-status.json',
    '"QUEUED"', '"RUNNING"', '"COMPLETE"', '"FAILED"',
    '"INDETERMINATE_PROVIDER_WORK"',
    'csv-first-enrichments',
    'new ThreadPoolExecutor(',
    'new ArrayBlockingQueue<>(MAX_QUEUED_JOBS)',
    'MAX_CONCURRENT_JOBS = 1',
    'MAX_QUEUED_JOBS = 8',
    'RejectedExecutionException',
    'CSV_FIRST_ENRICHMENT_JOB_CAPACITY',
    'ApiRole.OPERATOR', 'ApiRole.VIEWER',
]:
    if token not in handler:
        raise AssertionError(f'async compatibility enrichment handler missing {token!r}')

for forbidden in ['Executors.newFixedThreadPool', 'newCachedThreadPool', 'newSingleThreadExecutor']:
    if forbidden in handler or forbidden in local_handler:
        raise AssertionError(f'async enrichment must not use an unbounded executor: {forbidden}')

for token in [
    'new CsvFirstEnrichmentJobHttpHandler(',
    'CsvFirstLocalEnrichmentExecutor',
    'WAITING_FOR_LOCAL_WORKER',
    'GLOBAL_PUBLIC_INTELLIGENCE_ONLY',
    'tenantDatabaseStateUsed',
    'MAX_CONCURRENT_JOBS = 1',
    'MAX_QUEUED_JOBS = 8',
]:
    if token not in local_handler:
        raise AssertionError(f'async local enrichment wrapper missing {token!r}')

for token in [
    'READING_LOCAL_PUBLIC_INTELLIGENCE',
    'BUILDING_LOCAL_PUBLIC_INTELLIGENCE_SNAPSHOT',
    'ENRICHING_CSV_FROM_LOCAL_PUBLIC_INTELLIGENCE',
    'target.clear()',
    'collect-public-vulnerability-intel.py',
]:
    if token == 'collect-public-vulnerability-intel.py':
        if token in executor:
            raise AssertionError('shared local enrichment executor must not invoke live provider collector')
    elif token not in executor:
        raise AssertionError(f'shared local enrichment executor missing {token!r}')

if 'new CsvFirstLocalEnrichmentJobHttpHandler' not in launcher:
    raise AssertionError('async local enrichment handler is not registered')
if 'new CsvFirstLocalEnrichmentHttpHandler' not in launcher:
    raise AssertionError('synchronous local enrichment handler is not registered')
if 'new CsvFirstEnrichmentJobHttpHandler(dataDirectory, maximumUploadBytes, authenticator)' in launcher:
    raise AssertionError('product launcher must not register live legacy async enrichment transport')
if 'new CsvFirstEnrichmentHttpHandler(dataDirectory, maximumUploadBytes, authenticator)' in launcher:
    raise AssertionError('product launcher must not register live legacy synchronous enrichment transport')

legacy_call = "const response = await api('/api/v1/csv-first-enrichments', {"
async_call = "const response = await api('/api/v1/csv-first-enrichment-jobs', {"
if source_flow.count(legacy_call) != 1:
    raise AssertionError('customer-flow legacy call shape drifted; async build transform must fail closed')
for token in [legacy_call, async_call, 'count != 1']:
    if token not in transform:
        raise AssertionError(f'async runtime transform missing {token!r}')

for token in [
    'stabilize-csv-first-async-runtime.py',
    'csv-first-job-status.js',
    'csv-first-job-status.css',
]:
    if token not in compile_sh:
        raise AssertionError(f'compile bundle missing {token}')

for token in [
    'CSV_FIRST_ENRICHMENT_JOB_STATUS_UI_V1',
    "window.setTimeout(() => refresh(panel, id), 1500)",
    'reviewControl(complete',
    'data-review-findings-button',
    'response.status === 404',
    'legacyRuns.add(id)',
    "data.status === 'QUEUED' || data.status === 'RUNNING'",
    'panel.dataset.jobState = status',
]:
    if token not in status_ui:
        raise AssertionError(f'job-status UI missing {token!r}')

for forbidden in ['progressPercent', 'Math.round(data.progress', 'width: `${data.progress']:
    if forbidden in status_ui:
        raise AssertionError(f'job-status UI fabricates provider progress: {forbidden}')

for token in ['csv-job-progress', '@keyframes csv-job-indeterminate', 'prefers-reduced-motion']:
    if token not in status_css:
        raise AssertionError(f'job-status CSS missing {token}')

print('CSV-first async local enrichment job checks: PASS')
