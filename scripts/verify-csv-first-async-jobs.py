#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
handler = (ROOT / 'src/main/java/io/rbvm/csv/CsvFirstEnrichmentJobHttpHandler.java').read_text(encoding='utf-8')
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
    'MAX_CONCURRENT_JOBS = 2',
    'MAX_QUEUED_JOBS = 8',
    'RejectedExecutionException',
    'CSV_FIRST_ENRICHMENT_JOB_CAPACITY',
    'ApiRole.OPERATOR', 'ApiRole.VIEWER',
]:
    if token not in handler:
        raise AssertionError(f'async enrichment handler missing {token!r}')

for forbidden in ['Executors.newFixedThreadPool', 'newCachedThreadPool', 'newSingleThreadExecutor']:
    if forbidden in handler:
        raise AssertionError(f'async enrichment must not use an unbounded executor: {forbidden}')

if 'new CsvFirstEnrichmentJobHttpHandler' not in launcher:
    raise AssertionError('async enrichment handler is not registered')
if 'new CsvFirstEnrichmentHttpHandler' not in launcher:
    raise AssertionError('legacy synchronous enrichment route must remain available for compatibility')

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
    "reviewControl(complete",
    "data-review-findings-button",
    "response.status === 404",
    "legacyRuns.add(id)",
    "data.status === 'QUEUED' || data.status === 'RUNNING'",
    "panel.dataset.jobState = status",
]:
    if token not in status_ui:
        raise AssertionError(f'job-status UI missing {token!r}')

for forbidden in ['progressPercent', 'Math.round(data.progress', 'width: `${data.progress']:
    if forbidden in status_ui:
        raise AssertionError(f'job-status UI fabricates provider progress: {forbidden}')

for token in ['csv-job-progress', '@keyframes csv-job-indeterminate', 'prefers-reduced-motion']:
    if token not in status_css:
        raise AssertionError(f'job-status CSS missing {token}')

print('CSV-first async enrichment job checks: PASS')
