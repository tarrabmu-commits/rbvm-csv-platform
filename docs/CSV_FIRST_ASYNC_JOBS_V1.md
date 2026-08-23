# CSV-first Async Enrichment Jobs V1

`CSV_FIRST_ENRICHMENT_JOB_HTTP_V1` makes the customer upload flow non-blocking without changing vulnerability-evidence semantics.

## Product flow

1. The browser reads the uploaded CSV only to identify customer assets for the setup form.
2. `POST /api/v1/csv-first-enrichment-jobs` stages the exact CSV in a new run directory and returns `202 Accepted` with a `runId` immediately after staging and queue admission.
3. The browser opens Assets and polls `GET /api/v1/csv-first-enrichment-jobs/{runId}`.
4. The background job executes the established public-intelligence enrichment script.
5. `Review Findings` remains disabled until status is `COMPLETE`.
6. Completed jobs expose the established immutable run artifacts through `/api/v1/csv-first-enrichments/{runId}/...`; contextual analysis and MVP priority continue to use those existing contracts.

## Capacity and memory boundary

The in-process executor is deliberately bounded:

- 2 concurrently running enrichment jobs.
- 8 queued jobs.
- Further submissions fail closed with HTTP 503 `CSV_FIRST_ENRICHMENT_JOB_CAPACITY` instead of growing an unbounded queue.

Each job retains the existing ten-minute process execution limit. This protects the service; it is not an SLA.

## Status semantics

Persisted `job-status.json` values are `QUEUED`, `RUNNING`, `COMPLETE`, or `FAILED`. Stages describe the current coarse operation. V1 intentionally declares `INDETERMINATE_PROVIDER_WORK`; it does not fabricate a percentage because the underlying providers do not yet publish one common progress contract.

## Compatibility

The legacy synchronous `/api/v1/csv-first-enrichments` POST remains registered. The product browser bundle opts into the async endpoint through a fail-closed build transform while older API clients remain compatible.

A run remains `INPUT_CSV_ONLY` and `databaseStateUsed=false`. No CVSS/EPSS multiplication, priority inference, Organizational Risk calculation, customer-context inference, or canonical database materialization is introduced by this transport change.
