# CSV-first Canonical Finding Handoff V1

## Purpose

This workflow converts a completed stateless CSV-first run into canonical scanner evidence without changing the meaning of the original upload.

It reuses the existing canonical CSV import service. It does not create a second importer and it does not calculate Organizational Risk.

## Boundary

```text
CSV-first run
  original input.csv
        |
        v
GET /api/v1/csv-first-sources/{runId}
        |
        v
POST /api/v1/csv-imports
  X-Source-Profile-Id: <explicit integration identity>
  X-CSV-Contract: WAZUH_CSV_V1 | WAZUH_CSV_V2
        |
        v
PREVIEW_READY
        |
        | explicit operator confirmation only
        v
POST /api/v1/csv-imports/{importId}/confirm
        |
        v
Canonical assets / vulnerabilities / exposures / findings
```

## Original evidence only

The handoff always reads the exact `input.csv` stored for the CSV-first run.

It never submits `enriched.csv` to the scanner evidence importer. Public CVSS/EPSS/KEV/CISA enrichment and customer contextual analysis remain separate evidence layers.

`CSV_FIRST_SOURCE_ARTIFACT_HTTP_V1` exposes the original bytes to authenticated viewers and returns `X-RBVM-Source-SHA256` for traceability.

## Source Profile

`Source Profile ID` is explicit integration identity. It is not inferred from asset name, filename, CVE, or customer risk context.

The canonical importer already uses Source Profile plus CSV contract and file SHA in its import identity and replay controls.

## Explicit contract

The operator must select either:

- `WAZUH_CSV_V1`
- `WAZUH_CSV_V2`

No v1/v2 conversion is performed by the handoff.

## Two-step mutation

Creating the preview does not materialize canonical Findings.

Canonical materialization occurs only after the operator explicitly invokes Confirm. The UI intentionally begins with Confirm disabled and enables it only after a successful preview has returned an exact `importId`.

## Resulting capability

After confirmation, the existing canonical model provides the stable Finding identity required by downstream evidence workflows including:

- Applicability;
- Finding-to-Reachability association;
- Finding-to-Business-Service / Business Impact association;
- Decision Input Snapshot construction.

This handoff does not auto-link Reachability or Business Impact and does not infer risk, priority, SLA, MAV, or any CVSS Environmental metric.
