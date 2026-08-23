# CSV-first Contextual Analysis HTTP V1

Contract ID: `CSV_FIRST_CONTEXTUAL_ANALYSIS_HTTP_V1`

## Purpose

This transport connects one completed stateless CSV-first public-intelligence run to the existing server-side contextual CVSS and risk-method-admission engines without duplicating scoring logic in the browser.

It does not read current Cases or tenant database state and it does not calculate Organizational Risk.

## Flow

1. `POST /api/v1/csv-first-enrichments` with the customer vulnerability CSV.
2. Public intelligence enrichment creates the immutable run-scoped artifacts:
   - enriched CSV;
   - public-intelligence snapshot;
   - enrichment report.
3. The customer completes `RBVM_CUSTOMER_ASSET_BUNDLE_V3` context, including direct CVSS v4 CR/IR/AR requirements.
4. `POST /api/v1/csv-first-enrichments/{runId}/analyses` with that JSON bundle.
5. The server executes, without a shell:
   - `analyze-csv-run-evidence.py`;
   - `evaluate-rbvm-v2-method-candidates.py`.
6. A new immutable `analysisId` is created for every successful contextual analysis.

## Immutable analysis artifacts

Each successful analysis is stored under a distinct server-owned directory identified by `(runId, analysisId)`.

The following artifacts are retrievable by authenticated viewers:

```text
GET /api/v1/csv-first-enrichments/{runId}/analyses/{analysisId}/customer-bundle
GET /api/v1/csv-first-enrichments/{runId}/analyses/{analysisId}/csv
GET /api/v1/csv-first-enrichments/{runId}/analyses/{analysisId}/summary
GET /api/v1/csv-first-enrichments/{runId}/analyses/{analysisId}/method-admission
```

A later POST never overwrites a prior successful analysis. It receives another `analysisId`.

Failed or interrupted analysis attempts delete their partial analysis directory and never expose a partial decision artifact.

## Semantics

The analysis CSV may contain official-FIRST-compatible contextual technical severity:

- `CVSS-B`
- `CVSS-BT`
- `CVSS-BE`
- `CVSS-BTE`

EPSS remains exploitation probability. KEV/SSVC remain threat evidence. Asset Criticality and Internet Facing remain customer context. CR/IR/AR are direct CVSS v4 Security Requirements.

`Internet Facing` is not converted to `MAV`.

No CVSS value is multiplied by EPSS.

## Risk-method admission

The method-admission artifact is produced by `RBVM_V2_METHOD_ADMISSION_V1` and currently preserves the expected state:

```text
NO_V2_PRIMARY_METHOD_ADMITTED
```

Contextual CVSS is `NOT_A_RISK_METHOD`. Formula V1 is a legacy reference for this CSV-first V2 flow. Existing OWASP-derived and Microsoft-derived V1 methods remain blocked unless their exact Decision Input V3 evidence contract is satisfied.

## Organizational Risk

The transport response explicitly declares:

```text
organizationalRisk = NON_COMPUTABLE
```

This is not a failure of contextual CVSS calculation. It preserves the boundary between technical severity and an as-yet unapproved Organizational Risk composition.

## Security and execution boundary

- analysis creation requires `OPERATOR` role;
- artifact reads require `VIEWER` role;
- customer context must use a JSON content type;
- request size is bounded by the server upload limit;
- Python commands are invoked with `ProcessBuilder` argument arrays, never `bash -c` or `sh -c`;
- scripts must be regular non-symlink files under the configured repository root;
- process duration and captured diagnostics are bounded.
