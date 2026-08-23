# Canonical Import Finding Manifest V1

Contract ID: `CANONICAL_IMPORT_FINDING_MANIFEST_HTTP_V1`

## Purpose

Expose the exact canonical `Finding_ID` values materialized from one completed canonical CSV import so downstream Applicability and Finding-context association workflows do not need to infer identity.

## Route

```text
GET /api/v1/canonical-imports/{importId}/findings.csv
```

The route is read-only and requires `VIEWER` authorization.

## Exact lineage

A Finding is resolved only through persisted canonical provenance:

```text
rbvm.import_observation
        ↓ observation_id
rbvm.observation
        ↓ observation_id
rbvm.exposure_observation
        ↓ exposure_id
rbvm.exposure
        ↓
Finding_ID = rbvm.exposure.id
```

The exporter is scoped by the exact `import_id` and only accepts a `COMPLETED` canonical import.

It does **not** match or infer Finding identity from hostname, asset name, CVE, product, filename, severity, or timestamps.

## CSV columns

```text
Import_ID
Finding_ID
Source_Row_Number
Source_Profile_Key
Agent
CVE_ID
Affected_Product
Finding_Status
Severity
```

`Source_Row_Number` is provenance back to the source CSV row. If multiple observations from the same import map to the same canonical Finding, the manifest emits the Finding once and preserves the minimum linked source row number for deterministic ordering/reference.

## Semantics

This manifest is an identity/provenance artifact only.

It does not:

- assess Applicability;
- auto-link Reachability;
- auto-link Business Service or Business Impact;
- infer `MAV` from Internet-facing state;
- calculate CVSS;
- combine CVSS with EPSS;
- calculate risk, priority, treatment, or SLA.

## Downstream use

After a canonical import is confirmed, these exact `Finding_ID` values are valid subjects for the existing explicit APIs:

```text
/api/v1/findings/{findingId}/reachability-links/...
/api/v1/findings/{findingId}/business-service-links/...
```

Those association APIs retain their own semantics: customer-confirmed `LINKED` / `UNLINKED`, immutable revision history, and optimistic concurrency through `ETag` / `If-Match`.

Applicability remains a separate evidence family using `APPLICABILITY_CSV_V1`.

## Failure semantics

- PostgreSQL canonical projection unavailable → `503 CANONICAL_FINDING_MANIFEST_UNAVAILABLE`.
- No completed import with the requested identifier → `404 COMPLETED_IMPORT_NOT_FOUND`.
- Manifest can be header-only when a completed import produced no linked canonical Findings.
