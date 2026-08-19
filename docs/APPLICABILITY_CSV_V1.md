# APPLICABILITY_CSV_V1

`APPLICABILITY_CSV_V1` is a separate, finding-scoped assessment contract. It does not replace or modify `WAZUH_CSV_V1`.

## Why it is separate

The Wazuh vulnerability CSV is source evidence about detection. Applicability is a later assessment about whether that detected CVE actually applies to the deployed component/configuration. Keeping the two contracts separate prevents scanner observations from being rewritten as analyst conclusions.

```text
WAZUH_CSV_V1
    |
    v
Canonical Finding
    |
    +---- no applicability row ----> UNKNOWN / unassessed
    |
    +---- APPLICABILITY_CSV_V1 ----> explicit assessed applicability
```

## Contract

Required headers:

```text
Finding_ID,Applicability_Status,Applicability_Reason,Evidence_Source,Evaluated_At
```

### `Finding_ID`

Platform-generated canonical finding identifier. In PostgreSQL, `Finding_ID` is the tenant-scoped `rbvm.exposure.id` UUID.

This is deliberate: `rbvm.exposure` already represents the canonical finding grain used by the platform:

```text
Source Profile
+ Asset
+ CVE
+ Component
```

For `WAZUH_CSV_V1`, the component identity is source-limited because package version and architecture are unavailable. For `WAZUH_CSV_V2`, the component identity includes the stronger package evidence provided by that contract.

The applicability CSV intentionally does not repeat `Agent`, `CVE_ID`, or `Affected_Product` as an identity mechanism. This avoids ambiguous reassociation and avoids pretending that `WAZUH_CSV_V1` provides stable Agent ID, package version, or architecture.

### `Applicability_Status`

Allowed values:

```text
APPLICABLE
NOT_APPLICABLE
UNKNOWN
```

An `UNKNOWN` row means the finding **was assessed**, but the available evidence was inconclusive.

If a finding has no applicability row, its state remains:

```text
status   = UNKNOWN
assessed = false
```

### `Applicability_Reason`

Required free-text rationale for the assessment. It must describe why the evidence supports the chosen status.

### `Evidence_Source`

Required provenance for the assessment, for example a vendor advisory, distribution advisory, internal configuration review, or another identifiable evidence source.

### `Evaluated_At`

Required ISO-8601 timestamp with timezone recording when the assessment was made.

## Example

```csv
Finding_ID,Applicability_Status,Applicability_Reason,Evidence_Source,Evaluated_At
11111111-1111-4111-8111-111111111111,APPLICABLE,Installed component and vulnerable functionality are present,Vendor advisory,2026-08-18T10:00:00Z
22222222-2222-4222-8222-222222222222,NOT_APPLICABLE,Vulnerable functionality is not exposed in this deployment,Vendor advisory,2026-08-18T10:05:00Z
33333333-3333-4333-8333-333333333333,UNKNOWN,Available configuration evidence is insufficient to determine applicability,Internal review,2026-08-18T10:10:00Z
```

## Determinism and duplicate handling

Multiple assessments for the same finding are allowed when `Evaluated_At` differs; this preserves assessment history.

For the same `Finding_ID + Evaluated_At`:

- an exact replay inside one CSV is deduplicated by the contract analyzer;
- an exact replay of evidence already stored in PostgreSQL is treated idempotently and is not inserted again;
- conflicting content is quarantined rather than overwriting history.

Each persisted row carries an `evidence_sha256` derived from the normalized finding ID, status, reason, evidence source, and evaluation timestamp. The importer also derives a deterministic assessment UUID from that digest.

## PostgreSQL persistence model

`V9__applicability_persistence.sql` adds immutable historical storage:

```text
rbvm.applicability_assessment
    id
    tenant_id
    finding_id
    status
    reason
    evidence_source
    evaluated_at
    ingested_at
    evidence_sha256
```

The `(tenant_id, finding_id)` foreign key points to `rbvm.exposure(tenant_id, id)`. This makes both finding existence and tenant ownership database-enforced properties.

Two read models are defined:

```text
rbvm.current_applicability_assessment
```

contains only the latest explicit assessment for findings that have one, while:

```text
rbvm.finding_applicability
```

contains every canonical finding and represents findings without an explicit assessment as:

```text
applicability_status   = UNKNOWN
applicability_assessed = false
```

The assessment history is append-only for the runtime role; UPDATE, DELETE, and TRUNCATE are revoked.

## Transactional importer

`PostgresApplicabilityImporter` is the persistence boundary for the contract.

The import flow is:

```text
APPLICABILITY_CSV_V1
        |
        v
contract validation
        |
        v
accepted assessment rows
        |
        v
serializable PostgreSQL transaction
        |
        +---- Finding_ID absent from tenant ------> persistence quarantine
        |
        +---- exact persisted replay -------------> replay / no insert
        |
        +---- same-time different evidence -------> persistence quarantine
        |
        +---- valid new assessment ---------------> immutable INSERT
        |
        v
commit + catalog revision when new evidence was inserted
```

A fatal database error rolls back the persistence transaction. Contract-level invalid rows and persistence-level unsafe rows remain distinguishable in `ApplicabilityImportResult`.

Cross-tenant finding references are not reassigned: lookup is tenant-scoped, so a UUID that exists only under another tenant is treated as unavailable to the current import and is quarantined.

## Operator/API workflow

Applicability operations are enabled only when the PostgreSQL runtime is available with schema version 9 or newer. The platform exposes two dedicated operations:

```text
GET  /api/v1/applicability-findings.csv
POST /api/v1/applicability-imports
```

The operator flow is:

```text
Wazuh CSV materialized
        |
        v
GET applicability-findings.csv
        |
        v
review canonical Finding_ID + asset/CVE/product context
        |
        v
create APPLICABILITY_CSV_V1 for findings actually assessed
        |
        v
POST applicability-imports
        |
        v
Inserted / Replayed / Quarantined result
        |
        v
current applicability read model
```

The reference export is intentionally **not** an assessment file. Its columns are:

```text
Finding_ID
Agent
CVE_ID
Affected_Product
Severity
Current_Applicability_Status
Current_Applicability_Assessed
Current_Applicability_Reason
Current_Evidence_Source
Current_Evaluated_At
```

The `Current_*` names are deliberate. They prevent the reference export from being accidentally uploaded as `APPLICABILITY_CSV_V1` and falsely turning every listed finding into an explicit assessment. The operator must create the five-column assessment contract and include only findings for which an applicability evaluation was actually performed.

The import response keeps contract-level and persistence-level results separate, including:

```text
insertedAssessments
replayedAssessments
contractDeduplicatedRows
contractQuarantinedRows
persistenceQuarantinedRows
totalDeduplicatedRows
totalQuarantinedRows
```

The HTTP upload is streamed to a bounded temporary file using the platform upload limit. The temporary file is deleted after the transactional importer completes or fails.

### Normal finding reads

When PostgreSQL schema V9+ is active, normal case detail reads also decorate each exposure with the canonical finding UUID and current applicability evidence. The existing hashed `exposureId` remains unchanged for API compatibility; the additional fields are:

```text
findingId
applicabilityStatus
applicabilityAssessed
applicabilityReason
applicabilityEvidenceSource
applicabilityEvaluatedAt
```

This prevents the operator from having to infer a `Finding_ID` from Agent/CVE/Product text and makes current applicability visible alongside the finding itself. Local-memory or pre-V9 runtimes do not fabricate these fields.

## Current boundary

The following applicability foundation is now implemented:

- finding-scoped domain states (`APPLICABLE`, `NOT_APPLICABLE`, `UNKNOWN`);
- explicit unassessed vs assessed-UNKNOWN semantics;
- separate `APPLICABILITY_CSV_V1` contract;
- CSV validation and deterministic within-file replay handling;
- persistent `Finding_ID = rbvm.exposure.id` mapping;
- immutable PostgreSQL assessment history;
- tenant/finding foreign-key boundary;
- latest/current applicability read views;
- transactional PostgreSQL importer with persisted replay idempotency and conflict quarantine;
- authenticated finding-reference CSV export for operators;
- authenticated applicability upload endpoint and structured import result;
- current applicability surfaced on normal PostgreSQL finding/exposure reads;
- runtime health/metrics capability visibility for applicability operations.

Applicability remains independent from:

- scanner detection;
- finding lifecycle;
- CVSS severity;
- KEV / EPSS / exploitability;
- remediation priority and SLA;
- organizational risk or future RBVM decisions.
