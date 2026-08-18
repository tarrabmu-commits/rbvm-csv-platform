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

Platform-generated canonical finding identifier. In the current PostgreSQL implementation it maps to the finding/exposure UUID. The assessment CSV intentionally does not repeat `Agent`, `CVE_ID`, or `Affected_Product` as an identity mechanism.

This avoids ambiguous reassociation and avoids pretending that `WAZUH_CSV_V1` provides stable Agent ID, package version, or architecture.

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

- an exact replay is deduplicated;
- conflicting content is quarantined as `CONFLICTING_ASSESSMENT_TIMESTAMP`.

This prevents two different applicability states from competing at the same evidence timestamp.

## Current boundary

This increment validates and parses the contract only. It does not yet persist the assessments or verify that a `Finding_ID` exists in the selected tenant. Tenant-scoped lookup and historical persistence are the next implementation step.

Applicability remains independent from:

- scanner detection;
- finding lifecycle;
- CVSS severity;
- KEV / EPSS / exploitability;
- remediation priority and SLA;
- organizational risk or future RBVM decisions.
