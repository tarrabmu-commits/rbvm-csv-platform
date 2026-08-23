# CVSS v4 Context Resolver V2

Contract ID: `CVSS_V4_CONTEXT_RESOLVER_V2`

This resolver prepares standards-aligned CVSS v4 Threat and Environmental inputs without deriving organization-specific metrics from unrelated labels.

## Inputs

- Unambiguous published CVSS v4 Base assessment for the CVE.
- CISA KEV evidence and any published CVSS v4 Threat metric `E`.
- Optional customer-declared CVSS v4 Security Requirements:
  - `cvssConfidentialityRequirement` -> `CR`
  - `cvssIntegrityRequirement` -> `IR`
  - `cvssAvailabilityRequirement` -> `AR`
- Existing customer `Asset Criticality` and `Internet Facing` evidence remain separate context and are not converted into CVSS metrics.

Customer Security Requirement values are stored directly as CVSS metric values: `X`, `L`, `M`, or `H`. `X` means Not Defined. No ordinal or numeric conversion is performed.

## Threat E resolution

Resolution order remains:

1. Preserve a published non-`X` CVSS v4 `E` value.
2. If CISA KEV is `LISTED` and no published non-`X` `E` exists, resolve `E:A` (`Attacked`).
3. Otherwise leave `E:X` (`Not Defined`).
4. If KEV is `LISTED` but a published non-`A` `E` exists, emit `AMBIGUOUS_CONFLICT`; do not silently choose one.

`KEV=NOT_LISTED` never becomes `E:U`.

## Environmental Security Requirements

V2 accepts only direct customer declarations using FIRST CVSS v4 semantics:

```text
CR = X | L | M | H
IR = X | L | M | H
AR = X | L | M | H
```

These declarations are organization-specific requirements for Confidentiality, Integrity, and Availability. They are not inferred from `Asset Criticality`, Business Impact labels, scanner severity, EPSS, KEV, or any public source.

If all three are `X`, the Environmental Security Requirement group is not assessed and the previously calculated CVSS-B/CVSS-BT result is preserved.

If one or more of CR/IR/AR is non-`X`, the official FIRST-compatible CVSS v4 engine recalculates contextual technical severity. The resulting nomenclature is `CVSS-BE` when no Threat metric is explicitly assessed, or `CVSS-BTE` when Threat is assessed/resolved.

## Modified Base metrics

`MAV` and the other Modified Base metrics remain `X` in this resolver version. In particular:

- `Internet Facing=YES` does not imply `MAV:N`.
- `Internet Facing=NO` does not imply local or adjacent attack vector.

A later resolver may set Modified Base metrics only from exact finding/deployment evidence under a separate versioned contract.

## Context modes

- `UNAVAILABLE`: no unambiguous published CVSS v4 Base assessment.
- `B_ONLY`: Base exists; no explicit Threat or Environmental enrichment is assessed.
- `BT`: Base + explicit/resolved Threat.
- `BE`: Base + direct customer Environmental Security Requirements.
- `BTE`: Base + explicit/resolved Threat + direct customer Environmental Security Requirements.

## Output semantics

The calculated score remains **contextual technical vulnerability severity**. It is not Organizational Risk, Priority, Treatment, or SLA.

EPSS remains a separate exploitation probability and must not be multiplied by CVSS.

## Forbidden shortcuts

- CVSS v3.1 -> CVSS v4 conversion.
- KEV `NOT_LISTED` -> `E:U`.
- Asset Criticality -> `CR/IR/AR` mapping.
- Business Impact level -> `CR/IR/AR` mapping.
- Internet Facing -> `MAV` mapping.
- Highest-score-wins source resolution.
- CVSS x EPSS.
