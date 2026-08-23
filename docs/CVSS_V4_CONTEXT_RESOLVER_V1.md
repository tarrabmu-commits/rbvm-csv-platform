# CVSS v4 Context Resolver V1

Contract ID: `CVSS_V4_CONTEXT_RESOLVER_V1`

This resolver prepares standards-aligned CVSS v4 context inputs without inventing organization-specific environmental metrics.

## Inputs

- Published CVSS v4 assessment for the CVE (`CVSS4_Status=PRESENT`).
- CISA KEV evidence.
- Optional published CVSS v4 Threat metric `E` when already present in the source vector.
- Customer MVP Asset Criticality.
- Customer MVP Internet Facing state.

## Threat E resolution

Resolution order:

1. If a published CVSS v4 `E` value exists, preserve it.
2. If KEV is `LISTED` and no published `E` exists, resolve `E:A` (`Attacked`).
3. If neither applies, use `E:X` (`Not Defined`).
4. If KEV is `LISTED` but a published non-`A` E value exists, mark the resolver `AMBIGUOUS_CONFLICT`; do not silently choose one.

`KEV=NOT_LISTED` never becomes `E:U`.

## Environmental metrics

The MVP customer fields are deliberately not converted to CVSS environmental metrics:

- `Asset Criticality` is a scalar organizational label; it is not equivalent to CVSS `CR`, `IR`, or `AR`.
- `Internet Facing` is an asset-level declaration; it is not equivalent to finding/endpoint-specific `MAV`.

Therefore V1 resolves:

```text
CR = X
IR = X
AR = X
MAV = X
```

unless a later evidence contract supplies semantically exact values.

## Context modes

- `UNAVAILABLE`: no unambiguous published CVSS v4 Base assessment.
- `B_ONLY`: Base assessment exists but no explicit Threat enrichment is resolved.
- `BT_INPUT_READY`: Base assessment exists and Threat E is explicitly resolved.

This contract does not calculate an organizational risk score. A later official CVSS v4 calculation engine may consume the resolved CVSS inputs and produce CVSS-B or CVSS-BT technical severity. Such a score remains technical severity, not organizational risk.

## Forbidden shortcuts

- CVSS v3.1 -> CVSS v4 conversion.
- KEV `NOT_LISTED` -> `E:U`.
- Asset Criticality -> `CR/IR/AR` mapping.
- Internet Facing -> `MAV:N` or another Modified Attack Vector value.
- CVSS x EPSS.
- Highest-score-wins source resolution.
