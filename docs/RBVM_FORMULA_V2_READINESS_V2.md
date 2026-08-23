# RBVM Formula V2 Readiness V2

Contract ID: `RBVM_FORMULA_V2_READINESS_V2`

This document supersedes the **current-state assessment** in `RBVM_FORMULA_V2_READINESS_V1` without mutating the historical V1 readiness artifact.

Formula V1 remains immutable.

## What changed since Readiness V1

The following technical-severity blockers are now resolved:

1. public CVSS v4 acquisition is implemented;
2. semantically equivalent CVSS v4 assessments are normalized without false ambiguity from explicit optional `X` metrics;
3. the FIRST-compatible CVSS v4 engine recalculates Base and Threat scores;
4. KEV may conservatively resolve Threat `E:A` when no conflicting published E value exists;
5. `RBVM_CUSTOMER_ASSET_BUNDLE_V3` captures direct customer CR/IR/AR values using native CVSS `X/L/M/H` semantics;
6. `CVSS_V4_CONTEXT_RESOLVER_V2` can produce `CVSS-B`, `CVSS-BT`, `CVSS-BE`, or `CVSS-BTE` contextual technical severity.

Therefore contextual CVSS v4 technical severity is now **computable when its required evidence exists**.

## Current evidence tuple

For one CSV-first finding the platform can preserve:

```text
Contextual CVSS v4 technical severity
FIRST EPSS 30-day exploitation probability
CISA KEV state
CISA SSVC enrichment when published
Customer Asset Criticality
Customer Internet Facing declaration
Customer direct CVSS CR / IR / AR requirements
```

These values remain semantically distinct.

## Organizational Risk status

`NON_COMPUTABLE`

Current method-admission state: `NO_V2_PRIMARY_METHOD_ADMITTED`.

The reason is no longer “CVSS Environmental context is unavailable.”

The current blockers are:

1. no approved `RBVM_FORMULA_V2` identity/version/SHA or canonical representation;
2. no authoritative published composition that turns contextual CVSS + EPSS + KEV + organization context into Organizational Risk;
3. the current CSV-first contract is not an exact `RBVM_DECISION_INPUT_SNAPSHOT_V3` and does not provide first-class Applicability evidence;
4. asset-level `Internet Facing` is not exact Finding/endpoint Reachability and cannot satisfy `NETWORK_REACHABILITY_CSV_V1` semantics;
5. CR/IR/AR are CVSS Security Requirements, not Business/Mission Impact evidence and cannot satisfy `BUSINESS_IMPACT_CSV_V1` semantics;
6. the existing OWASP-derived and Microsoft-derived methods require exact Decision Input V3 evidence and use their own explicit RBVM local mappings;
7. no empirical calibration/acceptance corpus has approved a V2 local composition or Low/Medium/High thresholds.

## Existing method disposition

`RBVM_V2_METHOD_ADMISSION_V1` enforces the current disposition:

| Candidate | Current disposition | Reason |
|---|---|---|
| Contextual CVSS v4 | `NOT_A_RISK_METHOD` | technical severity only |
| RBVM Formula V1 | `LEGACY_REFERENCE_ONLY` | immutable V1 contract; no coercion from CSV-first V2 |
| OWASP-derived RBVM V1 | `BLOCKED_INPUT_CONTRACT` | requires exact Decision Input V3; RBVM mapping is local policy |
| Microsoft P×D-derived RBVM V1 | `BLOCKED_INPUT_CONTRACT` | requires exact Decision Input V3; RBVM mapping is local policy |
| Future RBVM Formula V2 | `METHOD_NOT_APPROVED` | no exact method identity exists |

No catalog order, score magnitude, vendor name, or implementation availability is a selection rule.

## Smallest defensible next steps

Before approving an Organizational Risk formula, RBVM must close the evidence and calibration boundary in this order:

1. acquire/associate exact Finding-scoped Reachability evidence rather than using `Internet Facing` as a proxy;
2. acquire/associate Business/Mission Impact evidence rather than treating CR/IR/AR or scalar criticality as impact;
3. preserve Applicability explicitly when a candidate method requires it;
4. construct one immutable V2 decision/risk evidence snapshot binding the exact contextual CVSS and organization evidence used;
5. benchmark candidate risk-method mappings on a frozen corpus;
6. approve a local method only if every mapping, threshold, reducer, gate, and missing-evidence rule is explicit and SHA-bound;
7. keep Risk separate from Priority, Treatment, and SLA.

## Formula identity requirements remain unchanged

Any eventual V2 Organizational Risk formula must freeze at least:

```text
formulaId
formulaVersion
canonicalRepresentation
sha256
inputContractVersion
outputSemantics
outputScale
roundingMode
bounds
missingEvidencePolicy
staleEvidencePolicy
ambiguousEvidencePolicy
```

If the output is categorical, every threshold/matrix cell must be in the canonical representation. If the method is calibrated empirically, the calibration dataset identity and acceptance criteria must also be preserved.

## Forbidden shortcuts

- CVSS × EPSS.
- `KEV=NOT_LISTED` interpreted as no exploitation risk.
- `Internet Facing` interpreted as exact Reachability or MAV.
- Asset Criticality mapped to CR/IR/AR without direct assessment.
- CR/IR/AR interpreted as Business Impact.
- highest vendor score wins.
- catalog order selects the method.
- missing evidence becomes zero/low/worst-case without an explicit versioned policy.

Until those conditions are met, the correct output is contextual severity + independent threat/context evidence + admission/readiness state, with Organizational Risk explicitly `NON_COMPUTABLE`.
