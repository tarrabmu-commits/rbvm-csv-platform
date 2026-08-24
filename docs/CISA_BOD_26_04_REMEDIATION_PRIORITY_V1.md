# CISA BOD 26-04 Remediation Priority V1

Contract ID: `CISA_BOD_26_04_REMEDIATION_PRIORITY_METHOD_V1`

Classification: `CISA_REMEDIATION_PRIORITY_METHOD`

Canonical SHA-256:

`64066ae687fd98c6db48fa224316446dc579737ff6c16321f155de69c5f0e9ff`

Source decision table: `cisa:DT_BOD2604:1.0.0`

Source outcome group: `cisa:BOD2604:1.0.0`

Primary implementation reference:

`https://certcc.github.io/SSVC/howto/cisa_response/`

## Purpose

This contract adopts the CISA BOD 26-04 response-timeline decision model as the platform's **remediation priority method**.

It is deliberately not an Organizational Risk formula. It does not replace, modify, or reinterpret `RBVM_FORMULA_V1` or any derived-risk methodology.

`RBVM_MVP_PRIORITY_POLICY_V1` remains frozen as a legacy/benchmark policy and is not reused to implement this method.

## Canonical decision points

BOD 26-04 uses exactly four decision points:

| Decision point | Semantic ID | Values | Source of truth in RBVM |
|---|---|---|---|
| In KEV | `cisa:KEV:1.0.0` | `N / Y` | validated CISA KEV membership evidence |
| Publicly Exposed | `cisa:PE:1.0.0` | `N / Y` | explicit customer evidence matching the CISA definition |
| Automatable | `ssvc:A:2.0.0` | `N / Y` | CISA Vulnrichment SSVC evidence |
| Technical Impact | `ssvc:TI:1.0.0` | `P / T` | CISA Vulnrichment SSVC evidence |

The generic CISA Vulnrichment `Exploitation` value is **not** a BOD 26-04 input. BOD uses `In KEV` instead.

## Publicly Exposed boundary

`Publicly Exposed` means the asset is accessible to unauthenticated or untrusted entities through public networks.

The existing customer `internetFacing` field is not automatically equivalent to this decision point. It remains a separate legacy/coarse customer-context declaration.

Therefore:

```text
internetFacing=YES
    does not imply
PubliclyExposed=Y
```

A future customer-bundle revision must capture `publiclyExposed` explicitly. Legacy bundles must upgrade it to `UNKNOWN`, never infer `Y` or `N`.

## Canonical outcomes

The canonical result is one of:

| Key | Meaning |
|---|---|
| `FSU` | Fix on system upgrade |
| `60D` | Remediate within 60 days |
| `14D` | Remediate within 14 days |
| `3D` | Remediate within 3 days |
| `3DF` | Remediate within 3 days and perform forensic triage/investigation |

These keys are the canonical platform output. `LOW / MEDIUM / HIGH / CRITICAL` is a separate presentation mapping and is not part of this decision table or its SHA.

## Canonical 16-row decision table

| In KEV | Publicly Exposed | Automatable | Technical Impact | Outcome |
|---|---|---|---|---|
| N | N | N | P | FSU |
| Y | N | N | P | 14D |
| N | Y | N | P | 60D |
| N | N | Y | P | 60D |
| N | N | N | T | FSU |
| Y | Y | N | P | 14D |
| Y | N | Y | P | 14D |
| N | Y | Y | P | 14D |
| Y | N | N | T | 14D |
| N | Y | N | T | 14D |
| N | N | Y | T | 60D |
| Y | Y | Y | P | 3D |
| Y | Y | N | T | 3DF |
| Y | N | Y | T | 3DF |
| N | Y | Y | T | 3D |
| Y | Y | Y | T | 3DF |

## Missing/invalid evidence

The binary table must only be evaluated when all four canonical decision points are present and valid.

Missing evidence is not negative evidence:

```text
missing KEV evidence              != N
missing Publicly Exposed evidence != N
missing Automatable evidence      != N
missing Technical Impact evidence != P
```

The later input-snapshot/decision-engine contract must return `INCOMPLETE` (with exact blockers) when any required input is missing, invalid, ambiguous, or otherwise unusable. It must not guess a table row.

## SSVC resolution boundary

`scripts/cisa_bod_26_04.py` resolves only:

- `Automatable`: `Yes/Y -> Y`, `No/N -> N`;
- `Technical Impact`: `Partial/P -> P`, `Total/T -> T`.

Blank values become `MISSING`. Unrecognized nonblank values become `INVALID`.

The raw CISA Vulnrichment profile version/timestamp/source provenance must be retained by the future BOD input snapshot. The resolver does not transform generic SSVC Exploitation into KEV.

## Explicit non-inputs

The following evidence remains useful elsewhere but does not change the CISA BOD 26-04 outcome:

- CVSS-B / CVSS-BT / CVSS-BE / CVSS-BTE technical severity;
- FIRST EPSS probability or percentile;
- Asset Criticality;
- Business / Mission Impact;
- legacy customer `internetFacing`;
- RBVM Formula / Organizational Risk results.

## Implementation sequence

1. canonical table and strict SSVC value resolver — this increment;
2. explicit customer `PubliclyExposed` field;
3. immutable BOD input snapshot with exact four-input provenance;
4. fail-closed BOD decision engine;
5. append-only persistence (next schema version after current V31);
6. API;
7. UI with canonical outcome plus separate presentation mapping;
8. exhaustive table, missing-state, provenance, persistence, API, UI, and non-interference tests.
