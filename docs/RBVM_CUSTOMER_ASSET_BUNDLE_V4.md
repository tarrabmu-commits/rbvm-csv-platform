# RBVM Customer Asset Bundle V4

Contract ID: `RBVM_CUSTOMER_ASSET_BUNDLE_V4`

Schema version: `4`

## Purpose

V4 extends the reusable customer asset-context bundle with an **explicit CISA Publicly Exposed decision point** for the CISA BOD 26-04 remediation-priority method.

The new field is deliberately independent from the existing `internetFacing` field.

## Asset record

```json
{
  "customerAssetKey": "asset-001",
  "displayName": "payments-prod-01",
  "assetCriticality": "HIGH",
  "internetFacing": "YES",
  "publiclyExposed": "UNKNOWN",
  "cvssConfidentialityRequirement": "H",
  "cvssIntegrityRequirement": "M",
  "cvssAvailabilityRequirement": "H"
}
```

### `publiclyExposed`

Allowed values:

- `YES`
- `NO`
- `UNKNOWN`

Semantic ID: `cisa:PE:1.0.0`

`YES` means the customer has explicitly assessed the asset as accessible to unauthenticated or untrusted entities through public networks, matching the CISA BOD 26-04 decision-point definition.

`NO` means the customer has explicitly assessed that this definition does not apply.

`UNKNOWN` means the decision point has not been established. It is valid customer data and must remain unresolved/incomplete for BOD evaluation.

## Critical non-inference rule

```text
internetFacing=YES
    !=
publiclyExposed=YES
```

No migration, UI, analyzer, resolver, snapshot builder, or decision engine may derive `publiclyExposed` from `internetFacing`, hostname, IP address, Network Reachability evidence, CVSS, KEV, EPSS, Asset Criticality, or Business Impact.

`internetFacing` remains in V4 only for backward compatibility with the existing customer-context and frozen `RBVM_MVP_PRIORITY_POLICY_V1` benchmark.

## Backward compatibility

The customer UI accepts V1/V2/V3 bundles. When an older bundle is loaded:

```text
V1/V2/V3
  ↓
publiclyExposed = UNKNOWN
```

No older field is inspected to infer `YES` or `NO`.

V1/V2 also continue to upgrade missing CVSS v4 `CR/IR/AR` declarations to `X`. V3 preserves its direct `X/L/M/H` security requirements.

The evidence-analysis loader accepts its previously supported V2/V3 contracts and V4; older supported records are upgraded to `publiclyExposed=UNKNOWN`.

## Save semantics

`publiclyExposed=UNKNOWN` is allowed to be saved and downloaded. The platform must not force the customer to invent a binary answer in order to persist asset context.

A later BOD input snapshot will therefore mark the Publicly Exposed dimension as missing/unresolved and the BOD decision as `INCOMPLETE` until explicit evidence is available.

## Separation from CVSS and organizational context

This field does not modify:

- CVSS-B/CVSS-BT/CVSS-BE/CVSS-BTE technical severity;
- EPSS probability or percentile;
- Asset Criticality;
- Business/Mission Impact;
- Organizational Risk formulas;
- the frozen MVP Pareto benchmark.

Its only canonical remediation-priority role is as the `cisa:PE:1.0.0` decision point in `CISA_BOD_26_04_REMEDIATION_PRIORITY_METHOD_V1`.
