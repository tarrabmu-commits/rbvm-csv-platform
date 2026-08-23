# RBVM Customer Asset Bundle V3

Contract ID: `RBVM_CUSTOMER_ASSET_BUNDLE_V3`

Schema version: `3`

## Purpose

V3 extends the reusable customer asset-context bundle with direct FIRST CVSS v4 Environmental Security Requirements. It does not derive those requirements from Asset Criticality or any public intelligence source.

## Asset record

Each `assets[]` record contains:

```text
customerAssetKey

displayName

assetCriticality

internetFacing

cvssConfidentialityRequirement
cvssIntegrityRequirement
cvssAvailabilityRequirement
```

The three CVSS requirement fields accept only native CVSS v4 values:

```text
X = Not Defined
L = Low
M = Medium
H = High
```

They map directly by field identity:

```text
cvssConfidentialityRequirement -> CR
cvssIntegrityRequirement       -> IR
cvssAvailabilityRequirement    -> AR
```

This is direct metric capture, not a policy mapping.

## Semantics

- `assetCriticality` remains a scalar organization label and is not converted to CR/IR/AR.
- `internetFacing` remains an asset-level current-state declaration and is not converted to MAV or treated as endpoint-scoped `NETWORK_REACHABILITY_CSV_V1` evidence.
- CR/IR/AR may remain `X` independently when the customer has not assessed that requirement.
- Public CVE sources cannot authoritatively provide these organization-specific Security Requirements.

## Backward compatibility

- `RBVM_CUSTOMER_ASSET_BUNDLE_V2` remains accepted. Its CR/IR/AR values resolve to `X` because V2 did not carry those fields.
- UI import also continues to accept V1 and upgrades missing Environmental requirements to `X`.
- V3 export never fabricates values during upgrade.

## Decision boundary

V3 can support official CVSS-BE/CVSS-BTE contextual technical severity through `CVSS_V4_CONTEXT_RESOLVER_V2`.

It does not define an Organizational Risk formula, Priority, Treatment decision, or SLA.
