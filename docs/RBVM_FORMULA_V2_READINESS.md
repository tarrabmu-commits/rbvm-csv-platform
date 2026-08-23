# RBVM Formula V2 Readiness

Contract ID: `RBVM_FORMULA_V2_READINESS_V1`

Formula V1 remains immutable. This document defines the evidence boundary for a future V2 and intentionally does not invent numeric weights, probability transforms, severity multipliers, or Low/Medium/High thresholds.

## Candidate evidence tuple

For one finding:

```text
CVSS v4 technical severity evidence
+ FIRST EPSS 30-day exploitation probability
+ CISA KEV / CISA SSVC threat evidence
+ customer Asset Criticality
+ customer Internet Facing declaration
```

These inputs have different semantics and are not mathematically interchangeable.

## Current V2 computation status

`NON_COMPUTABLE` for Organizational Risk.

Reason: there is no authoritative published composition that transforms the current tuple into an organizational-risk scalar or risk tier, and the project has not approved a local composition policy.

This status is deliberate. It prevents an undocumented weighted sum, multiplier, odds transform, or matrix from becoming a false standard.

## What is computable now

- Public-intelligence coverage and missingness.
- CVSS v4 Base assessment presence/ambiguity.
- Conservative Threat E resolution under `CVSS_V4_CONTEXT_RESOLVER_V1`.
- CVSS context mode (`UNAVAILABLE`, `B_ONLY`, `BT_INPUT_READY`).
- EPSS probability as published by FIRST.
- KEV listed/not-listed evidence as observed from the complete catalog snapshot.
- CISA SSVC enrichment fields when published.
- Customer-declared Asset Criticality and Internet Facing state.
- Side-by-side benchmark output preserving each evidence field independently.

## Still blocked

1. No approved organizational-risk composition policy.
2. Scalar Asset Criticality cannot be silently mapped to CVSS `CR/IR/AR`.
3. Asset-level Internet Facing cannot be silently mapped to finding-level `MAV` or exact reachability.
4. EPSS probability must not be multiplied by ordinal CVSS severity.
5. Missing/ambiguous evidence cannot become zero, low, or worst-case without an explicit versioned policy.

## Required identity for an eventual V2 formula

Any future approved formula must freeze:

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

Every transform, threshold, gate, and weight must be inside the canonical representation covered by the SHA-256.

## Separation of outputs

A future V2 Organizational Risk result must remain separate from:

- CVSS severity;
- EPSS probability;
- KEV/SSVC threat evidence;
- Priority;
- Treatment;
- SLA.

Until the composition policy is approved and calibrated, the correct platform output is evidence + readiness + explicit `NON_COMPUTABLE`, not a fabricated risk score.
