# Derived Risk Methodologies V1

Status: `IMPLEMENTED_DOMAIN_ONLY`

Classification: `STANDARD_DERIVED`

Input: one exact `RBVM_DECISION_INPUT_SNAPSHOT_V3`

Implemented methodologies:

- `OWASP_DERIVED_RBVM_V1`
- `MICROSOFT_PD_DERIVED_RBVM_V1`

These evaluators are deterministic RBVM adaptations of published external risk models. They are **not** official OWASP or Microsoft-produced scores. The source equation is preserved separately from the RBVM mapping that converts exact Decision Input evidence into the source model's variables.

The existing `RBVM_FORMULA_V1` remains immutable and replayable for historical results. These derived methodologies do not overwrite it and are not yet wired into V23 Formula-result persistence, the Formula HTTP APIs, or the browser UI.

## 1. Shared evidence boundary

Both methodologies consume only one already-resolved exact Decision Input V3 snapshot. They never query current state, select a latest evidence row, choose a methodology on behalf of the caller, infer missing evidence, or produce Priority, Treatment, SLA, or remediation deadlines.

Required dimensions:

1. Applicability
2. Technical Severity
3. Known Exploitation
4. Exploitation Probability
5. Asset Context
6. Network Reachability
7. Business / Mission Impact

Shared terminal behavior preserves the existing Formula-readiness semantics:

- `NOT_APPLICABLE` is terminal and non-numeric.
- any required `MISSING`, `STALE`, or `AMBIGUOUS` dimension is `NON_COMPUTABLE`.
- unknown Business Criticality, unknown Reachability, or unknown Business Impact level is `NON_COMPUTABLE`.
- multiple Reachability sub-grains are non-computable rather than implicitly reduced.
- Business Impact may contain multiple dimensions only for one normalized Business Service; the retained impact value uses `MAX` for that one service.
- no partial-score reweighting occurs when required evidence is unavailable.

The common normalized evidence vector is:

```text
CVSS                = CVSS_v3.1_Base / 10
EPSS                = EPSS_Probability
KEV                 = LISTED -> 1; NOT_LISTED -> 0
Reachability        = REACHABLE -> 1; NOT_REACHABLE -> 0
BusinessCriticality = LOW 0.25; MODERATE 0.5; HIGH 0.75; MISSION_CRITICAL 1
BusinessImpact      = NEGLIGIBLE 0; LOW 0.25; MODERATE 0.5; HIGH 0.75; SEVERE 1
```

`KEV NOT_LISTED -> 0` and `NOT_REACHABLE -> 0` mean zero contribution from those mapped factors only. They do not assert that exploitation is impossible or that the Finding is safe.

## 2. OWASP-derived RBVM V1

Contract fixture: `docs/fixtures/OWASP_DERIVED_RBVM_V1.json`

SHA-256:

```text
03a72c8479e834174dc6985580d2543ad61b01628a79da5d59c5b5785e80c9c3
```

Provider/source: OWASP, **OWASP Risk Rating Methodology**.

Published source equation:

```text
Risk = Likelihood * Impact
```

OWASP also publishes a repeatable approach that averages factor scores, divides Likelihood and Impact into LOW/MEDIUM/HIGH on a 0..9 scale, and combines those axis bands in a severity matrix. OWASP explicitly describes its framework as customizable for an organization.

RBVM maps its available evidence into that published shape as follows:

```text
EPSS factor         = 9 * EPSS
KEV factor          = 9 * KEV
Reachability factor = 9 * Reachability

Likelihood = MEAN(EPSS factor, KEV factor, Reachability factor)

CVSS factor         = 9 * CVSS
Criticality factor  = 9 * BusinessCriticality
Impact factor       = 9 * BusinessImpact

Impact = MEAN(CVSS factor, Criticality factor, Impact factor)

Numeric Risk Product = Likelihood * Impact
```

Axis bands preserve the OWASP thresholds:

```text
LOW    = [0, 3)
MEDIUM = [3, 6)
HIGH   = [6, 9]
```

The final rating preserves the OWASP severity matrix:

| Impact \\ Likelihood | LOW | MEDIUM | HIGH |
|---|---|---|---|
| LOW | NOTE | LOW | MEDIUM |
| MEDIUM | LOW | MEDIUM | HIGH |
| HIGH | MEDIUM | HIGH | CRITICAL |

The numeric product is retained for reproducibility and comparison on `0.0000..81.0000`; the matrix rating remains distinct from remediation Priority.

Baseline acceptance profile:

```text
CVSS 6.5
EPSS 0.10
KEV NOT_LISTED
Reachability REACHABLE
Business Criticality MODERATE
Business Impact MODERATE

Likelihood = 3.3000
Impact     = 4.9500
Risk       = 16.3350
Rating     = MEDIUM
```

## 3. Microsoft Probability x Damage-derived V1

Contract fixture: `docs/fixtures/MICROSOFT_PD_DERIVED_RBVM_V1.json`

SHA-256:

```text
b22520b7b5a7d5f06782270feaf6729089ebafef79f20aea43dddf18396dcce6
```

Provider/source: Microsoft, **Threats and Countermeasures / Threat Modeling**.

Published source equation:

```text
Risk = Probability * Damage Potential
```

Microsoft describes Probability and Damage Potential on 1..10 scales, producing a 1..100 risk scale. The source notes that the scale can be divided into bands but does not prescribe one exact universal band boundary in the cited model. This implementation therefore does **not** invent a Microsoft HIGH/MEDIUM/LOW rating.

RBVM mapping:

```text
ProbabilityBase = MEAN(EPSS, KEV, Reachability)
Probability     = 1 + 9 * ProbabilityBase

DamageBase      = MEAN(CVSS, BusinessCriticality, BusinessImpact)
DamagePotential = 1 + 9 * DamageBase

Risk = Probability * DamagePotential
```

Output scale: `1.0000..100.0000`.

Baseline acceptance profile using the same evidence as above:

```text
Probability      = 4.3000
Damage Potential = 5.9500
Risk             = 25.5850
Rating           = not defined by this contract
```

No RBVM Priority band is silently attached to this score.

## 4. Why the two evaluators share an evidence adapter

The implementation uses one shared exact-evidence gate/normalization layer, `RbvmDerivedRiskEvidence`, before applying either published-model shape. This prevents two methodology implementations from silently disagreeing about whether evidence is missing, stale, ambiguous, cross-service, or structurally invalid.

That shared adapter is not a source-selection layer. It receives only `RbvmResolvedDecisionInput`, which is already bound to the exact immutable evidence identities in Decision Input V3.

## 5. Catalog semantics

`RbvmDerivedRiskMethodologyCatalog` exposes the implemented definitions for deterministic discovery. Catalog order is stable only for deterministic representation; it has **no precedence semantics** and does not define a default or preferred methodology.

A future API/UI may let the operator explicitly select a methodology. It must not auto-select one by catalog order.

## 6. Persistence and transport boundary

This increment intentionally stops before persistence and HTTP transport.

V23 Formula-result storage and canonical explanation currently encode `RBVM_FORMULA_V1` semantics. Reusing that path without a versioned generic explanation contract would make historical replay ambiguous. The next multi-methodology persistence increment must therefore bind at least:

```text
inputSnapshotSha256
methodologyId
methodologySha256
exact result payload/explanation identity
```

and must replay through the exact methodology implementation identified by that immutable identity.

Until that contract exists, the two new methodologies are pure deterministic domain evaluators and comparison candidates only.

## 7. Source references

- OWASP Risk Rating Methodology: `https://owasp.org/www-community/OWASP_Risk_Rating_Methodology`
- Microsoft Threats and Countermeasures PDF: `https://download.microsoft.com/download/d/8/c/d8c02f31-64af-438c-a9f4-e31acb8e3333/threats_countermeasures.pdf`

The external documents support the source-model shapes. The RBVM evidence mappings, categorical normalization, and exact shared gating rules are project policy and are visibly SHA-bound in the methodology fixtures.
