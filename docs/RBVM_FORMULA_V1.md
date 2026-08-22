# RBVM Formula V1

Contract ID: `RBVM_FORMULA_V1`

Status: `ACCEPTED`

Formula SHA-256: `88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e`

Input: `RBVM_DECISION_INPUT_SNAPSHOT_V3`

Output: `RBVM Relative Risk Index`, `0.00 .. 100.00`

This document defines the accepted numeric Formula V1 after the approved Formula-readiness decisions and Stage 8 golden-case corpus. It defines a transparent relative index for one canonical Finding. It does **not** define Priority, Treatment, SLA, remediation deadlines, financial loss, or exploitation probability.

## 1. Classification of this contract

The evidence semantics are inherited from their authoritative source contracts and from the existing standards baseline. The numeric Formula itself is **RBVM_POLICY**.

No NIST, FIRST, CISA, CERT/SEI, OWASP, MITRE, Open FAIR, or vendor document mandates the weights or mappings in this Formula. They are intentionally visible, versioned, SHA-bound policy choices so they can be reviewed, tested, calibrated, or replaced by a later Formula version without rewriting historical results.

The design follows the existing Formula Atlas conclusions:

- CVSS remains technical severity, not risk.
- EPSS remains exploitation probability, not risk.
- KEV remains known-exploitation evidence, not a complete risk result.
- Reachability remains exact Finding-scoped exposure evidence.
- Business Criticality and Business Impact remain customer-owned context.
- the output is a dimensionless relative index, not expected loss or a treatment decision.

## 2. Eligibility and terminal behavior

Eligibility is exactly the approved `RBVM_FORMULA_READINESS_DECISIONS_V1` state machine.

1. Applicability is evaluated first.
2. `NOT_APPLICABLE` is terminal and produces no number.
3. Applicability `UNKNOWN`, or any required `MISSING / STALE / AMBIGUOUS` dimension, produces `NON_COMPUTABLE` with the approved reason code.
4. KEV `UNKNOWN`, Business Criticality `UNKNOWN`, Reachability `UNKNOWN`, and Business Impact level `UNKNOWN` remain non-computable.
5. Exactly one effective Reachability sub-grain and exactly one normalized Business Service are required.
6. Multiple Business Impact dimensions for that one service are permitted.

There is no partial-score reweighting and no numeric substitute for unavailable evidence.

## 3. Formula-consumed normalized factors

For an eligible Finding, Formula V1 derives six bounded values in `[0,1]`.

### 3.1 Technical Severity — `S`

```text
S = CVSS_v3.1_Base / 10
```

Weight: `0.20`

The exact selected CVSS Base evidence/vector/source remains in explanation provenance. Only the Base score participates in arithmetic.

### 3.2 Exploitation Probability — `P`

```text
P = EPSS_Probability
```

Weight: `0.20`

EPSS percentile remains excluded from Formula V1 arithmetic.

### 3.3 Known Exploitation — `K`

Weight: `0.15`

```text
LISTED      -> 1
NOT_LISTED  -> 0
```

`NOT_LISTED -> 0` means **zero contribution from this categorical Formula factor only**. It does not mean the vulnerability is not exploitable, safe, or threat-free. EPSS, CVSS, Reachability, and organizational context remain independent contributors.

### 3.4 Reachability — `R`

Weight: `0.15`

For the one exact Finding-associated Reachability sub-grain:

```text
REACHABLE      -> 1
NOT_REACHABLE  -> 0
```

`NOT_REACHABLE -> 0` is scoped only to that exact associated origin/endpoint evidence. It does not zero the Finding Risk Result and does not assert that every possible attack path is unreachable.

Origin scope, origin label, protocol, port, target service, method, source, observation time, and exact binding event remain explanation provenance but are not additional arithmetic factors in Formula V1.

### 3.5 Business Criticality — `C`

Weight: `0.15`

```text
LOW               -> 0.25
MODERATE          -> 0.5
HIGH              -> 0.75
MISSION_CRITICAL  -> 1
```

Environment, Business Service, Business Owner, display name, and customer key do not contribute separate arithmetic.

### 3.6 Business / Mission Impact — `I`

Weight: `0.15`

Each present impact level for the one associated normalized Business Service maps as:

```text
NEGLIGIBLE  -> 0
LOW         -> 0.25
MODERATE    -> 0.5
HIGH        -> 0.75
SEVERE      -> 1
```

When more than one impact dimension exists for the same service, Formula V1 uses the explicitly declared reducer:

```text
I = MAX(mapped impact levels)
```

This is a deliberate **RBVM_POLICY** choice, not a hidden implementation shortcut. It prevents a newly recorded low-impact dimension from diluting a separately confirmed high/severe impact dimension. All retained impact dimensions remain present in the deterministic explanation.

Formula V1 does not assign different arithmetic weights to `AVAILABILITY / INTEGRITY / CONFIDENTIALITY / SAFETY / FINANCIAL / REGULATORY / OPERATIONAL / REPUTATIONAL / MISSION / OTHER`; the impact level is the arithmetic value and the dimension remains explanation context.

## 4. Numeric equation

For an eligible Finding:

```text
Raw =
    0.20 * S
  + 0.20 * P
  + 0.15 * K
  + 0.15 * R
  + 0.15 * C
  + 0.15 * I

RBVM Relative Risk Index = ROUND_HALF_EVEN(100 * Raw, 2)
```

The factor weights sum exactly to `1.00`.

Intermediate arithmetic uses decimal precision `34`. Binary floating-point arithmetic is not part of Formula semantics.

The raw weighted sum must remain in `[0,1]`; the implementation must fail rather than silently clamp an out-of-range result caused by invalid mappings or arithmetic drift.

## 5. Why this V1 shape was selected

The Formula Atlas found no authoritative universal RBVM numeric formula. V1 therefore favors a visible baseline over hidden complexity.

The selected model is a monotonic weighted additive relative index because it:

- preserves independent visibility of all six Formula-relevant dimensions after Applicability;
- does not make any single categorical factor an automatic final-risk override;
- avoids raw `CVSS × EPSS`, which the readiness contract explicitly did not authorize;
- avoids an all-factor multiplicative model where a zero-valued categorical contribution could annihilate the full result and be misread as safety;
- avoids hidden thresholds and risk tiers;
- makes every policy constant inspectable and SHA-bound;
- satisfies the Stage 8 material-sensitivity and exclusion relations;
- provides a simple baseline that can later be calibrated empirically under a new Formula identity.

The higher `0.20` weights for the two native bounded quantitative signals (CVSS Base and EPSS probability), and `0.15` for each categorical/context factor, are RBVM V1 policy. They are not claimed to be statistically fitted or standards-mandated.

## 6. Stage 8 trade-offs resolved by this Formula

Stage 8 intentionally left cross-dimension trade-offs unordered. This Formula resolves them visibly.

Using the frozen semantic profiles:

| Case | Formula V1 result |
|---|---:|
| `BASE_PROFILE` | `45.00` |
| `GC-ALL-ADVERSE` | `95.60` |
| `GC-CRITICAL-NOT-LISTED-LOW-EPSS` | `49.80` |
| `GC-MEDIUM-KEV-HIGH-EPSS` | `70.00` |
| `GC-HIGH-TECH-LOW-IMPACT-ISOLATED` | `27.50` |
| `GC-LOWER-TECH-MISSION-REACHABLE` | `60.00` |
| `GC-BUSINESS-IMPACT-MULTI-DIMENSION-SAME-SERVICE` | `48.75` |

Therefore V1 chooses:

```text
medium CVSS + KEV LISTED + high EPSS
>
critical CVSS + NOT_LISTED + low EPSS
```

and:

```text
lower technical severity + mission-critical + reachable + severe impact
>
high technical severity + low criticality + not-reachable + low impact
```

These are Formula V1 policy outcomes, not universal standards claims.

## 7. Canonical identity

The source artifact is `docs/fixtures/RBVM_FORMULA_V1.json`.

Canonical payload format: `RBVM_FORMULA_CANONICAL_BINARY_V1`.

Formula V1 additionally freezes the factor-definition and final-rule encoding used inside the ordered definitions required by `RBVM_FORMULA_CANONICALIZATION_V1`.

Each factor encodes, in order:

1. signed 32-bit ordinal;
2. factor ID string;
3. evidence-dimension ID string;
4. canonical decimal weight;
5. transform ID string;
6. sorted parameter map of string -> canonical decimal;
7. sorted categorical mapping of string -> canonical decimal;
8. nullable reducer ID string.

Each final rule encodes, in order:

1. signed 32-bit ordinal;
2. rule ID string;
3. rule type string;
4. sorted parameter map of string -> canonical decimal.

The ordered rule list occupies the canonicalization contract's ordered interaction/gate-definition slot. V1 contains one final aggregation rule and no hidden interaction rules.

The canonical payload is `1290` bytes and its SHA-256 is:

```text
88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e
```

`formulaSha256` and `canonicalPayloadByteLength` are source-artifact metadata and are excluded from the bytes being hashed.

## 8. Explanation semantics

A computed explanation must report, in the stable Decision Input dimension order:

- exact native evidence and binding provenance from Decision Input V3;
- the normalized Formula-consumed value;
- factor/transform ID;
- factor weight;
- weighted contribution before output scaling;
- Business Impact reducer inputs and selected maximum when multiple dimensions exist;
- final Formula identity/SHA and exact rounded result.

For `NOT_APPLICABLE` or `NON_COMPUTABLE`, the explanation contains no numeric substitute and carries the canonical terminal/gating reason codes.

## 9. Explicit non-goals

Formula V1 does not calculate or emit:

- remediation Priority;
- SLA or patch deadline;
- treatment action;
- ticket assignment;
- compensating-control effectiveness;
- expected financial loss;
- probability of compromise;
- portfolio/asset aggregation;
- a source winner that is not already fixed by Decision Input methodology.

Those remain separate later contracts.

## 10. Runtime acceptance boundary

The accepted Formula contract is implemented by the pure evaluator `io.rbvm.decision.RbvmFormulaV1`. Runtime acceptance requires executable verification to prove:

- exact Formula canonical bytes reproduce the declared SHA;
- all Stage 8 terminal/state cases preserve their result state and reason;
- all six material-sensitivity pairs are strictly increasing;
- EPSS percentile, Environment, and Business Owner exclusion pairs remain exactly equal;
- the all-adverse profile dominates the base profile;
- the resolved cross-dimension trade-offs reproduce the frozen Formula V1 expected results;
- repeated evaluation is decimal-deterministic;
- Formula arithmetic does not use any field excluded by the readiness decisions;
- the evaluator accepts only exact resolved `RBVM_DECISION_INPUT_SNAPSHOT_V3` inputs and does not query current state or select evidence.

The Java runtime currently returns an ephemeral Formula result with Formula identity, Decision Input identity, final state/value, and visible factor contributions. Durable result persistence, canonical result/explanation serialization, API/UI exposure, Priority, Treatment, and SLA remain outside this increment.
