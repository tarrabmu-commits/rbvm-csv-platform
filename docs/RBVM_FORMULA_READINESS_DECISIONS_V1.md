# RBVM Formula Readiness Decisions V1

Contract ID: `RBVM_FORMULA_READINESS_DECISIONS_V1`

Status: `APPROVED_FOR_GOLDEN_CASE_DESIGN`

This contract closes the remaining semantic decisions that must be fixed before any numeric `RBVM_FORMULA_V1` proposal is authored. It contains **no weights, coefficients, numeric thresholds, scoring equation, priority tier, SLA, treatment rule, or remediation timeline**.

The authoritative runtime input remains one exact `RBVM_DECISION_INPUT_SNAPSHOT_V3` plus its exact resolved native evidence. Formula V1 must not evaluate V1/V2 snapshots, current-state views, asset aggregates, CVE aggregates, or dashboard summaries.

## 1. Formula result state machine

Formula V1 shall have exactly three top-level result states:

- `COMPUTED`
- `NOT_APPLICABLE`
- `NON_COMPUTABLE`

Only `COMPUTED` may contain a numeric Risk Result.

`NOT_APPLICABLE` and `NON_COMPUTABLE` contain **no numeric substitute**. They are not score zero, minimum risk, low risk, or priority decisions.

## 2. Applicability gate

Applicability is evaluated before every other Formula transform.

| Decision Input state/value | Formula behavior |
|---|---|
| `PRESENT + APPLICABLE` | continue to Formula eligibility checks |
| `PRESENT + NOT_APPLICABLE` | terminal `NOT_APPLICABLE`; no numeric Risk Result |
| `PRESENT + UNKNOWN` | terminal `NON_COMPUTABLE: APPLICABILITY_UNKNOWN` |
| `MISSING` | terminal `NON_COMPUTABLE: APPLICABILITY_MISSING` |
| `STALE` | terminal `NON_COMPUTABLE: APPLICABILITY_STALE` |
| `AMBIGUOUS` | terminal `NON_COMPUTABLE: APPLICABILITY_AMBIGUOUS` |

`NOT_APPLICABLE` is deliberately distinct from numeric zero because zero would still be a numeric Formula result and could be misread as a low-risk applicable Finding.

## 3. Evidence-quality gate

Formula V1 uses a strict complete-evidence policy.

After Applicability passes as `PRESENT + APPLICABLE`, every remaining required Formula dimension must be `PRESENT` before numeric computation is allowed:

1. Technical Severity / CVSS v3.1
2. Known Exploitation / CISA KEV
3. Exploitation Probability / FIRST EPSS
4. Asset Context
5. Network Reachability
6. Business / Mission Impact

For any of these dimensions:

- `MISSING` -> `NON_COMPUTABLE: <DIMENSION>_MISSING`
- `STALE` -> `NON_COMPUTABLE: <DIMENSION>_STALE`
- `AMBIGUOUS` -> `NON_COMPUTABLE: <DIMENSION>_AMBIGUOUS`

Formula V1 therefore has no partial-score normalization, no reweighting around missing dimensions, and no implicit neutral value.

This is intentionally conservative. A later Formula version may introduce an explicit partial-evidence policy, but that would require a distinct Formula identity/version/SHA and new golden cases.

## 4. Technical Severity input

Formula V1 consumes the exact selected CVSS v3.1 Base evidence reference from Decision Input V3.

The contributing technical value is the validated CVSS v3.1 Base score together with its exact vector/version/source provenance.

CVSS remains technical severity evidence. Formula V1 must not describe the CVSS Base score itself as organizational risk.

A future CVSS v4.0 evidence family, if added, must be a separate native evidence contract and must not silently replace v3.1 in Formula V1.

## 5. CISA KEV input

The valid categorical values are:

- `LISTED`
- `NOT_LISTED`

`LISTED` is evidence that exploitation in the wild is known from the validated catalog snapshot.

`NOT_LISTED` is valid evidence of absence from that complete validated snapshot only. It does not mean not exploitable and is not equivalent to a zero threat value.

A missing KEV dimension never becomes `NOT_LISTED`.

## 6. FIRST EPSS input

Formula V1 uses **EPSS probability only** as the exploitation-probability input.

The selected probability is the exact published `[0,1]` probability bound to the referenced EPSS model version, score date, source, and observation provenance.

`EPSS_Percentile` is excluded from Formula V1 arithmetic. It may be retained for explanation or analytics, but it cannot contribute a second exploitation factor because it is a population-relative transformation of the probability rather than an independent signal.

Formula V1 must not directly multiply CVSS Base by EPSS probability. Any future combination of technical severity and exploitation probability must have explicit semantics in the Formula contract and golden-case validation; raw multiplication is not authorized by this readiness decision.

Missing EPSS is never probability zero.

## 7. Asset Context input

Formula V1 treats Asset Context as customer-owned context.

The only Asset Context field authorized to influence Formula V1 numerically is `Business_Criticality` from the exact selected native evidence / managed-asset revision.

The following fields remain explanation/context fields and do not independently contribute arithmetic in Formula V1:

- Environment
- Business Service
- Business Owner
- display name / customer key

This prevents hidden double counting of exposure or service impact through loosely related metadata.

If the selected Asset Context evidence has `Business_Criticality = UNKNOWN`, Formula V1 returns:

`NON_COMPUTABLE: BUSINESS_CRITICALITY_UNKNOWN`

No hostname, operating system, product name, environment label, owner, or scanner metadata may infer Business Criticality.

## 8. Reachability input and multi-target rule

Decision Input V3 already guarantees that Reachability evidence is admitted only through exact customer-confirmed Finding↔Reachability Scope association provenance and same-asset target matching.

Formula V1 adds one further deterministic eligibility rule:

- exactly **one effective Reachability sub-grain** may contribute to one computed Finding result.

If zero effective sub-grains survive Decision Input selection, the dimension is `MISSING` and the complete-evidence gate applies.

If more than one distinct effective Reachability sub-grain is present, Formula V1 returns:

`NON_COMPUTABLE: REACHABILITY_MULTI_SUBGRAIN`

Formula V1 must not choose the first target, the most internet-facing target, the highest port/service, a maximum, an average, or any other hidden reduction.

For the one allowed sub-grain, an explicit native `UNKNOWN` reachability status is not a neutral value; it returns:

`NON_COMPUTABLE: REACHABILITY_VALUE_UNKNOWN`

The exact origin scope, normalized origin label, transport protocol, target port semantics, native status, source, and binding event remain part of explanation provenance.

## 9. Business / Mission Impact input and multi-service rule

Decision Input V3 already guarantees that Business Impact evidence is admitted only through exact customer-confirmed Finding↔Business Service association provenance and same-asset normalized-service matching.

Formula V1 permits exactly **one effective normalized Business Service** for a computed Finding result.

If evidence references span more than one normalized Business Service, Formula V1 returns:

`NON_COMPUTABLE: BUSINESS_IMPACT_MULTI_SERVICE`

Within that single service, multiple distinct impact dimensions are allowed and are preserved as a structured impact vector rather than silently collapsed.

Formula V1 must not reduce multiple impact dimensions using `max`, `min`, average, first-row, or highest-severity logic unless the eventual canonical Formula artifact explicitly defines the transform for every supported impact dimension.

If any contributing impact dimension has an explicit native `UNKNOWN` impact value, Formula V1 returns:

`NON_COMPUTABLE: BUSINESS_IMPACT_VALUE_UNKNOWN`

This decision closes the service-association ambiguity without inventing an impact aggregation rule before Stage 9.

## 10. Compensating controls

Compensating-control effectiveness is **outside Formula V1**.

The current seven Decision Input families contain no first-class, independently versioned compensating-control effectiveness evidence. Formula V1 therefore cannot infer controls from:

- Reachability status
- Environment
- workflow state
- remediation state
- ticket state
- free-text notes
- asset owner
- scanner metadata

If compensating controls are later required in the risk calculation, they must enter through a new evidence contract and a new Formula version.

## 11. Output semantics and scale

The numeric Formula V1 output, when `COMPUTED`, shall be named:

`RBVM Relative Risk Index`

Approved scale:

`0.00 .. 100.00`

The value is dimensionless and relative to the semantics of the exact Formula version. It is **not**:

- probability of exploitation
- expected financial loss
- annualized loss expectancy
- CVSS severity
- remediation priority
- SLA duration
- treatment decision

A score of `0.00` is still a computed result for an applicable Finding with complete valid evidence under the Formula model. It is therefore semantically different from `NOT_APPLICABLE` and `NON_COMPUTABLE`.

The Formula artifact must define exact bounds and rounding. Formula V1 shall use decimal arithmetic and output exactly two decimal places; the exact intermediate precision and rounding mode must be frozen in the Formula canonical artifact before implementation.

## 12. Canonical Formula artifact requirements

The future `RBVM_FORMULA_V1` artifact must define at least:

- `formulaId`
- `formulaVersion`
- `formulaSemantics`
- `inputContractId = RBVM_DECISION_INPUT_SNAPSHOT_V3`
- `outputName = RBVM Relative Risk Index`
- `outputMinimum = 0.00`
- `outputMaximum = 100.00`
- `outputScale = 2 decimal places`
- exact arithmetic transforms
- exact categorical mappings
- exact weights/coefficients if any
- exact gates/interactions if any
- exact intermediate precision
- exact rounding mode
- missing/stale/ambiguous policies
- multi-subgrain policies
- deterministic explanation schema version
- canonical payload format identifier
- SHA-256 of canonical payload

Canonical representation must be deterministic, order-stable, and independent of source file formatting or display labels. Every numeric constant or decision rule that can change a Risk Result must be covered by the Formula SHA-256.

Historical recomputation must use the exact persisted Formula identity/SHA; a newer Formula may never silently replace it.

## 13. Deterministic explanation contract

Every Formula result must include a deterministic machine-readable explanation with:

- result state: `COMPUTED | NOT_APPLICABLE | NON_COMPUTABLE`
- Formula ID/version/SHA
- Decision Input snapshot ID/SHA/evaluatedAt
- methodology revision/SHA
- ordered dimension entries in the fixed Decision Input dimension order
- dimension state
- exact retained evidence reference IDs/SHA/source/observedAt
- exact binding event provenance when present
- normalized value consumed by the Formula when applicable
- transform identifier applied by the Formula when applicable
- contribution/intermediate value when applicable
- terminal/gating reason codes
- final numeric result only when state is `COMPUTED`

Explanation ordering must be stable so exact replay can produce byte-equivalent canonical explanation semantics.

## 14. Approved terminal reason codes

Stage 8 golden cases must cover at least these reason families:

- `APPLICABILITY_UNKNOWN`
- `APPLICABILITY_MISSING`
- `APPLICABILITY_STALE`
- `APPLICABILITY_AMBIGUOUS`
- `<DIMENSION>_MISSING`
- `<DIMENSION>_STALE`
- `<DIMENSION>_AMBIGUOUS`
- `BUSINESS_CRITICALITY_UNKNOWN`
- `REACHABILITY_MULTI_SUBGRAIN`
- `REACHABILITY_VALUE_UNKNOWN`
- `BUSINESS_IMPACT_MULTI_SERVICE`
- `BUSINESS_IMPACT_VALUE_UNKNOWN`

Reason-code text shown in UI may evolve independently. Canonical reason identifiers may not be inferred from localized/display prose.

## 15. Explicit separation from Priority / Treatment / SLA

Formula V1 produces only a Risk Result state and, for `COMPUTED`, the `RBVM Relative Risk Index`.

It does not emit remediation deadlines, priority tiers, treatment actions, assignment, campaign membership, or accepted-risk transitions.

CISA directives, SSVC-style decision tables, customer remediation policy, and SLA logic belong to later Priority/Treatment contracts.

## 16. Stage 7 closure status

The following readiness decisions are now closed by this contract:

- evaluation unit = one Finding + one Decision Input V3
- Applicability terminal semantics
- EPSS probability vs percentile usage
- Reachability association semantics
- Business Impact association semantics
- missing/stale/ambiguous policy
- multi-subgrain policy
- compensating-controls scope
- Formula output semantics and scale
- canonical Formula artifact requirements
- deterministic explanation requirements
- separation from Priority/Treatment/SLA

The only remaining pre-Formula gate is **Stage 8: versioned golden cases and invariants with approved expected ordering/behavior**.

No numeric Formula may be implemented until Stage 8 is closed.