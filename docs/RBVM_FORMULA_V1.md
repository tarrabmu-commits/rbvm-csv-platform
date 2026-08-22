# RBVM Formula V1

Contract ID: `RBVM_FORMULA_V1`

Formula version: `1`

Formula semantics: `FINDING_SCOPED_POLICY_WEIGHTED_RELATIVE_RISK_INDEX`

Input contract: `RBVM_DECISION_INPUT_SNAPSHOT_V3`

Output: `RBVM Relative Risk Index`

Canonical definition: `docs/fixtures/RBVM_FORMULA_V1.json`

Canonical payload format: `RBVM_FORMULA_CANONICAL_BINARY_V1`

Formula SHA-256: `e10976aaae2a6e21ffacd80f9184a2a1eb6b73c83dd097708023be8e71857948`

This is a versioned **relative policy index**, not an exploitation probability, expected-loss model, CVSS extension, remediation priority, SLA, or treatment decision.

## 1. Design boundary

Formula V1 evaluates exactly one canonical Finding through exactly one immutable Decision Input V3 and its exact resolved native evidence.

It does not query current evidence, current association views, asset aggregates, Case aggregates, or dashboards while computing a result. It does not select evidence or re-run methodology policy. Those decisions are already frozen in the Decision Input snapshot.

The Formula therefore starts only after exact-evidence provenance, association eligibility, as-of semantics, source filtering, freshness, and ambiguity have already been resolved.

## 2. Result states

The Stage 7 result state machine is authoritative:

- `COMPUTED`
- `NOT_APPLICABLE`
- `NON_COMPUTABLE`

Only `COMPUTED` contains a numeric `RBVM Relative Risk Index`.

Formula V1 must preserve the Stage 7 terminal reason identifiers exactly. It never converts `NOT_APPLICABLE`, missing evidence, stale evidence, ambiguous evidence, or an explicit unknown value into numeric zero.

## 3. Why the Formula is additive

Formula V1 deliberately uses an additive normalized policy index.

Rejected for V1:

- raw CVSS × EPSS multiplication, because CVSS Base is an ordinal severity score while EPSS is a calibrated probability;
- probability-like `1 - product(1-p)` combinations across heterogeneous factors, because the required independence/probability semantics do not exist;
- multiplicative/geometric aggregation of severity, exposure, and business impact, because zero-collapse and ratio-scale assumptions would be stronger than the evidence contracts support;
- an equal-weight six-factor sum that independently counts KEV and EPSS, because confirmed exploitation and forward exploitation probability answer related threat questions and should not be silently double-counted.

The additive form keeps every point contribution explicit and preserves the correct output claim: a dimensionless relative RBVM index.

## 4. Formula equation

For a Formula-eligible Finding define five normalized factors in `[0,1]`:

- `S` = Technical Severity factor
- `X` = Exploitation Evidence factor
- `R` = Network Reachability factor
- `C` = Business Criticality factor
- `I` = Business / Mission Impact factor

The unrounded index is:

`RawIndex = 25*S + 25*X + 15*R + 10*C + 25*I`

The weights sum exactly to 100 points.

The final result is:

`RiskIndex = RawIndex rounded to exactly 2 decimal places using HALF_UP`

All intermediate arithmetic uses exact Java `BigDecimal` semantics without binary floating point and without intermediate rounding.

## 5. Technical Severity factor — 25 points

`S = CVSS_v3.1_Base / 10`

Examples:

- Base `0.0` -> `S = 0`
- Base `6.5` -> `S = 0.65`
- Base `10.0` -> `S = 1`

Only the exact validated CVSS v3.1 Base score contributes arithmetic. The vector and provenance remain in the deterministic explanation but do not add a second numeric contribution.

This transform does not redefine CVSS. CVSS remains technical severity evidence; the 25-point contribution is an RBVM Formula policy transform.

## 6. Exploitation Evidence factor — 25 points

Formula V1 combines KEV and EPSS into one exploitation-evidence factor so they are not independently double-counted.

`X = 1` when CISA KEV status is `LISTED`.

Otherwise, when KEV status is `NOT_LISTED`:

`X = EPSS_Probability`

The transform ID is:

`KEV_LISTED_OVERRIDE_ELSE_EPSS_PROBABILITY`

Important semantics:

- `X` is a dimensionless **Formula factor**, not a probability after the KEV override is applied;
- KEV `LISTED` means confirmed exploitation evidence takes precedence over a possibly low EPSS forecast;
- KEV `NOT_LISTED` does not mean no exploitation; it only means no listing in the exact validated catalog snapshot;
- EPSS percentile never changes Formula arithmetic;
- a KEV-listed Finding still retains its exact EPSS evidence in the explanation, but the EPSS probability contributes zero additional points because the single exploitation factor has already been overridden by direct exploitation evidence.

Current PostgreSQL KEV persistence intentionally stores only `LISTED` or `NOT_LISTED`; absence of usable KEV evidence becomes a Decision Input `MISSING` state rather than a fabricated `UNKNOWN` membership row. The Formula contract nevertheless preserves the Stage 7 `KEV_VALUE_UNKNOWN` terminal semantics for any future exact evidence source capable of carrying a present explicit unknown value.

## 7. Network Reachability factor — 15 points

Formula V1 requires exactly one effective Finding-scoped Reachability sub-grain.

Mapping:

| Reachability status | `R` |
|---|---:|
| `NOT_REACHABLE` | `0` |
| `REACHABLE` | `1` |

`UNKNOWN` is terminal `NON_COMPUTABLE: REACHABILITY_VALUE_UNKNOWN`.

The following remain exact explanation/provenance fields but do not change Formula V1 arithmetic:

- Origin Scope
- Origin Label
- Transport Protocol
- Target Port
- Target Service
- Reachability Method

This deliberately avoids inventing an Internet > Partner > Internal numeric network-zone hierarchy. A later Formula version or later Priority/Treatment policy may introduce such semantics explicitly.

## 8. Business Criticality factor — 10 points

Only customer-confirmed Business Criticality contributes from Asset Context.

| Business Criticality | `C` |
|---|---:|
| `LOW` | `0.25` |
| `MODERATE` | `0.5` |
| `HIGH` | `0.75` |
| `MISSION_CRITICAL` | `1` |

`UNKNOWN` is terminal `NON_COMPUTABLE: BUSINESS_CRITICALITY_UNKNOWN`.

Environment, Business Service label, and Business Owner are explanation/context only and cannot change Formula V1 arithmetic.

The 10-point weight is intentionally lower than the direct Business Impact factor because Business Criticality is a coarser asset-level customer classification and can overlap conceptually with service-specific impact. Formula V1 uses it as supporting organizational context without letting it duplicate the full Business Impact contribution.

## 9. Business / Mission Impact factor — 25 points

Formula V1 requires exactly one normalized Business Service.

Each confirmed impact level maps to:

| Impact level | value |
|---|---:|
| `NEGLIGIBLE` | `0` |
| `LOW` | `0.25` |
| `MODERATE` | `0.5` |
| `HIGH` | `0.75` |
| `SEVERE` | `1` |

If the one Business Service contains multiple impact dimensions, Formula V1 explicitly computes:

`I = MAX(mapped impact level across that service)`

This `MAX` is an explicit, SHA-bound Formula rule. It is not the hidden reduction prohibited by the readiness contract.

The rationale is conservative and monotonic: adding a lower-impact dimension must not dilute an already confirmed severe business/mission consequence, which a simple average could do.

Impact Dimension, Impact Method, and Impact Statement remain in the explanation. Formula V1 does not assign different numeric importance to Availability, Integrity, Confidentiality, Safety, Financial, Regulatory, Mission, or other impact-dimension names.

## 10. Weight rationale

The Formula allocates the 100-point range as follows:

| Factor | Maximum contribution |
|---|---:|
| Technical Severity | 25 |
| Exploitation Evidence | 25 |
| Network Reachability | 15 |
| Business Criticality | 10 |
| Business / Mission Impact | 25 |

These are normative RBVM **policy weights**, not coefficients fitted to empirical loss data.

The structure gives equal top-level emphasis to intrinsic technical severity, exploitation evidence, and direct business/mission impact. Finding-specific reachability receives a substantial but smaller contextual contribution. Coarse Business Criticality receives a supporting contribution to reduce double counting with direct Business Impact.

Any change to these weights is a Formula semantic change and therefore requires a distinct Formula canonical payload/SHA and new Formula-bound expected outputs.

## 11. Arithmetic exclusions

Changing only one of these fields cannot change the Formula V1 Risk Index:

- CVSS vector when the validated Base score is unchanged;
- KEV date-added, due-date, or ransomware-campaign metadata;
- EPSS percentile, model-version label, or score-date when probability and evidence identity are otherwise fixed;
- Environment, Business Service display label, or Business Owner;
- Reachability Origin Scope/Label, protocol, port, service, or method when the exact associated sub-grain and status remain valid;
- Business Impact dimension name, method, or statement when the set of mapped impact levels and single-service gate are unchanged.

These exclusions are present in the canonical Formula definition and covered by the Formula SHA.

## 12. Bounds and rounding

All normalized factors are constrained to `[0,1]` and all weights are non-negative and sum to 100, therefore:

`0 <= RawIndex <= 100`

The implementation uses exact `BigDecimal` addition, multiplication, and division by terminating decimal `10`.

There is no intermediate rounding.

Final output uses:

`setScale(2, RoundingMode.HALF_UP)`

The display form always shows two decimal places. Canonical decimal identity uses the representation rules from `RBVM_FORMULA_CANONICALIZATION_V1`, where display scale is encoded separately.

## 13. Formula canonical payload

The canonical JSON definition is a human-readable source artifact only. Formula identity is the SHA-256 of the custom binary canonical payload, not the JSON file bytes.

Formula V1 extends the Stage 7 nested encoding rules as follows.

Each factor encodes, in ascending ordinal:

1. signed 32-bit ordinal;
2. factor ID string;
3. transform ID string;
4. ordered input-dimension string list;
5. canonical decimal weight points;
6. parameter list sorted lexicographically by parameter key.

Each rule encodes, in ascending ordinal:

1. signed 32-bit ordinal;
2. rule ID;
3. rule type;
4. condition ID;
5. outcome ID;
6. parameter list sorted lexicographically by parameter key.

Parameter types are:

- `DECIMAL`: canonical decimal string;
- `STRING`: canonical semantic string;
- `DECIMAL_MAP`: entry count, then key/canonical-decimal entries sorted lexicographically by key;
- `STRING_LIST`: element count followed by strings in the explicitly declared semantic order.

The exact canonical payload length for this Formula is `3212` bytes.

Formula SHA-256:

`e10976aaae2a6e21ffacd80f9184a2a1eb6b73c83dd097708023be8e71857948`

## 14. Deterministic explanation

Every evaluation retains:

- Formula ID/version/SHA;
- Decision Input contract/SHA/Finding/evaluatedAt;
- methodology revision/SHA;
- result state and terminal reason code where applicable;
- all exact evidence references and binding provenance through the referenced Decision Input;
- each normalized factor value;
- each factor transform ID;
- each weighted point contribution;
- explicit `EPSS_SUPERSEDED_BY_KEV` explanation state when KEV is listed;
- selected maximum Business Impact level and the complete same-service impact vector;
- final Risk Index only for `COMPUTED`.

Factor contribution order is fixed by Formula factor ordinal. Evidence-reference ordering remains the deterministic order supplied by Decision Input V3 / resolved input validation.

## 15. Golden-case obligations

Formula V1 must satisfy `RBVM_FORMULA_GOLDEN_CASES_V1` without modifying that contract.

In particular:

- all 21 generated missing/stale/ambiguous cases remain non-computable;
- all explicit unknown/multi-subgrain/multi-service terminal cases remain non-computable;
- the six controlled material-sensitivity pairs are strictly increasing;
- EPSS percentile-only, Environment-only, and Business Owner-only changes are arithmetic equalities;
- the all-adverse profile dominates the base profile;
- Stage 8 trade-off pairs are allowed to become ordered now because the Formula weights are explicit and SHA-bound.

Exact numeric expected outputs are stored separately and bound to this exact Formula SHA.

## 16. Explicit non-goals

Formula V1 contains no:

- risk tier / Low-Medium-High label;
- remediation priority;
- remediation deadline or SLA;
- treatment decision;
- accepted-risk workflow;
- monetary loss estimate;
- portfolio aggregation;
- compensating-control inference;
- attack-path inference;
- customer-context inference from scanner metadata.

Those belong to later separately versioned contracts.