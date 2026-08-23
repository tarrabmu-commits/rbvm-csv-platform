# RBVM MVP Priority Policy V1 — Methodology Freeze

Freeze contract: `RBVM_MVP_PRIORITY_POLICY_V1_FREEZE_V1`

Status: **FROZEN_FOR_MVP**

Frozen on: **2026-08-24**

Method: `RBVM_MVP_PRIORITY_POLICY_V1`

Canonical method SHA-256:

`88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388`

Machine-readable freeze manifest:

`docs/fixtures/RBVM_MVP_PRIORITY_POLICY_V1_FREEZE.json`

## Freeze decision

`RBVM_MVP_PRIORITY_POLICY_V1` is the accepted treatment-priority methodology for the CSV-first MVP.

The freeze does **not** promote the policy to an Organizational Risk method. Its frozen output semantics remain:

```text
RELATIVE_TREATMENT_PRIORITY_PARETO_FRONT_WITHIN_INPUT_SET
```

and:

```text
Organizational Risk = NON_COMPUTABLE
```

The purpose of this freeze is to prevent a working MVP decision method from drifting through small implementation, UI, threshold, or mapping changes that would silently change decisions while retaining the same method identity.

## Frozen semantic core

The following five dimensions are the complete V1 ranking input set:

| Order | Dimension | Exact source | Frozen ordering / range |
|---|---|---|---|
| 1 | CISA KEV | `KEV_Listed` | `false=0`, `true=1` |
| 2 | Customer Internet Facing | `Internet_Facing` | `NO=0`, `YES=1` |
| 3 | Customer Asset Criticality | `Asset_Criticality` | `LOW=1`, `MODERATE=2`, `HIGH=3`, `MISSION_CRITICAL=4` |
| 4 | FIRST EPSS | `EPSS_Probability` | continuous `[0,1]`, higher is stronger urgency evidence |
| 5 | Contextual CVSS v4 | `CVSS4_Context_Score` | continuous `[0,10]`, higher is stronger technical-severity evidence |

There are no additional hidden dimensions.

The categorical mappings above are **RBVM local policy**, not a claim that CISA, FIRST, NIST, ISO, or the CVSS specification defines those mappings.

## Frozen dominance and fronting rules

For complete rows `A` and `B`:

```text
A dominates B
iff
A >= B on every frozen dimension
and
A > B on at least one frozen dimension
```

The rankable set is then processed by iterative nondominated sorting:

```text
Front 1 = current nondominated set
remove Front 1
Front 2 = next nondominated set
...
```

`Front 1` is therefore the highest **relative** treatment-priority frontier in that exact input set. It is not a risk severity, probability, SLA class, or universal priority score.

Adding or removing findings can legitimately change front numbers without changing the policy.

## Frozen missing-evidence behavior

Every one of the five dimensions is mandatory for ranking.

Missing or invalid required evidence yields:

```text
RBVM_MVP_Priority_Status = UNRANKABLE_MISSING_EVIDENCE
```

with explicit blocker codes.

V1 must never silently map missing evidence to:

- zero;
- lowest urgency;
- highest urgency;
- a default category;
- a synthetic average;
- an inferred value from another evidence dimension.

## Frozen no-weight / no-threshold rule

The canonical representation contains:

```text
weights = []
thresholds = []
```

V1 therefore must not acquire any of the following without becoming a new method version:

- `CVSS × EPSS`;
- weighted sums;
- EPSS Low/Medium/High bands used for ranking;
- CVSS cutoffs used for ranking;
- special numeric bonuses for KEV;
- penalties or bonuses for Internet Facing;
- implicit tie breakers inside a Pareto front.

Charts may group values for presentation only when the grouping does not change the server-side priority result and is clearly labeled as presentation.

## Frozen evidence boundaries

The following boundaries are part of the methodology identity:

- `KEV NOT_LISTED` is not `not exploitable` or `safe`;
- customer `Internet_Facing` is coarse asset context, not exact Finding/endpoint reachability and not CVSS `MAV`;
- `Asset_Criticality` is not CVSS `CR/IR/AR`;
- EPSS is exploitation probability evidence, not impact or risk;
- contextual CVSS v4 is technical-severity evidence, not Organizational Risk;
- CISA SSVC/Vulnrichment evidence does not become `Track / Track* / Attend / Act` unless an explicit decision output is supplied and admitted;
- CISA KEV due dates are external federal reference dates, not a customer SLA.

## Frozen output contract

The row-preserving output adds exactly these methodology columns:

```text
RBVM_MVP_Priority_Status
RBVM_MVP_Priority_Front
RBVM_MVP_Priority_Dominated_By
RBVM_MVP_Priority_Dominates
RBVM_MVP_Priority_Blockers
RBVM_MVP_Priority_Explanation
RBVM_MVP_Priority_Method_SHA256
```

The report contract remains:

```text
RBVM_MVP_PRIORITY_REPORT_V1
```

The HTTP derivation contract remains:

```text
CSV_FIRST_MVP_PRIORITY_HTTP_V1
```

## Explainability freeze

Explainability is bound to:

```text
RBVM_MVP_PRIORITY_EXPLAINABILITY_V1
```

and must continue to declare:

```text
changesPriority = false
```

The explanation may clarify wording, but it may only render already-admitted inputs, the emitted front, emitted domination counts, and explicit missing-evidence blockers. Explanation code must not add a scoring signal or change ranking.

## Golden regression lock

The deterministic golden fixture is:

```text
testdata/rbvm-mvp-priority-golden.csv
```

Frozen file SHA-256:

```text
7a2fc323ce1e619386f20023b4ec84b7331241890a95691db7a577dbb0f50853
```

Frozen expected outcome:

| Case | Status | Front |
|---|---|---:|
| `A_KNOWN_EXPLOITED_STRONG_CONTEXT` | `RANKED_RELATIVE_ONLY` | 1 |
| `B_HIGHER_PROBABILITY_NO_KEV` | `RANKED_RELATIVE_ONLY` | 1 |
| `C_KEV_BUT_LOWER_CONTEXT` | `RANKED_RELATIVE_ONLY` | 2 |
| `D_DOMINATED_BASELINE` | `RANKED_RELATIVE_ONLY` | 3 |
| `E_MISSING_CUSTOMER_EXPOSURE` | `UNRANKABLE_MISSING_EVIDENCE` | — |
| `F_MAX_TECHNICAL_TRADEOFF` | `RANKED_RELATIVE_ONLY` | 1 |

Aggregate outcome:

```text
rankedRows = 5
unrankableRows = 1
frontCounts = {1: 3, 2: 1, 3: 1}
```

Row-order independence remains mandatory.

## Live benchmark lock

The live validation contract remains:

```text
CSV_V2_LIVE_BENCHMARK_V4
```

The live benchmark is intentionally not frozen to exact current EPSS probabilities, KEV contents, or public CVSS availability because those external data sources evolve.

Instead, the methodology freeze requires the live benchmark to continue validating structural invariants:

- priority output remains row-preserving;
- exact policy ID and SHA are emitted;
- explainability contract is present;
- Organizational Risk remains `NON_COMPUTABLE`;
- customer Internet Facing never infers CVSS `MAV`;
- no V2 Organizational Risk method is silently auto-admitted.

## Change control

A change to any of the following is a **semantic methodology change** and must not be released as `RBVM_MVP_PRIORITY_POLICY_V1`:

- dimension set;
- source columns;
- categorical mappings;
- dimension orientation;
- dominance rule;
- nondominated-front construction;
- missing/invalid evidence treatment;
- addition of any weight;
- addition of any threshold used in ranking;
- output semantics;
- claim that the output is Organizational Risk.

Such a change requires, at minimum:

1. a new method identity/version, normally `RBVM_MVP_PRIORITY_POLICY_V2`;
2. a new canonical representation and SHA-256;
3. a new/updated golden benchmark with explicit rationale;
4. an explicit migration/compatibility statement;
5. benchmark and UI updates that identify the new method rather than silently reusing V1.

## Changes permitted without V2

Changes may remain V1 only when they are demonstrated to be decision-equivalent, for example:

- documentation clarification;
- presentation-only visualization;
- explainability wording while `changesPriority=false` remains true;
- performance refactoring proven output-equivalent;
- additional regression cases that do not change existing frozen expectations.

The freeze verifier is intentionally part of the full CI suite. If a permitted implementation refactor changes the canonical SHA, golden results, missing-evidence semantics, output columns, or live-benchmark invariants, it is not proven decision-equivalent and must not merge as V1.

## Boundary to future Organizational Risk

Freezing the MVP policy closes the treatment-priority methodology for the MVP; it does not solve Organizational Risk.

A future risk method must have a separate approved identity and evidence contract, including defensible treatment of business/mission impact, exact applicability/reachability where required, stale/ambiguous evidence, output scale, calibration, and decision thresholds. It must not be smuggled into this frozen Pareto policy.
