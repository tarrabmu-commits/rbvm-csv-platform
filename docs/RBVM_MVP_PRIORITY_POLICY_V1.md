# RBVM MVP Priority Policy V1

Policy ID: `RBVM_MVP_PRIORITY_POLICY_V1`

Classification: `RBVM_POLICY`

Canonical SHA-256:

`88d5cdb8702c6c0ed2c033c3df6b8abbe1aa392f44f4507685b54082a16dc388`

## Purpose

This policy gives the CSV-first MVP a usable **relative treatment priority** without pretending that the current evidence is sufficient for Organizational Risk.

It is deliberately **not** `RBVM_FORMULA_V2` and does not change the current Organizational Risk state:

```text
RBVM_V2_Status = NON_COMPUTABLE
```

The policy exists because the current MVP has useful but semantically different signals:

- CISA KEV confirmed-listing state;
- customer-declared asset-level Internet Facing state;
- customer-declared Asset Criticality;
- FIRST EPSS 30-day exploitation probability;
- contextual CVSS v4 technical severity.

No published authority defines a universal weighted formula that combines those values into Organizational Risk. Therefore V1 uses nondominated/Pareto fronts instead of weights or thresholds.

## Inputs

A row is rankable only when all five values are valid:

| Dimension | Source column | Direction |
|---|---|---|
| CISA KEV | `KEV_Listed` | listed is stronger urgency evidence |
| Customer Internet Facing | `Internet_Facing` | `YES` is treated as stronger customer-declared exposure context than `NO` |
| Asset Criticality | `Asset_Criticality` | `MISSION_CRITICAL > HIGH > MODERATE > LOW` |
| FIRST EPSS | `EPSS_Probability` | higher probability is stronger exploitation-likelihood evidence |
| Contextual CVSS v4 | `CVSS4_Context_Score` | higher score is stronger technical-severity evidence |

The categorical ordering is explicit **local policy**. It is not a FIRST, CISA, NIST, ISO, or CVSS standard mapping.

`Internet_Facing=YES` remains coarse customer-declared asset context. It is **not** exact Finding/endpoint Reachability and does not become CVSS `MAV`.

`KEV=NOT_LISTED` is only the catalog observation state. It is **not** interpreted as no exploitation risk.

## Method

For two complete rows `A` and `B`, `A` dominates `B` only when:

```text
A >= B on every dimension
AND
A > B on at least one dimension
```

The algorithm then performs iterative nondominated sorting:

1. all currently nondominated rows become `Front 1`;
2. remove them;
3. the next nondominated set becomes `Front 2`;
4. repeat until all rankable rows have a front.

Interpretation:

```text
Front 1 = highest relative treatment-priority frontier in this exact input set
Front 2 = next relative frontier
...
```

A front number is **not** a risk severity label, SLA, remediation deadline, probability, or universal score.

Because the method is relative, adding or removing findings can change front numbers.

## Missing evidence

Missing or invalid values are not mapped to zero, low, or worst-case.

The row becomes:

```text
RBVM_MVP_Priority_Status = UNRANKABLE_MISSING_EVIDENCE
```

with explicit blockers.

## Forbidden shortcuts

The canonical method contains:

```text
weights = []
thresholds = []
```

Therefore it does not use:

- CVSS × EPSS;
- arbitrary weighted sums;
- invented EPSS Low/Medium/High thresholds;
- invented CVSS risk thresholds;
- `KEV NOT_LISTED = safe`;
- `Internet Facing = exact Reachability`;
- Asset Criticality as CVSS CR/IR/AR;
- treatment priority as Organizational Risk.

## Output contract

`scripts/rank-rbvm-mvp-priority.py` emits:

- a row-preserving ranked CSV;
- `RBVM_MVP_PRIORITY_REPORT_V1` JSON;
- exact policy SHA;
- ranked/unrankable counts;
- Pareto-front counts;
- explicit unrankable reasons;
- input/output SHA-256 values.

The output CSV adds:

```text
RBVM_MVP_Priority_Status
RBVM_MVP_Priority_Front
RBVM_MVP_Priority_Dominated_By
RBVM_MVP_Priority_Dominates
RBVM_MVP_Priority_Blockers
RBVM_MVP_Priority_Method_SHA256
```

## Boundary with RBVM Formula V2

This policy is a practical MVP prioritization mechanism only.

A future `RBVM_FORMULA_V2` Organizational Risk method still requires an approved identity, version, SHA, exact evidence contract, explicit missing/stale/ambiguous rules, and defensible business-impact/reachability semantics. Until then:

```text
Treatment Priority = computable when the five MVP signals are complete
Organizational Risk = NON_COMPUTABLE
```
