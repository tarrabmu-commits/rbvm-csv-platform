# RBVM Formula Catalog API V1

Status: `IMPLEMENTED`

Contract: `RBVM_FORMULA_CATALOG_API_V1`

## Purpose

The Formula catalog exposes immutable Formula identity metadata to authenticated consumers so they do not duplicate or hard-code the SHA/version of `RBVM_FORMULA_V1`.

The catalog is discovery-only. It does not evaluate a Formula, build a Decision Input, select current evidence, materialize a result, or choose a preferred Formula.

## Transport

```text
GET /api/v1/formulas
```

The route requires `VIEWER` and is part of the existing Formula Result runtime capability. Authorization is resolved before runtime-capability lookup, matching the Formula Result transport boundary.

The route accepts no query parameters. There is no pagination because the current accepted catalog contains one immutable Formula identity.

## Selection semantics

Every successful response declares:

```text
selectionSemantics = EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT
```

Catalog ordering is deterministic presentation order only. It does not mean first, preferred, current, latest, primary, or default.

The current catalog entry is derived directly from the accepted Java Formula contract:

```text
formulaId        = RBVM_FORMULA_V1
formulaVersion   = 1
formulaSha256    = 88bf31f510089b4209b1ffcf1c15b39fef60548209875334f084888316e9028e
classification  = RBVM_POLICY
inputContractId  = RBVM_DECISION_INPUT_SNAPSHOT_V3
outputName       = RBVM Relative Risk Index
numericRange     = 0.00 .. 100.00
resultStates     = COMPUTED | NOT_APPLICABLE | NON_COMPUTABLE
```

The SHA is not a second source of truth in the HTTP layer: `FormulaCatalogApi` reads `RbvmFormulaV1.FORMULA_SHA256`, `FORMULA_ID`, `FORMULA_VERSION`, and `OUTPUT_NAME` directly.

## Output semantics

The catalog explicitly classifies Formula V1 output as:

```text
DIMENSIONLESS_RELATIVE_RISK_INDEX_NOT_PRIORITY_SLA_TREATMENT_OR_PROBABILITY
```

Only `COMPUTED` carries a numeric Relative Risk Index. `NOT_APPLICABLE` and `NON_COMPUTABLE` remain terminal nonnumeric states in the Formula Result contract.

The catalog must not be interpreted as claiming that the Formula arithmetic is mandated by an external standard. The numeric Formula is versioned RBVM policy.

## Relationship to Formula Result reads

A client can discover the exact Formula SHA here and then perform the existing exact persisted-result lookup:

```text
GET /api/v1/formula-results
  ?inputSnapshotSha256={sha256}
  &formulaSha256={formulaSha256}
```

Successful Formula Result reads remain replay-verified and exact-identity only.

## Relationship to materialization

The existing Operator command remains unchanged:

```text
POST /api/v1/formula-result-materializations/{inputSnapshotSha256}
```

Materialization evaluates only the accepted `RBVM_FORMULA_V1` implementation against one exact already-persisted Decision Input V3 snapshot. The catalog does not change that command or introduce a Formula selector into it.

## Explicit non-goals

The catalog defines no:

- `latest` or `current` Formula;
- default, primary, or preferred Formula;
- Formula priority or ordering semantics;
- cross-methodology normalization;
- Priority, Treatment, SLA, remediation deadline, or remediation ranking;
- browser presentation policy.

A future browser Formula presentation must consume this catalog rather than hard-code Formula identity metadata.
