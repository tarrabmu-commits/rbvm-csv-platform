# Derived Risk Result Persistence V1

Status: `IMPLEMENTED`

Database migration: `V24__derived_risk_result_persistence.sql`

Canonical payload: `RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1`

## Purpose

V24 persists exact results from the externally sourced derived methodologies introduced in `DERIVED_RISK_METHODOLOGIES_V1` without changing the historical `RBVM_FORMULA_V1` persistence contract.

The two persistence families remain intentionally separate:

```text
RBVM_FORMULA_V1
  -> rbvm.formula_result
  -> RBVM_FORMULA_EXPLANATION_CANONICAL_BINARY_V1

OWASP_DERIVED_RBVM_V1 / MICROSOFT_PD_DERIVED_RBVM_V1
  -> rbvm.derived_risk_result
  -> RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1
```

V24 does not reinterpret old Formula V1 rows and does not widen `formula_result` into a generic table after the fact.

## Immutable identity

Each persisted derived result is bound to:

- exact persisted `RBVM_DECISION_INPUT_SNAPSHOT_V3` SHA-256;
- exact Finding UUID;
- derived methodology ID;
- methodology version;
- methodology SHA-256;
- result state;
- nullable terminal reason or computed score/scale/rating;
- exact canonical payload bytes and SHA-256;
- persistence time.

The uniqueness key is the exact snapshot plus exact methodology identity. The same snapshot may therefore hold one OWASP-derived result and one Microsoft-derived result without either becoming a default or winner.

## Append/replay semantics

`PostgresDerivedRiskResultStore` uses three outcomes:

- `INSERTED` — first exact result for the snapshot/methodology identity;
- `REPLAYED` — exact retry with byte-identical canonical result content;
- `RESULT_CONFLICT` — same snapshot/methodology identity but different result content.

Runtime access is `SELECT, INSERT` only. `UPDATE`, `DELETE`, and `TRUNCATE` are explicitly revoked.

## Historical replay

`DerivedRiskResultReplayVerifier` performs only exact historical replay:

```text
persisted derived result
        ↓
exact inputSnapshotSha256
        ↓
exact persisted Decision Input V3
        ↓
exact native evidence + binding resolution
        ↓
exact methodology ID/version/SHA lookup
        ↓
methodology evaluation
        ↓
canonical result regeneration
        ↓
byte-for-byte equality required
```

It does not rebuild Decision Input, read `current_*` evidence, select a `latest` row, infer a preferred methodology, or fall back to another methodology when the exact implementation identity is unavailable.

## Terminal semantics

`NOT_APPLICABLE` and `NON_COMPUTABLE` remain non-numeric. They persist a reason code and no numeric score, scale, or rating.

`COMPUTED` results persist the methodology-native numeric score and numeric scale. `rating` is nullable because OWASP-derived V1 defines a rating while Microsoft Probability x Damage-derived V1 intentionally does not invent one.

No stored numeric value is a remediation Priority, SLA, Treatment, deadline, expected loss, or cross-methodology normalized score.

## Live verification

`PostgresV24DerivedRiskLiveSelfTest` proves on real PostgreSQL that:

- schema migration reaches V24;
- both implemented derived methodologies can persist against the same exact Decision Input V3 snapshot;
- first writes are `INSERTED`;
- exact retries are `REPLAYED`;
- one row per exact methodology identity is retained;
- read-by-result-SHA and read-by-snapshot/methodology both replay successfully;
- historical replay regenerates byte-identical canonical result content;
- the runtime role cannot update, delete, or truncate derived-risk history.

## Boundary

V24 introduces persistence and exact replay only. It does not introduce HTTP transport, browser presentation, methodology preference, cross-methodology averaging, Priority, Treatment, SLA, remediation deadline, ranking, or ticketing policy.
