# Derived Risk Result Materialization V1

Status: `IMPLEMENTED_RUNTIME`

Input identity:

```text
inputSnapshotSha256
+ methodologyId
+ methodologySha256
```

Output: one replay-verified `RBVM_DERIVED_RISK_RESULT_CANONICAL_BINARY_V1` result.

## Purpose

The production materializer turns one already-persisted exact Decision Input V3 snapshot into one exact derived methodology result without introducing current-state selection or a preferred methodology.

The caller must choose the methodology explicitly. Catalog order is never used as a default.

## Exact execution path

```text
explicit inputSnapshotSha256
        +
explicit methodologyId + methodologySha256
        ↓
load exact persisted Decision Input V3
        ↓
resolve only its captured native evidence + bindings
        ↓
resolve exact implemented methodology identity
        ↓
evaluate that methodology only
        ↓
canonicalize result
        ↓
append/replay V24 persistence
        ↓
reload exact result SHA
        ↓
exact historical replay verification
        ↓
return INSERTED or REPLAYED result
```

The materializer never rebuilds Decision Input, reads `current_*`, selects `latest` evidence, chooses the first catalog entry, falls back to another methodology, or averages methodologies.

## Methodology identity

Both the canonical methodology ID and methodology SHA-256 are required. A known ID with a different SHA is rejected before evaluation. An unknown ID is rejected; it is not mapped to a default.

Current identities remain the SHA-bound implementations declared by `DERIVED_RISK_METHODOLOGIES_V1`:

- `OWASP_DERIVED_RBVM_V1`
- `MICROSOFT_PD_DERIVED_RBVM_V1`

## Persistence behavior

The materializer delegates to `DerivedRiskResultStore` and accepts only:

- `INSERTED` for a first exact result;
- `REPLAYED` for a byte-identical exact retry.

`RESULT_CONFLICT` is surfaced as a fail-closed materialization error and is never overwritten.

After install/replay the exact canonical result is reloaded by SHA and passed through `DerivedRiskResultReplayVerifier`. A response is returned only when replay regenerates the same canonical result identity.

## Terminal semantics

`NOT_APPLICABLE` and `NON_COMPUTABLE` remain first-class materialized results with no numeric substitute. Missing/stale/ambiguous required evidence is not reweighted away.

## Boundary

This increment does not expose HTTP transport or browser UI. It does not define a preferred/default methodology, cross-methodology normalized score, Priority, Treatment, SLA, remediation deadline, ranking, or ticketing workflow.

The next transport increment may expose this runtime only if the request carries the exact snapshot and methodology identity explicitly.
