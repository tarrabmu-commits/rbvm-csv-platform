# RBVM Formula UI V1

Status: `IMPLEMENTED_UI`

Contract: `RBVM_FORMULA_V1_PRESENTATION_UI_V1`

## Purpose

Frontend System V2 presents the persisted `RBVM_FORMULA_V1` result inside the existing component-specific Finding investigation flow without recomputing Formula arithmetic in the browser.

The browser is a presentation and exact-command client only. Formula identity, Formula result content, canonical explanation identity, and replay verification remain server-owned contracts.

## Entry point

The Finding drawer exposes a dedicated **RBVM Formula** tab. This remains separate from **Risk methodologies** because the contracts have different semantics:

- `RBVM_FORMULA_V1` is classified `RBVM_POLICY` and produces the dimensionless `RBVM Relative Risk Index` on `0.00 .. 100.00` only when the result state is `COMPUTED`.
- OWASP/Microsoft derived methodologies are `STANDARD_DERIVED` adaptations with their own native scales and semantics.

The UI does not merge, average, normalize, or rank these outputs.

## Exact identity workflow

For one explicit component-specific Finding, the UI reads:

```text
GET /api/v1/formulas
GET /api/v1/findings/{findingId}/decision-input-snapshots?limit=100
```

Only `RBVM_DECISION_INPUT_SNAPSHOT_V3` snapshots are eligible.

The Formula catalog must advertise:

```text
selectionSemantics = EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT
```

Both selectors start empty. Catalog order and Decision Input history order are presentation-only; the UI never treats the first row as current, latest, preferred, primary, or default.

After the operator explicitly selects both identities, the UI performs exact lookup:

```text
GET /api/v1/formula-results?inputSnapshotSha256={snapshotSha256}&formulaSha256={formulaSha256}
```

The Formula SHA is read from `RBVM_FORMULA_CATALOG_API_V1`. It is not hard-coded into browser JavaScript.

## Missing exact result

HTTP `404` means no persisted result exists for that exact snapshot/Formula identity. The UI does not convert absence into zero or any other risk value.

An Operator may invoke the existing exact Formula V1 materialization command:

```text
POST /api/v1/formula-result-materializations/{inputSnapshotSha256}
```

The command carries no request body and no query selector. Authentication/authorization and Formula V1 materialization semantics remain backend responsibilities.

## Result presentation

A successful exact read is already replay-verified by `RBVM_FORMULA_RESULT_API_V1`. The UI displays server-returned values only:

- result state: `COMPUTED / NOT_APPLICABLE / NON_COMPUTABLE`
- `relativeRiskIndex` only for `COMPUTED`
- terminal reason codes for non-computed results
- persisted time
- exact Formula ID/SHA and Decision Input snapshot SHA
- canonical explanation SHA and replay-verification state
- per-dimension state
- normalized value returned by the explanation
- applied factor/transform identifier
- weighted contribution returned by the explanation
- exact native evidence UUID/SHA/source/time
- exact association binding UUID/SHA/kind when present

The browser does not decode the canonical payload and does not regenerate canonical explanation bytes.

## Semantic boundary

The UI does not create or infer:

```text
Formula result = Priority
Formula result = SLA
Formula result = Treatment
Formula result = remediation deadline
Formula result = exploitation probability
Formula result = expected loss
```

It performs no browser-side Formula arithmetic, weight application, normalization, score conversion, ranking, or thresholding.

## Browser state

Formula selections and results are ephemeral page state only. They are not written to `localStorage`, `sessionStorage`, cookies, URL query state, or another browser persistence mechanism.

## Shared-host invariant

All legacy Frontend System V2 HTML entry points remain byte-identical and contain the same Formula presentation progressive enhancement. The Formula UI does not create a parallel application shell or route-specific implementation.
