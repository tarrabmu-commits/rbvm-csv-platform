# Risk Method Selection Policy Administration UI V1

Contract: `RISK_METHOD_SELECTION_POLICY_ADMIN_UI_V1`

## Purpose

This browser increment exposes the already-versioned Risk Method Selection Policy control plane without inventing a current or default policy. It is an administration surface for immutable tenant-scoped policy revisions, not a scoring algorithm and not an activation pointer.

The UI deliberately keeps two different concepts separate:

- **risk result comparison** remains Finding-scoped and compares methodology-native results only on the same exact Decision Input V3 snapshot;
- **Risk Method Selection Policy administration** is tenant-scoped and binds one immutable policy revision to one exact accepted risk-method identity.

## Explicit method discovery

The UI reads both existing method catalogs:

- `GET /api/v1/formulas`
- `GET /api/v1/derived-risk-methodologies`

Both catalogs must advertise `EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT` before policy administration is enabled. Formula entries are represented as `RBVM_FORMULA`; standard-derived entries are represented as `STANDARD_DERIVED`.

Catalog order is presentation-only. It creates no precedence, preference, fallback, or default. The method selector begins empty and the user must select one exact identity.

## Install one immutable policy revision

Installation requires two explicit inputs:

1. a positive policy revision typed by the operator;
2. one exact method family + ID + version + SHA selected from the accepted catalogs.

The UI calls only the exact installation route:

`POST /api/v1/risk-method-selection-policy-installations/{revision}/{methodFamily}/{methodId}/{methodVersion}/{methodSha256}`

The request has no body and no query parameters. The browser does not inspect existing policy revisions to derive a revision number. It does not compute `max + 1`, choose a first catalog item, or retry a conflict with a different revision automatically.

A `409` revision conflict is shown as an explicit conflict. The operator must deliberately choose a different revision if that is the intended change. A `403` states that the Operator role is required.

Successful `INSERTED` and `REPLAYED` responses display the immutable policy revision, policy SHA-256, method identity, canonical payload format, ETag, and Location returned by the server.

## Read one exact historical policy

The historical read form also begins empty and requires both immutable identifiers:

- policy revision;
- policy SHA-256.

It calls only:

`GET /api/v1/risk-method-selection-policies/{revision}/{policySha256}`

There is no policy collection lookup and no max-revision, latest, current, active, preferred, or default lookup. A `404` remains an exact-identity miss; the browser does not fall back to another revision.

## Activation boundary

Persisting a Risk Method Selection Policy revision does **not** establish which revision is operationally active. Multiple immutable revisions may coexist. A future operational activation mechanism must be a separate versioned, auditable contract that references an exact policy revision and policy SHA.

Until such a contract exists, the UI never labels a policy revision as current, active, latest, or default and never highlights a result methodology as organizationally selected merely because a policy revision exists.

## Scoring boundary

The UI does not alter Formula V1 or standard-derived result semantics. It does not average, normalize, rank, combine, or convert methodology outputs. It does not create Priority, Treatment, SLA, remediation deadline, exploitation probability, or expected-loss semantics.

## Browser-state boundary

Policy identity is not stored in `localStorage` or `sessionStorage`. Closing or reloading the browser does not manufacture a remembered active selection. Exact persisted policy identity is always read from the server using revision + SHA.
