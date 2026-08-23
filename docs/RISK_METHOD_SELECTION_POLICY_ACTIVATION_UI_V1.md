# Risk Method Selection Policy Activation UI V1

Contract: `RISK_METHOD_SELECTION_POLICY_ACTIVATION_UI_V1`

## Purpose

This Frontend V2 increment presents and administers the separate V26 Risk Method Selection Policy activation stream. It does not change immutable V25 policy revisions and it does not infer an active methodology from policy revision order, catalog order, Formula identity, or any risk score.

The activation stream is tenant-scoped and append-only. One activation event is either:

- `ACTIVE`, referencing one exact persisted policy revision + policy SHA-256; or
- `CLEARED`, explicitly recording that no policy is active.

`never activated` is different from `CLEARED`.

## Current explicit activation

The UI reads only:

`GET /api/v1/risk-method-selection-policy-activation/current`

The response must advertise `CURRENT_IS_GREATEST_EXPLICIT_ACTIVATION_REVISION_NEVER_POLICY_REVISION` before it is presented as valid activation state.

`current` means the event with the greatest explicit **activation revision**. It never means the greatest policy revision and it never means the first or preferred method in a catalog.

A `404` is presented as `never activated`; it is not converted into `CLEARED`, ACTIVE, a default method, or another fallback state.

## Append an explicit event

The write form begins with every identity input empty. The browser does not generate any of them.

For `ACTIVE`, the operator must provide:

- a positive activation revision;
- `ACTIVE` explicitly;
- an exact persisted policy revision;
- the exact lowercase policy SHA-256;
- an explicit UTC ISO-8601 `recordedAt` instant.

The UI calls only:

`POST /api/v1/risk-method-selection-policy-activation-events/{activationRevision}/ACTIVE/{policyRevision}/{policySha256}/{recordedAt}`

For `CLEARED`, the operator must provide:

- a positive activation revision;
- `CLEARED` explicitly;
- an explicit UTC ISO-8601 `recordedAt` instant.

The UI calls only:

`POST /api/v1/risk-method-selection-policy-activation-events/{activationRevision}/CLEARED/{recordedAt}`

The browser never computes `max + 1`, never auto-increments a conflicting revision, and never substitutes browser time for `recordedAt`. This preserves the server's canonical replay identity: the same authenticated actor and same exact path reconstruct the same immutable event.

A `403` states that the Operator role is required. A `404` on ACTIVE means the exact policy revision + SHA does not exist. A `409` remains an explicit revision conflict or stale activation revision; the browser does not choose another revision automatically.

## Exact historical read

Historical activation reads require both immutable identifiers and begin empty:

- activation revision;
- event SHA-256.

The UI calls only:

`GET /api/v1/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}`

A `404` is an exact-identity miss. The browser does not list activation events or fall back to another event.

## Presentation and audit identity

Successful current/read/write responses display the exact activation identity and provenance exposed by the API, including:

- activation revision and state;
- exact policy revision + SHA when ACTIVE;
- authenticated `changedBy` identity;
- `recordedAt`;
- event SHA-256;
- canonical payload format;
- ETag and Location when returned.

The UI does not reconstruct event SHA-256 or canonical payload bytes in JavaScript.

## Separation from policy administration

`RISK_METHOD_SELECTION_POLICY_ADMIN_UI_V1` remains the immutable policy-revision administration contract. Installing a V25 policy revision does not activate it. Activation is performed only through this separate V26 contract.

The two surfaces share the `Risk policy` tab for operator usability but retain separate contract markers and verifiers.

## Browser-state and scoring boundaries

Activation identity is not stored in `localStorage`, `sessionStorage`, cookies, or query-state defaults. Reloading the browser always reads persisted activation state from the server.

The activation UI does not average, normalize, rank, or reinterpret Formula/derived methodology outputs. It creates no Priority, Treatment, SLA, remediation deadline, exploitation probability, expected-loss, or remediation-ranking semantics.

## Shared Frontend V2 hosts

The contract is inserted identically into all nine legacy Frontend V2 HTML hosts. Repository verification requires those hosts to remain byte-identical and English-only.
