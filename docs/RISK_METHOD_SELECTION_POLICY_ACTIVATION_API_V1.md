# RBVM Risk Method Selection Policy Activation API V1

## Purpose

`RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_API_V1` exposes the V26 append-only activation stream without changing the immutable V25 policy registry.

Activation answers one narrow control-plane question: which exact persisted Risk Method Selection Policy is explicitly active for the tenant, or has that pointer been explicitly cleared?

It does not evaluate Formula or standard-derived risk, rank methodologies, calculate Priority, select Treatment, assign SLA, or create remediation deadlines.

## Current explicit activation

`GET /api/v1/risk-method-selection-policy-activation/current`

Authorization: `VIEWER`.

`current` has one precise V26 meaning: the event with the greatest **activation revision** in the append-only activation stream. It does not mean the greatest policy revision, the first/last catalog item, the newest Formula, or a preferred methodology.

Outcomes:

- `200 ACTIVE` — the current event points to one exact persisted policy revision and policy SHA.
- `200 CLEARED` — an explicit event records that no policy is active.
- `404 RISK_METHOD_SELECTION_POLICY_ACTIVATION_NOT_FOUND` — no activation event has ever been persisted.

Never-activated is therefore distinct from explicitly `CLEARED`.

## Exact historical activation read

`GET /api/v1/risk-method-selection-policy-activations/{activationRevision}/{eventSha256}`

Authorization: `VIEWER`.

Both immutable identities are required. A revision that exists under another event SHA is still `404` for this exact lookup. There is no activation collection endpoint and no query selector.

Successful reads return:

- strong `ETag` derived from the event SHA,
- `Location` containing the same exact activation revision and event SHA,
- canonical activation payload Base64,
- activation state,
- exact policy revision/SHA when state is `ACTIVE`,
- authenticated `changedBy`, explicit `recordedAt`, and V1 empty `changeNote`.

## Append an ACTIVE event

`POST /api/v1/risk-method-selection-policy-activation-events/{activationRevision}/ACTIVE/{policyRevision}/{policySha256}/{recordedAt}`

Authorization: `OPERATOR`.

Every decision input is explicit:

- positive activation revision,
- positive exact policy revision,
- exact lowercase policy SHA-256,
- explicit ISO-8601 `recordedAt` instant.

`changedBy` is taken from the authenticated principal. V1 fixes `changeNote` to the empty string and accepts no request body or query parameters.

The explicit timestamp is part of canonical event identity. Repeating the same exact path as the same authenticated actor therefore reconstructs the same canonical event and can return `200 REPLAYED`. The server never generates an activation revision and never chooses a policy from revision order or catalog order.

The exact policy revision and SHA must already exist in the V25 immutable registry. Otherwise the command returns `404 RISK_METHOD_SELECTION_POLICY_NOT_FOUND`.

## Append a CLEARED event

`POST /api/v1/risk-method-selection-policy-activation-events/{activationRevision}/CLEARED/{recordedAt}`

Authorization: `OPERATOR`.

`CLEARED` carries no policy revision or policy SHA. It explicitly records no active policy and is not inferred from missing data.

## Append outcomes

- `201 INSERTED` — new immutable activation revision appended.
- `200 REPLAYED` — same activation revision and canonical event identity already exist.
- `409 RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION_CONFLICT` — that activation revision is already bound to a different event.
- `409 STALE_RISK_METHOD_SELECTION_POLICY_ACTIVATION_REVISION` — a greater explicit activation revision already exists; the API never back-dates a new current-state event.

No command auto-increments a revision.

## Canonical response identity

Responses expose `RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_V1` fields and `RBVM_RISK_METHOD_SELECTION_POLICY_ACTIVATION_EVENT_CANONICAL_BINARY_V1` payload bytes.

The activation response semantics are:

`CURRENT_IS_GREATEST_EXPLICIT_ACTIVATION_REVISION_NEVER_POLICY_REVISION`

That statement is a control-plane ordering rule only. It does not imply a scoring rank or methodology precedence.

## Capability and authorization ordering

V25 policy persistence remains available on PostgreSQL schema 25. Activation transport requires V26.

The existing Risk Method Selection Policy router resolves the route and required role before API capability use. Therefore:

- unauthenticated activation reads/writes receive `401` before V26 availability is disclosed,
- `VIEWER` attempts to append activation events receive `403` before V26 availability is disclosed,
- only an authorized caller can receive `503 RISK_METHOD_SELECTION_POLICY_ACTIVATION_PERSISTENCE_UNAVAILABLE` when the policy registry exists but V26 activation persistence does not.

The runtime attaches the V26 activation store to the V25 policy store only when schema version is at least 26; no server-wide policy API disablement is required for schema 25.

## Deliberate exclusions

V1 has no:

- activation collection/list route,
- implicit `latest` query parameter,
- max-policy-revision selection,
- catalog-order selection,
- default/preferred/fallback methodology,
- browser activation control,
- score averaging or normalization,
- Priority, Treatment, SLA, or remediation ranking semantics.

Browser presentation/administration of the explicit active pointer is a separate UI increment and must consume these exact V26 identities rather than recreate activation logic in JavaScript.
