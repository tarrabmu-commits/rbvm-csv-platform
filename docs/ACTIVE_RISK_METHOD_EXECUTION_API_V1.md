# Active Risk Method Execution API V1

`RBVM_ACTIVE_RISK_METHOD_EXECUTION_API_V1` is the exact transport for executing one explicitly selected primary risk method and reading the immutable V27 execution binding that proves what was executed.

## Execution identity

Execution is allowed only through:

`POST /api/v1/active-risk-method-executions/{activationRevision}/{activationEventSha256}/{inputSnapshotSha256}`

All three identities are required and explicit:

- `activationRevision` is the exact historical activation revision.
- `activationEventSha256` is the exact canonical V26 activation event identity.
- `inputSnapshotSha256` is the exact already-persisted Decision Input V3 snapshot identity.

The API never substitutes the current activation, current policy, greatest policy revision, latest Decision Input, newest result, catalog order, a preferred method, or a default method. There is deliberately no execution route containing `current`.

The POST route requires `OPERATOR` permission. Query parameters and request bodies are rejected. Authorization is resolved before V27 capability lookup, so an unauthorized caller cannot use the route to discover whether execution persistence is enabled.

## Exact resolution and execution

The materializer performs the following exact chain:

1. Resolve the supplied activation revision and verify the supplied activation event SHA.
2. Reject an exact `CLEARED` event; `CLEARED` is not interpreted as a fallback to another policy.
3. Resolve the exact policy revision + policy SHA referenced by the `ACTIVE` event.
4. Require the selected PRIMARY method identity to remain executable in the current catalog.
5. Execute that exact method against the supplied exact Decision Input V3 snapshot.
6. Verify that the native result reports the same snapshot SHA and exact method family/ID/version/SHA.
7. Persist or replay `RBVM_ACTIVE_RISK_METHOD_EXECUTION_BINDING_V1`.

Formula and standard-derived methods keep their native result contracts. The execution API does not normalize, average, rank, or convert results between methodologies.

## Idempotency and replay

The immutable execution key is the exact activation event SHA + exact Decision Input snapshot SHA. A successful first execution returns HTTP `201` with `executionStatus: INSERTED`. An exact retry returns HTTP `200` with `executionStatus: REPLAYED` and does not re-execute the risk method when the immutable execution binding already exists.

A different binding for the same exact execution key fails closed as an execution conflict. Missing or stale evidence is not remapped during replay because the Decision Input identity is already frozen.

## Immutable binding read

Exact historical reads use:

`GET /api/v1/active-risk-method-execution-bindings/{bindingSha256}`

The route requires `VIEWER` permission. The binding SHA is the only selector; query parameters and request bodies are rejected. There is no collection/list endpoint and no current/latest binding lookup.

The response includes:

- exact activation revision + activation event SHA;
- exact policy revision + policy SHA;
- PRIMARY selection role;
- exact method family, ID, version, and SHA;
- exact Decision Input snapshot SHA;
- exact native result family + result SHA;
- canonical execution-binding payload format and Base64 payload;
- canonical binding SHA;
- `resultLocation` pointing to the exact native Formula or Derived Risk Result read route.

Successful responses include a strong `ETag` based on the binding SHA and `Location` pointing to the exact immutable binding read route.

## Status semantics

Execution uses the following relevant outcomes:

- `201`: immutable execution binding inserted.
- `200`: exact immutable execution binding replayed.
- `400`: malformed identity, forbidden query parameters, or forbidden request body.
- `401`: authentication required.
- `403`: authenticated identity lacks the required role.
- `404`: exact activation, Decision Input, or binding identity does not exist.
- `409`: activation is explicitly `CLEARED`, the selected historical method is unavailable, or immutable native-result/binding content conflicts.
- `422`: the supplied persisted input is not Decision Input Snapshot V3.
- `500`: persisted exact identities fail execution-integrity verification.
- `503`: V27 Active Risk Method Execution runtime is unavailable.

## Boundary with organizational decisions

This contract records and exposes **risk-method execution provenance** only. It does not turn the selected method into Priority, Treatment, SLA, remediation deadline, ownership, or remediation workflow. A Formula result remains an RBVM Relative Risk Index; a derived methodology result remains that methodology's native derived result. The active-method selection and execution layer must not silently collapse these separate semantics.
