# Active Risk Method Execution UI V1

`ACTIVE_RISK_METHOD_EXECUTION_UI_V1` is the Frontend V2 presentation for the exact execution and immutable binding-read operations exposed by `RBVM_ACTIVE_RISK_METHOD_EXECUTION_API_V1`.

The module is a progressive enhancement of the existing **Risk policy** drawer tab. It does not create a second policy tab and it does not change Risk Method Selection Policy administration or activation semantics.

## Exact execution only

The execution form requires three operator-supplied immutable identities:

- exact positive activation revision;
- exact lowercase activation event SHA-256;
- exact lowercase persisted Decision Input V3 snapshot SHA-256.

All three controls start empty every time the UI is constructed. The browser does not derive, remember, copy, or pre-fill them from the current activation display, resolved-active-method display, policy catalog, case detail, URL query state, `localStorage`, `sessionStorage`, cookies, or prior execution responses.

The submit operation is exactly:

`POST /api/v1/active-risk-method-executions/{activationRevision}/{activationEventSha256}/{inputSnapshotSha256}`

The request has no query selector and no request body. Operator authorization remains a server concern. The UI never exposes a **Run current** action and never calls a current/resolved activation endpoint to choose what should execute.

An exact retry may return `REPLAYED`; the UI presents this as replay of the immutable execution binding. Replay does not re-execute the risk method, does not make a fresh selection, and does not substitute another policy or method.

## Exact binding read

Historical execution provenance is read only by the canonical binding identity:

`GET /api/v1/active-risk-method-execution-bindings/{bindingSha256}`

The binding SHA input also starts empty. There is no execution collection lookup, binding collection lookup, latest lookup, or fallback lookup. A `404` means that exact binding is unavailable; the UI does not substitute another binding.

## Provenance presented

For a valid API response, the UI presents the exact immutable chain:

- activation revision and activation event SHA;
- policy revision and policy SHA;
- selection role;
- method family, ID, version, and SHA;
- Decision Input snapshot SHA;
- native result family and result SHA;
- execution binding SHA and canonical format;
- native result location;
- response `ETag` and `Location`.

The response must advertise `EXPLICIT_ACTIVATION_REVISION_EVENT_SHA_AND_DECISION_INPUT_SHA_ONLY_NO_CURRENT_DEFAULT`. A response that does not advertise this semantic is not presented as valid execution provenance.

## Fail-closed operator behavior

The UI preserves server distinctions instead of inventing fallback behavior:

- `403`: Operator role is required for execution.
- `404`: the exact activation identity, Decision Input identity, or exact binding identity is unavailable; no fallback identity is selected.
- `409`: an exact activation may be `CLEARED`, the exact historical selected method may be unavailable, or immutable execution content may conflict; no alternate policy or method is selected.
- `422`: execution requires an exact persisted Decision Input Snapshot V3.
- `500`: the exact activation/policy/method/input/result chain failed integrity verification.
- `503`: V27 Active Risk Method Execution persistence is unavailable.

## Deliberate non-semantics

Execution provenance remains separate from organizational remediation decisions. This UI does not calculate, infer, persist, or display a Priority tier, Treatment decision, SLA, remediation deadline, ownership assignment, or remediation workflow state.

Formula and standard-derived results remain native independent result contracts. The UI does not average methodologies, normalize them into a common score, use catalog order as precedence, or turn an active method into a default method.
