# RBVM Decision Input API V1

`RBVM_DECISION_INPUT_API_V1` exposes immutable Decision Input identities needed by Formula-facing operator workflows without introducing a hidden selector.

## Boundaries

The API does not select a Finding, methodology revision, methodology SHA, evaluation time, evidence source winner, or Decision Input snapshot for the caller. It does not compute Formula results and contains no Priority, Treatment, or SLA semantics.

Decision Input materialization is explicit:

`POST /api/v1/decision-input-materializations`

The JSON body must contain exactly:

- `findingId`
- `methodologyRevision`
- `methodologyPolicySha256`
- `evaluatedAt`

The methodology revision and SHA must identify the same registered immutable methodology. The evaluation instant is part of snapshot identity and must be supplied by the caller. PostgreSQL schema V23 is required by this operator transport stage.

A first immutable install returns HTTP `201`; an idempotent replay returns HTTP `200`. Both return `Location` for the exact snapshot SHA and a strong `ETag`. A conflicting canonical snapshot for the exact Finding/methodology/evaluatedAt identity returns `409` rather than silently replacing history.

Formula-facing materialization requires the resulting snapshot to be `RBVM_DECISION_INPUT_SNAPSHOT_V3`. The materialization path reloads the stored snapshot by exact SHA and verifies the canonical bytes before returning success.

## Exact reads

`GET /api/v1/decision-input-snapshots/{snapshotSha256}` reads one exact immutable snapshot identity. Historical V1/V2 snapshots can remain readable; the Formula materialization command is still restricted to V3.

`GET /api/v1/findings/{findingId}/decision-input-snapshots` returns immutable history for one Finding. Ordering by `evaluatedAt DESC, snapshotSha256 DESC` is only a deterministic keyset-pagination rule. No row is labeled or implied to be `latest` or `current`.

The history cursor is the pair:

- `beforeEvaluatedAt`
- `beforeSnapshotSha256`

Both values must be supplied together.

## Methodology catalog

`GET /api/v1/decision-methodologies` returns installed methodology identities. Ascending revision order is pagination-only and carries no source precedence, policy precedence, or recommendation.

`GET /api/v1/decision-methodologies/{revision}` reads one exact registered revision and returns its policy SHA, canonical payload, and explicit evidence-selection/freshness rules.

There is deliberately no `current`, `latest`, `default`, or `preferred` methodology endpoint.

## Authorization and capability disclosure

Read routes require `VIEWER`; Decision Input materialization requires `OPERATOR`. Route-specific authorization is resolved before the runtime capability is looked up, matching the Formula transport security ordering. An unauthenticated caller therefore receives `401`, and a Viewer attempting materialization receives `403`, before V23 availability can be inferred.

## Provenance returned to clients

Exact snapshot reads expose:

- snapshot contract, semantics, SHA, Finding ID, methodology revision/SHA, and `evaluatedAt`;
- canonical payload format and Base64 canonical payload;
- all seven dimension states;
- exact native evidence UUID/SHA/source/time references;
- exact binding UUID/SHA/source/time when the evidence depends on an explicit association.

Missing, stale, and ambiguous states remain distinct. The API never converts them to zero, safe, not reachable, low impact, or another fabricated evidence value.

## Formula handoff

The browser may use a snapshot SHA returned by this API as the selector for:

`POST /api/v1/formula-result-materializations/{inputSnapshotSha256}`

That separate Formula command accepts only the exact already-persisted Decision Input identity. It does not rebuild the Decision Input or consult current evidence/association state.
