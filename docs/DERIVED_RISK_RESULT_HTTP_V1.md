# Derived Risk Result HTTP V1

## Purpose

This contract exposes the two implemented derived-risk methodologies over HTTP without changing their independent semantics or introducing a platform winner.

The transport is a thin adapter over `RBVM_DERIVED_RISK_RESULT_API_V1`, `RBVM_DERIVED_RISK_METHODOLOGY_CATALOG_API_V1`, and `RBVM_DERIVED_RISK_RESULT_MATERIALIZATION_API_V1`. Successful result reads and materializations remain bound to exact Decision Input V3 provenance and deterministic historical replay.

## Runtime requirement

The transport is available only when PostgreSQL projection is active and schema V24 or newer is installed. If the runtime is unavailable, an authorized request receives HTTP `503` with `DERIVED_RISK_RESULT_PERSISTENCE_UNAVAILABLE`.

Authorization is resolved before runtime-capability lookup. An unauthenticated caller therefore receives `401`, and a viewer attempting materialization receives `403`, without learning whether V24 derived-risk persistence is enabled.

## Methodology catalog

`GET /api/v1/derived-risk-methodologies`

Requires `VIEWER` permission. The response contract is `RBVM_DERIVED_RISK_METHODOLOGY_CATALOG_API_V1` and declares:

`EXPLICIT_ID_AND_SHA_ONLY_NO_DEFAULT`

The catalog contains SHA-bound definitions for the implemented methodologies, currently `OWASP_DERIVED_RBVM_V1` and `MICROSOFT_PD_DERIVED_RBVM_V1`. Catalog order is deterministic representation only. It is not preference, precedence, ranking, or a default methodology.

## Exact result reads

Two immutable read forms are supported and require `VIEWER` permission:

`GET /api/v1/derived-risk-results/{resultSha256}`

and

`GET /api/v1/derived-risk-results?inputSnapshotSha256={sha256}&methodologyId={canonicalId}&methodologySha256={sha256}`

All three tuple selectors are required for the collection lookup. Unknown, duplicate, or additional query parameters are rejected. There is no `latest`, `current`, preferred-result, or fallback selector.

Before a successful response is returned, the persisted result is replayed from the exact persisted Decision Input V3 snapshot, its captured native evidence and association bindings, and the exact implemented methodology identity. A replay mismatch fails closed.

The response preserves methodology-native output semantics. `numericScore`, `numericScale`, and `rating` are not converted into a common cross-methodology scale. Terminal `NOT_APPLICABLE` and `NON_COMPUTABLE` results retain null numeric output rather than receiving fabricated values.

## Explicit materialization

`POST /api/v1/derived-risk-result-materializations/{inputSnapshotSha256}/{methodologyId}/{methodologySha256}`

Requires `OPERATOR` permission. The command accepts no request body and no query parameters. The complete immutable selection is explicit in the path:

- one already-persisted Decision Input V3 SHA-256;
- one canonical methodology ID;
- that methodology's exact canonical SHA-256.

A non-canonical methodology alias is not accepted as historical identity even if an internal catalog search could resolve it case-insensitively.

The first deterministic append returns HTTP `201` and `materializationStatus: INSERTED`. An exact retry returns HTTP `200` and `materializationStatus: REPLAYED` without creating another row. Both successful outcomes require deterministic replay verification and return `replayVerified: true`, a strong `ETag`, and a `Location` pointing to the exact `/api/v1/derived-risk-results/{resultSha256}` resource.

## Security and observability

Health exposes `derivedRiskResults` with catalog, read, materialization, and replay-verification capability flags. Prometheus-style metrics expose `rbvm_derived_risk_result_api_enabled` as `1` or `0`.

The transport uses the platform's existing bearer authentication, role authorization, rate limiting, correlation IDs, problem responses, no-store caching, and security headers.

## Explicit non-goals

This increment does not define a primary/preferred/default methodology. It does not average, normalize, merge, rank, or otherwise collapse OWASP-derived and Microsoft-derived outputs. It does not derive Priority, Treatment, SLA, remediation deadline, or workflow ranking. It does not add browser UI.

Those decisions, if introduced later, must remain a separate policy/UI layer over the exact methodology results rather than changing the historical result contract.
